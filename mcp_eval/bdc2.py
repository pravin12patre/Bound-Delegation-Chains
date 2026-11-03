"""Bound Delegation Chains (BDC), HTTP profile used with MCP.

Token (JSON, Ed25519-signed by the AS, compact form payload.signature):
  typ, sub (user), gid (consent grant id), act (ordered actor chain), aud (resource URI),
  scope (sorted list), cnf (holder public key, base64url), iat, exp, jti
Exchange request (signed by the current holder): tok, to (next agent), aud, scope, nonce, iat
Request proof (header BDC-PoP, signed by the holder):
  th = SHA-256(token), htm, htu, bh = SHA-256(body), aud, nonce, iat
"""
import base64, hashlib, json, os, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
ub64 = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
sha = lambda b: b64(hashlib.sha256(b if isinstance(b, bytes) else b.encode()).digest())
raw_pub = lambda k: k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
raw_priv = lambda k: k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                     serialization.NoEncryption())


from constraints import scope_covers, allows as scope_allows, parse as parse_entry, ConstraintError


class Reject(Exception):
    """Authorization failure, with a short reason."""


def sign(obj, sk):
    p = json.dumps(obj, separators=(',', ':'), sort_keys=True).encode()
    return b64(p) + '.' + b64(sk.sign(p))


def verify(tok, pk):
    try:
        p, s = tok.split('.')
        pk.verify(ub64(s), ub64(p))
    except (InvalidSignature, ValueError) as e:
        raise Reject('signature') from e
    return json.loads(ub64(p))


def peek(tok):
    return json.loads(ub64(tok.split('.')[0]))


class AuthorizationServer:
    def __init__(self, sk=None, ttl=60):
        self.sk = sk or Ed25519PrivateKey.generate(); self.pk = self.sk.public_key()
        self.ttl = ttl
        self.registry, self.consents, self.revoked, self.seen = {}, {}, set(), set()

    def register(self, agent_id, pk):
        """One key per agent identity (the model's OneKeyPerAgent): re-registration with another key is refused."""
        old = self.registry.get(agent_id)
        if old is not None and raw_pub(old) != raw_pub(pk):
            raise Reject('agent already registered')
        self.registry[agent_id] = pk

    def consent(self, user, agent, scope):
        for e in scope:
            parse_entry(e)                                                      # canonical entries only
        gid = b64(os.urandom(9))
        self.consents[gid] = (user, agent, set(scope))
        return gid

    def revoke(self, gid):
        self.revoked.add(gid)
        return sign(dict(revoke=gid, iat=int(time.time())), self.sk)          # notice to push to resources

    def _tok(self, sub, gid, act, aud, scope, holder, exp):
        now = int(time.time())
        return sign(dict(typ='bdc', sub=sub, gid=gid, act=act, aud=aud, scope=sorted(scope),
                         cnf=b64(raw_pub(self.registry[holder])), iat=now, exp=min(exp, now + self.ttl),
                         jti=b64(os.urandom(9))), self.sk)

    def issue_root(self, gid):
        if gid in self.revoked:
            raise Reject('revoked')
        user, agent, scope = self.consents[gid]
        return self._tok(user, gid, [agent], 'as', scope, agent, int(time.time()) + self.ttl)

    def exchange(self, request):
        body = json.loads(ub64(request.split('.')[0]))
        t = verify(body['tok'], self.pk)                                        # AS signature
        verify(request, Ed25519PublicKey.from_public_bytes(ub64(t['cnf'])))     # holder signed the request
        if t['exp'] < time.time():
            raise Reject('expired')
        if t['gid'] in self.revoked:
            raise Reject('revoked')                                             # revocation
        if t['aud'] != 'as':
            raise Reject('not a delegation credential')                         # purpose separation
        if body['nonce'] in self.seen:
            raise Reject('replay')
        self.seen.add(body['nonce'])
        try:
            covered = scope_covers(t['scope'], body['scope'])
        except ConstraintError:
            raise Reject('malformed scope')
        if not covered:
            raise Reject('escalation')                                          # attenuation
        if body['to'] not in self.registry:
            raise Reject('unknown agent')
        return self._tok(t['sub'], t['gid'], t['act'] + [body['to']], body['aud'], body['scope'],
                         body['to'], t['exp'])

    def bearer_for(self, gid, aud):
        """Baseline: an audience-restricted bearer access token (what MCP's OAuth profile requires)."""
        user, agent, scope = self.consents[gid]
        return self._tok(user, gid, [agent], aud, scope, agent, int(time.time()) + self.ttl)


class Agent:
    def __init__(self, name, sk=None):
        self.name = name; self.sk = sk or Ed25519PrivateKey.generate(); self.pk = self.sk.public_key()

    def delegation_request(self, tok, to, aud, scope):
        return sign(dict(tok=tok, to=to, aud=aud, scope=sorted(scope), nonce=b64(os.urandom(12)),
                         iat=int(time.time())), self.sk)

    def proof(self, tok, method, url, body, aud):
        return sign(dict(th=sha(tok), htm=method, htu=url, bh=sha(body), aud=aud, nonce=b64(os.urandom(12)),
                         iat=int(time.time())), self.sk)


class ResourceGuard:
    """Checks a request at an MCP server (resource) with audience `aud`."""

    def __init__(self, aud, as_pk, skew=60):
        self.aud, self.as_pk, self.skew = aud, as_pk, skew
        self.cache = {}                                                         # nonce -> expiry
        self.revoked = set()                                                    # grants revoked by AS push
        self.nonce_store = None                                                 # optional shared store (async)

    def _fresh(self, nonce, iat):
        now = time.time()
        if abs(now - iat) > self.skew:
            raise Reject('stale proof')
        if len(self.cache) > 100000:
            self.cache = {n: e for n, e in self.cache.items() if e > now}
        if self.cache.get(nonce, 0) > now:
            raise Reject('replay')
        self.cache[nonce] = now + 2 * self.skew

    def revoke_notice(self, notice):
        """Signed revocation pushed by the AS: {'revoke': gid, 'iat': ...}."""
        d = verify(notice, self.as_pk)
        self.revoked.add(d['revoke'])

    def check(self, tok, pop, method, url, body, op, args=None, nonce_check=True):
        t = verify(tok, self.as_pk)
        if t['exp'] < time.time():
            raise Reject('expired')
        if t['gid'] in self.revoked:
            raise Reject('revoked')
        if t['aud'] != self.aud:
            raise Reject('audience')
        p = verify(pop, Ed25519PublicKey.from_public_bytes(ub64(t['cnf'])))    # holder proof
        if p['th'] != sha(tok) or p['htm'] != method or p['htu'] != url or p['bh'] != sha(body) \
                or p['aud'] != self.aud:
            raise Reject('proof binding')
        if nonce_check:
            self._fresh(p['nonce'], p['iat'])
        if op is not None and not scope_allows(t['scope'], op, args):
            raise Reject('scope')
        t['_pop'] = p
        return t

    def check_bearer(self, tok, op, args=None):
        t = verify(tok, self.as_pk)
        if t['exp'] < time.time():
            raise Reject('expired')
        if t['aud'] != self.aud:
            raise Reject('audience')
        if op is not None and not scope_allows(t['scope'], op, args):
            raise Reject('scope')
        return t
