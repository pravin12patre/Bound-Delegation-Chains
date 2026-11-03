"""Strong standards baseline: OAuth 2.0 token exchange (RFC 8693) with DPoP (RFC 9449), resource
indicators (RFC 8707), nested `act` claims, and enforced scope attenuation at every exchange.

Delegation follows RFC 8693: the delegate (new actor) authenticates to the AS with its own key
(private_key_jwt-style signed request), presents the delegator's token as `subject_token`, requests a
scope and a resource, and a DPoP proof binds the new token to the delegate's key. As in RFC 8693, the AS
validates the subject token but does not require proof of possession of it, and nested `act` claims are
informational (RFC 8693, Sec. 4.1); `may_act` (Sec. 4.4) is honored when present.
Resources verify the AS signature, expiry, audience, scope and a DPoP proof (htm, htu, ath, jti, iat)
with a jti replay cache. Token revocation (RFC 7009) revokes an individual token.
"""
import os, time, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from bdc2 import sign, verify, peek, Reject, b64, ub64, sha, raw_pub
from constraints import scope_covers, allows


class OAuthAS:
    """hardened=True adds AS policy that RFC 8693 permits but does not require: the subject token's holder
    must countersign each exchange (naming the actor, scope and resource), tokens carry a lineage id `sid`,
    and revoking a token revokes its whole lineage at the AS. Resources then also check a body hash."""
    def __init__(self, sk, ttl=60, hardened=False):
        self.sk, self.pk, self.ttl, self.hardened = sk, sk.public_key(), ttl, hardened
        self.registry, self.revoked_jti, self.revoked_sid = {}, set(), set()

    def register(self, client_id, pk):
        old = self.registry.get(client_id)
        if old is not None and raw_pub(old) != raw_pub(pk):
            raise Reject('client already registered')
        self.registry[client_id] = pk

    def _tok(self, sub, client, act, aud, scope, exp, may_act=None, sid=None):
        now = int(time.time())
        c = dict(typ='at+jwt', sub=sub, client_id=client, aud=aud, scope=sorted(scope),
                 cnf=b64(raw_pub(self.registry[client])), iat=now, exp=min(exp, now + self.ttl), jti=b64(os.urandom(9)))
        if self.hardened:
            c['sid'] = sid or b64(os.urandom(9))
        if act:
            c['act'] = act
        if may_act:
            c['may_act'] = {'sub': may_act}
        return sign(c, self.sk)

    def issue(self, user, client, scope, aud='as', may_act=None):
        return self._tok(user, client, None, aud, scope, int(time.time()) + self.ttl, may_act)

    def token_exchange(self, request):
        """request: signed by the requesting client (the new actor):
           {grant_type, subject_token, client_id, scope, resource, nonce}"""
        body = peek(request)
        client = body['client_id']
        if client not in self.registry:
            raise Reject('unknown client')
        verify(request, self.registry[client])                         # client authentication + DPoP key
        st = verify(body['subject_token'], self.pk)                     # subject token valid
        if st['exp'] < time.time():
            raise Reject('expired')
        if st['jti'] in self.revoked_jti:
            raise Reject('revoked')
        if 'may_act' in st and st['may_act'].get('sub') != client:
            raise Reject('may_act')
        if self.hardened:
            if st.get('sid') in self.revoked_sid:
                raise Reject('revoked lineage')
            try:                                                         # holder of the subject token approves
                ap = verify(body['subject_proof'], Ed25519PublicKey.from_public_bytes(ub64(st['cnf'])))
            except (KeyError, Reject):
                raise Reject('no holder approval')
            if ap.get('th') != sha(body['subject_token']) or ap.get('actor') != client \
                    or ap.get('resource') != body['resource'] or sorted(ap.get('scope', [])) != sorted(body['scope']):
                raise Reject('holder approval mismatch')
        if not scope_covers(st['scope'], body['scope']):
            raise Reject('escalation')                                   # enforced attenuation
        prev = {'sub': st['client_id']}
        if 'act' in st:
            prev['act'] = st['act']                                      # nested act: informational
        return self._tok(st['sub'], client, prev, body['resource'], body['scope'], st['exp'], sid=st.get('sid'))

    def revoke_token(self, tok):                                         # RFC 7009: this token only
        p = peek(tok)
        self.revoked_jti.add(p['jti'])
        if self.hardened and 'sid' in p:
            self.revoked_sid.add(p['sid'])                               # hardened: the whole lineage


def te_request(client_name, client_sk, subject_token, scope, resource, subject_proof=None):
    d = dict(grant_type='urn:ietf:params:oauth:grant-type:token-exchange', subject_token=subject_token,
             client_id=client_name, scope=sorted(scope), resource=resource, nonce=b64(os.urandom(12)))
    if subject_proof:
        d['subject_proof'] = subject_proof
    return sign(d, client_sk)


def holder_approval(holder_sk, subject_token, actor, scope, resource):
    return sign(dict(th=sha(subject_token), actor=actor, scope=sorted(scope), resource=resource,
                     nonce=b64(os.urandom(12)), iat=int(time.time())), holder_sk)


def dpop_proof(sk, tok, method, url, body=None):
    d = dict(htm=method, htu=url, ath=sha(tok), jti=b64(os.urandom(12)), iat=int(time.time()))
    if body is not None:
        d['bh'] = sha(body)                                              # hardened: content digest covered
    return sign(d, sk)


class DPoPGuard:
    def __init__(self, aud, as_pk, skew=60, hardened=False):
        self.aud, self.as_pk, self.skew, self.cache, self.hardened = aud, as_pk, skew, {}, hardened

    def check(self, tok, proof, method, url, op, args, body=b''):
        t = verify(tok, self.as_pk)
        if t['exp'] < time.time():
            raise Reject('expired')
        if t['aud'] != self.aud:
            raise Reject('audience')
        p = verify(proof, Ed25519PublicKey.from_public_bytes(ub64(t['cnf'])))
        if p['htm'] != method or p['htu'] != url or p['ath'] != sha(tok):
            raise Reject('proof binding')
        if self.hardened and p.get('bh') != sha(body):
            raise Reject('proof binding')
        now = time.time()
        if abs(now - p['iat']) > self.skew:
            raise Reject('stale proof')
        if self.cache.get(p['jti'], 0) > now:
            raise Reject('replay')
        self.cache[p['jti']] = now + 2 * self.skew
        if op is not None and not allows(t['scope'], op, args):
            raise Reject('scope')
        return t
