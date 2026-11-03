"""Client side of the MCP evaluation: agents, AS calls and an httpx2 auth handler that attaches BDC proofs."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpx2
from bdc2 import Agent, b64, raw_pub


class BDCAuth(httpx2.Auth):
    """Signs every MCP HTTP request: Authorization: BDC <token>, BDC-PoP: proof over method, URL, body."""
    requires_request_body = True

    def __init__(self, agent, token, aud, tamper=None):
        self.agent, self.token, self.aud, self.tamper = agent, token, aud, tamper
        self.last = None

    def auth_flow(self, request):
        url = f'{request.url.scheme}://{request.url.netloc.decode()}{request.url.path}'
        body = request.content
        pop = self.agent.proof(self.token, request.method, url, body, self.aud)
        if self.tamper == 'replay' and self.last and request.method == 'POST':
            pop = self.last                                   # resend an earlier proof
        if request.method == 'POST':
            self.last = pop
        request.headers['Authorization'] = 'BDC ' + self.token
        request.headers['BDC-PoP'] = pop
        yield request


class BearerAuth(httpx2.Auth):
    def __init__(self, token):
        self.token = token

    def auth_flow(self, request):
        request.headers['Authorization'] = 'Bearer ' + self.token
        yield request


class ASClient:
    def __init__(self, base):
        self.base = base
        self.http = httpx2.Client(timeout=30)

    def post(self, path, **kw):
        r = self.http.post(self.base + path, **kw)
        return r.status_code, r.json()

    def register(self, agent):
        return self.post('/register', json={'agent': agent.name, 'pk': b64(raw_pub(agent.pk))})

    def consent(self, user, agent, scope):
        return self.post('/consent', json={'user': user, 'agent': agent, 'scope': scope})[1]['gid']

    def root(self, gid):
        return self.post('/root', json={'gid': gid})

    def bearer(self, gid, aud):
        return self.post('/bearer', json={'gid': gid, 'aud': aud})[1]['token']

    def exchange(self, holder, tok, to, aud, scope):
        return self.post('/exchange', content=holder.delegation_request(tok, to, aud, scope))

    def revoke(self, gid):
        return self.post('/revoke', json={'gid': gid})


class DPoPAuth(httpx2.Auth):
    """RFC 9449-style client: Authorization: DPoP <token>, DPoP: proof over method, URL and token hash."""
    requires_request_body = True

    def __init__(self, sk, token, body_swap=None, cover_body=False):
        self.sk, self.token, self.body_swap, self.cover_body = sk, token, body_swap, cover_body

    def auth_flow(self, request):
        from oauth_strong import dpop_proof
        url = f'{request.url.scheme}://{request.url.netloc.decode()}{request.url.path}'
        request.headers['Authorization'] = 'DPoP ' + self.token
        request.headers['DPoP'] = dpop_proof(self.sk, self.token, request.method, url,
                                             request.content if self.cover_body else None)
        if self.body_swap and b'tools/call' in request.content:      # on-path change after the proof was made
            a, b = self.body_swap
            new = request.content.replace(a, b)
            request.stream = httpx2.ByteStream(new) if hasattr(httpx2, 'ByteStream') else new
            request._content = new
            request.headers['Content-Length'] = str(len(new))
        yield request
