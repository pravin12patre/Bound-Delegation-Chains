"""BDC versus the strongest standards composition: OAuth token exchange (RFC 8693) + DPoP (RFC 9449)
+ resource indicators + enforced attenuation (+ optional may_act), on real MCP servers.
Results -> results/oauth_compare.json"""
import asyncio, json, os, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import httpx2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from bdc2 import Agent, raw_priv, b64, raw_pub
from client import BDCAuth, DPoPAuth, ASClient
from oauth_strong import te_request, holder_approval
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

PY = sys.executable
K = os.path.join(HERE, 'keys_cmp'); os.makedirs(K, exist_ok=True)
open(os.path.join(K, 'as.key'), 'wb').write(raw_priv(Ed25519PrivateKey.generate()))
U = lambda p: f'http://127.0.0.1:{p}'
ASP, BX, BY, DX, DY, HX, HY = 8700, 8701, 8702, 8711, 8712, 8721, 8722
AUD = {p: U(p) + '/mcp' for p in (BX, BY, DX, DY, HX, HY)}
procs = []


def start():
    procs.append(subprocess.Popen([PY, 'services.py', 'as', '--port', str(ASP), '--keydir', K,
                                   '--push', f'{U(BX)}/_revoke,{U(BY)}/_revoke'], cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    for p, mode in [(BX, 'bdc'), (BY, 'bdc'), (DX, 'dpop'), (DY, 'dpop'), (HX, 'dpoph'), (HY, 'dpoph')]:
        procs.append(subprocess.Popen([PY, 'services.py', 'mcp', '--port', str(p), '--keydir', K, '--aud', AUD[p], '--mode', mode],
                                      cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(6)


async def call(url, auth, tool='query_inventory', args=None):
    try:
        async with create_mcp_http_client(auth=auth) as http:
            async with Client(streamable_http_client(url, http_client=http)) as c:
                r = await c.call_tool(tool, args or {'model': 'civic'})
                return not r.is_error
    except Exception:
        return False


class BDCSwap(BDCAuth):
    """BDC client whose request body is changed on path after the proof was computed."""
    def auth_flow(self, request):
        url = f'{request.url.scheme}://{request.url.netloc.decode()}{request.url.path}'
        pop = self.agent.proof(self.token, request.method, url, request.content, self.aud)
        request.headers['Authorization'] = 'BDC ' + self.token; request.headers['BDC-PoP'] = pop
        if b'tools/call' in request.content:
            new = request.content.replace(b'civic', b'f150')
            request.stream = httpx2.ByteStream(new); request._content = new; request.headers['Content-Length'] = str(len(new))
        yield request


def te(path, **kw):
    r = httpx2.post(U(ASP) + path, **kw)
    return r.status_code, r.json()


async def main():
    start()
    out = []
    try:
        asc = ASClient(U(ASP))
        a1, a2, a3, m = Agent('orchestrator'), Agent('pricing-agent'), Agent('inventory-agent'), Agent('other-org-agent')
        for a in (a1, a2, a3, m):
            asc.register(a)
            te('/te/register', json={'agent': a.name, 'pk': b64(raw_pub(a.pk))})
        scope = ['tool:query_inventory', 'tool:get_price']

        def bdc_chain():
            gid = asc.consent('alice', a1.name, scope)
            t1 = asc.root(gid)[1]['token']
            t2 = asc.exchange(a1, t1, a2.name, 'as', scope)[1]['token']
            t3 = asc.exchange(a2, t2, a3.name, AUD[BX], ['tool:query_inventory'])[1]['token']
            return gid, t1, t2, t3

        def oauth_chain(may_act=False):
            t1 = te('/te/issue', json={'user': 'alice', 'client': a1.name, 'scope': scope, 'may_act': a2.name if may_act else None})[1]['token']
            t2 = te('/te/exchange', content=te_request(a2.name, a2.sk, t1, scope, 'as'))[1]['token']
            t3 = te('/te/exchange', content=te_request(a3.name, a3.sk, t2, ['tool:query_inventory'], AUD[DX]))[1]['token']
            return t1, t2, t3

        res = {}
        for scheme in ('BDC', 'OAuth TE+DPoP', 'OAuth TE+DPoP+may_act', 'OAuth TE+DPoP hardened'):
            r = {}
            if scheme == 'BDC':
                gid, t1, t2, t3 = bdc_chain()
                r['honest three-agent chain'] = await call(AUD[BX], BDCAuth(a3, t3, AUD[BX]))
                # a token that reached another agent is exchanged by it (stolen token / chain splicing)
                st, j = asc.exchange(m, t2, m.name, AUD[BX], ['tool:query_inventory'])
                r['delegator token exchanged by another agent (splicing)'] = st == 200
                st, j = asc.exchange(m, t1, m.name, AUD[BX], ['tool:query_inventory'])
                r['root token exchanged by another agent (splicing)'] = st == 200
                r['delegated token used with attacker key'] = await call(AUD[BX], BDCAuth(m, t3, AUD[BX]))
                r['request body changed after the proof'] = await call(AUD[BX], BDCSwap(a3, t3, AUD[BX]))
                st, _ = asc.exchange(a2, t2, a3.name, AUD[BX], ['tool:update_price'])
                r['re-delegation asks for a broader scope'] = st == 200
                r['token at another MCP server'] = await call(AUD[BY], BDCAuth(a3, t3, AUD[BY]))
                r['tool outside the token scope'] = await call(AUD[BX], BDCAuth(a3, t3, AUD[BX]), 'update_price', {'model': 'civic', 'price': 1})
                asc.revoke(gid); time.sleep(0.2)
                st, _ = asc.exchange(a2, t2, a3.name, AUD[BX], ['tool:query_inventory'])
                r['after revoking the user\'s authority: further delegation'] = st == 200
                r['after revoking the user\'s authority: downstream token'] = await call(AUD[BX], BDCAuth(a3, t3, AUD[BX]))
            elif scheme.endswith('hardened'):
                P = '/teh'
                t1 = te(P + '/issue', json={'user': 'alice', 'client': a1.name, 'scope': scope})[1]['token']
                t2 = te(P + '/exchange', content=te_request(a2.name, a2.sk, t1, scope, 'as', holder_approval(a1.sk, t1, a2.name, scope, 'as')))[1]['token']
                t3 = te(P + '/exchange', content=te_request(a3.name, a3.sk, t2, ['tool:query_inventory'], AUD[HX],
                                                             holder_approval(a2.sk, t2, a3.name, ['tool:query_inventory'], AUD[HX])))[1]['token']
                H = lambda sk, t, **kw: DPoPAuth(sk, t, cover_body=True, **kw)
                r['honest three-agent chain'] = await call(AUD[HX], H(a3.sk, t3))
                st, j = te(P + '/exchange', content=te_request(m.name, m.sk, t2, ['tool:query_inventory'], AUD[HX],
                                                               holder_approval(m.sk, t2, m.name, ['tool:query_inventory'], AUD[HX])))
                r['delegator token exchanged by another agent (splicing)'] = st == 200
                st, j = te(P + '/exchange', content=te_request(m.name, m.sk, t1, ['tool:query_inventory'], AUD[HX],
                                                               holder_approval(m.sk, t1, m.name, ['tool:query_inventory'], AUD[HX])))
                r['root token exchanged by another agent (splicing)'] = st == 200
                r['delegated token used with attacker key'] = await call(AUD[HX], H(m.sk, t3))
                r['request body changed after the proof'] = await call(AUD[HX], H(a3.sk, t3, body_swap=(b'civic', b'f150')))
                st, _ = te(P + '/exchange', content=te_request(a3.name, a3.sk, t2, ['tool:update_price'], AUD[HX],
                                                               holder_approval(a2.sk, t2, a3.name, ['tool:update_price'], AUD[HX])))
                r['re-delegation asks for a broader scope'] = st == 200
                r['token at another MCP server'] = await call(AUD[HY], H(a3.sk, t3))
                r['tool outside the token scope'] = await call(AUD[HX], H(a3.sk, t3), 'update_price', {'model': 'civic', 'price': 1})
                te(P + '/revoke', json={'token': t1})
                st, _ = te(P + '/exchange', content=te_request(a3.name, a3.sk, t2, ['tool:query_inventory'], AUD[HX],
                                                               holder_approval(a2.sk, t2, a3.name, ['tool:query_inventory'], AUD[HX])))
                r['after revoking the user\'s authority: further delegation'] = st == 200
                r['after revoking the user\'s authority: downstream token'] = await call(AUD[HX], H(a3.sk, t3))
            else:
                ma = scheme.endswith('may_act')
                t1, t2, t3 = oauth_chain(ma)
                r['honest three-agent chain'] = await call(AUD[DX], DPoPAuth(a3.sk, t3))
                st, j = te('/te/exchange', content=te_request(m.name, m.sk, t2, ['tool:query_inventory'], AUD[DX]))
                r['delegator token exchanged by another agent (splicing)'] = st == 200
                if st == 200:
                    r['  ... attacker then calls the tool with that token'] = await call(AUD[DX], DPoPAuth(m.sk, j['token']))
                st, j = te('/te/exchange', content=te_request(m.name, m.sk, t1, ['tool:query_inventory'], AUD[DX]))
                r['root token exchanged by another agent (splicing)'] = st == 200
                r['delegated token used with attacker key'] = await call(AUD[DX], DPoPAuth(m.sk, t3))
                r['request body changed after the proof'] = await call(AUD[DX], DPoPAuth(a3.sk, t3, body_swap=(b'civic', b'f150')))
                st, _ = te('/te/exchange', content=te_request(a3.name, a3.sk, t2, ['tool:update_price'], AUD[DX]))
                r['re-delegation asks for a broader scope'] = st == 200
                r['token at another MCP server'] = await call(AUD[DY], DPoPAuth(a3.sk, t3))
                r['tool outside the token scope'] = await call(AUD[DX], DPoPAuth(a3.sk, t3), 'update_price', {'model': 'civic', 'price': 1})
                te('/te/revoke', json={'token': t1})          # RFC 7009 revocation of the user's (root) token
                st, _ = te('/te/exchange', content=te_request(a3.name, a3.sk, t2, ['tool:query_inventory'], AUD[DX]))
                r['after revoking the user\'s authority: further delegation'] = st == 200
                r['after revoking the user\'s authority: downstream token'] = await call(AUD[DX], DPoPAuth(a3.sk, t3))
            res[scheme] = r
            print(scheme, json.dumps(r, indent=0), flush=True)
        # also report what the resource can rely on in the accepted token
        json.dump(res, open(os.path.join(HERE, '..', 'results', 'oauth_compare.json'), 'w'), indent=1)
    finally:
        for p in procs:
            p.terminate()


if __name__ == '__main__':
    asyncio.run(main())
