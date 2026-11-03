"""End-to-end evaluation of BDC on real MCP servers (official Python SDK, Streamable HTTP).

Starts one authorization server and four MCP servers as separate processes, then runs
(1) attack tests, (2) per-call latency, (3) exchange latency, (4) throughput, (5) an offline
attenuation comparison (macaroons). Results -> results/mcp_eval.json
"""
import asyncio, json, os, subprocess, sys, time, statistics, platform
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import httpx2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from bdc2 import Agent, raw_priv, peek, sign, ub64, b64
from client import BDCAuth, BearerAuth, ASClient
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

PY = sys.executable
KEYS = os.path.join(HERE, 'keys')
AS = 'http://127.0.0.1:8100'
A_AUD, B_AUD = 'http://127.0.0.1:8101/mcp', 'http://127.0.0.1:8102/mcp'
BEAR, NONE = 'http://127.0.0.1:8103/mcp', 'http://127.0.0.1:8104/mcp'
N_LAT = int(os.environ.get('N_LAT', 500))


def start():
    os.makedirs(KEYS, exist_ok=True)
    open(os.path.join(KEYS, 'as.key'), 'wb').write(raw_priv(Ed25519PrivateKey.generate()))
    procs = [subprocess.Popen([PY, 'services.py', 'as', '--port', '8100', '--keydir', KEYS], cwd=HERE)]
    for port, aud, mode in [(8101, A_AUD, 'bdc'), (8102, B_AUD, 'bdc'), (8103, BEAR, 'bearer'), (8104, NONE, 'none')]:
        procs.append(subprocess.Popen([PY, 'services.py', 'mcp', '--port', str(port), '--keydir', KEYS,
                                       '--aud', aud, '--mode', mode], cwd=HERE))
    time.sleep(5)
    return procs


async def call(url, auth, tool='query_inventory', args=None):
    """One MCP session making one tools/call. Returns (accepted, detail)."""
    try:
        async with create_mcp_http_client(auth=auth) as http:
            async with Client(streamable_http_client(url, http_client=http)) as c:
                r = await c.call_tool(tool, args or {'model': 'civic'})
                return (not r.is_error), str(r.structured_content)
    except Exception as e:  # rejected at HTTP level (403) surfaces as a client error
        return False, type(e).__name__


def stats(url, reset=True):
    base = url.rsplit('/mcp', 1)[0]
    return httpx2.get(base + '/_stats' + ('?reset=1' if reset else '')).json()


class Tamper(BDCAuth):
    """Attack variants of the auth handler."""

    def auth_flow(self, request):
        url = f'{request.url.scheme}://{request.url.netloc.decode()}{request.url.path}'
        body = request.content
        if self.tamper == 'body' and b'tools/call' in body:
            body = body.replace(b'civic', b'f150')            # proof for a different argument
        if self.tamper == 'replay' and self.last is not None and b'tools/call' in request.content:
            pop = self.last
        else:
            pop = self.agent.proof(self.token, request.method, url, body, self.aud)
        if b'tools/call' in request.content:
            self.last = pop
        request.headers['Authorization'] = 'BDC ' + self.token
        if self.tamper != 'nopop':
            request.headers['BDC-PoP'] = pop
        yield request


async def replay_attack(agent, tok):
    """Capture a valid tools/call (token + proof) and resend it byte-for-byte."""
    cap = {}

    class Capture(BDCAuth):
        def auth_flow(self, request):
            url = f'{request.url.scheme}://{request.url.netloc.decode()}{request.url.path}'
            pop = self.agent.proof(self.token, request.method, url, request.content, self.aud)
            request.headers['Authorization'] = 'BDC ' + self.token
            request.headers['BDC-PoP'] = pop
            if b'tools/call' in request.content:
                cap['h'] = dict(request.headers); cap['b'] = request.content
            yield request
    ok1, _ = await call(A_AUD, Capture(agent, tok, A_AUD))
    stats(A_AUD)
    h = {k: v for k, v in cap['h'].items() if k.lower() not in ('content-length', 'host')}
    r = httpx2.post(A_AUD, headers=h, content=cap['b'])
    return ok1, r.status_code


async def attacks(asc, agents):
    a1, a2, a3, mal = agents
    out = []

    def rec(name, accepted, reason, expect):
        out.append(dict(test=name, accepted=accepted, reason=reason, expected=expect,
                        ok=(accepted == (expect == 'accept'))))

    gid = asc.consent('alice', a1.name, ['tool:query_inventory', 'tool:get_price'])
    t1 = asc.root(gid)[1]['token']
    t2 = asc.exchange(a1, t1, a2.name, 'as', ['tool:query_inventory', 'tool:get_price'])[1]['token']
    st, r = asc.exchange(a2, t2, a3.name, A_AUD, ['tool:query_inventory'])
    t3 = r['token']
    stats(A_AUD)
    ok, _ = await call(A_AUD, BDCAuth(a3, t3, A_AUD))
    rec('honest three-agent chain, in-scope tool', ok, 'accept' if ok else stats(A_AUD)['decisions'], 'accept')
    ok, _ = await call(A_AUD, BDCAuth(a3, t3, A_AUD), 'update_price', {'model': 'civic', 'price': 1})
    rec('tool outside the token scope', ok, stats(A_AUD)['decisions'], 'reject')
    st, r = asc.exchange(a2, t2, a3.name, A_AUD, ['tool:update_price'])
    rec('re-delegation requests a broader scope', st == 200, r.get('error'), 'reject')
    st, r = asc.exchange(mal, t2, mal.name, A_AUD, ['tool:query_inventory'])
    rec('stolen token exchanged by another agent', st == 200, r.get('error'), 'reject')
    ok, _ = await call(A_AUD, BDCAuth(mal, t3, A_AUD))
    rec('stolen token presented with attacker key', ok, stats(A_AUD)['decisions'], 'reject')
    st, r = asc.exchange(a3, t3, a1.name, A_AUD, ['tool:query_inventory'])
    rec('resource token used as a delegation credential', st == 200, r.get('error'), 'reject')
    st, r = asc.register(Agent(a2.name))                # attacker re-registers an honest agent's name with its own key
    rec('agent identity re-registered with another key', st == 200, r.get('error'), 'reject')
    ok, _ = await call(A_AUD, Tamper(a3, t3, A_AUD, tamper='nopop'))
    rec('token without proof of possession', ok, stats(A_AUD)['decisions'], 'reject')
    ok, _ = await call(A_AUD, Tamper(a3, t3, A_AUD, tamper='body'))
    rec('request body altered after signing', ok, stats(A_AUD)['decisions'], 'reject')
    ok1, code = await replay_attack(a3, t3)
    rec('captured request replayed', code == 200, stats(A_AUD)['decisions'], 'reject')
    ok, _ = await call(B_AUD, BDCAuth(a3, t3, B_AUD))
    rec('token presented at another MCP server', ok, stats(B_AUD)['decisions'], 'reject')
    p = peek(t3); p['act'] = [a1.name, a3.name]                          # drop a hop from the chain
    forged = b64(json.dumps(p, separators=(',', ':'), sort_keys=True).encode()) + '.' + t3.split('.')[1]
    ok, _ = await call(A_AUD, BDCAuth(a3, forged, A_AUD))
    rec('actor chain edited in the token', ok, stats(A_AUD)['decisions'], 'reject')
    asc.revoke(gid)
    st, r = asc.exchange(a2, t2, a3.name, A_AUD, ['tool:query_inventory'])
    rec('exchange after the user revokes the grant', st == 200, r.get('error'), 'reject')
    ok, _ = await call(A_AUD, BDCAuth(a3, t3, A_AUD))
    rec('already-issued token after revocation (until expiry)', ok, 'accepted within TTL', 'accept')
    # baseline: audience-restricted bearer token (current MCP profile)
    gid2 = asc.consent('alice', a1.name, ['tool:query_inventory'])
    bt = asc.bearer(gid2, BEAR)
    ok, _ = await call(BEAR, BearerAuth(bt))
    rec('[bearer] honest request', ok, 'accept', 'accept')
    ok, _ = await call(BEAR, BearerAuth(bt))
    rec('[bearer] stolen token used by another party', ok, 'no holder check', 'accept')
    ok, _ = await call(BEAR.replace('8103', '8101'), BearerAuth(bt))
    rec('[bearer] token at another server', ok, 'audience', 'reject')
    return out


async def latency():
    res = {}
    asc = ASClient(AS)
    agents = [Agent(f'agent{i}') for i in range(8)]
    for a in agents:
        asc.register(a)
    scope = ['tool:query_inventory', 'tool:get_price']
    gid = asc.consent('bob', agents[0].name, scope)
    toks = {1: asc.root(gid)[1]['token']}
    # exchange latency over HTTP (AS round trip), per hop
    ex = []
    for _ in range(300):
        t0 = time.perf_counter(); asc.exchange(agents[0], toks[1], agents[1].name, A_AUD, scope)
        ex.append((time.perf_counter() - t0) * 1e3)
    res['exchange_http_ms'] = dict(median=statistics.median(ex), p99=sorted(ex)[int(0.99 * len(ex)) - 1])
    tok = toks[1]
    for h in range(1, 6):
        # resource token for a chain of h+1 agents, and the delegation credential to extend the chain
        final = asc.exchange(agents[h - 1], tok, agents[h].name, A_AUD, scope)[1]['token']
        toks[h + 1] = (final, agents[h])
        tok = asc.exchange(agents[h - 1], tok, agents[h].name, 'as', scope)[1]['token']

    async def loop_raw(url, auth, n):
        xs = []
        async with create_mcp_http_client(auth=auth) as http:
            async with Client(streamable_http_client(url, http_client=http)) as c:
                for i in range(n + 50):
                    t0 = time.perf_counter()
                    await c.call_tool('query_inventory', {'model': 'civic'})
                    if i >= 50:
                        xs.append((time.perf_counter() - t0) * 1e3)
        return xs

    gidb = asc.consent('bob', agents[0].name, scope)
    bt = asc.bearer(gidb, BEAR)
    configs = [('none', NONE, lambda: None), ('bearer', BEAR, lambda: BearerAuth(bt))]
    configs += [(f'bdc{L}', A_AUD, (lambda L=L: BDCAuth(toks[L][1], toks[L][0], A_AUD))) for L in (2, 3, 4, 5, 6)]
    samples = {k: [] for k, _, _ in configs}
    guard = {k: [] for k, _, _ in configs}
    rounds = 5
    for r in range(rounds):                       # interleave configurations to cancel drift
        for k, url, mk in configs:
            if url != NONE:
                stats(url)
            xs = await loop_raw(url, mk(), N_LAT // rounds)
            samples[k] += xs
            if url != NONE:
                guard[k] += [stats(url)['median_us']]
    for k, _, _ in configs:
        xs = sorted(samples[k])
        res[k] = dict(median=statistics.median(xs), p99=xs[int(0.99 * len(xs)) - 1], n=len(xs),
                      guard_median_us=statistics.median(guard[k]) if guard[k] else None)
    for L in (2, 3, 4, 5, 6):
        res[f'bdc{L}']['token_bytes'] = len(toks[L][0])
    res['bearer']['token_bytes'] = len(bt)
    return res


async def throughput(conc=8, secs=8):
    asc = ASClient(AS)
    a = [Agent('t0'), Agent('t1')]
    for x in a:
        asc.register(x)
    scope = ['tool:query_inventory']
    gid = asc.consent('carol', 't0', scope)
    t1 = asc.root(gid)[1]['token']
    t2 = asc.exchange(a[0], t1, 't1', A_AUD, scope)[1]['token']
    bt = asc.bearer(gid, BEAR)
    out = {}
    for name, url, mk in [('none', NONE, lambda: None), ('bearer', BEAR, lambda: BearerAuth(bt)),
                          ('bdc', A_AUD, lambda: BDCAuth(a[1], t2, A_AUD))]:
        stop = time.perf_counter() + secs
        count = [0]

        async def worker():
            async with create_mcp_http_client(auth=mk()) as http:
                async with Client(streamable_http_client(url, http_client=http)) as c:
                    while time.perf_counter() < stop:
                        await c.call_tool('query_inventory', {'model': 'civic'})
                        count[0] += 1
        await asyncio.gather(*[worker() for _ in range(conc)])
        out[name] = count[0] / secs
    out['concurrency'] = conc
    return out


def macaroons():
    """Offline attenuation baseline: one first-party caveat per hop (actor + scope), HMAC chain."""
    from pymacaroons import Macaroon, Verifier
    key = os.urandom(32)
    rows = {}
    for L in (2, 3, 4, 5, 6):
        m = Macaroon(location='as', identifier='grant-1', key=key)
        m.add_first_party_caveat('sub = alice')
        m.add_first_party_caveat('scope = tool:query_inventory,tool:get_price')
        for h in range(1, L):
            m = Macaroon.deserialize(m.serialize())
            m.add_first_party_caveat(f'act{h} = agent{h}')
            m.add_first_party_caveat('scope = tool:query_inventory')
        s = m.serialize()
        xs = []
        for _ in range(3000):
            t0 = time.perf_counter()
            v = Verifier(); v.satisfy_general(lambda c: True)
            v.verify(Macaroon.deserialize(s), key)
            xs.append((time.perf_counter() - t0) * 1e6)
        rows[L] = dict(bytes=len(s), verify_median_us=statistics.median(xs))
    return rows


async def main():
    procs = start()
    try:
        asc = ASClient(AS)
        agents = [Agent('orchestrator'), Agent('pricing-agent'), Agent('inventory-agent'), Agent('mallory')]
        for a in agents:
            asc.register(a)
        res = dict(env=dict(python=platform.python_version(), cpus=os.cpu_count(),
                            cpu=platform.processor() or platform.machine()))
        res['attacks'] = await attacks(asc, agents)
        for t in res['attacks']:
            print(('PASS ' if t['ok'] else 'FAIL ') + t['test'], '|', t['reason'])
        res['latency'] = await latency()
        print(json.dumps(res['latency'], indent=1)[:2500])
        res['throughput'] = await throughput()
        print(res['throughput'])
        res['macaroons'] = macaroons()
        print(res['macaroons'])
        os.makedirs(os.path.join(HERE, '..', 'results'), exist_ok=True)
        json.dump(res, open(os.path.join(HERE, '..', 'results', 'mcp_eval.json'), 'w'), indent=1, default=str)
    finally:
        for p in procs:
            p.terminate()


if __name__ == '__main__':
    asyncio.run(main())
