"""Experiments added in revision: push revocation, parameter-constrained scopes, replicated MCP servers
(replay across replicas), wide-area round trips, and token size with enterprise identifiers.
Results -> results/revision.json
"""
import asyncio, json, os, subprocess, sys, time, statistics, hashlib
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import httpx2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from bdc2 import Agent, AuthorizationServer, ResourceGuard, Reject, raw_priv, b64, raw_pub
from client import BDCAuth, BearerAuth, ASClient
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

PY = sys.executable
KEYS = os.path.join(HERE, 'keys_rev')
U = lambda p: f'http://127.0.0.1:{p}'
AS_P, A_P, BEAR_P = 8200, 8201, 8203
G_RR, G_AFF, G_SH, NONCE_P = 8210, 8220, 8230, 8239
RTTS = [10, 40, 80]
procs = []


def spawn(*args):
    procs.append(subprocess.Popen([PY, *args], cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))


def start():
    os.makedirs(KEYS, exist_ok=True)
    open(os.path.join(KEYS, 'as.key'), 'wb').write(raw_priv(Ed25519PrivateKey.generate()))
    reps = {G_RR: [8211, 8212], G_AFF: [8221, 8222], G_SH: [8231, 8232]}
    push = [U(A_P) + '/_revoke'] + [U(p) + '/_revoke' for ps in reps.values() for p in ps]
    spawn('services.py', 'as', '--port', str(AS_P), '--keydir', KEYS, '--push', ','.join(push))
    spawn('services.py', 'mcp', '--port', str(A_P), '--keydir', KEYS, '--aud', U(A_P) + '/mcp', '--mode', 'bdc')
    spawn('services.py', 'mcp', '--port', str(BEAR_P), '--keydir', KEYS, '--aud', U(BEAR_P) + '/mcp', '--mode', 'bearer')
    spawn('services.py', 'nonce', '--port', str(NONCE_P))
    for lb, ps in reps.items():
        for p in ps:
            extra = ['--nonce-store', U(NONCE_P) + '/setnx'] if lb == G_SH else []
            spawn('services.py', 'mcp', '--port', str(p), '--keydir', KEYS, '--aud', U(lb) + '/mcp', '--mode', 'bdc', *extra)
        spawn('services.py', 'lb', '--port', str(lb), '--backends', ','.join(U(p) for p in ps),
              '--policy', 'affinity' if lb == G_AFF else 'rr')
    for i, r in enumerate(RTTS):
        spawn('delayproxy.py', str(8300 + i), str(AS_P), str(r))
        spawn('delayproxy.py', str(8400 + i), str(A_P), str(r))
        spawn('delayproxy.py', str(8500 + i), str(BEAR_P), str(r))
    time.sleep(7)


def stats(base, reset=True):
    return httpx2.get(base + '/_stats' + ('?reset=1' if reset else '')).json()


async def session_calls(url, auth, n, tool='query_inventory', args=None, warm=20):
    xs = []
    async with create_mcp_http_client(auth=auth) as http:
        async with Client(streamable_http_client(url, http_client=http)) as c:
            for i in range(n + warm):
                t0 = time.perf_counter()
                await c.call_tool(tool, args or {'model': 'civic'})
                if i >= warm:
                    xs.append((time.perf_counter() - t0) * 1e3)
    return xs


async def one_call(url, auth, tool='query_inventory', args=None):
    try:
        async with create_mcp_http_client(auth=auth) as http:
            async with Client(streamable_http_client(url, http_client=http)) as c:
                r = await c.call_tool(tool, args or {'model': 'civic'})
                return not r.is_error
    except Exception:
        return False


def med(xs):
    xs = sorted(xs)
    return dict(median=statistics.median(xs), p99=xs[max(0, int(0.99 * len(xs)) - 1)], n=len(xs))


# ------------------------------------------------------------------ E1 push revocation
async def e1_revocation(asc, ag):
    gid = asc.consent('alice', ag[0].name, ['tool:query_inventory'])
    t1 = asc.root(gid)[1]['token']
    tok = asc.exchange(ag[0], t1, ag[1].name, U(A_P) + '/mcp', ['tool:query_inventory'])[1]['token']
    out = dict(trials=[])
    for trial in range(20):
        g = asc.consent('alice', ag[0].name, ['tool:query_inventory'])
        t = asc.exchange(ag[0], asc.root(g)[1]['token'], ag[1].name, U(A_P) + '/mcp', ['tool:query_inventory'])[1]['token']
        accepted_after, first_reject_ms = 0, None
        async with create_mcp_http_client(auth=BDCAuth(ag[1], t, U(A_P) + '/mcp')) as http:
            async with Client(streamable_http_client(U(A_P) + '/mcp', http_client=http)) as c:
                for _ in range(20):
                    await c.call_tool('query_inventory', {'model': 'civic'})
                loop = asyncio.get_running_loop()
                t0 = time.perf_counter()
                rv = loop.run_in_executor(None, lambda: asc.revoke(g))
                while True:
                    try:
                        r = await c.call_tool('query_inventory', {'model': 'civic'})
                        ok = not r.is_error
                    except Exception:
                        ok = False
                    if ok:
                        accepted_after += 1
                    else:
                        first_reject_ms = (time.perf_counter() - t0) * 1e3
                        break
                st, body = await rv
        out['trials'].append(dict(push_ms=body['push_ms'], pushed=body['pushed'], first_reject_ms=first_reject_ms,
                                  accepted_after_revoke_call=accepted_after))
    out['push_ms'] = med([t['push_ms'] for t in out['trials']])
    out['first_reject_ms'] = med([t['first_reject_ms'] for t in out['trials']])
    out['max_accepted_after'] = max(t['accepted_after_revoke_call'] for t in out['trials'])
    # what a hijacked agent could do in one TTL without push: sequential call rate on one session
    xs = await session_calls(U(A_P) + '/mcp', BDCAuth(ag[1], tok, U(A_P) + '/mcp'), 300)
    out['sequential_call_ms'] = med(xs)
    out['calls_per_ttl60_sequential'] = 60000 / statistics.median(xs)
    return out


# ------------------------------------------------------------------ E2 parameter-constrained scopes
async def e2_constraints(asc, ag):
    A = U(A_P) + '/mcp'
    grant = ['tool:query_inventory', 'tool:update_price?model=in:civic,f150,model3&price<=40000']
    gid = asc.consent('alice', ag[0].name, grant)
    t1 = asc.root(gid)[1]['token']
    tests = []
    st, r = asc.exchange(ag[0], t1, ag[1].name, A, ['tool:update_price?model=in:civic,f150&price<=30000'])
    tests.append(dict(test='narrower bounds on re-delegation', expected='accept', outcome='accept' if st == 200 else r.get('error')))
    t2 = r['token']
    st, r = asc.exchange(ag[0], t1, ag[1].name, A, ['tool:update_price?model=in:civic&price<=50000'])
    tests.append(dict(test='raising the numeric bound', expected='reject', outcome='accept' if st == 200 else r.get('error')))
    st, r = asc.exchange(ag[0], t1, ag[1].name, A, ['tool:update_price?price<=30000'])
    tests.append(dict(test='dropping the model allowlist', expected='reject', outcome='accept' if st == 200 else r.get('error')))
    st, r = asc.exchange(ag[0], t1, ag[1].name, A, ['tool:update_price?model=in:civic,mustang&price<=30000'])
    tests.append(dict(test='adding a model to the allowlist', expected='reject', outcome='accept' if st == 200 else r.get('error')))
    for args, exp, name in [({'model': 'civic', 'price': 25000}, 'accept', 'call within bounds'),
                            ({'model': 'civic', 'price': 35000}, 'reject', 'price above the delegated bound'),
                            ({'model': 'model3', 'price': 25000}, 'reject', 'model outside the delegated allowlist'),
                            ({'model': 'civic', 'price': '25000'}, 'reject', 'price passed as a string')]:
        ok = await one_call(A, BDCAuth(ag[1], t2, A), 'update_price', args)
        tests.append(dict(test=name, expected=exp, outcome='accept' if ok else 'reject'))
    for t in tests:
        t['ok'] = (t['outcome'] == 'accept') == (t['expected'] == 'accept')
    # cost of constraints: in-process exchange and resource check, token size
    srv = AuthorizationServer(); a0, a1 = Agent('agent-0'), Agent('agent-1')
    srv.register(a0.name, a0.pk); srv.register(a1.name, a1.pk)
    rg = ResourceGuard('urn:r', srv.pk)
    cost = []
    for n in (1, 5, 10, 20):
        for c in (0, 2):
            scope = [f'tool:t{i}' + ('?amount<=1000&region=in:apac,eu,us' if c else '') for i in range(n)]
            g = srv.consent('u', a0.name, scope); root = srv.issue_root(g)
            reqs = [a0.delegation_request(root, a1.name, 'urn:r', scope) for _ in range(1500)]
            xs = []
            for q in reqs:
                t0 = time.perf_counter(); tok = srv.exchange(q); xs.append((time.perf_counter() - t0) * 1e6)
            body = b'{}'
            ys = []
            for _ in range(1500):
                pop = a1.proof(tok, 'POST', 'http://x/mcp', body, 'urn:r')
                t0 = time.perf_counter(); rg.check(tok, pop, 'POST', 'http://x/mcp', body, f'tool:t{n-1}', {'amount': 10, 'region': 'eu'})
                ys.append((time.perf_counter() - t0) * 1e6)
            cost.append(dict(entries=n, constraints_per_entry=c, token_bytes=len(tok), exchange_us=statistics.median(xs),
                             check_us=statistics.median(ys)))
    return dict(tests=tests, cost=cost)


# ------------------------------------------------------------------ E3 replicated MCP servers
async def e3_replicas(asc, ag):
    out = {}
    for name, port in [('round-robin, local caches', G_RR), ('token affinity, local caches', G_AFF), ('round-robin, shared store', G_SH)]:
        aud = U(port) + '/mcp'
        gid = asc.consent('alice', ag[0].name, ['tool:query_inventory'])
        tok = asc.exchange(ag[0], asc.root(gid)[1]['token'], ag[1].name, aud, ['tool:query_inventory'])[1]['token']
        cap = {}

        class Capture(BDCAuth):
            def auth_flow(self, request):
                url = f'{request.url.scheme}://{request.url.netloc.decode()}{request.url.path}'
                pop = self.agent.proof(self.token, request.method, url, request.content, self.aud)
                request.headers['Authorization'] = 'BDC ' + self.token; request.headers['BDC-PoP'] = pop
                if b'tools/call' in request.content:
                    cap['h'] = dict(request.headers); cap['b'] = request.content
                yield request
        ok = await one_call(aud, Capture(ag[1], tok, aud))
        h = {k: v for k, v in cap['h'].items() if k.lower() not in ('content-length',)}
        replays = [httpx2.post(aud, headers=h, content=cap['b']) for _ in range(4)]
        accepted = sum(r.status_code == 200 for r in replays)
        xs = await session_calls(aud, BDCAuth(ag[1], tok, aud), 300)
        out[name] = dict(honest_ok=ok, replays_sent=4, replays_accepted=accepted,
                         replicas_hit=sorted({r.headers.get('x-replica') for r in replays}), call_ms=med(xs))
    return out


# ------------------------------------------------------------------ E4 wide-area round trips
async def e4_wan(ag):
    out = {}
    for i, rtt in enumerate([0] + RTTS):
        asp = U(AS_P) if rtt == 0 else U(8300 + i - 1)
        mcp = U(A_P) + '/mcp' if rtt == 0 else U(8400 + i - 1) + '/mcp'
        bear = U(BEAR_P) + '/mcp' if rtt == 0 else U(8500 + i - 1) + '/mcp'
        asc = ASClient(asp)
        asc.http.get(asp + '/')                     # open the keep-alive connection
        scope = ['tool:query_inventory']
        setup = {}
        for k in (2, 3, 4, 5, 6):
            xs = []
            for _ in range(15):
                gid = asc.consent('bob', ag[0].name, scope)
                tok = asc.root(gid)[1]['token']
                t0 = time.perf_counter()
                for h in range(1, k):                   # delegation credentials, then the resource token
                    aud = U(A_P) + '/mcp' if h == k - 1 else 'as'
                    tok = asc.exchange(ag[h - 1], tok, ag[h].name, aud, scope)[1]['token']
                xs.append((time.perf_counter() - t0) * 1e3)
            setup[k] = med(xs)
        gid = asc.consent('bob', ag[0].name, scope)
        tok = asc.exchange(ag[0], asc.root(gid)[1]['token'], ag[1].name, U(A_P) + '/mcp', scope)[1]['token']
        bt = asc.bearer(gid, U(BEAR_P) + '/mcp')
        call_bdc = med(await session_calls(mcp, BDCAuth(ag[1], tok, U(A_P) + '/mcp'), 150))
        call_bear = med(await session_calls(bear, BearerAuth(bt), 150))
        out[rtt] = dict(setup_ms=setup, call_bdc_ms=call_bdc, call_bearer_ms=call_bear)
    return out


# ------------------------------------------------------------------ E5 token size with enterprise identifiers
def e5_sizes():
    from pymacaroons import Macaroon
    styles = {
        'short': lambda i: f'agent{i}',
        'SPIFFE ID': lambda i: f'spiffe://prod.acme-motors.example/ns/agents/sa/agent-{i:02d}',
        'HTTPS URI': lambda i: f'https://agents.acme-motors.example/.well-known/agent-card/agent-{i:02d}.json',
        'did:key': lambda i: 'did:key:z6Mk' + hashlib.sha256(str(i).encode()).hexdigest()[:44],
        # compact form: the token carries a 128-bit digest of each SPIFFE ID; the AS keeps the mapping
        'SPIFFE digest': lambda i: b64(hashlib.sha256(f'spiffe://prod.acme-motors.example/ns/agents/sa/agent-{i:02d}'.encode()).digest()[:16]),
    }
    res = {}
    for style, f in styles.items():
        srv = AuthorizationServer()
        ags = [Agent(f(i)) for i in range(9)]
        for a in ags:
            srv.register(a.name, a.pk)
        scope = ['tool:query_inventory', 'tool:get_price']
        g = srv.consent('alice@example.com', ags[0].name, scope)
        tok = srv.issue_root(g)
        rows = {}
        key = os.urandom(32)
        m = Macaroon(location='as', identifier='grant-1', key=key)
        m.add_first_party_caveat('sub = alice@example.com')
        m.add_first_party_caveat('scope = ' + ','.join(scope))
        m.add_first_party_caveat('act0 = ' + ags[0].name)
        for k in range(2, 9):
            final = srv.exchange(ags[k - 2].delegation_request(tok, ags[k - 1].name, 'https://dealer.example/mcp', scope))
            tok = srv.exchange(ags[k - 2].delegation_request(tok, ags[k - 1].name, 'as', scope))
            m.add_first_party_caveat(f'act{k-1} = ' + ags[k - 1].name)
            m.add_first_party_caveat('scope = ' + ','.join(scope))
            rows[k] = dict(bdc=len(final), macaroon=len(m.serialize()), id_len=len(ags[k - 1].name))
        res[style] = rows
    return res


async def main():
    start()
    try:
        asc = ASClient(U(AS_P))
        ag = [Agent(f'agent-{i}') for i in range(8)]
        for a in ag:
            asc.register(a)
        res = {}
        res['revocation'] = await e1_revocation(asc, ag); print('E1', json.dumps({k: v for k, v in res['revocation'].items() if k != 'trials'}))
        res['constraints'] = await e2_constraints(asc, ag); print('E2', json.dumps(res['constraints'])[:1500])
        res['replicas'] = await e3_replicas(asc, ag); print('E3', json.dumps(res['replicas']))
        res['wan'] = await e4_wan(ag); print('E4', json.dumps(res['wan'])[:3000])
        res['sizes'] = e5_sizes(); print('E5', json.dumps(res['sizes']))
        json.dump(res, open(os.path.join(HERE, '..', 'results', 'revision.json'), 'w'), indent=1, default=str)
    finally:
        for p in procs:
            p.terminate()


if __name__ == '__main__':
    asyncio.run(main())
