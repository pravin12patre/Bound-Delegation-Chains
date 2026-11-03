"""Replay under concurrency and fail-over, plus a throughput sweep over client concurrency.
Results -> results/replay2.json"""
import asyncio, json, os, subprocess, sys, time, statistics
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import httpx2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from bdc2 import Agent, raw_priv
from client import BDCAuth, BearerAuth, ASClient
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

PY = sys.executable
K = os.path.join(HERE, 'keys_rp'); os.makedirs(K, exist_ok=True)
open(os.path.join(K, 'as.key'), 'wb').write(raw_priv(Ed25519PrivateKey.generate()))
U = lambda p: f'http://127.0.0.1:{p}'
ASP, SINGLE, NONCE = 8800, 8801, 8839
GROUPS = {'round robin, per-replica caches': (8810, [8811, 8812], 'rr', False),
          'token affinity, per-replica caches': (8820, [8821, 8822], 'affinity', False),
          'round robin, shared store': (8830, [8831, 8832], 'rr', True)}
TP = {'none': 8841, 'bearer': 8842, 'bdc': 8843}
P = {}


def spawn(key, *args):
    P[key] = subprocess.Popen([PY, 'services.py', *args], cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def replica(port, lb, shared):
    spawn(port, 'mcp', '--port', str(port), '--keydir', K, '--aud', U(lb) + '/mcp', '--mode', 'bdc',
          *(['--nonce-store', U(NONCE) + '/setnx'] if shared else []))


def start():
    spawn('as', 'as', '--port', str(ASP), '--keydir', K)
    spawn('nonce', 'nonce', '--port', str(NONCE))
    spawn(SINGLE, 'mcp', '--port', str(SINGLE), '--keydir', K, '--aud', U(SINGLE) + '/mcp', '--mode', 'bdc')
    for name, (lb, reps, pol, shared) in GROUPS.items():
        for r in reps:
            replica(r, lb, shared)
        spawn(lb, 'lb', '--port', str(lb), '--backends', ','.join(U(r) for r in reps), '--policy', pol)
    for mode, p in TP.items():
        spawn(p, 'mcp', '--port', str(p), '--keydir', K, '--aud', U(p) + '/mcp', '--mode', mode)
    time.sleep(8)


class Template(BDCAuth):
    """Records the headers of a real tools/call so that fresh signed requests can be built from it."""
    def auth_flow(self, request):
        url = f'{request.url.scheme}://{request.url.netloc.decode()}{request.url.path}'
        request.headers['Authorization'] = 'BDC ' + self.token
        request.headers['BDC-PoP'] = self.agent.proof(self.token, request.method, url, request.content, self.aud)
        if b'tools/call' in request.content:
            self.h = {k: v for k, v in request.headers.items() if k.lower() not in ('content-length', 'bdc-pop')}
            self.b = request.content
        yield request


async def template(url, agent, tok):
    t = Template(agent, tok, url)
    async with create_mcp_http_client(auth=t) as http:
        async with Client(streamable_http_client(url, http_client=http)) as c:
            await c.call_tool('query_inventory', {'model': 'civic'})
    return t


async def burst(url, agent, tok, tpl, copies, client):
    """Sign one new request and send `copies` identical copies at once; return how many were executed."""
    body = tpl.b.replace(b'"id":', b'"id":9', 1) if b'"id":' in tpl.b else tpl.b
    h = dict(tpl.h); h['BDC-PoP'] = agent.proof(tok, 'POST', url, body, url)
    rs = await asyncio.gather(*[client.post(url, headers=h, content=body) for _ in range(copies)], return_exceptions=True)
    return sum(1 for r in rs if not isinstance(r, Exception) and r.status_code == 200)


async def main():
    start()
    asc = ASClient(U(ASP))
    ag = [Agent('orchestrator'), Agent('inventory-agent')]
    for a in ag:
        asc.register(a)

    def tok(aud):
        gid = asc.consent('alice', ag[0].name, ['tool:query_inventory'])
        return asc.exchange(ag[0], asc.root(gid)[1]['token'], ag[1].name, aud, ['tool:query_inventory'])[1]['token']

    res = {}
    try:
        # concurrent replay: 30 trials x 50 simultaneous copies of one signed request
        conc = {}
        targets = {'single server': U(SINGLE) + '/mcp', **{n: U(g[0]) + '/mcp' for n, g in GROUPS.items()}}
        async with httpx2.AsyncClient(timeout=30, limits=httpx2.Limits(max_connections=100)) as client:
            for name, url in targets.items():
                t = tok(url); tpl = await template(url, ag[1], t)
                counts = [await burst(url, ag[1], t, tpl, 50, client) for _ in range(30)]
                conc[name] = dict(trials=30, copies=50, executed_total=sum(counts), max_per_trial=max(counts),
                                  trials_with_more_than_one=sum(c > 1 for c in counts))
                print('conc', name, conc[name], flush=True)
        res['concurrent'] = conc
        # fail-over: request served by one replica, that replica dies, the same request is replayed
        fo = {}
        for name in ('token affinity, per-replica caches', 'round robin, shared store'):
            lb, reps, pol, shared = GROUPS[name]
            url = U(lb) + '/mcp'
            accepted = 0
            for trial in range(5):
                t = tok(url); tpl = await template(url, ag[1], t)
                body = tpl.b.replace(b'"id":', b'"id":7', 1)
                h = dict(tpl.h); h['BDC-PoP'] = ag[1].proof(t, 'POST', url, body, url)
                r1 = httpx2.post(url, headers=h, content=body)
                served = int(r1.headers.get('x-replica', '0'))
                P[reps[served]].terminate(); P[reps[served]].wait()
                r2 = httpx2.post(url, headers=h, content=body)
                accepted += int(r2.status_code == 200 and r2.headers.get('x-replica') != str(served))
                replica(reps[served], lb, shared); time.sleep(4)
            fo[name] = dict(trials=5, replay_after_failover_accepted=accepted)
            print('failover', name, fo[name], flush=True)
        res['failover'] = fo
        # throughput sweep
        a1 = ag[1]
        tps = {}
        for mode, p in TP.items():
            url = U(p) + '/mcp'
            gid = asc.consent('carol', ag[0].name, ['tool:query_inventory'])
            t = asc.exchange(ag[0], asc.root(gid)[1]['token'], a1.name, url, ['tool:query_inventory'])[1]['token'] if mode == 'bdc' else None
            bt = asc.bearer(gid, url) if mode == 'bearer' else None
            mk = {'none': lambda: None, 'bearer': lambda: BearerAuth(bt), 'bdc': lambda: BDCAuth(a1, t, url)}[mode]
            tps[mode] = {}
            for conc_n in (1, 2, 4, 8, 16, 32):
                stop = time.perf_counter() + 5
                n = [0]

                async def worker():
                    async with create_mcp_http_client(auth=mk()) as http:
                        async with Client(streamable_http_client(url, http_client=http)) as c:
                            while time.perf_counter() < stop:
                                await c.call_tool('query_inventory', {'model': 'civic'}); n[0] += 1
                await asyncio.gather(*[worker() for _ in range(conc_n)])
                tps[mode][conc_n] = n[0] / 5
            print('tp', mode, tps[mode], flush=True)
        res['throughput_sweep'] = tps
        json.dump(res, open(os.path.join(HERE, '..', 'results', 'replay2.json'), 'w'), indent=1)
    finally:
        for p in P.values():
            p.terminate()


if __name__ == '__main__':
    asyncio.run(main())
