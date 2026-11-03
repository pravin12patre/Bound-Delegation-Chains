"""Steady-state throughput: 8 concurrent clients, 30 s per run, 3 interleaved repetitions. -> results/steady.json"""
import asyncio, json, os, subprocess, sys, time, statistics
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from bdc2 import Agent, raw_priv
from client import BDCAuth, BearerAuth, ASClient
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
PY = sys.executable; K = os.path.join(HERE, 'keys_st'); os.makedirs(K, exist_ok=True)
open(os.path.join(K, 'as.key'), 'wb').write(raw_priv(Ed25519PrivateKey.generate()))
U = lambda p: f'http://127.0.0.1:{p}'
P = {'none': 8951, 'bearer': 8952, 'bdc': 8953}
async def main():
    ps = [subprocess.Popen([PY, 'services.py', 'as', '--port', '8950', '--keydir', K], cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
    ps += [subprocess.Popen([PY, 'services.py', 'mcp', '--port', str(p), '--keydir', K, '--aud', U(p) + '/mcp', '--mode', m], cwd=HERE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for m, p in P.items()]
    time.sleep(6)
    try:
        asc = ASClient(U(8950)); a0, a1 = Agent('o'), Agent('w'); asc.register(a0); asc.register(a1)
        def mk(m):                                  # fresh tokens per run (60 s lifetime)
            gid = asc.consent('carol', 'o', ['tool:query_inventory'])
            if m == 'bdc':
                tok = asc.exchange(a0, asc.root(gid)[1]['token'], 'w', U(P['bdc']) + '/mcp', ['tool:query_inventory'])[1]['token']
                return lambda: BDCAuth(a1, tok, U(P['bdc']) + '/mcp')
            if m == 'bearer':
                bt = asc.bearer(gid, U(P['bearer']) + '/mcp')
                return lambda: BearerAuth(bt)
            return lambda: None
        res = {m: [] for m in P}
        for rep in range(3):
            for m, p in P.items():
                url = U(p) + '/mcp'; auth = mk(m); stop = time.perf_counter() + 30; n = [0]
                async def worker():
                    async with create_mcp_http_client(auth=auth()) as http:
                        async with Client(streamable_http_client(url, http_client=http)) as c:
                            while time.perf_counter() < stop:
                                await c.call_tool('query_inventory', {'model': 'civic'}); n[0] += 1
                await asyncio.gather(*[worker() for _ in range(8)])
                res[m].append(n[0] / 30); print(m, rep, n[0] / 30, flush=True)
        out = {m: dict(mean=statistics.mean(v), sd=statistics.stdev(v), runs=v) for m, v in res.items()}
        out['setup'] = '8 clients, 30 s per run, 3 interleaved repetitions'
        json.dump(out, open(os.path.join(HERE, '..', 'results', 'steady.json'), 'w'), indent=1)
        print({m: (round(out[m]['mean']), round(out[m]['sd'], 1)) for m in P})
    finally:
        for p in ps: p.terminate()
asyncio.run(main())
