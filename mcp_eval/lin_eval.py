"""Linearization of revocation and authorization under concurrency: 8 clients call in a loop with one grant
while it is revoked; the guard logs when each request was authorized and completed, and when the revocation
was applied. Checks that no request is authorized after the revocation is applied, and counts in-flight
requests (authorized before, completed after). Results -> results/linearization.json"""
import asyncio, json, os, shutil, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import httpx2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from bdc2 import Agent, raw_priv
from client import BDCAuth, ASClient
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

PY = sys.executable
K = os.path.join(HERE, 'keys_lin'); shutil.rmtree(K, ignore_errors=True); os.makedirs(K)
open(os.path.join(K, 'as.key'), 'wb').write(raw_priv(Ed25519PrivateKey.generate()))
U = lambda p: f'http://127.0.0.1:{p}'
ASP, RS = 8900, 8901
AUD = U(RS) + '/mcp'


async def main():
    ps = [subprocess.Popen([PY, 'services.py', 'as', '--port', str(ASP), '--keydir', K, '--revlog', os.path.join(K, 'log.jsonl'),
                            '--push', f'{U(RS)}|{AUD}'], cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
          subprocess.Popen([PY, 'services.py', 'mcp', '--port', str(RS), '--keydir', K, '--aud', AUD, '--mode', 'bdc',
                            '--rev2-as', U(ASP), '--revstate', os.path.join(K, 'rs.json')], cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
    time.sleep(5)
    try:
        asc = ASClient(U(ASP)); a0, a1 = Agent('orchestrator'), Agent('worker')
        asc.register(a0); asc.register(a1)
        trials = []
        for _ in range(20):
            gid = asc.consent('alice', a0.name, ['tool:query_inventory'])
            tok = asc.exchange(a0, asc.root(gid)[1]['token'], a1.name, AUD, ['tool:query_inventory'])[1]['token']
            stop = asyncio.Event()

            async def worker():
                async with create_mcp_http_client(auth=BDCAuth(a1, tok, AUD)) as http:
                    async with Client(streamable_http_client(AUD, http_client=http)) as c:
                        while not stop.is_set():
                            try:
                                r = await c.call_tool('query_inventory', {'model': 'civic'})
                                if r.is_error:
                                    return
                            except Exception:
                                return
            tasks = [asyncio.create_task(worker()) for _ in range(8)]
            await asyncio.sleep(0.3)
            await asyncio.get_running_loop().run_in_executor(None, lambda: asc.revoke(gid))
            await asyncio.wait(tasks, timeout=5); stop.set()
            tr = httpx2.get(U(RS) + '/_revtrace', params={'gid': gid}).json()
            ap, reqs = tr['applied'], tr['requests']
            trials.append(dict(authorized=len(reqs), authorized_after_apply=sum(1 for a, d in reqs if a > ap),
                               in_flight_at_apply=sum(1 for a, d in reqs if a <= ap and d is not None and d > ap)))
        out = dict(trials=len(trials), clients=8, authorized_total=sum(t['authorized'] for t in trials),
                   authorized_after_apply=sum(t['authorized_after_apply'] for t in trials),
                   max_in_flight_at_apply=max(t['in_flight_at_apply'] for t in trials), detail=trials)
        print({k: v for k, v in out.items() if k != 'detail'})
        json.dump(out, open(os.path.join(HERE, '..', 'results', 'linearization.json'), 'w'), indent=1)
    finally:
        for p in ps:
            p.terminate()


if __name__ == '__main__':
    asyncio.run(main())
