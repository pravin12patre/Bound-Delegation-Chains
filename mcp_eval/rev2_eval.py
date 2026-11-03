"""Revocation protocol tests: sequenced notices, heartbeats, pull on gap, fail-closed staleness,
message authentication, persistence across resource and AS restarts. Results -> results/revocation2.json"""
import asyncio, json, os, shutil, subprocess, sys, time, statistics
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import httpx2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from bdc2 import Agent, raw_priv, sign
from client import BDCAuth, ASClient
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

PY = sys.executable
K = os.path.join(HERE, 'keys_rev2'); shutil.rmtree(K, ignore_errors=True); os.makedirs(K)
open(os.path.join(K, 'as.key'), 'wb').write(raw_priv(Ed25519PrivateKey.generate()))
U = lambda p: f'http://127.0.0.1:{p}'
AS_ID = 'https://as.example'
ASP, X, Y, Z = 8600, 8601, 8602, 8603
AUD = {p: U(p) + '/mcp' for p in (X, Y, Z)}
HB, HMAX = 1.0, 3.0
procs = {}


def start_as():
    procs['as'] = subprocess.Popen([PY, 'services.py', 'as', '--port', str(ASP), '--keydir', K, '--revlog', os.path.join(K, 'revlog.jsonl'),
                                    '--as-id', AS_ID, '--hb', str(HB), '--push', ','.join(f'{U(p)}|{AUD[p]}' for p in (X, Y, Z))],
                                   cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_rs(p):
    procs[p] = subprocess.Popen([PY, 'services.py', 'mcp', '--port', str(p), '--keydir', K, '--aud', AUD[p], '--mode', 'bdc',
                                 '--rev2-as', U(ASP), '--as-id', AS_ID, '--revstate', os.path.join(K, f'rev_{p}.json'), '--hmax', str(HMAX)],
                                cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop(name):
    procs[name].terminate(); procs[name].wait()


def ctl(**kw):
    return httpx2.post(U(ASP) + '/_ctl', json={k: list(v) for k, v in kw.items()}).json()


def setup_agents():
    asc = ASClient(U(ASP))
    ag = [Agent('orchestrator'), Agent('inventory-agent')]
    for a in ag:
        asc.register(a)
    return asc, ag


def token(asc, ag, port):
    gid = asc.consent('alice', ag[0].name, ['tool:query_inventory'])
    t = asc.exchange(ag[0], asc.root(gid)[1]['token'], ag[1].name, AUD[port], ['tool:query_inventory'])[1]['token']
    return gid, t


async def loop_until_reject(port, agent, tok, action, limit=15.0):
    """Call in a loop; run `action` after warm-up; return (ms from action to first rejection, calls accepted after action)."""
    accepted, t0 = 0, None
    async with create_mcp_http_client(auth=BDCAuth(agent, tok, AUD[port])) as http:
        async with Client(streamable_http_client(AUD[port], http_client=http)) as c:
            for _ in range(5):
                await c.call_tool('query_inventory', {'model': 'civic'})
            loop = asyncio.get_running_loop()
            fut = loop.run_in_executor(None, action); t0 = time.perf_counter()
            while time.perf_counter() - t0 < limit:
                try:
                    r = await c.call_tool('query_inventory', {'model': 'civic'})
                    ok = not r.is_error
                except Exception:
                    ok = False
                if not ok:
                    await fut
                    return (time.perf_counter() - t0) * 1e3, accepted
                accepted += 1
                await asyncio.sleep(0.005)
            await fut
    return None, accepted


async def one_call(port, agent, tok):
    try:
        async with create_mcp_http_client(auth=BDCAuth(agent, tok, AUD[port])) as http:
            async with Client(streamable_http_client(AUD[port], http_client=http)) as c:
                r = await c.call_tool('query_inventory', {'model': 'civic'})
                return not r.is_error
    except Exception:
        return False


def med(xs):
    xs = sorted(x for x in xs if x is not None)
    return dict(median=statistics.median(xs), max=max(xs), n=len(xs)) if xs else None


async def main():
    start_as(); [start_rs(p) for p in (X, Y)]; time.sleep(5)
    asc, ag = setup_agents()
    res = {}
    try:
        # T1 normal push
        lags = []
        for _ in range(15):
            gid, t = token(asc, ag, X)
            lags.append(await loop_until_reject(X, ag[1], t, lambda: asc.revoke(gid)))
        res['push'] = dict(first_reject_ms=med([l for l, _ in lags]), max_accepted_after=max(a for _, a in lags))
        print('T1', res['push'], flush=True)
        # T2 missed notice: the heartbeat reveals the gap and the resource pulls
        ctl(drop_notice=[AUD[X]])
        lags = []
        for _ in range(8):
            gid, t = token(asc, ag, X)
            lags.append(await loop_until_reject(X, ag[1], t, lambda: asc.revoke(gid)))
        ctl(drop_notice=[])
        res['missed_notice'] = dict(first_reject_ms=med([l for l, _ in lags]), max_accepted_after=max(a for _, a in lags), hb_s=HB)
        print('T2', res['missed_notice'], flush=True)
        # T3 partition from the AS: no heartbeats, no pulls -> fail closed after hmax; recovery after heal
        part = []
        for _ in range(4):
            gid, t = token(asc, ag, X)
            await one_call(X, ag[1], t)
            ms, acc = await loop_until_reject(X, ag[1], t, lambda: ctl(drop_hb=[AUD[X]], drop_fetch=[AUD[X]]))
            st = httpx2.get(U(X) + '/_stats').json()['decisions']
            ctl(drop_hb=[], drop_fetch=[])
            t1 = time.perf_counter()
            while not await one_call(X, ag[1], t):
                await asyncio.sleep(0.05)
            part.append(dict(fail_closed_ms=ms, recover_ms=(time.perf_counter() - t1) * 1e3, stale_rejections=st.get('revocation state stale', 0)))
        res['partition'] = dict(fail_closed_ms=med([p['fail_closed_ms'] for p in part]), recover_ms=med([p['recover_ms'] for p in part]),
                                hmax_s=HMAX, trials=part)
        print('T3', {k: v for k, v in res['partition'].items() if k != 'trials'}, flush=True)
        # T4 message authentication
        as_sk = Ed25519PrivateKey.from_private_bytes(open(os.path.join(K, 'as.key'), 'rb').read())
        evil = Ed25519PrivateKey.generate()
        gid, t = token(asc, ag, X)
        last = httpx2.post(U(X) + '/_hb', content=sign(dict(typ='bdc-hb', iss=AS_ID, aud=AUD[X], seq=0, iat=time.time()), as_sk)).json()
        cases = {
            'notice signed by another key': sign(dict(typ='bdc-rev', iss=AS_ID, aud=AUD[X], seq=999, gid=gid, iat=time.time()), evil),
            'genuine notice for another resource': sign(dict(typ='bdc-rev', iss=AS_ID, aud=AUD[Y], seq=999, gid=gid, iat=time.time()), as_sk),
            'notice naming another issuer': sign(dict(typ='bdc-rev', iss='https://evil.example', aud=AUD[X], seq=999, gid=gid, iat=time.time()), as_sk),
            'heartbeat presented as a notice': sign(dict(typ='bdc-hb', iss=AS_ID, aud=AUD[X], seq=999, iat=time.time()), as_sk),
            'notice older than the skew window': sign(dict(typ='bdc-rev', iss=AS_ID, aud=AUD[X], seq=999, gid=gid, iat=time.time() - 100), as_sk),
        }
        msg_tests = []
        for name, m in cases.items():
            r = httpx2.post(U(X) + '/_revoke', content=m)
            still_ok = await one_call(X, ag[1], t)
            msg_tests.append(dict(test=name, status=r.status_code, reason=r.json().get('error'), token_still_accepted=still_ok,
                                  ok=(r.status_code == 403 and still_ok)))
        # replay of a previously applied genuine notice is ignored
        gid2, t2 = token(asc, ag, X)
        n = asc.revoke(gid2)[1]
        replay = sign(dict(typ='bdc-rev', iss=AS_ID, aud=AUD[X], seq=n['seq'], gid=gid2, iat=time.time()), as_sk)
        r = httpx2.post(U(X) + '/_revoke', content=replay).json()
        msg_tests.append(dict(test='replayed genuine notice', status=200, reason=r.get('result'), token_still_accepted=await one_call(X, ag[1], t),
                              ok=r.get('result') == 'ignored'))
        res['messages'] = msg_tests
        for m in msg_tests:
            print('T4', m, flush=True)
        # T5 resource restart and new replica
        gid3, t3 = token(asc, ag, X); asc.revoke(gid3)
        gid4, t4 = token(asc, ag, X)
        stop(X); start_rs(X); time.sleep(4)
        restart = dict(revoked_rejected=not await one_call(X, ag[1], t3), live_accepted=await one_call(X, ag[1], t4))
        gz, tz = token(asc, ag, Z); asc.revoke(gz)                     # revoked before Z exists
        gz2, tz2 = token(asc, ag, Z)
        start_rs(Z); time.sleep(4)
        t0 = time.perf_counter()
        restart['new_replica_revoked_rejected'] = not await one_call(Z, ag[1], tz)
        restart['new_replica_live_accepted'] = await one_call(Z, ag[1], tz2)
        restart['new_replica_state'] = json.load(open(os.path.join(K, f'rev_{Z}.json')))['last']
        res['restart'] = restart; print('T5', restart, flush=True)
        # T6 AS restart: the log persists, sequence numbers continue
        before = ctl()['seq']
        stop('as'); start_as(); time.sleep(4)
        asc, ag2 = setup_agents()
        g5, t5 = token(asc, ag2, X)
        r = asc.revoke(g5)[1]
        time.sleep(0.5)
        res['as_restart'] = dict(seq_before=before, seq_after=r['seq'], continued=r['seq'] == before + 1,
                                 revoked_rejected=not await one_call(X, ag2[1], t5))
        print('T6', res['as_restart'], flush=True)
        json.dump(res, open(os.path.join(HERE, '..', 'results', 'revocation2.json'), 'w'), indent=1, default=str)
    finally:
        for p in procs.values():
            p.terminate()


if __name__ == '__main__':
    asyncio.run(main())
