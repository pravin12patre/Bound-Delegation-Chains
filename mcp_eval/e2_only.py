import asyncio, json, os, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import rev_eval as R
from bdc2 import Agent
from client import ASClient
async def main():
    R.spawn('services.py', 'as', '--port', str(R.AS_P), '--keydir', R.KEYS)
    R.spawn('services.py', 'mcp', '--port', str(R.A_P), '--keydir', R.KEYS, '--aud', R.U(R.A_P) + '/mcp', '--mode', 'bdc')
    time.sleep(5)
    try:
        asc = ASClient(R.U(R.AS_P)); ag = [Agent(f'agent-{i}') for i in range(3)]
        for a in ag: asc.register(a)
        r = await R.e2_constraints(asc, ag)
        for t in r['tests']: print(t)
        p = os.path.join(HERE, '..', 'results', 'revision.json'); d = json.load(open(p)); d['constraints'] = r; json.dump(d, open(p, 'w'), indent=1)
    finally:
        for p in R.procs: p.terminate()
asyncio.run(main())
