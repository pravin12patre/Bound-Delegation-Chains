import asyncio, json, os, statistics, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_eval as R
async def main():
    procs = R.start()
    try:
        runs = [await R.throughput(conc=8, secs=8) for _ in range(4)]
    finally:
        for p in procs: p.terminate()
    out = {k: dict(mean=statistics.mean(r[k] for r in runs), sd=statistics.stdev(r[k] for r in runs)) for k in ('none','bearer','bdc')}
    out['runs'] = runs
    p = os.path.join(R.HERE, '..', 'results', 'mcp_eval.json')
    d = json.load(open(p)); d['throughput_repeated'] = out; json.dump(d, open(p, 'w'), indent=1)
    print(json.dumps({k: out[k] for k in ('none','bearer','bdc')}))
asyncio.run(main())
