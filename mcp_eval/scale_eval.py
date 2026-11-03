"""Exchange and resource-check cost versus scope size, with the indexed coverage check. -> results/scale.json"""
import json, os, statistics, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bdc2 import AuthorizationServer, Agent, ResourceGuard
srv = AuthorizationServer(); a0, a1 = Agent('agent-0'), Agent('agent-1')
srv.register(a0.name, a0.pk); srv.register(a1.name, a1.pk)
rg = ResourceGuard('urn:r', srv.pk)
rows = []
for tools in (1, 10, 50, 100, 200):
    for per_tool in (1, 4):
        scope = [f'tool:t{i:03d}?amount<={1000 + j}&region=in:apac,eu,us' for i in range(tools) for j in range(per_tool)]
        g = srv.consent('u', a0.name, scope); root = srv.issue_root(g)
        reqs = [a0.delegation_request(root, a1.name, 'urn:r', scope) for _ in range(300)]
        xs = []
        for q in reqs:
            t0 = time.perf_counter(); tok = srv.exchange(q); xs.append((time.perf_counter() - t0) * 1e3)
        ys = []
        for _ in range(300):
            pop = a1.proof(tok, 'POST', 'http://x/mcp', b'{}', 'urn:r')
            t0 = time.perf_counter(); rg.check(tok, pop, 'POST', 'http://x/mcp', b'{}', f'tool:t{tools-1:03d}', {'amount': 10, 'region': 'eu'})
            ys.append((time.perf_counter() - t0) * 1e3)
        rows.append(dict(tools=tools, entries=len(scope), token_bytes=len(tok), exchange_ms=statistics.median(xs), check_ms=statistics.median(ys)))
        print(rows[-1], flush=True)
json.dump(rows, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'results', 'scale.json'), 'w'), indent=1)
