"""HTTP services for the MCP evaluation.

  python services.py as  --port P --keydir D             authorization server (token exchange, revocation)
  python services.py mcp --port P --keydir D --aud URI --mode {none,bearer,bdc}
                                                         MCP server (official SDK, Streamable HTTP) behind
                                                         an ASGI guard enforcing the chosen mode
"""
import argparse, json, os, sys, time, statistics
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from bdc2 import AuthorizationServer, ResourceGuard, Reject, ub64, b64


def load_as_key(keydir):
    return Ed25519PrivateKey.from_private_bytes(open(os.path.join(keydir, 'as.key'), 'rb').read())


# ----------------------------------------------------------------- authorization server
def as_app(keydir, push=(), ttl=60, revlog=None, as_id='https://as.example', hb=1.0):
    srv = AuthorizationServer(sk=load_as_key(keydir), ttl=ttl)
    import httpx2, asyncio
    from starlette.responses import PlainTextResponse
    rev2 = revlog is not None
    if rev2:
        from revocation import RevocationLog, notice as mk_notice, heartbeat as mk_hb, revset as mk_set
        log = RevocationLog(revlog)
        srv.revoked |= {gid for _, gid in log.entries}       # survive AS restarts
        targets = [p.split('|', 1) for p in push]             # base_url|aud
    ctl = dict(drop_notice=set(), drop_hb=set(), drop_fetch=set())
    client = {}

    def http():
        if 'c' not in client:
            client['c'] = httpx2.AsyncClient(timeout=5)
        return client['c']

    async def hb_loop():
        while True:
            await asyncio.sleep(hb)
            msgs = [(u, mk_hb(srv.sk, as_id, a, log.seq)) for u, a in targets if a not in ctl['drop_hb']]
            await asyncio.gather(*[http().post(u + '/_hb', content=m) for u, m in msgs], return_exceptions=True)

    import contextlib

    @contextlib.asynccontextmanager
    async def lifespan(app):
        task = asyncio.get_running_loop().create_task(hb_loop()) if rev2 and targets else None
        yield
        if task:
            task.cancel()

    async def register(req):
        d = await req.json()
        try:
            srv.register(d['agent'], Ed25519PublicKey.from_public_bytes(ub64(d['pk'])))
        except Reject as e:
            return JSONResponse({'error': str(e)}, status_code=403)
        return JSONResponse({'ok': True})

    async def consent(req):
        d = await req.json()
        return JSONResponse({'gid': srv.consent(d['user'], d['agent'], d['scope'])})

    async def root(req):
        d = await req.json()
        try:
            return JSONResponse({'token': srv.issue_root(d['gid'])})
        except Reject as e:
            return JSONResponse({'error': str(e)}, status_code=403)

    async def bearer(req):
        d = await req.json()
        return JSONResponse({'token': srv.bearer_for(d['gid'], d['aud'])})

    async def exchange(req):
        body = (await req.body()).decode()
        try:
            return JSONResponse({'token': srv.exchange(body)})
        except Reject as e:
            return JSONResponse({'error': str(e)}, status_code=403)

    async def revoke(req):
        gid = (await req.json())['gid']
        notice = srv.revoke(gid)
        t0 = time.perf_counter()
        if rev2:                                   # durable log first, then signed, sequenced notices
            seq = log.append(gid)
            msgs = [(u, mk_notice(srv.sk, as_id, a, seq, gid)) for u, a in targets if a not in ctl['drop_notice']]
            await asyncio.gather(*[http().post(u + '/_revoke', content=m) for u, m in msgs], return_exceptions=True)
            return JSONResponse({'ok': True, 'seq': seq, 'push_ms': (time.perf_counter() - t0) * 1e3, 'pushed': len(msgs)})
        if push:                                   # v1: push the signed notice to every registered resource server
            async with httpx2.AsyncClient(timeout=10) as c:
                await asyncio.gather(*[c.post(u, content=notice) for u in push])
        return JSONResponse({'ok': True, 'push_ms': (time.perf_counter() - t0) * 1e3, 'pushed': len(push)})

    from oauth_strong import OAuthAS
    te = OAuthAS(srv.sk, ttl=ttl)
    teh = OAuthAS(srv.sk, ttl=ttl, hardened=True)

    def pick(req):
        return teh if req.url.path.startswith('/teh/') else te

    async def te_register(req):
        d = await req.json()
        try:
            for x in (te, teh):
                x.register(d['agent'], Ed25519PublicKey.from_public_bytes(ub64(d['pk'])))
        except Reject as e:
            return JSONResponse({'error': str(e)}, status_code=403)
        return JSONResponse({'ok': True})

    async def te_issue(req):
        d = await req.json()
        return JSONResponse({'token': pick(req).issue(d['user'], d['client'], d['scope'], d.get('aud', 'as'), d.get('may_act'))})

    async def te_exchange(req):
        try:
            return JSONResponse({'token': pick(req).token_exchange((await req.body()).decode())})
        except Reject as e:
            return JSONResponse({'error': str(e)}, status_code=403)

    async def te_revoke(req):
        pick(req).revoke_token((await req.json())['token'])
        return JSONResponse({'ok': True})

    async def revocations(req):
        aud, since = req.query_params['aud'], int(req.query_params.get('since', 0))
        if aud in ctl['drop_fetch']:
            return JSONResponse({'error': 'unavailable'}, status_code=503)
        return PlainTextResponse(mk_set(srv.sk, as_id, aud, log, since))

    async def control(req):
        d = await req.json()
        for k in ctl:
            if k in d:
                ctl[k] = set(d[k])
        return JSONResponse({'ok': True, 'seq': log.seq if rev2 else None})

    return Starlette(routes=[Route('/register', register, methods=['POST']),
                             Route('/consent', consent, methods=['POST']),
                             Route('/root', root, methods=['POST']),
                             Route('/bearer', bearer, methods=['POST']),
                             Route('/exchange', exchange, methods=['POST']),
                             Route('/revoke', revoke, methods=['POST']),
                             Route('/revocations', revocations, methods=['GET']),
                             Route('/te/register', te_register, methods=['POST']),
                             Route('/te/issue', te_issue, methods=['POST']),
                             Route('/te/exchange', te_exchange, methods=['POST']),
                             Route('/te/revoke', te_revoke, methods=['POST']),
                             Route('/teh/issue', te_issue, methods=['POST']),
                             Route('/teh/exchange', te_exchange, methods=['POST']),
                             Route('/teh/revoke', te_revoke, methods=['POST']),
                             Route('/_ctl', control, methods=['POST'])],
                     lifespan=lifespan)


# ----------------------------------------------------------------- MCP server + guard
def build_mcp(aud):
    from mcp.server.mcpserver import MCPServer
    server = MCPServer('dealer-inventory')
    stock = {'civic': 12, 'model3': 4, 'f150': 9}
    prices = {'civic': 24500, 'model3': 38990, 'f150': 41200}

    @server.tool()
    def query_inventory(model: str) -> int:
        """Units in stock for a model."""
        return stock.get(model, 0)

    @server.tool()
    def get_price(model: str) -> int:
        """List price for a model."""
        return prices.get(model, 0)

    @server.tool()
    def update_price(model: str, price: int) -> int:
        """Change a list price (privileged)."""
        prices[model] = price
        return price

    return server.streamable_http_app(stateless_http=True, json_response=True)


class Guard:
    """ASGI middleware: verifies BDC (or bearer) on every POST to the MCP endpoint and
    authorizes tools/call against the token scope ('tool:<name>')."""

    def __init__(self, app, mode, aud, as_pk, nonce_store=None, rev2=None):
        self.app, self.mode, self.aud = app, mode, aud
        self.rg = ResourceGuard(aud, as_pk)
        from oauth_strong import DPoPGuard
        self.dg = DPoPGuard(aud, as_pk, hardened=(mode == 'dpoph'))
        self.rev = None
        if rev2:                                   # rev2 = dict(as_url, as_id, path, hmax)
            from revocation import RevocationState
            import httpx2
            pc = {}

            async def pull(since):
                if 'c' not in pc:
                    pc['c'] = httpx2.AsyncClient(timeout=3)
                r = await pc['c'].get(rev2['as_url'] + '/revocations', params={'aud': aud, 'since': since})
                if r.status_code != 200:
                    raise Reject('pull failed')
                return r.text
            self.rev = RevocationState(rev2['path'], rev2['as_id'], aud, as_pk, pull, hmax=rev2['hmax'])
        self.nonce_store = nonce_store
        self.http = None
        self.times, self.decisions = [], {}
        self.trace = {}                            # gid -> list of (authorized_at, completed_at)

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        if scope['path'] == '/_stats':
            t = sorted(self.times)
            out = dict(n=len(t), median_us=statistics.median(t) if t else None,
                       p99_us=t[int(0.99 * len(t)) - 1] if t else None, decisions=self.decisions)
            if scope.get('query_string') == b'reset=1':
                self.times, self.decisions = [], {}
            return await JSONResponse(out)(scope, receive, send)
        if scope['path'] == '/_revtrace':
            from urllib.parse import parse_qs
            gid = parse_qs(scope.get('query_string', b'').decode()).get('gid', [''])[0]
            applied = self.rev.applied_at.get(gid) if self.rev is not None else None
            return await JSONResponse({'applied': applied, 'requests': self.trace.get(gid, [])})(scope, receive, send)
        if scope['path'] in ('/_revoke', '/_hb') and scope['method'] == 'POST':
            body = b''
            while True:
                m = await receive(); body += m.get('body', b'')
                if not m.get('more_body'):
                    break
            try:
                if self.rev is not None:
                    fn = self.rev.on_notice if scope['path'] == '/_revoke' else self.rev.on_heartbeat
                    r = await fn(body.decode())
                    return await JSONResponse({'ok': True, 'result': r, 'last': self.rev.last})(scope, receive, send)
                self.rg.revoke_notice(body.decode())
                return await JSONResponse({'ok': True})(scope, receive, send)
            except Reject as e:
                return await JSONResponse({'error': str(e)}, status_code=403)(scope, receive, send)
        if self.mode == 'none' or scope['method'] != 'POST':
            return await self.app(scope, receive, send)
        body = b''
        while True:
            m = await receive()
            body += m.get('body', b'')
            if not m.get('more_body'):
                break
        headers = {k.decode().lower(): v.decode() for k, v in scope['headers']}
        t0 = time.perf_counter()
        try:
            op, args = self._op(body)
            auth = headers.get('authorization', '')
            url = f"http://{headers.get('host', '')}{scope['path']}"
            if self.mode in ('dpop', 'dpoph'):
                if not auth.startswith('DPoP ') or 'dpop' not in headers:
                    raise Reject('no token')
                self.dg.check(auth[5:], headers['dpop'], 'POST', url, op, args, body)
            elif self.mode == 'bearer':
                if not auth.startswith('Bearer '):
                    raise Reject('no token')
                self.rg.check_bearer(auth[7:], op, args)
            else:
                if not auth.startswith('BDC '):
                    raise Reject('no token')
                if 'bdc-pop' not in headers:
                    raise Reject('no proof')
                t = self.rg.check(auth[4:], headers['bdc-pop'], 'POST', url, body, op, args,
                                  nonce_check=self.nonce_store is None)
                if self.nonce_store is not None:          # replicated servers: one shared nonce store
                    if self.http is None:
                        import httpx2
                        self.http = httpx2.AsyncClient(timeout=5)
                    r = await self.http.post(self.nonce_store, json={'nonce': t['_pop']['nonce'], 'ttl': 120})
                    if r.status_code != 200:
                        raise Reject('replay')
                if self.rev is not None:
                    # Linearization point. admit() may await a pull, but its final membership test and the
                    # dispatch below run in one step of the single-threaded event loop, as does applying a notice.
                    await self.rev.admit(t['gid'])
                    rec = [time.time(), None]
                    self.trace.setdefault(t['gid'], []).append(rec)
            self.times.append((time.perf_counter() - t0) * 1e6)
            self.decisions['accept'] = self.decisions.get('accept', 0) + 1
        except Reject as e:
            self.decisions[str(e)] = self.decisions.get(str(e), 0) + 1
            return await JSONResponse({'error': 'unauthorized', 'reason': str(e)}, status_code=403)(scope, receive, send)

        sent = False
        rec_local = locals().get('rec')

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {'type': 'http.request', 'body': body, 'more_body': False}
            return await receive()
        try:
            return await self.app(scope, replay, send)
        finally:
            if rec_local is not None:
                rec_local[1] = time.time()

    @staticmethod
    def _op(body):
        from constraints import strict_json, ConstraintError
        try:
            msg = strict_json(body)
        except (ValueError, ConstraintError):
            raise Reject('malformed')
        msgs = msg if isinstance(msg, list) else [msg]
        calls = [m.get('params', {}) for m in msgs if isinstance(m, dict) and m.get('method') == 'tools/call']
        if len(calls) > 1:
            raise Reject('batched tool calls')
        if not calls:
            return None, None
        return f"tool:{calls[0].get('name')}", calls[0].get('arguments') or {}


def mcp_app(keydir, aud, mode, nonce_store=None, rev2=None):
    inner = build_mcp(aud)
    pk = load_as_key(keydir).public_key()
    return Guard(inner, mode, aud, pk, nonce_store=nonce_store, rev2=rev2)


# ----------------------------------------------------------------- shared nonce store (for replicated MCP servers)
def nonce_app():
    seen = {}

    async def setnx(req):
        d = await req.json(); now = time.time()
        if seen.get(d['nonce'], 0) > now:
            return JSONResponse({'new': False}, status_code=409)
        seen[d['nonce']] = now + d.get('ttl', 120)
        if len(seen) > 200000:
            for k in [k for k, e in seen.items() if e <= now]:
                del seen[k]
        return JSONResponse({'new': True})
    return Starlette(routes=[Route('/setnx', setnx, methods=['POST'])])


# ----------------------------------------------------------------- load balancer in front of MCP replicas
def lb_app(backends, policy):
    import httpx2, hashlib, itertools
    rr = itertools.cycle(range(len(backends)))
    client = httpx2.AsyncClient(timeout=30)

    async def app(scope, receive, send):
        if scope['type'] != 'http':
            return
        body = b''
        while True:
            m = await receive(); body += m.get('body', b'')
            if not m.get('more_body'):
                break
        headers = [(k.decode(), v.decode()) for k, v in scope['headers'] if k.decode().lower() != 'content-length']
        auth = dict((k.lower(), v) for k, v in headers).get('authorization', '')
        if policy == 'affinity' and auth:          # route by the token: every request under one token hits one replica
            i = int(hashlib.sha256(auth.encode()).hexdigest(), 16) % len(backends)
        else:
            i = next(rr)
        r = None
        for k in range(len(backends)):                 # fail over to the next replica if this one is down
            j = (i + k) % len(backends)
            url = backends[j] + scope['path'] + (('?' + scope['query_string'].decode()) if scope['query_string'] else '')
            try:
                r = await client.request(scope['method'], url, headers=headers, content=body)
                i = j
                break
            except httpx2.TransportError:
                continue
        if r is None:
            await send({'type': 'http.response.start', 'status': 502, 'headers': []})
            await send({'type': 'http.response.body', 'body': b'no replica'})
            return
        out = [(k.encode(), v.encode()) for k, v in r.headers.items() if k.lower() not in ('content-length', 'transfer-encoding', 'content-encoding')]
        out.append((b'x-replica', str(i).encode()))
        await send({'type': 'http.response.start', 'status': r.status_code, 'headers': out})
        await send({'type': 'http.response.body', 'body': r.content})
    return app


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('role'); ap.add_argument('--port', type=int); ap.add_argument('--keydir')
    ap.add_argument('--aud', default=''); ap.add_argument('--mode', default='bdc')
    ap.add_argument('--push', default=''); ap.add_argument('--ttl', type=int, default=60)
    ap.add_argument('--nonce-store', default=None); ap.add_argument('--backends', default=''); ap.add_argument('--policy', default='rr')
    ap.add_argument('--revlog', default=None); ap.add_argument('--as-id', default='https://as.example'); ap.add_argument('--hb', type=float, default=1.0)
    ap.add_argument('--rev2-as', default=None); ap.add_argument('--revstate', default=None); ap.add_argument('--hmax', type=float, default=3.0)
    a = ap.parse_args()
    if a.role == 'as':
        app = as_app(a.keydir, [u for u in a.push.split(',') if u], a.ttl, a.revlog, a.as_id, a.hb)
    elif a.role == 'nonce':
        app = nonce_app()
    elif a.role == 'lb':
        app = lb_app(a.backends.split(','), a.policy)
    else:
        rev2 = dict(as_url=a.rev2_as, as_id=a.as_id, path=a.revstate, hmax=a.hmax) if a.rev2_as else None
        app = mcp_app(a.keydir, a.aud, a.mode, a.nonce_store, rev2)
    uvicorn.run(app, host='127.0.0.1', port=a.port, log_level='warning', access_log=False)
