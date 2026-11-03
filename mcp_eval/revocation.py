"""Revocation state for BDC: authenticated, sequenced, persistent, with bounded staleness.

Messages (all Ed25519-signed by the AS, compact JSON as in bdc2.sign):
  notice    {typ:'bdc-rev',    iss, aud, seq, gid, iat}       pushed on each revocation
  heartbeat {typ:'bdc-hb',     iss, aud, seq, iat}            pushed every h seconds; seq = latest
  set       {typ:'bdc-revset', iss, aud, upto, entries:[[seq, gid], ...], since, iat}   pulled on demand
`iss` names the AS, `aud` the resource the message is for; `typ` prevents one message type from being
used as another. Grant identifiers are random and never reused, and revocation is terminal (a renewed
grant gets a new identifier), so the revoked set only grows and ordering against grant creation does not
matter. The AS keeps an append-only, durable log; `seq` is the log position, so it stays monotonic across
AS restarts and fail-over to a replica that shares the log.

Resource rules:
  * accept a message only if signature, typ, iss, aud verify and |now - iat| <= skew;
  * notice with seq == last+1: apply; seq <= last: ignore (duplicate or replay); seq > last+1: gap, pull set;
  * heartbeat: refresh the freshness clock; if seq > last, pull the missing entries;
  * on start-up (new replica, or restart with the persisted state) pull everything after the persisted
    `last` before accepting any request;
  * if no valid notice, heartbeat or set has arrived for more than `hmax` seconds, try one pull; if that
    fails, reject every request ('revocation state stale') until fresh again (fail closed).
Consequently a resource that keeps receiving heartbeats accepts a revoked grant for at most about one
heartbeat interval plus one pull after the revocation, and one that does not stops accepting anything
after hmax.
"""
import json, os, threading, time
from bdc2 import sign, verify, Reject


class RevocationLog:
    """AS side: append-only durable log of revoked grants."""

    def __init__(self, path):
        self.path, self.entries, self.lock = path, [], threading.Lock()
        if os.path.exists(path):
            for line in open(path):
                if line.strip():
                    self.entries.append(json.loads(line))

    @property
    def seq(self):
        return len(self.entries)

    def append(self, gid):
        with self.lock:
            e = [self.seq + 1, gid]
            with open(self.path, 'a') as f:
                f.write(json.dumps(e) + '\n'); f.flush(); os.fsync(f.fileno())
            self.entries.append(e)
            return e[0]

    def since(self, n):
        return [e for e in self.entries if e[0] > n]


def notice(sk, iss, aud, seq, gid):
    return sign(dict(typ='bdc-rev', iss=iss, aud=aud, seq=seq, gid=gid, iat=time.time()), sk)


def heartbeat(sk, iss, aud, seq):
    return sign(dict(typ='bdc-hb', iss=iss, aud=aud, seq=seq, iat=time.time()), sk)


def revset(sk, iss, aud, log, since):
    return sign(dict(typ='bdc-revset', iss=iss, aud=aud, since=since, upto=log.seq,
                     entries=log.since(since), iat=time.time()), sk)


class RevocationState:
    """Resource side."""

    def __init__(self, path, iss, aud, as_pk, pull, hmax=3.0, skew=30.0):
        self.path, self.iss, self.aud, self.as_pk, self.pull = path, iss, aud, as_pk, pull
        self.hmax, self.skew = hmax, skew
        self.last, self.revoked, self.fresh_at, self.synced = 0, set(), 0.0, False
        self.events, self.applied_at = [], {}
        if path and os.path.exists(path):
            d = json.load(open(path))
            self.last, self.revoked = d['last'], set(d['revoked'])

    def _persist(self):
        if self.path:
            tmp = self.path + '.tmp'
            json.dump(dict(last=self.last, revoked=sorted(self.revoked)), open(tmp, 'w'))
            os.replace(tmp, self.path)

    def _check(self, msg, typ):
        d = verify(msg, self.as_pk)                       # raises Reject('signature')
        if d.get('typ') != typ or d.get('iss') != self.iss or d.get('aud') != self.aud:
            raise Reject('revocation message context')
        if abs(time.time() - d['iat']) > self.skew:
            raise Reject('revocation message stale')
        return d

    def _apply(self, entries, upto):
        for seq, gid in sorted(entries):
            if seq == self.last + 1:
                self.revoked.add(gid); self.last = seq; self.applied_at.setdefault(gid, time.time())
        self._persist()
        if self.last < upto:
            raise Reject('revocation set incomplete')

    async def sync(self):
        d = self._check(await self.pull(self.last), 'bdc-revset')
        if d['since'] != self.last:
            raise Reject('revocation set mismatch')
        self._apply(d['entries'], d['upto'])
        self.fresh_at, self.synced = time.time(), True
        self.events.append(('sync', time.time(), self.last))

    async def on_notice(self, msg):
        d = self._check(msg, 'bdc-rev')
        if d['seq'] <= self.last:
            return 'ignored'
        if d['seq'] == self.last + 1:
            self.revoked.add(d['gid']); self.last = d['seq']; self.applied_at.setdefault(d['gid'], time.time()); self._persist()
            self.fresh_at = time.time()
            return 'applied'
        await self.sync()                                  # gap: a notice was missed
        return 'gap-synced'

    async def on_heartbeat(self, msg):
        d = self._check(msg, 'bdc-hb')
        if d['seq'] > self.last:
            await self.sync()                              # a notice was missed
            return 'gap-synced'
        self.fresh_at = time.time()
        return 'fresh'

    async def admit(self, gid):
        """Called for every request before authorization."""
        if not self.synced or time.time() - self.fresh_at > self.hmax:
            try:
                await self.sync()
            except Exception:
                raise Reject('revocation state stale')
        if gid in self.revoked:
            raise Reject('revoked')
