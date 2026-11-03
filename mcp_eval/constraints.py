"""Parameter-constrained scope entries: grammar, canonical form, coverage and evaluation.

Grammar (ABNF, RFC 5234; ALPHA, DIGIT from RFC 5234; unreserved, pct-encoded from RFC 3986):
  entry      = "tool:" name [ "?" constraint *( "&" constraint ) ]
  name       = 1*64( ALPHA / DIGIT / "_" / "-" / "." )
  constraint = arg "<=" number / arg "=in:" value *( "," value )
  arg        = 1*64( ALPHA / DIGIT / "_" )
  number     = [ "-" ] ( "0" / %x31-39 *DIGIT ) [ "." *DIGIT %x31-39 ]   ; no exponent, no trailing zeros
  value      = 1*( unreserved / pct-encoded )                           ; UTF-8, upper-case hex

Canonical form (required; anything else is rejected):
  constraints sorted by arg, each arg at most once; allowlist values distinct and sorted by their
  decoded code points; percent-encoding exactly for characters outside `unreserved`; numbers as above,
  "-0" not allowed. Unknown constraint kinds and empty allowlists are rejected.

Evaluation against tool arguments (top-level JSON object of the tools/call):
  "<=" requires a JSON number (not a boolean), finite, compared exactly as a decimal;
  "in:" requires a JSON string equal, code point for code point, to one of the decoded values.
  A constrained argument that is missing, null, an object or an array is rejected.
"""
import json, re
from functools import lru_cache
from decimal import Decimal, InvalidOperation
from urllib.parse import quote, unquote

NAME = re.compile(r'[A-Za-z0-9_.\-]{1,64}\Z')
ARG = re.compile(r'[A-Za-z0-9_]{1,64}\Z')
NUM = re.compile(r'-?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?\Z')
VAL = re.compile(r'([A-Za-z0-9\-._~]|%[0-9A-F]{2})+\Z')
UNRESERVED = '-._~'


class ConstraintError(ValueError):
    pass


def enc(v):
    return quote(v, safe=UNRESERVED)


def fmt_num(d):
    s = format(d.normalize(), 'f')
    if '.' in s:
        s = s.rstrip('0').rstrip('.')
    if s in ('-0', ''):
        s = '0'
    return s


@lru_cache(maxsize=1 << 16)
def parse(entry):
    """Results are cached and must be treated as read-only. -> (tool, {arg: ('le', Decimal) | ('in', frozenset[str])}); raises ConstraintError if not canonical."""
    if not isinstance(entry, str) or not entry.startswith('tool:'):
        raise ConstraintError('not a tool entry')
    name, sep, q = entry[5:].partition('?')
    if not NAME.match(name):
        raise ConstraintError('bad tool name')
    if sep and not q:
        raise ConstraintError('empty constraint list')
    cons = {}
    for c in (q.split('&') if q else []):
        if '<=' in c:
            k, v = c.split('<=', 1)
            if not ARG.match(k) or not NUM.match(v) or v == '-0':
                raise ConstraintError('bad bound')
            val = ('le', Decimal(v))
        elif '=in:' in c:
            k, v = c.split('=in:', 1)
            parts = v.split(',')
            if not ARG.match(k) or not all(VAL.match(p) for p in parts):
                raise ConstraintError('bad allowlist')
            dec = [unquote(p, errors='strict') for p in parts]
            if any(enc(d) != p for d, p in zip(dec, parts)):
                raise ConstraintError('non-canonical encoding')
            if len(set(dec)) != len(dec) or dec != sorted(dec):
                raise ConstraintError('allowlist not distinct and sorted')
            val = ('in', frozenset(dec))
        else:
            raise ConstraintError('unknown constraint kind')
        if k in cons:
            raise ConstraintError('repeated argument')
        cons[k] = val
    if list(cons) != sorted(cons):
        raise ConstraintError('constraints not sorted')
    return 'tool:' + name, cons


def serialize(tool, cons):
    parts = []
    for k in sorted(cons):
        kind, v = cons[k]
        parts.append(f'{k}<={fmt_num(v)}' if kind == 'le' else f'{k}=in:' + ','.join(enc(x) for x in sorted(v)))
    return tool + ('?' + '&'.join(parts) if parts else '')


def covers(parent, child):
    """Every call allowed by child is allowed by parent (child at least as strict)."""
    pt, pc = parse(parent); ct, cc = parse(child)
    if pt != ct:
        return False
    for k, (kind, v) in pc.items():
        if k not in cc or cc[k][0] != kind:
            return False
        if kind == 'le' and not cc[k][1] <= v:
            return False
        if kind == 'in' and not cc[k][1] <= v:
            return False
    return True


def index(scope):
    idx = {}
    for e in scope:
        idx.setdefault(parse(e)[0], []).append(e)
    return idx


def scope_covers(parent_scope, child_scope):
    """Indexed by tool name: cost linear in the number of entries per tool."""
    idx = index(parent_scope)
    return all(any(covers(p, c) for p in idx.get(parse(c)[0], ())) for c in child_scope)


def _arg_ok(kind, v, a):
    if kind == 'le':
        if isinstance(a, bool) or not isinstance(a, (int, Decimal)):
            return False
        a = Decimal(a)
        return a.is_finite() and a <= v
    return isinstance(a, str) and a in v


def allows(scope, op, args):
    for e in scope:
        if e.partition('?')[0] != op:              # only entries for the called tool are parsed
            continue
        t, cons = parse(e)
        if t == op and all(_arg_ok(kind, v, (args or {}).get(k)) for k, (kind, v) in cons.items()):
            return True
    return False


def _no_dupes(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ConstraintError('duplicate JSON key')
    return dict(pairs)


def _no_const(c):
    raise ConstraintError('non-finite number')


def strict_json(body):
    """Parse a JSON-RPC body: duplicate keys and NaN/Infinity rejected, non-integers as exact decimals."""
    return json.loads(body, object_pairs_hook=_no_dupes, parse_float=Decimal, parse_constant=_no_const)
