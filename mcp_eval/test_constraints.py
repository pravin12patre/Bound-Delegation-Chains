"""Property-based and edge-case tests for parameter-constrained scopes (run: pytest -q test_constraints.py)."""
import json, os, sys
from decimal import Decimal
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pytest
from hypothesis import given, settings, strategies as st, HealthCheck
from constraints import (parse, serialize, covers, scope_covers, allows, strict_json, ConstraintError, fmt_num)

N = int(os.environ.get('PBT_EXAMPLES', 20000))
TOOLS = ['tool:update_price', 'tool:transfer', 'tool:query']
ARGS = ['amount', 'model', 'price', 'region']
VALUES = ['civic', 'f150', 'model3', 'a,b', 'x y', 'é', 'civіc', '%41', 'Z']   # includes reserved chars and a look-alike

bounds = st.decimals(min_value=-10**6, max_value=10**6, places=2, allow_nan=False, allow_infinity=False).map(lambda d: Decimal(fmt_num(d)))
constraint = st.one_of(bounds.map(lambda b: ('le', b)),
                       st.frozensets(st.sampled_from(VALUES), min_size=1, max_size=5).map(lambda s: ('in', s)))
entries = st.builds(lambda t, c: serialize(t, c), st.sampled_from(TOOLS),
                    st.dictionaries(st.sampled_from(ARGS), constraint, max_size=3))
arg_values = st.one_of(st.integers(-2 * 10**6, 2 * 10**6), bounds, st.sampled_from(VALUES), st.booleans(), st.none(),
                       st.lists(st.integers(), max_size=2), st.dictionaries(st.text(max_size=2), st.integers(), max_size=1))
calls = st.tuples(st.sampled_from(TOOLS), st.dictionaries(st.sampled_from(ARGS), arg_values, max_size=4))
S = settings(max_examples=N, deadline=None, suppress_health_check=list(HealthCheck))


@S
@given(entries)
def test_canonical_round_trip(e):
    t, c = parse(e)
    assert serialize(t, c) == e


@S
@given(entries)
def test_reflexive(e):
    assert covers(e, e)


@S
@given(entries, entries, entries)
def test_transitive(a, b, c):
    if covers(a, b) and covers(b, c):
        assert covers(a, c)


@S
@given(entries, entries, calls)
def test_sound(p, c, call):
    """If p covers c, every call c allows is also allowed by p (refinement only narrows)."""
    tool, args = call
    if covers(p, c) and allows([c], tool, args):
        assert allows([p], tool, args)


@S
@given(st.lists(entries, min_size=1, max_size=6), st.lists(entries, min_size=1, max_size=6), calls)
def test_scope_sound(ps, cs, call):
    tool, args = call
    if scope_covers(ps, cs) and allows(cs, tool, args):
        assert allows(ps, tool, args)


# ---------------------------------------------------------------- grammar edge cases
@pytest.mark.parametrize('bad', [
    'tool:x?b<=1&a<=2',            # not sorted
    'tool:x?a<=1&a<=2',            # repeated argument
    'tool:x?a<=1&a=in:b',          # conflicting kinds for one argument
    'tool:x?a<=01', 'tool:x?a<=1.50', 'tool:x?a<=-0', 'tool:x?a<=1e5', 'tool:x?a<=+1', 'tool:x?a<=.5',
    'tool:x?a=in:b,a',             # allowlist not sorted
    'tool:x?a=in:a,a',             # allowlist not distinct
    'tool:x?a=in:', 'tool:x?a=in:a%2cb', 'tool:x?a=in:a b', 'tool:x?a=in:a&b',
    'tool:x?a>=1', 'tool:x?a!=1', 'tool:x?', 'tool:?a<=1', 'tool:x y', 'x?a<=1', 'tool:x?a-b<=1',
])
def test_rejects_non_canonical(bad):
    with pytest.raises(ConstraintError):
        parse(bad)


E = 'tool:update_price?model=in:civic,f150&price<=30000'


@pytest.mark.parametrize('args,ok', [
    ({'model': 'civic', 'price': 25000}, True),
    ({'model': 'civic', 'price': Decimal('30000')}, True),
    ({'model': 'civic', 'price': Decimal('30000.01')}, False),
    ({'model': 'civic', 'price': -0}, True),
    ({'model': 'civic', 'price': Decimal('1E+400')}, False),
    ({'model': 'civic', 'price': True}, False),          # boolean is not a number
    ({'model': 'civic', 'price': '25000'}, False),       # string is not a number
    ({'model': 'civic', 'price': None}, False),
    ({'model': 'civic', 'price': [25000]}, False),
    ({'model': 'civic', 'price': {'v': 25000}}, False),
    ({'model': 'civic'}, False),                          # missing constrained argument
    ({'model': 'civіc', 'price': 1}, False),              # Cyrillic look-alike
    ({'model': 'Civic', 'price': 1}, False),
    ({'model': ['civic'], 'price': 1}, False),
    ({'model': 'civic', 'price': 1, 'note': 'x'}, True),  # unconstrained extra arguments are not restricted
])
def test_argument_edge_cases(args, ok):
    assert allows([E], 'tool:update_price', args) is ok


@pytest.mark.parametrize('body', [
    '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"update_price","arguments":{"price":1,"price":99999}}}',
    '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"update_price","arguments":{"price":NaN}}}',
    '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"update_price","arguments":{"price":Infinity}}}',
])
def test_body_rejected(body):
    with pytest.raises(ConstraintError):
        strict_json(body)


def test_decimal_exact():
    m = strict_json('{"a":{"price":30000.000000000000001}}')
    assert not allows([E], 'tool:update_price', {'model': 'civic', 'price': m['a']['price']})
