"""Generate the unbounded-chain BDC Tamarin model and its ablation variants.

Token: <'T', U, A1, g, ch, aud, s, pkh>
  U   user (subject), A1 first agent, g consent id, ch actor chain (A1 for the root token,
  <An, ch_prev> after each exchange, i.e. the holder is the head), aud audience, s scope (multiset),
  pkh holder key.
Variants: full, nopop (R skips holder PoP), noatten (AS skips attenuation), noaud (R skips audience),
          noreplay (no nonce cache), noxpop (AS skips the holder signature on exchange requests),
          norevoke (AS ignores revocation).
"""
import os, sys

VARIANTS = ['full', 'nopop', 'noatten', 'noaud', 'noreplay', 'noxpop', 'norevoke']


def model(v):
    L = []
    a = L.append
    a('theory BDC_' + v + '\nbegin\n\nbuiltins: signing, multiset\n')
    a('''
rule Agent_key:
  [ Fr(~k) ] --[ KeyGen($X) ]-> [ !Ltk($X, ~k), !Pk($X, pk(~k)), Out(pk(~k)) ]

rule Reveal_agent:
  [ !Ltk(X, k) ] --[ Compromised(X) ]-> [ Out(k) ]

rule AS_key:
  [ Fr(~kas) ] --[ OnlyOnceAS() ]-> [ !LtkAS(~kas), !PkAS(pk(~kas)), Out(pk(~kas)) ]

// User U consents (out of band) to agent A1 acting with scope s; g identifies the grant.
rule Consent:
  [ Fr(~g), In(s) ] --[ Grant($U, $A1, s, ~g) ]-> [ !Consent($U, $A1, s, ~g) ]

// User revokes a grant at the AS.
rule Revoke:
  [ !Consent(U, A1, s, g) ] --[ Revoke(g) ]-> [ ]

rule AS_issue_root:
  let m = <'T', U, A1, g, A1, 'as', s, pk1> in
  [ !Consent(U, A1, s, g), !Pk(A1, pk1), !LtkAS(kas) ]
  --[ Issue(U, A1, g, A1, 'as', s), Live(g) ]->
  [ Out(<m, sign(m, kas)>) ]
''')
    # ---------- agent delegation: holder X is head of the chain; root (ch = X) or delegated (ch = <X, p>)
    for hk, chpat in [('root', 'X'), ('deleg', '<X, p>')]:
        for sk, spat, sreq in [('eq', 's', 's'), ('sub', 's2 + rest', 's2')]:
            a(f'''
rule Agent_delegate_{hk}_{sk}:
  let m = <'T', U, A1, g, {chpat}, 'as', {spat}, pk(k)>
      x = <'XR', m, sig, An, R, {sreq}, ~nx> in
  [ !Ltk(X, k), !PkAS(pkas), In(<m, sig>), In(<An, R>), Fr(~nx) ]
  --[ Eq(verify(sig, m, pkas), true), Delegate(X, An, R, U, {sreq}, {chpat}) ]->
  [ Out(<x, sign(x, k)>) ]
''')
    # ---------- AS exchange
    xpop = '' if v == 'noxpop' else ', Eq(verify(sx, x, pkh), true)'
    live = '' if v == 'norevoke' else ', Live(g)'
    scopes = [('any', 's', 's2')] if v == 'noatten' else [('eq', 's', 's'), ('sub', 's2 + rest', 's2')]
    for hk, chpat, holder in [('root', 'A1', 'A1'), ('deleg', '<Ap, p>', 'Ap')]:
        for sk, spat, snew in scopes:
            a(f'''
rule AS_exchange_{hk}_{sk}:
  let m  = <'T', U, A1, g, {chpat}, 'as', {spat}, pkh>
      x  = <'XR', m, sig, An, R, {snew}, nx>
      m2 = <'T', U, A1, g, <An, {chpat}>, R, {snew}, pkn> in
  [ !LtkAS(kas), !Pk(An, pkn), In(<x, sx>) ]
  --[ Eq(verify(sig, m, pk(kas)), true){xpop},
      Issue(U, A1, g, <An, {chpat}>, R, {snew}), Hop(U, A1, g, {holder}, An, R, {snew}, {chpat}){live} ]->
  [ Out(<m2, sign(m2, kas)>) ]
''')
    # ---------- holder invokes a resource (delegated tokens only)
    for sk, spat in [('eq', 'op'), ('sub', 'op + rest')]:
        a(f'''
rule Agent_invoke_{sk}:
  let m = <'T', U, A1, g, <X, p>, R, {spat}, pk(k)>
      q = <'REQ', m, op, R, ~n> in
  [ !Ltk(X, k), !PkAS(pkas), In(<m, sig>), Fr(~n), In(op) ]
  --[ Eq(verify(sig, m, pkas), true), Send(X, R, U, <X, p>, op, ~n) ]->
  [ Out(<m, sig, op, ~n, sign(q, k)>) ]
''')
    # ---------- resource server
    audpat = 'Rany' if v == 'noaud' else '$R'
    for sk, spat in [('eq', 'op'), ('sub', 'op + rest')]:
        pop = '' if v == 'nopop' else ", Eq(verify(sr, <'REQ', m, op, $R, n>, pkh), true)"
        a(f'''
rule R_accept_{sk}:
  let m = <'T', U, A1, g, <Al, p>, {audpat}, {spat}, pkh> in
  [ !PkAS(pkas), In(<m, sig, op, n, sr>) ]
  --[ Eq(verify(sig, m, pkas), true){pop}, Accept($R, U, A1, g, <Al, p>, op, n), RNonce($R, n) ]->
  [ ]
''')
    a('''
restriction Equality:
  "All x y #i. Eq(x, y) @ #i ==> x = y"

restriction SingleAS:
  "All #i #j. OnlyOnceAS() @ #i & OnlyOnceAS() @ #j ==> #i = #j"

restriction OneKeyPerAgent:
  "All X #i #j. KeyGen(X) @ #i & KeyGen(X) @ #j ==> #i = #j"

// The AS issues nothing for a grant after the user has revoked it.
restriction RevokedGrant:
  "All g #i #j. Live(g) @ #i & Revoke(g) @ #j ==> #i < #j"
''')
    if v != 'noreplay':
        a('''
restriction ReplayCache:
  "All R n #i #j. RNonce(R, n) @ #i & RNonce(R, n) @ #j ==> #i = #j"
''')
    a('''
// Sanity: a chain of three distinct agents completes without any compromise.
lemma executable:
  exists-trace
  "Ex R U A1 A2 A3 g op n #i #k. Accept(R, U, A1, g, <A3, <A2, A1>>, op, n) @ #i & Grant(U, A1, op, g) @ #k
     & not (Ex X #c. Compromised(X) @ #c) & not (A1 = A2) & not (A2 = A3) & not (A1 = A3)"

// Invariant (by induction): every token the AS issues carries a scope within the user's grant.
lemma scope_invariant [use_induction, reuse]:
  "All U A1 g ch aud s #i. Issue(U, A1, g, ch, aud, s) @ #i ==>
     (Ex s0 #j. Grant(U, A1, s0, g) @ #j & #j < #i & ((s0 = s) | (Ex r. s0 = s + r)))"

// P1 No escalation, for chains of any length and with every agent possibly compromised.
lemma attenuation:
  "All R U A1 g ch op n #i. Accept(R, U, A1, g, ch, op, n) @ #i ==>
     (Ex s0 #j. Grant(U, A1, s0, g) @ #j & ((s0 = op) | (Ex r. s0 = op + r)))"

// P2 Holder and audience binding: an accepted request from an honest final holder was sent by it, to R.
lemma holder_and_audience:
  "All R U A1 g Al p op n #i. Accept(R, U, A1, g, <Al, p>, op, n) @ #i
     & not (Ex #c. Compromised(Al) @ #c) ==>
     (Ex #j. Send(Al, R, U, <Al, p>, op, n) @ #j & #j < #i)"

// P3a Every accepted chain was issued by the AS for this audience, with a scope covering op.
lemma accepted_chain_issued:
  "All R U A1 g ch op n #i. Accept(R, U, A1, g, ch, op, n) @ #i ==>
     (Ex s #j. Issue(U, A1, g, ch, R, s) @ #j & #j < #i & ((s = op) | (Ex r. s = op + r)))"

// P3b Prefix closure: every issued chain extends a chain the AS issued earlier for the same grant.
lemma chain_prefix_issued:
  "All U A1 g Ap An R s p #i. Hop(U, A1, g, Ap, An, R, s, p) @ #i ==>
     (Ex aud s1 #j. Issue(U, A1, g, p, aud, s1) @ #j & #j < #i)"

// P3d Purpose separation: every hop extends a delegation credential (a token whose audience is the AS);
// a token issued for a resource can be used at that resource but never exchanged.
lemma extends_delegation_credential:
  "All U A1 g Ap An R s p #i. Hop(U, A1, g, Ap, An, R, s, p) @ #i ==>
     (Ex s1 #j. Issue(U, A1, g, p, 'as', s1) @ #j & #j < #i)"

// P3c Hop authenticity: each hop whose delegator is honest was requested by that delegator,
// to that delegate, for that audience and scope.
lemma hop_authentic:
  "All U A1 g Ap An R s p #i. Hop(U, A1, g, Ap, An, R, s, p) @ #i
     & not (Ex #c. Compromised(Ap) @ #c) ==>
     (Ex #j. Delegate(Ap, An, R, U, s, p) @ #j & #j < #i)"

// P4 No replay of an honest holder's request.
lemma no_replay:
  "All R U A1 g ch op n #i #k. Accept(R, U, A1, g, ch, op, n) @ #i & Accept(R, U, A1, g, ch, op, n) @ #k
     ==> #i = #k"

// P5 Revocation: anything accepted after a revocation used a token issued before it.
lemma revocation:
  "All R U A1 g ch op n #i #j. Accept(R, U, A1, g, ch, op, n) @ #i & Revoke(g) @ #j & #j < #i ==>
     (Ex aud s #k. Issue(U, A1, g, ch, aud, s) @ #k & #k < #j)"

// Attacker-strength variants
lemma attenuation_honest_agents:
  "All R U A1 g ch op n #i. Accept(R, U, A1, g, ch, op, n) @ #i & not (Ex X #c. Compromised(X) @ #c) ==>
     (Ex s0 #j. Grant(U, A1, s0, g) @ #j & ((s0 = op) | (Ex r. s0 = op + r)))"

lemma holder_and_audience_network_only:
  "All R U A1 g Al p op n #i. Accept(R, U, A1, g, <Al, p>, op, n) @ #i
     & not (Ex X #c. Compromised(X) @ #c) ==>
     (Ex #j. Send(Al, R, U, <Al, p>, op, n) @ #j & #j < #i)"

lemma hop_authentic_network_only:
  "All U A1 g Ap An R s p #i. Hop(U, A1, g, Ap, An, R, s, p) @ #i
     & not (Ex X #c. Compromised(X) @ #c) ==>
     (Ex #j. Delegate(Ap, An, R, U, s, p) @ #j & #j < #i)"

end
''')
    out = ''.join(L)
    if v == 'noatten':
        out = out.replace('lemma scope_invariant [use_induction, reuse]', 'lemma scope_invariant [use_induction]')
        out = out.replace('// P1 No escalation', '''// Helper (sound in this model): every issued token belongs to a grant the user made earlier.
lemma issue_has_grant [use_induction, reuse]:
  "All U A1 g ch aud s #i. Issue(U, A1, g, ch, aud, s) @ #i ==>
     (Ex s0 #j. Grant(U, A1, s0, g) @ #j & #j < #i)"

// Honest-agent version of the invariant (used for the honest-agent attenuation lemma).
lemma scope_invariant_honest [use_induction, reuse]:
  "(not (Ex X #c. Compromised(X) @ #c)) ==>
   (All U A1 g ch aud s #i. Issue(U, A1, g, ch, aud, s) @ #i ==>
     (Ex s0 #j. Grant(U, A1, s0, g) @ #j & #j < #i & ((s0 = s) | (Ex r. s0 = s + r))))"

// P1 No escalation''')
    out = out.replace('\nend\n', '\n' + ATTACKS.get(v, '') + '\nend\n')
    if v == 'full':
        out = out.replace('\nend\n', '\n' + SANITY + '\nend\n')
    return out


# Non-vacuity checks for the full model: behaviors that the restrictions must not exclude.
SANITY = '''// NV1: a token issued before revocation can still be used after it (P5's premise is reachable).
lemma nv_used_after_revocation:
  exists-trace
  "Ex R U A1 A2 g op n #i #j. Accept(R, U, A1, g, <A2, A1>, op, n) @ #i & Revoke(g) @ #j & #j < #i
     & not (Ex X #c. Compromised(X) @ #c)"

// NV2: the replay cache does not block repeated honest use: two requests with different nonces are accepted.
lemma nv_repeated_use:
  exists-trace
  "Ex R U A1 A2 g op n1 n2 #i #k. Accept(R, U, A1, g, <A2, A1>, op, n1) @ #i & Accept(R, U, A1, g, <A2, A1>, op, n2) @ #k
     & not (n1 = n2) & not (Ex X #c. Compromised(X) @ #c)"

// NV3: compromise is reachable: a compromised holder gets a request accepted (P2's condition is not vacuous).
lemma nv_compromised_holder:
  exists-trace
  "Ex R U A1 A2 g op n #i #c. Accept(R, U, A1, g, <A2, A1>, op, n) @ #i & Compromised(A2) @ #c"
'''


# Attack witnesses: an exists-trace lemma whose trace violates the property the variant breaks.
ATTACKS = {
    'noatten': '''// Witness against P1: a compromised first agent obtains 'write' although the user granted only 'read'.
lemma attack_escalation:
  exists-trace
  "Ex R U A1 A2 g n #i #j. Accept(R, U, A1, g, <A2, A1>, 'write', n) @ #i & Grant(U, A1, 'read', g) @ #j"
''',
    'noreplay': '''// Witness against P4: one request of an honest agent is executed twice, with no compromise.
lemma attack_replay:
  exists-trace
  "Ex R U A1 A2 g op n #i #k. Accept(R, U, A1, g, <A2, A1>, op, n) @ #i & Accept(R, U, A1, g, <A2, A1>, op, n) @ #k
     & not (#i = #k) & not (Ex X #c. Compromised(X) @ #c)"
''',
    'norevoke': '''// Witness against P5: after the user revokes, the AS still issues a token that a resource accepts.
lemma attack_after_revocation:
  exists-trace
  "Ex R U A1 A2 g s n #i #j #h #r. Issue(U, A1, g, A1, 'as', s) @ #r & Revoke(g) @ #j
     & Hop(U, A1, g, A1, A2, R, s, A1) @ #h & #r < #j & #j < #h
     & Accept(R, U, A1, g, <A2, A1>, s, n) @ #i & not (Ex X #c. Compromised(X) @ #c)"
''',
}


if __name__ == '__main__':
    for v in (sys.argv[1:] or VARIANTS):
        open(os.path.join(os.path.dirname(os.path.abspath(__file__)), f'n_{v}.spthy'), 'w').write(model(v))
    print('ok')
