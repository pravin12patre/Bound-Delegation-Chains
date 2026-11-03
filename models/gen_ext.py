"""Extended BDC model: constrained (refined) scope entries and signed revocation push.

Built from the full model of gen.py by adding
  * an abstract refinement constructor cn(e, k): a scope entry e refined by constraint k.
    The AS issues a refined entry cn(e, k) only if e is an entry of the presented token (coverage).
    Whether cn(e, k) really narrows e is a property of the constraint language (checked by the
    implementation's property-based tests); the model proves that every accepted entry is reached
    from a granted entry by a chain of AS-performed refinements.
  * revocation push: on revocation the AS outputs sig_AS(<'REV', g>); a resource that has received
    a valid notice for g accepts no further request under g.
Variants: ext (all checks), ext_nocover (AS refines entries not held by the presenter),
          ext_nosig (resource accepts unsigned revocation notices).
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen import model

VARIANTS = ['ext', 'ext_nocover', 'ext_nosig']


def ext(v):
    s = model('full').replace('theory BDC_full', 'theory BDC_' + v)
    s = s.replace('builtins: signing, multiset\n', 'builtins: signing, multiset\nfunctions: cn/2\n')
    # signed revocation notice
    s = s.replace('''rule Revoke:
  [ !Consent(U, A1, s, g) ] --[ Revoke(g) ]-> [ ]''', '''rule Revoke:
  [ !Consent(U, A1, s, g), !LtkAS(kas) ] --[ Revoke(g) ]-> [ Out(<<'REV', g>, sign(<'REV', g>, kas)>) ]

// A resource learns of a revocation from a notice (signed by the AS unless ext_nosig).
rule R_learn_revocation:
  [ !PkAS(pkas), In(<<'REV', g>, sg>) ]
  --[ ''' + ('' if v == 'ext_nosig' else "Eq(verify(sg, <'REV', g>, pkas), true), ") + '''RLearn($R, g) ]->
  [ !RRevoked($R, g) ]''')
    rules = []
    # honest delegator requests a refined entry of one of its entries
    for hk, chpat in [('root', 'X'), ('deleg', '<X, p>')]:
        for sk, spat in [('one', 'e')]:
            rules.append(f'''
rule Agent_delegate_{hk}_refine_{sk}:
  let m = <'T', U, A1, g, {chpat}, 'as', {spat}, pk(k)>
      x = <'XR', m, sig, An, R, cn(e, kk), ~nx> in
  [ !Ltk(X, k), !PkAS(pkas), In(<m, sig>), In(<An, R, kk>), Fr(~nx) ]
  --[ Eq(verify(sig, m, pkas), true), Delegate(X, An, R, U, cn(e, kk), {chpat}) ]->
  [ Out(<x, sign(x, k)>) ]
''')
    # AS refinement exchange: coverage = the refined entry's base is an entry of the presented token
    for hk, chpat, holder in [('root', 'A1', 'A1'), ('deleg', '<Ap, p>', 'Ap')]:
        pats = [('any', 'sany')] if v == 'ext_nocover' else [('one', 'e')]
        for sk, spat in pats:
            rules.append(f'''
rule AS_exchange_{hk}_refine_{sk}:
  let m  = <'T', U, A1, g, {chpat}, 'as', {spat}, pkh>
      x  = <'XR', m, sig, An, R, cn(e, kk), nx>
      m2 = <'T', U, A1, g, <An, {chpat}>, R, cn(e, kk), pkn> in
  [ !LtkAS(kas), !Pk(An, pkn), In(<x, sx>) ]
  --[ Eq(verify(sig, m, pk(kas)), true), Eq(verify(sx, x, pkh), true),
      Issue(U, A1, g, <An, {chpat}>, R, cn(e, kk)), Hop(U, A1, g, {holder}, An, R, cn(e, kk), {chpat}),
      Refine(U, A1, g, e, cn(e, kk), {chpat}, 'as', {spat}), Live(g) ]->
  [ Out(<m2, sign(m2, kas)>) ]
''')
    s = s.replace('\nrestriction Equality:', ''.join(rules) + '''
// A resource that has learned of the revocation of g accepts nothing more under g.
restriction PushedRevocation:
  "All R U A1 g ch op n #i #j. Accept(R, U, A1, g, ch, op, n) @ #i & RLearn(R, g) @ #j ==> #i < #j"

restriction Equality:''')
    # invariant and P1 generalized: every issued or accepted entry is granted or AS-refined
    s = s.replace('''lemma scope_invariant [use_induction, reuse]:
  "All U A1 g ch aud s #i. Issue(U, A1, g, ch, aud, s) @ #i ==>
     (Ex s0 #j. Grant(U, A1, s0, g) @ #j & #j < #i & ((s0 = s) | (Ex r. s0 = s + r)))"''',
                  '''lemma scope_invariant [use_induction, reuse]:
  "All U A1 g ch aud s #i. Issue(U, A1, g, ch, aud, s) @ #i ==>
     (Ex s0 #j. Grant(U, A1, s0, g) @ #j & #j < #i & ((s0 = s) | (Ex r. s0 = s + r)))
   | (Ex p pc pa ps #j. Refine(U, A1, g, p, s, pc, pa, ps) @ #j & ((#j < #i) | (#j = #i)))"''')
    s = s.replace('''lemma attenuation:
  "All R U A1 g ch op n #i. Accept(R, U, A1, g, ch, op, n) @ #i ==>
     (Ex s0 #j. Grant(U, A1, s0, g) @ #j & ((s0 = op) | (Ex r. s0 = op + r)))"''',
                  '''lemma attenuation:
  "All R U A1 g ch op n #i. Accept(R, U, A1, g, ch, op, n) @ #i ==>
     (Ex s0 #j. Grant(U, A1, s0, g) @ #j & ((s0 = op) | (Ex r. s0 = op + r)))
   | (Ex p pc pa ps #j. Refine(U, A1, g, p, op, pc, pa, ps) @ #j & #j < #i)"

// P1c Refinement closure: every refined entry refines an entry of a token issued earlier under the
// same grant, so (by induction on refinement steps) each accepted entry is reached from a granted entry
// by a finite chain of AS refinements cn(.,.).
lemma refine_closure:
  "All U A1 g e c ch aud s1 #i. Refine(U, A1, g, e, c, ch, aud, s1) @ #i ==>
     (Ex #j. Issue(U, A1, g, ch, aud, s1) @ #j & #j < #i)"

// P1d Coverage: the refined entry is an entry of the presented token's scope.
lemma refine_covers:
  "All U A1 g e c ch aud s1 #i. Refine(U, A1, g, e, c, ch, aud, s1) @ #i ==> (s1 = e) | (Ex r. s1 = e + r)"

// P5a Notice authenticity: a resource learns of a revocation only if the user revoked the grant.
lemma notice_authentic:
  "All R g #i. RLearn(R, g) @ #i ==> (Ex #j. Revoke(g) @ #j & #j < #i)"

// P5b Push effectiveness: after a resource learns of the revocation of g, it accepts nothing under g.
lemma push_effective:
  "All R U A1 g ch op n #i #j. Accept(R, U, A1, g, ch, op, n) @ #i & RLearn(R, g) @ #j ==> #i < #j"''')
    s = s.replace('''lemma attenuation_honest_agents:
  "All R U A1 g ch op n #i. Accept(R, U, A1, g, ch, op, n) @ #i & not (Ex X #c. Compromised(X) @ #c) ==>
     (Ex s0 #j. Grant(U, A1, s0, g) @ #j & ((s0 = op) | (Ex r. s0 = op + r)))"''',
                  '''lemma attenuation_honest_agents:
  "All R U A1 g ch op n #i. Accept(R, U, A1, g, ch, op, n) @ #i & not (Ex X #c. Compromised(X) @ #c) ==>
     (Ex s0 #j. Grant(U, A1, s0, g) @ #j & ((s0 = op) | (Ex r. s0 = op + r)))
   | (Ex p pc pa ps #j. Refine(U, A1, g, p, op, pc, pa, ps) @ #j & #j < #i)"''')
    # Reuse lemmas apply only to lemmas below them: move the scope invariant and the lemmas that need it
    # to the end so that the other proofs do not case-split on it.
    i0 = s.index('// Invariant (by induction)'); i1 = s.index('// P2 Holder and audience binding')
    block = s[i0:i1]
    s = s[:i0] + s[i1:]
    j0 = s.index('lemma attenuation_honest_agents:'); j1 = s.index('lemma holder_and_audience_network_only:')
    honest = s[j0:j1]
    s = s[:j0] + s[j1:]
    # P1c..P5b live inside block after attenuation; keep them before the invariant
    k = block.index('// P1c Refinement closure')
    tail = block[k:]
    head = block[:k]
    s = s.replace('\nend\n', '\n' + tail + '\n' + head + '\n' + honest + '\nend\n', 1)
    s = s.replace('// P3c Hop authenticity', '''// Helper: every issued token belongs to a grant the user made earlier.
lemma issue_has_grant [use_induction, reuse]:
  "All U A1 g ch aud s #i. Issue(U, A1, g, ch, aud, s) @ #i ==>
     (Ex s0 #j. Grant(U, A1, s0, g) @ #j & #j < #i)"

// P3c Hop authenticity''', 1)
    if v == 'ext':
        s = s.replace('\nend\n', '''
// NV4: a refined entry is accepted at a resource (the refinement path is reachable).
lemma nv_refined_accept:
  exists-trace
  "Ex R U A1 A2 g e k n #i. Accept(R, U, A1, g, <A2, A1>, cn(e, k), n) @ #i & not (Ex X #c. Compromised(X) @ #c)"

// NV5: a resource can learn a revocation after having accepted under the grant (the push path is reachable).
lemma nv_learn_after_accept:
  exists-trace
  "Ex R U A1 A2 g op n #i #j. Accept(R, U, A1, g, <A2, A1>, op, n) @ #i & RLearn(R, g) @ #j & #i < #j
     & not (Ex X #c. Compromised(X) @ #c)"

end
''', 1)
    if v == 'ext_nocover':
        s = s.replace('lemma scope_invariant [use_induction, reuse]', 'lemma scope_invariant [use_induction]')
        s = s.replace('\nend\n', '''
// Witness against P1c: the AS refines an entry ('pay') that the presented token never carried
// (the user granted only 'read').
lemma attack_refine_uncovered:
  exists-trace
  "Ex U A1 g c ch aud #i #j. Refine(U, A1, g, 'pay', c, ch, aud, 'read') @ #i & Grant(U, A1, 'read', g) @ #j"

end
''')
    if v == 'ext_nosig':
        s = s.replace('\nend\n', '''
// Witness against P5a: a resource learns of a revocation the user never made (denial of service).
lemma attack_forged_revocation:
  exists-trace
  "Ex R U A1 s g #i #k. RLearn(R, g) @ #i & Grant(U, A1, s, g) @ #k & not (Ex #j. Revoke(g) @ #j)"

end
''')
    return s


if __name__ == '__main__':
    d = os.path.dirname(os.path.abspath(__file__))
    for v in (sys.argv[1:] or VARIANTS):
        open(os.path.join(d, f'n_{v}.spthy'), 'w').write(ext(v))
    print('ok')
