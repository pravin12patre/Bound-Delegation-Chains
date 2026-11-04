# Audit of the models and implementation

This file records an audit of the artifact, done after the third review, to check that the proofs establish what the paper claims and that the implementation matches the models. It covers four things:

1. a clean-room reproduction from this archive;
2. a review of every restriction and lemma;
3. non-vacuity checks;
4. a model-to-code correspondence.

It also lists the problems the audit found and how each was fixed.

## 1. Clean-room reproduction

The archive was unpacked into an empty directory and a fresh Python virtual environment was created from `mcp_eval/requirements.txt`. Everything was then run from that copy:

* `models/reproduce_proofs.sh`
* `pytest test_constraints.py` with 20,000 examples per property
* `run_eval.py` (attack suite)
* `compare_eval.py`
* `lin_eval.py`
* `rev2_eval.py`

| Check | Paper | Clean-room result |
|---|---|---|
| Base model, all lemmas, all ablations | Tables 2, 3 | same verdicts (see `models/cleanroom_proofs.log`) |
| Extended model and its ablations | Table 4 | same verdicts |
| Non-vacuity lemmas (new) | Supplemental material, Appendix A | all proved |
| Property-based and edge-case tests | 46 tests | 46 passed |
| End-to-end attack suite | Table 7 | 17 of 17 as expected |
| OAuth comparison | Table 13 | same outcomes in every row |
| Revocation state (lost notice, partition, bad notices, restarts) | Table 9 | same outcomes; timings within noise |
| Linearization | Table 9 | 0 requests authorized after revocation was applied |

Timings in the clean-room run were taken while other jobs shared the two CPUs, so they are not used in the paper. The paper's times come from runs executed one at a time (`models/profile/profile.json`).

## 2. Restrictions

A Tamarin restriction removes traces from consideration. If a restriction excluded an attack instead of encoding a check, every proof that relied on it would be meaningless. Each restriction is listed below with the rule that triggers it and its role.

| Restriction | Triggered by | Encodes | Comment |
|---|---|---|---|
| `Equality` | every signature check (`Eq(verify(...), true)`) | signature verification at the AS and the resource | standard encoding of a check that succeeds |
| `SingleAS` | `AS_key` | one AS signing key | modeling assumption (trusted AS) |
| `OneKeyPerAgent` | `Agent_key` | the AS registry binds one key per agent name | was **not** enforced by the prototype; fixed (finding F1) |
| `RevokedGrant` | `Live(g)` in `AS_issue_root` and every `AS_exchange_*` rule | the AS refuses issuance after revocation | only AS rules emit `Live`; the attacker is not restricted |
| `ReplayCache` | `RNonce` in `R_accept_*` | the resource's nonce cache, one atomic set-if-absent per audience | replicated deployments must provide this (paper Section 7.8) |
| `PushedRevocation` (extended model) | `Accept` and `RLearn` | the resource consults its revoked set | P5b restates it; P5a is the substantive lemma |

None of these restrictions mentions attacker actions or `Compromised`, so none can rule out an attack by assumption. Non-vacuity lemmas (Section 3) show that the behaviors they constrain remain reachable.

## 3. Non-vacuity

Each property below is an implication. If its premise could never be reached because of a restriction, the property would hold vacuously. The following exists-trace lemmas show that the premises are reachable.

| Lemma | Shows | Model |
|---|---|---|
| `executable` | a three-agent chain is accepted with no compromise | base, extended |
| `nv_used_after_revocation` | a token issued before revocation is used after it, so P5's premise occurs | base |
| `nv_repeated_use` | the same holder gets two requests with different nonces accepted, so the replay cache does not block honest use | base |
| `nv_compromised_holder` | a compromised holder gets a request accepted, so compromise is reachable and P2's exception is not empty | base |
| `nv_refined_accept` | a refined entry `cn(e, k)` is accepted at a resource | extended |
| `nv_learn_after_accept` | a resource accepts under `g`, then learns of its revocation | extended |
| attack witnesses in each ablation | removing a check makes the corresponding violation reachable | ablations |

## 4. Lemma review

* **P1 `attenuation`.** "Accepted `op` is contained in a scope the user granted." Every agent may be compromised. The lemma does not require the grant to precede the acceptance, but `scope_invariant`, which is proved, does.
* **P2 `holder_and_audience`.** If the final holder is honest, it sent exactly this request (token, operation, nonce) to this resource.
* **P3a `accepted_chain_issued`.** The AS issued the accepted chain for this audience with a scope covering `op`.
* **P3b `chain_prefix_issued`.** Every hop extends a chain issued earlier under the same grant. With P3a, induction gives the whole chain (Theorem 2 in the paper).
* **P3c `hop_authentic`.** A hop whose delegator is honest was requested by that delegator, for that delegate, audience and scope. Honest agents sign attacker-chosen delegates, so P3c is about authorship, not intent (paper Section 3).
* **P3d `extends_delegation_credential`.** Every hop extends a token whose audience is the AS. This holds because the exchange rules match only such parents; it is a design property, stated as a lemma so that ablations and future changes cannot silently drop it.
* **P4 `no_replay`.** Two acceptances with identical arguments are the same event. The restriction is stronger (per resource and nonce), so P4 also holds across chains.
* **P5 `revocation`.** Anything accepted after revocation used a token issued before it. Time is not modeled, so the lemma does not bound how long such a token stays usable.
* **Extended model.** `refine_closure` and `refine_covers` give refinement provenance; `notice_authentic` gives signature origin together with the rule that notices are issued only on revocation.

## 5. Model-to-code correspondence

| Model element | Implementation |
|---|---|
| `AS_exchange_*`: verify the AS signature on the parent token | `bdc2.py`, `AuthorizationServer.exchange` (line `# AS signature`) |
| exchange PoP: request signed by the parent's `cnf` key | `AuthorizationServer.exchange` (`# holder signed the request`) |
| parent audience must be `'as'` (P3d) | `AuthorizationServer.exchange` (`not a delegation credential`) |
| `Live(g)` / `RevokedGrant` | `AuthorizationServer.exchange` and `issue_root` (`revoked`) |
| scope patterns `s` / `s2 + rest` (attenuation) | `constraints.scope_covers`, called in `exchange` (`escalation`) |
| `!Pk(An, pkn)` (delegate registered, one key) | `AuthorizationServer.register` (refuses a second key) and the registry lookup in `_tok` |
| `R_accept_*`: AS signature, audience `$R` | `ResourceGuard.check` (`audience`) |
| holder proof over `<'REQ', m, op, $R, n>` | `ResourceGuard.check` (`proof binding`); the implementation also binds method, URL and body hash |
| `ReplayCache` | `ResourceGuard._fresh` (single process); shared store via `services.nonce_app` (`SET`-if-absent) |
| scope `op` / `op + rest` | `constraints.allows` (tool name and argument constraints) |
| `cn(e, k)` refinement with coverage | `constraints.covers` (property-tested; not modeled concretely) |
| signed notice `<'REV', g>` and `RLearn` | `revocation.RevocationState.on_notice` / `_check`; the implementation adds `typ`, `iss`, `aud`, `seq`, `iat` |
| `PushedRevocation` | `revocation.RevocationState.admit`, called last in `services.Guard` before dispatch |
| Not modeled | expiry and clocks, heartbeats and staleness, persistence, JSON parsing, the exchange-request nonce cache at the AS |

## 6. Findings and fixes

* **F1: identity re-registration (fixed).** The model assumes one key per agent name, but the prototype's `register` overwrote an existing key. An attacker with access to the registration endpoint could have rebound an honest agent's name to its own key. `register` now refuses a second key for a registered name, and the attack suite has a new test for this.
* **F2: order of checks with a shared nonce store (fixed).** In the shared-store configuration, the guard awaited the store after the revocation check, so a notice could arrive between the check and dispatch. The revocation check is now the last step before dispatch, as the paper's linearization rule states. This fix came after the clean-room run; the attack suite and the replicated-replay experiments were rerun afterwards with unchanged results (`results/mcp_eval_regression_check.json`, `results/replay2_after_fix_check.json`).
* **F3: artifact statement in the PDF (fixed earlier).** A LaTeX macro defined with `\newcommand` never compared equal to an empty macro, so the PDF printed "available at" with no link.
* **F4: exchange-request replay is not modeled (no change).** The AS rejects repeated exchange-request nonces, but the model does not include this check. A replayed exchange request would only reissue a token bound to the same delegate's key, so no property depends on it.
* **F5: refinement in the model applies to single-entry tokens (no change).** This is stated in the paper.

## 7. Out of scope

This audit does not cover:

* side channels;
* the correctness of the Ed25519 library, the MCP SDK or Tamarin itself;
* the computational soundness of the symbolic model;
* behavior under clock skew beyond the configured window.
