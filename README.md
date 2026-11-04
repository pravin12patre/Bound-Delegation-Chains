# Bound Delegation Chains: artifact

This archive is the exact version used to produce every result in the paper *Bound Delegation Chains: Securing Delegated Authority in the Model Context Protocol*.

| Paper item | Where |
|---|---|
| Tables 2, 3, 5 (base model: lemmas incl. P3d and non-vacuity, ablations, run time and memory) | `models/` (`gen.py`, `n_*.spthy`, `proofs/`, `profile/`) |
| Table 4, Section 5.5 (extended model: refinement, revocation notices) | `models/gen_ext.py`, `models/n_ext*.spthy`, `models/extended/` |
| Supplemental material, Appendix A (commands, versions), audit | `models/reproduce_proofs.sh`, `models/profile/prof.py`, `AUDIT.md`, `models/cleanroom_proofs.log` |
| Table 7 (end-to-end attacks), Table 8 (latency) | `mcp_eval/run_eval.py` → `results/mcp_eval.json`; rerun after the final code changes: `results/mcp_eval_regression_check.json` |
| Section 7.3 (throughput) | sweep: `mcp_eval/replay2_eval.py` → `results/replay2.json`; steady state: `mcp_eval/steady.py` → `results/steady.json` |
| Fig. 2 (token size with enterprise identifiers) | `mcp_eval/rev_eval.py` → `results/revision.json` → `sizes` |
| Section 4.6, Table 9 (revocation state, linearization) | `mcp_eval/revocation.py`, `mcp_eval/rev2_eval.py` → `results/revocation2.json`; `mcp_eval/lin_eval.py` → `results/linearization.json` |
| Section 4.5, Theorem 1, Table 10 (parameter constraints) | `mcp_eval/constraints.py` (grammar in the module docstring), `mcp_eval/test_constraints.py`, `mcp_eval/e2_only.py`, `mcp_eval/scale_eval.py` → `results/revision.json` → `constraints`, `results/scale.json`, `results/property_tests_20000.log` |
| Table 11 (emulated wide-area RTT) | `mcp_eval/rev_eval.py` (with `delayproxy.py`) → `results/revision.json` → `wan` |
| Table 12 (replicated servers: concurrent replay, fail-over) | `mcp_eval/replay2_eval.py` → `results/replay2.json`; rerun after the final guard change: `results/replay2_after_fix_check.json` |
| Tables 1, 13 (OAuth reference, `may_act` and hardened configurations) | `mcp_eval/oauth_strong.py`, `mcp_eval/compare_eval.py` → `results/oauth_compare.json` |

## 1. Formal models (Tamarin)

Requirements: Tamarin prover 1.10.0 and Maude 3.5 on `PATH`, Python 3.

```
cd models
./reproduce_proofs.sh
```

* `gen.py` generates the base model `n_full.spthy` and six ablations from one source, so the variants differ only in the removed check:
  `nopop` (resource skips the holder proof), `noaud` (resource skips the audience), `noxpop` (AS skips the holder signature on exchange requests),
  `noatten` (AS skips attenuation), `noreplay` (no nonce cache), `norevoke` (AS ignores revocation).
* `gen_ext.py` generates the extended model (`ext`) with the refinement constructor `cn/2` and signed revocation notices, and its ablations `ext_nocover` (AS refines entries the presenter does not hold) and `ext_nosig` (resource accepts unsigned notices).
* `proofs/` and `extended/` hold the outputs reported in the paper, including attack traces. `verdicts.json` summarizes Table 4.
* All runs use `--stop-on-trace=BFS --derivcheck-timeout=0`. Expected on 2 vCPUs: base model 83 s (285 MB); ablations 15–262 s (up to 1.1 GB); extended model 130 s (479 MB). All runs take about 22 minutes in total.
* Tamarin applies a lemma marked `reuse` to every lemma after it; the extended model therefore places its scope invariant last.

## 2. Implementation, tests and measurements

Requirements: Python 3.13 (3.11+ should work).

```
python3 -m venv venv && . venv/bin/activate
pip install -r mcp_eval/requirements.txt
cd mcp_eval
PBT_EXAMPLES=20000 pytest -q test_constraints.py   # property-based and edge-case tests (about 4 min)
N_LAT=1500 python run_eval.py      # attacks, latency, exchange latency, throughput, macaroons
python tp.py                        # repeated throughput runs
python rev_eval.py                  # WAN emulation, replicas (sequential), token sizes
python e2_only.py                   # end-to-end constraint tests
python scale_eval.py                # constraint cost up to 800 entries
python rev2_eval.py                 # revocation state: push, lost notice, partition, bad notices, restarts
python replay2_eval.py              # concurrent replay, fail-over, throughput sweep
python compare_eval.py              # BDC versus token exchange + DPoP: reference, may_act, hardened
python lin_eval.py                  # revocation versus concurrent authorization
python steady.py                    # 30 s steady-state throughput
```

Each script starts its authorization server, MCP servers (official MCP Python SDK, Streamable HTTP, stateless JSON mode), load balancers, nonce store or delay proxies as local processes, runs its experiment, writes its JSON file under `results/` and stops the processes.

* `bdc2.py`: tokens, exchange, request proofs and resource checks.
* `constraints.py`: grammar, canonical form, coverage and evaluation of parameter-constrained scope entries.
* `revocation.py`: revocation log (AS side) and revocation state (resource side).
* `oauth_strong.py`: the standards baselines (RFC 8693 token exchange, RFC 9449 DPoP, RFC 8707, enforced attenuation, `may_act`, RFC 7009), with a hardened option (holder countersignature, lineage revocation, body digest).
* `services.py`: the AS, the MCP server with the BDC, DPoP or bearer guard middleware, the shared nonce store and the load balancer.
* `client.py`: client-side auth handlers for BDC, DPoP and bearer tokens.
* `delayproxy.py`: TCP proxy adding RTT/2 delay in each direction.

Absolute latencies depend on the machine; the paper's numbers were measured on 2 vCPUs (x86-64) with all processes on the same host.

## License

Released for research and evaluation.
