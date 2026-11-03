#!/bin/bash
# Re-runs every proof reported in the paper. Requires tamarin-prover 1.10.0 and Maude 3.5 on PATH.
# Typical times on 2 vCPUs: full 83 s; ablations 15-262 s each; about 22 minutes in total.
set -u
cd "$(dirname "$0")"
python3 gen.py                       # regenerates n_<variant>.spthy from one source
T="tamarin-prover --stop-on-trace=BFS --derivcheck-timeout=0"
run() { v=$1; shift; args=""; for l in "$@"; do args="$args --prove=$l"; done
        [ -z "$args" ] && args="--prove"
        echo "== $v"; $T $args n_$v.spthy 2>&1 | sed -n '/summary of summaries/,$p' | grep -E "verified|falsified|processing"; }
COMMON="executable scope_invariant holder_and_audience accepted_chain_issued chain_prefix_issued extends_delegation_credential hop_authentic holder_and_audience_network_only hop_authentic_network_only"
run full
run nopop
run noaud
run noxpop
run noatten executable scope_invariant issue_has_grant scope_invariant_honest holder_and_audience accepted_chain_issued extends_delegation_credential \
    chain_prefix_issued hop_authentic no_replay revocation holder_and_audience_network_only hop_authentic_network_only attack_escalation
run noreplay $COMMON attenuation attenuation_honest_agents revocation
run noreplay attack_replay
run norevoke $COMMON attenuation attenuation_honest_agents no_replay
run norevoke attack_after_revocation

# Extended model: constrained refinement and revocation notices (Section 5.5)
python3 gen_ext.py
run ext
run ext_nocover refine_covers refine_closure attack_refine_uncovered
run ext_nosig notice_authentic push_effective attack_forged_revocation
