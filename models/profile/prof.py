"""Run each proof command reported in the paper, recording wall time and peak memory (max RSS of tamarin and maude)."""
import json, resource, subprocess, time, os, sys
os.environ.update(PATH='' + os.environ['PATH'], LANG='C.UTF-8')
TAM = 'tamarin-prover'
FLAGS = ['--stop-on-trace=BFS', '--derivcheck-timeout=0']
COMMON = 'executable scope_invariant holder_and_audience accepted_chain_issued chain_prefix_issued extends_delegation_credential hop_authentic holder_and_audience_network_only hop_authentic_network_only'.split()
RUNS = [('full', []), ('nopop', []), ('noaud', []), ('noxpop', []),
        ('noatten', 'executable scope_invariant issue_has_grant scope_invariant_honest holder_and_audience accepted_chain_issued chain_prefix_issued extends_delegation_credential hop_authentic no_replay revocation holder_and_audience_network_only hop_authentic_network_only attack_escalation'.split()),
        ('noreplay', COMMON + ['attenuation', 'attenuation_honest_agents', 'revocation']), ('noreplay', ['attack_replay']),
        ('norevoke', COMMON + ['attenuation', 'attenuation_honest_agents', 'no_replay']), ('norevoke', ['attack_after_revocation']),
        ('ext', []), ('ext_nocover', ['refine_covers', 'refine_closure', 'attack_refine_uncovered']), ('ext_nosig', ['notice_authentic', 'push_effective', 'attack_forged_revocation'])]
out = []
for v, lemmas in RUNS:
    args = [TAM] + (['--prove'] if not lemmas else [f'--prove={l}' for l in lemmas]) + FLAGS + [os.path.join('..', f'n_{v}.spthy')]
    # isolate memory accounting per run with a fresh child python
    code = ("import resource,subprocess,sys,time,json;t=time.time();r=subprocess.run(sys.argv[1:],capture_output=True,text=True);"
            "m=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss;print(json.dumps(dict(rc=r.returncode,wall=time.time()-t,maxrss_kb=m)));"
            "open('last.out','w').write(r.stdout+r.stderr)")
    r = subprocess.run([sys.executable, '-c', code] + args, capture_output=True, text=True)
    d = json.loads(r.stdout.strip().splitlines()[-1]); d.update(variant=v, lemmas=lemmas or 'all', cmd=' '.join(['tamarin-prover'] + args[1:]))
    txt = open('last.out').read(); open(f'{v}_{len(out)}.out', 'w').write(txt)
    d['verdicts'] = [l.strip() for l in txt.split('summary of summaries')[-1].splitlines() if '(all-traces)' in l or '(exists-trace)' in l]
    out.append(d); json.dump(out, open('profile.json', 'w'), indent=1)
    print(v, round(d['wall'], 1), 's', d['maxrss_kb'] // 1024, 'MB', flush=True)
