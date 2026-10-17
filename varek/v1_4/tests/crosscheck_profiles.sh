#!/bin/bash
# SPDX-License-Identifier: MIT
# crosscheck_profiles.sh — v1.29 (step 7): the ship gate's cross-check of
# the baseline and every shipped profile. Each is written as `varek run`
# writes it (for the user nobody, a working directory of its own), then the
# decision procedure, the certificate checker and the oracle must agree on
# it (tools/smt_crosscheck.py). Its reachability queries over the baseline's
# globs take minutes a policy, so it is a target of its own:
#   make crosscheck-profiles [CC_QUERIES=2]
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
Q="${CC_QUERIES:-2}"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
mkdir -p "$OUT/proj"
fail=0
for prof in none $(ls "$HERE/policies/agents/" | sed -n 's/\.profile\.txt$//p'); do
    PYTHONPATH="$HERE/tools" python3 -c "
import pwd, varek_baseline as b
p = None if '$prof' == 'none' else b.load_profile('$HERE/policies/agents/$prof.profile.txt')
open('$OUT/$prof.txt', 'w').write(b.generate('$OUT/proj', pwd.getpwnam('nobody'), '/tmp/varek-65534', p))"
    if python3 "$HERE/tools/smt_crosscheck.py" --vdp "$HERE/tools/vdp_check" --cert "$HERE/tools/vdp_cert_check" \
            --queries "$Q" "$OUT/$prof.txt" > "$OUT/$prof.out" 2>&1; then
        echo "crosscheck_profiles: $prof: $(tail -1 "$OUT/$prof.out")"
    else
        echo "crosscheck_profiles: $prof: FAIL"; tail -5 "$OUT/$prof.out"; fail=1
    fi
done
exit "$fail"
