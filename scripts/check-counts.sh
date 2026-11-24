#!/bin/sh
# Verify that documented suite counts still match freshly captured test logs.
# Usage: sh scripts/check-counts.sh <with-pe-log> <without-pe-log> [docs-dir]
#        sh scripts/check-counts.sh --self-test
set -u

usage() {
    printf 'Usage: %s <with-pe-log> <without-pe-log> [docs-dir]\n' "$0" >&2
    printf '       %s --self-test\n' "$0" >&2
}

# Print: <Results-lines> <passed> <failed> <skipped> <test_pelib-passed>
summarize_log() {
    awk '
        /^Results: / {
            results++
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^passed,?$/)       passed += $(i - 1)
                else if ($i ~ /^failed,?$/)  failed += $(i - 1)
                else if ($i ~ /^skipped,?$/) skipped += $(i - 1)
            }
        }
        /^test_pelib: / {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^passed,?$/) pelib += $(i - 1)
            }
        }
        END { printf "%d %d %d %d %d\n", results, passed, failed, skipped, pelib }
    ' "$1"
}

# Split a summary line into s_count/s_pass/s_fail/s_skip/s_pelib.
split_summary() {
    s_rest=${1#* }
    s_count=${1%% *}
    s_pass=${s_rest%% *}
    s_rest=${s_rest#* }
    s_fail=${s_rest%% *}
    s_rest=${s_rest#* }
    s_skip=${s_rest%% *}
    s_pelib=${s_rest##* }
}

# One required literal in one doc.
check_one() {
    co_file=$1
    co_string=$2
    if grep -Fq "$co_string" "$co_file"; then
        printf 'OK      %s: %s\n' "$co_file" "$co_string"
        return 0
    fi
    printf 'MISSING %s: %s\n' "$co_file" "$co_string"
    return 1
}

# A count that the docs spell in more than one literal form: accept any one.
check_any() {
    ca_file=$1
    shift
    for ca_string in "$@"; do
        if grep -Fq "$ca_string" "$ca_file"; then
            printf 'OK      %s: %s\n' "$ca_file" "$ca_string"
            return 0
        fi
    done
    printf 'MISSING %s: ' "$ca_file"
    ca_sep=''
    for ca_string in "$@"; do
        printf '%s%s' "$ca_sep" "$ca_string"
        ca_sep=' | '
    done
    printf '\n'
    return 1
}

# Compare the three docs with the numbers parsed from the two fresh logs.
check_docs() {
    cd_dir=$1
    cd_status=0
    for cd_name in README.md GAPS.md ARCHITECTURE.md; do
        cd_path=$cd_dir/$cd_name
        if [ ! -f "$cd_path" ]; then
            printf 'MISSING %s: <file absent>\n' "$cd_path"
            cd_status=1
            continue
        fi
        check_one "$cd_path" "$with_pass passed" || cd_status=1
        check_one "$cd_path" "$with_fail failed" || cd_status=1
        check_one "$cd_path" "$with_skip skipped" || cd_status=1
        check_one "$cd_path" "$without_pass passed" || cd_status=1
        check_one "$cd_path" "$without_fail failed" || cd_status=1
        check_one "$cd_path" "$without_skip skipped" || cd_status=1
        check_any "$cd_path" "test_pelib: $with_pelib passed" "$with_pelib passes with PE" || cd_status=1
        check_any "$cd_path" "test_pelib: $without_pelib passed" "$without_pelib without" || cd_status=1
    done
    return "$cd_status"
}

# Build clean and corrupted doc copies plus synthetic logs, then prove that
# the checker exits 0 on clean docs and 1 on a corrupted count.
run_self_test() {
    st_script=$1
    st_docs=$2
    if st_tmp=$(mktemp -d /tmp/opencode/check-counts-selftest.XXXXXX); then
        :
    else
        printf 'SELFTEST FAIL: cannot create temp dir under /tmp/opencode\n' >&2
        return 1
    fi
    trap 'rm -rf "$st_tmp"' EXIT HUP INT TERM

    mkdir -p "$st_tmp/docs" "$st_tmp/corrupt-docs" || return 1
    for st_name in README.md GAPS.md ARCHITECTURE.md; do
        if [ ! -f "$st_docs/$st_name" ]; then
            printf 'SELFTEST FAIL: source doc missing: %s\n' "$st_docs/$st_name" >&2
            return 1
        fi
        cp "$st_docs/$st_name" "$st_tmp/docs/$st_name" || return 1
        cp "$st_docs/$st_name" "$st_tmp/corrupt-docs/$st_name" || return 1
    done

    st_with_log=$st_tmp/with-pe.log
    st_without_log=$st_tmp/without-pe.log
    st_i=1
    while [ "$st_i" -le 19 ]; do
        printf 'Results: 8 passed, 0 failed\n' >> "$st_with_log"
        printf 'Results: 8 passed, 0 failed\n' >> "$st_without_log"
        st_i=$((st_i + 1))
    done
    printf 'Results: 26 passed, 0 failed, 0 skipped\n' >> "$st_with_log"
    printf 'Results: 20 passed, 0 failed, 4 skipped\n' >> "$st_without_log"
    printf 'test_pelib: 21 passed, 0 failed\n' >> "$st_with_log"
    printf 'test_pelib: 10 passed, 0 failed\n' >> "$st_without_log"

    if st_clean_out=$(sh "$st_script" "$st_with_log" "$st_without_log" "$st_tmp/docs" 2>&1); then
        st_clean_rc=0
    else
        st_clean_rc=$?
    fi

    if sed 's/178 passed/CORRUPTED passed/' "$st_tmp/corrupt-docs/README.md" > "$st_tmp/corrupt-readme" && \
       mv "$st_tmp/corrupt-readme" "$st_tmp/corrupt-docs/README.md"; then
        :
    else
        printf 'SELFTEST FAIL: could not corrupt temp doc\n' >&2
        return 1
    fi

    if st_corrupt_out=$(sh "$st_script" "$st_with_log" "$st_without_log" "$st_tmp/corrupt-docs" 2>&1); then
        st_corrupt_rc=0
    else
        st_corrupt_rc=$?
    fi

    printf 'SELFTEST clean-rc=%s corrupt-rc=%s\n' "$st_clean_rc" "$st_corrupt_rc"
    printf '%s\n' "$st_clean_out"
    printf '%s\n' "$st_corrupt_out"
    if [ "$st_clean_rc" -eq 0 ] && [ "$st_corrupt_rc" -eq 1 ]; then
        printf 'SELFTEST OK: clean docs pass (0), corrupted count detected (1)\n'
        return 0
    fi
    printf 'SELFTEST FAIL: expected clean-rc=0 and corrupt-rc=1\n' >&2
    return 1
}

script_dir=$(unset CDPATH; cd "$(dirname "$0")" && pwd -P) || exit 1
repo_dir=$(dirname "$script_dir")
default_docs=$repo_dir

case $0 in
    */*) self_script=$0 ;;
    *)   self_script=./$0 ;;
esac

if [ "${1:-}" = "--self-test" ]; then
    run_self_test "$self_script" "$default_docs"
    exit $?
fi

if [ "$#" -lt 2 ]; then
    usage
    exit 2
fi

with_log=$1
without_log=$2
if [ "$#" -ge 3 ] && [ -n "${3:-}" ]; then
    docs_dir=$3
elif [ -d "$without_log" ]; then
    docs_dir=$without_log
else
    docs_dir=$default_docs
fi

for log_file in "$with_log" "$without_log"; do
    if [ ! -r "$log_file" ]; then
        printf 'ERROR: unreadable log: %s\n' "$log_file" >&2
        exit 1
    fi
done

if with_summary=$(summarize_log "$with_log"); then
    :
else
    printf 'ERROR: cannot parse log: %s\n' "$with_log" >&2
    exit 1
fi
split_summary "$with_summary"
with_count=$s_count
with_pass=$s_pass
with_fail=$s_fail
with_skip=$s_skip
with_pelib=$s_pelib
printf 'with-pe results=%s passed=%s failed=%s skipped=%s pelib=%s\n' \
    "$with_count" "$with_pass" "$with_fail" "$with_skip" "$with_pelib"

if without_summary=$(summarize_log "$without_log"); then
    :
else
    printf 'ERROR: cannot parse log: %s\n' "$without_log" >&2
    exit 1
fi
split_summary "$without_summary"
without_count=$s_count
without_pass=$s_pass
without_fail=$s_fail
without_skip=$s_skip
without_pelib=$s_pelib
printf 'without-pe results=%s passed=%s failed=%s skipped=%s pelib=%s\n' \
    "$without_count" "$without_pass" "$without_fail" "$without_skip" "$without_pelib"

check_docs "$docs_dir"
exit $?
