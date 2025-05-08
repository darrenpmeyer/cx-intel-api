#!/usr/bin/env bash
set -eu
#DESC: script to check npm package-lock.json deps using Checkmarx Threat Intel API
SCRIPT_SOURCE="$(dirname "$(readlink -f "${0}")")" #%remove - only used for sourcing
source "${SCRIPT_SOURCE}/common_config.bash"

## change this if you want to use a non-standard package-lock.json location
NPM_PACKAGE_LOCK=${NPM_PACKAGE_LOCK:-'./package-lock.json'}
[[ -f "${NPM_PACKAGE_LOCK}" ]] || { >&2 echo "Can't find '${NPM_PACKAGE_LOCK}'; fatal"; exit 127; }

source "${SCRIPT_SOURCE}/common_threat_api.bash"

>&2 echo "Analyzing '${NPM_PACKAGE_LOCK}'"
base_query="$(jq -r '[.dependencies | to_entries[] | { "type": "npm", "name": "\(.key)", "version": "\(.value.version)" }]' < ${NPM_PACKAGE_LOCK})"
# cat <<< ${base_query}
package_count=$(jq length <<< "${base_query}")
query_results_file=$(mktemp)
query_file=$(mktemp)
>&2 echo "📦 ${package_count} packages identified"
if [[ $package_count -gt $CHECKMARX_THREAT_INTEL_MAXQUERY ]]
then
    inc_count=0
    sets=$(( $package_count / $CHECKMARX_THREAT_INTEL_MAXQUERY ))
    sets=$(( $sets + 1 ))
    >&2 echo "-> exceeds ${CHECKMARX_THREAT_INTEL_MAXQUERY} items, splitting into ${sets} queries"
    for (( start = 0; start < $package_count; start += $CHECKMARX_THREAT_INTEL_MAXQUERY ))
    do
        end=$(( $start + $CHECKMARX_THREAT_INTEL_MAXQUERY ))
        [[ $end -gt $package_count ]] && end=$package_count
        # >&2 echo "$(( $start + 1 ))-${end}"
        jq ".[$start:$end]" <<< "${base_query}" > "${query_file}"
        # >&2 echo "DEBUG query file '${query_file}'"
        this_run_count=$(jq length "${query_file}")
        inc_count=$(( $inc_count + $this_run_count ))
        >&2 echo "... 📦 ${inc_count} packages read"
        >&2 echo -e "preparing to query ${this_run_count} package(s)"
        _raw_query_threat_intel "${query_file}" >> "${query_results_file}"
    done
else
    >&2 echo "... 📦 $(jq length "${query_file}") packages read"
    cat <<< "${base_query}" > "${query_file}"
    _raw_query_threat_intel "${query_file}" >> "${query_results_file}"
fi

merge_threat_results "${query_results_file}"
rm "${query_results_file}"