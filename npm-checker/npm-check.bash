#!/usr/bin/env bash
set -eu

## set this environment variable in your build environment!
CHECKMARX_MPIAPI_KEY=${CHECKMARX_MPIAPI_KEY:-}

## configure this if you want; defaults to API server limit, 1000 packages per query
CHECKMARX_MPIAPI_MAXQUERY=${CHECKMARX_MPIAPI_MAXQUERY:-1000}

## configure this to change the exit code if risks are found; by default it exits 22
CHECKMARX_MPIAPI_EXITCODE=${CHECKMARX_MPIAPI_EXITCODE:-22}

## exit if no API key
[[ -z "${CHECKMARX_MPIAPI_KEY}" ]] && {
    >&2 echo "No API key provided, set CHECKMARX_MPIAPI_KEY"; exit 127;
}

query_results_file=$(mktemp -t queryresult)
# echo "[" > "${query_results_file}"

## looks for required tools in PATH; modify these if auto-detection fails
##  you can set the appropriate environment var (e.g. BIN_CURL for curl)
##  or modify the script as needed
_curl=${BIN_CURL:-$(which curl)}
_jq=${BIN_JQ:-$(which jq)}

[[ -x "${_curl}" ]] || { >&2 echo "Could not find 'curl' in path, adjust PATH or script"; exit 127; };
[[ -x "${_jq}" ]] || { >&2 echo "Could not find 'jq' in path, adjust PATH or script"; exit 127; };

declare -a packages
package_count=0

function join_comma() {
    local IFS=', '
    echo "$*"
}

function _raw_query_mpi() {
    query_file=${1}
    ## this uses curl to query the API, and jq to filter the results
    ## so that only packages with risks are returned
    >&2 echo "sending query to Checkmarx Malicious Package Identification API"
    web_result=$(mktemp -t webresult)
    "${_curl}" -# -L --compressed 'https://api.scs.checkmarx.com/v2/packages' \
      -H 'Content-type: application/json' \
      -H "Authorization: ${CHECKMARX_MPIAPI_KEY}" \
      --data "@${query_file}" > "${web_result}"
    # cat "${web_result}"
    "${_jq}" '[ .[] | select(.risks!=[]) ]' < "${web_result}"\
      || { code=$?; >&2 "Failure while parsing response: see '${web_result}'"; exit $code; }

    rm "${query_file}" "${web_result}"
}

function query_mpi() {
    ### query_mpi queries all packages in the `packages` array
    query_file="$(mktemp -t queryfile)"
    echo '[' > "${query_file}"

    >&2 echo -e "preparing to query ${#packages[@]} package(s)"
    echo $(join_comma "${packages[@]}") >> "${query_file}"
    echo ']' >> "${query_file}"

    _raw_query_mpi "${query_file}"
}

function merge_threat_results() {
    ## join all results together using JQ
    ## merge_threat_results "${query_results_file}"
    query_results_file=${1}
    tmp_query_results=$(mktemp)
    "${_jq}" -s 'add' < "${query_results_file}" > "${tmp_query_results}"
    rm "${query_results_file}" && mv "${tmp_query_results}" "${query_results_file}"

    ## now count results and exit if any risks were found
    risky_package_count=$(( $("${_jq}" 'length' < "${query_results_file}") + 0 ))
    if [[ $risky_package_count -gt 0 ]]
    then
        cat "${query_results_file}"
        >&2 echo "ALERT! found ${risky_package_count} packages with risks! Exiting with code ${CHECKMARX_MPIAPI_EXITCODE}"
        >&2 echo "... total of $package_count packages were examined"
        rm "${query_results_file}"
        exit ${CHECKMARX_MPIAPI_EXITCODE}
    else
        >&2 echo "✅ No risky packages identified in this review ($package_count examined)"
    fi
}

_npm=${BIN_NPM:-$(which npm)}
[[ -x "${_npm}" ]] || { >&2 echo "Could not find 'npm' in path, adjust PATH or script"; exit 127; };

function npm_pkg_spec() {
    pkg_name=$(echo "${1}" | cut -d ' ' -f 1)
    pkg_ver=$(echo "${1}" | cut -d ' ' -f 2)

    echo "{ \"type\": \"npm\", \"name\": \"${pkg_name}\", \"version\": \"${pkg_ver}\" }"
}

function process_npm_result() {
    >&2 echo "Examining input for NPM packages"
    query_results_file=$(mktemp)
    while IFS=$'\n' read -r line
    do
        [[ "${line}" =~ ^add[[:blank:]] ]] || continue
        package_spec="$(echo "${line}" | cut -d ' ' -f 2-)"

        packages+=("$(npm_pkg_spec "${package_spec}")")
        package_count=$(($package_count + 1))
        [[ $((${#packages[@]} % 100 )) -eq 0 ]] && >&2 echo "... 📦 $package_count packages read"

        if [[ ${#packages[@]} -eq ${CHECKMARX_MPIAPI_MAXQUERY} ]]
        then
            ## we hit the max size, run a query!
            query_mpi >> "${query_results_file}"
            # echo ',' >> "${query_results_file}"
            packages=()
            >&2 echo "Resuming examination of input for NPM packages"
        fi
    done
    >&2 echo "... 📦 $package_count packages read"

    query_mpi >> "${query_results_file}"
    merge_threat_results "${query_results_file}"
    rm "${query_results_file}"
}

FILE_SOURCE=${1:-}
if [[ "${FILE_SOURCE}" == "-" ]]
then
    process_npm_result
elif [[ -n "${FILE_SOURCE}" ]]
then
    >&2 echo "Using saved output from '${FILE_SOURCE}'"
    process_npm_result < "${FILE_SOURCE}"
else
    >&2 echo "Asking npm about packages to install using '${_npm}'"
    [[ -x "${_npm}" ]] || { >&2 echo "Could not find 'npm' in path, adjust PATH or script"; exit 127; };

    "${_npm}" install --dry-run | process_npm_result
fi

###
# npm-check.bash - script to check npm project dependencies using Checkmarx MPIAPI
#     Copyright (C) 2025  Darren P Meyer

#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU Affero General Public License as published
#     by the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.

#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU Affero General Public License for more details.

#     You should have received a copy of the GNU Affero General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.

