#!/usr/bin/env bash
set -eu
#DESC: script to check npm project dependencies using Checkmarx Threat Intel API
SCRIPT_SOURCE="$(dirname "$(readlink -f "${0}")")" #%remove - only used for sourcing
source "${SCRIPT_SOURCE}/common_config.bash" 
source "${SCRIPT_SOURCE}/common_threat_api.bash"

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

        if [[ ${#packages[@]} -eq ${CHECKMARX_THREAT_INTEL_MAXQUERY} ]]
        then
            ## we hit the max size, run a query!
            query_threat_intel >> "${query_results_file}"
            # echo ',' >> "${query_results_file}"
            packages=()
            >&2 echo "Resuming examination of input for NPM packages"
        fi
    done
    >&2 echo "... 📦 $package_count packages read"

    query_threat_intel >> "${query_results_file}"
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

###FOOTER
# npm-checker-base.bash - script to check npm project dependencies using Checkmarx Threat Intel API
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
