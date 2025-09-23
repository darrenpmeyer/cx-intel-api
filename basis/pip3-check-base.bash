#!/usr/bin/env bash
set -eu
#DESC: script to check Python project dependencies that are installable with pip3, using Checkmarx MPIAPI
SCRIPT_SOURCE="$(dirname "$(readlink -f "${0}")")" #%remove - only used for sourcing
source "${SCRIPT_SOURCE}/common_config.bash"
## configure this if you want; read report from this file, or generate to this file if it doesn't exist
##   default: will make a temp file
CHECKMARX_PIP3_REPORT_FILE=${CHECKMARX_PIP3_REPORT_FILE:-}
source "${SCRIPT_SOURCE}/common_threat_api.bash"

_pip=${BIN_PIP:-$(which pip3)}
[[ -x "${_pip}" ]] || { >&2 echo "Could not find 'pip3' in path, adjust PATH or script"; exit 127; };

function pypi_package_spec() {
    pkg_name=$(echo "${1}" | cut -d '|' -f 1)
    pkg_ver=$(echo "${1}" | cut -d '|' -f 2)

    echo "{ \"type\": \"pypi\", \"name\": \"${pkg_name}\", \"version\": \"${pkg_ver}\" }"
}

function process_pip3_result() {
    >&2 echo "Processing report from $(basename "${_pip}") resolution"
    package_list=($(jq -r '.install[]|.metadata|"\(.name)|\(.version)"' < "${CHECKMARX_PIP3_REPORT_FILE}")) 
    query_results_file=$(mktemp)
    for line in "${package_list[@]}"
    do
        packages+=("$(pypi_package_spec "${line}")")
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

function generate_pip3_report() {
    FILE_SOURCE=${1} ; shift
    >&2 echo "Asking $(basename "${_pip}") to resolve dependencies (report to '${FILE_SOURCE}')"
    "${_pip}" install --ignore-installed --dry-run --break-system-packages --report "${FILE_SOURCE}" "${@}" >&2
    echo "${FILE_SOURCE}"
}

if [[ -z "${CHECKMARX_PIP3_REPORT_FILE}" ]]
then
    ## set up a temp file
    CHECKMARX_PIP3_REPORT_FILE=$(mktemp)
    [[ -z "${@:-}" ]] && { >&2 echo "Need arguments for pip3, such as '.' or '-r requirements.txt'"; exit 127; }
    generate_pip3_report "${CHECKMARX_PIP3_REPORT_FILE}" "${@}"
fi

if ! [[ -f "${CHECKMARX_PIP3_REPORT_FILE}" ]]
then
    [[ -z "${@:-}" ]] && { >&2 echo "Need arguments for pip3, such as '.' or '-r requirements.txt'"; exit 127; }
    generate_pip3_report "${CHECKMARX_PIP3_REPORT_FILE}" "${@}"
fi

process_pip3_result "${CHECKMARX_PIP3_REPORT_FILE}"

### FOOTER
# pip3-check-base.bash
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
