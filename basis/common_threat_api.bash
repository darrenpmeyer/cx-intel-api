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