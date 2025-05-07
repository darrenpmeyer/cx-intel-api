function join_comma() {
    local IFS=', '
    echo "$*"
}

function query_threat_intel() {
    ### query_threat_intel queries all packages in the `packages` array
    query_file="$(mktemp -t queryfile)"
    echo '[' > "${query_file}"

    >&2 echo -e "preparing to query ${#packages[@]} package(s)"
    echo $(join_comma "${packages[@]}") >> "${query_file}"
    echo ']' >> "${query_file}"

    ## this uses curl to query the API, and jq to filter the results
    ## so that only packages with risks are returned
    >&2 echo "sending query to Checkmarx SCS Threat Intel API"
    web_result=$(mktemp -t webresult)
    "${_curl}" -# -L --compressed 'https://api.scs.checkmarx.com/v2/packages' \
      -H 'Content-type: application/json' \
      -H "Authorization: ${CHECKMARX_THREAT_INTEL_APIKEY}" \
      --data "@${query_file}" > "${web_result}"
    "${_jq}" '[ .[] | select(.risks!=[]) ]' < "${web_result}"\
      || { code=$?; >&2 "Failure while parsing response: see '${web_result}'"; exit $code; }

    rm "${query_file}" "${web_result}"
}
