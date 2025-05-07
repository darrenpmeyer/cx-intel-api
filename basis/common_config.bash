## set this environment variable in your build environment!
CHECKMARX_THREAT_INTEL_APIKEY=${CHECKMARX_THREAT_INTEL_APIKEY:-}

## configure this if you want; defaults to API server limit, 1000 packages per query
CHECKMARX_THREAT_INTEL_MAXQUERY=${CHECKMARX_THREAT_INTEL_MAXQUERY:-1000}

## configure this to change the exit code if risks are found; by default it exits 22
CHECKMARX_THREAT_INTEL_EXITCODE=${CHECKMARX_THREAT_INTEL_EXITCODE:-22}

## exit if no API key
[[ -z "${CHECKMARX_THREAT_INTEL_APIKEY}" ]] && { 
    >&2 echo "No API key provided, set CHECKMARX_THREAT_INTEL_APIKEY"; exit 127; 
}

query_results_file=$(mktemp -t queryresult)
# echo "[" > "${query_results_file}"

## looks for required tools in PATH; modify these if auto-detection fails
##  you can set the appropriate environment var (e.g. BIN_CURL for curl) 
##  or modify the script as needed
_curl=${BIN_CURL:-$(which curl)}
_jq=${BIN_JQ:-$(which jq)}
_npm=${BIN_NPM:-$(which npm)}

[[ -x "${_curl}" ]] || { >&2 echo "Could not find 'curl' in path, adjust PATH or script"; exit 127; };
[[ -x "${_jq}" ]] || { >&2 echo "Could not find 'jq' in path, adjust PATH or script"; exit 127; };

declare -a packages
package_count=0