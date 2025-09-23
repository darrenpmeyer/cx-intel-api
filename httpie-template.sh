#!/usr/bin/env /bin/bash
[[ -n "${1:-}" ]] || { >&2 echo "Must specifiy package source (e.g. 'npm')"; exit 1; }
PKG_SRC="${1:-}"
[[ -n "${2:-}" ]] || { >&2 echo "Must specifiy package name (e.g. 'node-ipc')"; exit 1; }
PKG_NAME="${2:-}"
[[ -n "${3:-}" ]] || { >&2 echo "Must specifiy package version (e.g. '9.2.2')"; exit 1; }
PKG_VER="${3:-}"

[[ -n "${CHECKMARX_MPIAPI_KEY}" ]] || { >&2 echo "CHECKMARX_MPIAPI_KEY must contain an API key"; exit 2; }

# cat << END
>&2 echo "Querying ${PKG_SRC} pacakge '${PKG_NAME}@${PKG_VER}'"
http 'https://api.scs.checkmarx.com/v2/packages' \
Authorization:${CHECKMARX_MPIAPI_KEY} \
  "[0][name]=${PKG_NAME}"\
  "[0][type]=${PKG_SRC}"\
  "[0][version]=${PKG_VER}"
# END

# curl -# -L --compressed 'https://api.scs.checkmarx.com/v2/packages' \
#       -H 'Content-type: application/json' \
#       -H "Authorization: ${CHECKMARX_THREAT_INTEL_APIKEY}" \
#       --data '[{"type": "${PKG_SRC}", "name": "${PKG_NAME}", "version": "${PKG_VER}"]' > "${web_result}"
