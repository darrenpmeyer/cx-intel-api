# `npm-check.bash` - Check npm project for malicious packages

```
env CHECKMARX_THREAT_INTEL_APIKEY=$(vault kv get /dev-secrets/cx-malware-api) \
  bash /path/to/npm-check.bash
```

Queries the Checkmarx SCS Threat Intel API to determine whether running `npm install` would result in installing a package that's potentially malicious. Exits non-zero if any risky packages are identified.

> Requires that `CHECKMARX_THREAT_INTEL_APIKEY` contain the API key; example above uses a `vault` program to retrieve the credential -- this is illustrative only, you must customize this to supply your API key secret

`npm-check.bash` will automatically run `npm install --dry-run` in the current working directory, and examine every package version that would be installed.

If risks are found for any package, the JSON record(s) for found risks will be printed to STDOUT and the script will exit with code 22.

## Arguments 

`npm-check.bash` takes a single *optional* argument (`INPUT_FILE`. If provided, npm will not be queried, but file or STDIN content will be used instead.

`INPUT_FILE` may be one of:

* **a file path**, in which case `npm-check.bash` will read packages from a file the contains lines of the form: 
  ```text
  add package-name VER
  ```
  such as would be produced by `npm install --dry-run > INPUT_FILE`

* **the character `-`**, in which case `npm-check.bash` will read packages data from STDIN in the same format as above, enabling:
  ```sh
  npm install --dry-run | env ... npm-check.bash
  ```

## Errors

* `0` -- no error, no risks found, proceed
* `22` -- risks found (this can be customized, see Additional configuration section)
* `127` -- a required tool was not found. Read error message printed to see which one, see Requirements section
* other -- a tool failed to complete successfully and returned its own error. Most commonly occurs when curl experiences a network error

## Known limitations

1. Does not support `npm upgrade` operations; the script is intended for full install operations in CI, using with output from `npm upgrade --dry-run` may not produce valid results.

2. There may be risks unidentified and/or not yet reported by the Threat Intel API; a lack of risks detected is not a guarantee of safety (this is true of all tools in this class... security is hard).

## Requirements

* POSIX (or close) enviromennt with `bash` available; tested on Linux and macOS
* Requires that `curl` and `jq` be available. 
* If not processing a file input, will also require `npm`
* Required tools will be used from the `PATH` if found, or can be specified with environment variables `BIN_CURL`, `BIN_JQ`, and `BIN_NPM`
* `CHECKMARX_THREAT_INTEL_APIKEY` must be set to a valid API key for the Threat Intel API; this is separate from Checkmarx One API keys. We strongly recommend storing this value in a vault (such as HashiCorp Vault, 1Password, GitHub Secrets, etc.) and retrieving it at runtime, especially in CI or similar environments.

## Additional Configuration

Configuration is made through environment variables. In addition to basic configuration specified above, you can set:

* `CHECKMARX_THREAT_INTEL_MAXQUERY` to control the maximum number of packages examined in each call to the API. This defaults to 1000, which is the maximum the API endpoint permits. You can reduce this if desired. In most cases, API use is billed on a number-of-queries basis.

* `CHECKMARX_THREAT_INTEL_EXITCODE` to control the shell exit code when threats are detected.