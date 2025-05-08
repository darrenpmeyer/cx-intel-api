# `npm-check.bash` - Check npm project for malicious packages

Acquire [`npm-check.bash`](npm-check.bash) and check [its SHA-512 sum](npm-check.bash.sha512) before setting it executable, for example:

```shell
sha512sum -c npm-check.bash.sha512 && chmod +x npm-check.bash
```

Or if you have the repo owner's public key, get [the signature file](npm-check.bash.asc) and:

```shell
gpg --verify - < npm-check.bash.asc && chmod +x npm-check.bash
```

Then run the following, adjusted to your environment:

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

## Example

In this example, `npm-check.bash` has been installed under `/usr/local/bin` and I'm using 1Password's CLI tool (`op`) to get the API key from my password vault to scan the `react-boilerplate` open-source NPM-based project.

```text
⋯›% env CHECKMARX_THREAT_INTEL_APIKEY=$(op item get 'Checkmarx Malicious Packages API' --reveal --fields credential) \
bash /usr/local/bin/npm-checker/npm-check.bash > risks.json && rm risks.json

Asking npm about packages to install using '/opt/homebrew/bin/npm'
Examining input for NPM packages
npm warn old lockfile
npm warn old lockfile The package-lock.json file was created with an old version of npm,
npm warn old lockfile so supplemental metadata must be fetched from the registry.
npm warn old lockfile
npm warn old lockfile This is a one-time fix-up, please be patient...
npm warn old lockfile
... 📦 100 packages read
... 📦 200 packages read
... 📦 300 packages read
... 📦 400 packages read
... 📦 500 packages read
... 📦 600 packages read
... 📦 700 packages read
... 📦 800 packages read
... 📦 900 packages read
... 📦 1000 packages read
preparing to query 1000 package(s)
sending query to Checkmarx SCS Threat Intel API
######################################################################## 100.0%
Resuming examination of input for NPM packages
... 📦 1100 packages read
... 📦 1200 packages read
... 📦 1300 packages read
... 📦 1400 packages read
... 📦 1500 packages read
... 📦 1600 packages read
... 📦 1700 packages read
... 📦 1800 packages read
... 📦 1823 packages read
preparing to query 823 package(s)
sending query to Checkmarx SCS Threat Intel API
######################################################################## 100.0%
✅ No risky packages identified in this review (1823 examined)
```

The script runs `npm install --dry-run` automatically in the `react-boilerplate` directory; NPM resolves the packages that would be installed, and the script reads them in. Since one API query can do up to 1000 packages at once, we send the first 1000 to the API, then resume reading the to-be-installed package list.

Since no risky packages were identified, we get an exit code of `0` and a nice green checkmark for our logs. If risky packages *had been* identified, we'd have got information about them along with a JSON document detailing risks output on STDOUT, which we redirect to `risks.json`. the `&& rm risks.json` says "if we exit 0, which means no risks, remove the empty risks.json file".

All 1823 npm packages are identified, resolved, and scanned -- without downloading any of them -- in just over 30 seconds. And the bulk of that time is spent by npm resolving and outputting the package lists.

## No Warranty

**This software is provided by the copyright holders and contributors “AS IS” and any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the copyright owner or contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.**