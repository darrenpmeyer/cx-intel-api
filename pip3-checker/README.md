# pip3-checker - Check `pip install`-able Python projects for malicious packages

```shell
env CHECKMARX_THREAT_INTEL_APIKEY=$(vault kv get /dev-secrets/cx-malware-api) \
  bash /path/to/pip3-check.bash -r requirements.txt
```

`pip3-check.bash` takes the same arugments as `pip3 install`, then uses pip to *simulate installation* to determine what packages would be installed. It then queries the Checkmarx SCS Threat Intel API to determine if any package versions have risk indicators for malice or actually are malicious.

If no risks are found, we exit with code `0`; otherwise with code `22` (this is configurable, see below).

You MUST set `CHECKMARX_THREAT_INTEL_APIKEY` to be a valid API token for the Threat Intel API; the example above needs to be adapted to set it appropriately. The `$(vault ...)` command is a simplified example of getting the required credential from a secrets vault.

**Requires** curl, jq, and pip3; they'll be detected in your `PATH` if possible, otherwise specify them using environment variables (see Configuration below)

## Arguments

We pass arguments to `pip3 install`; you must specify a valid target. This is almost always one of:

* a requirements file with `-r` like `-r requirements.txt`
* a module spec (like `requests==2.32.3`)
* a project path (often just `.`) that contains e.g. `setup.cfg` or `pyproject.toml`


## Errors

* `0` -- no error, no risks found, proceed
* `22` -- risks found (this can be customized, see Additional configuration section)
* `127` -- a required tool was not found. Read error message printed to see which one, see Requirements section
* other -- a tool failed to complete successfully and returned its own error. Most commonly occurs when curl experiences a network error


## Known Limitations

We do not currently support alternative package resolvers like `poetry`; however you can work around this for most systems by causing them to produce a `requirements.txt`, then using this script with `-r requirements.txt`. In some cases, you can produce a pip report and provide this via an environment variable (see Configuration below).

**WARNING** malicious packages sometimes can deliver payloads upon installation; ensure any workaround you implement for non-pip package managers do not install the packages!

## Configuration

Configure `pip3-check.bash` behavior by setting environment variables

* `CHECKMARX_THREAT_INTEL_APIKEY` (required) - credential key for the Checkmarx SCS Threat Intel API
* `CHECKMARX_THREAT_INTEL_MAXQUERY` (optional, default=1000) - number of package versions to query each time the API is called. Billing is per API call, so leaving this at the default of `1000` (the maximum) is strongly recommended
* `CHECKMARX_THREAT_INTEL_EXITCODE` (optional, default=22)
* `BIN_CURL` (optional, autodetected) specify the path to the `curl` binary; by default, this will be found in your `PATH`
* `BIN_JQ` (optional, autodetected) specify the path to the `jq` binary; by default, this will be found in your `PATH`
* `BIN_PIP` (optional, autodetected) specify the path to the `pip3` binary; by default, this will be found in your `PATH`
* `CHECKMARX_PIP3_REPORT_FILE` (optional, default=temporary file) specify a file where you want the JSON-format report of packages to be installed to be stored. By default, we will generate a temporary file for this use (using `mktemp`). If this file already exists, it will be used in lieu of using `pip3` to resolve packages.

## No Warranty

**This software is provided by the copyright holders and contributors “AS IS” and any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the copyright owner or contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.**