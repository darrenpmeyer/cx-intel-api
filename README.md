# Checkmarx MPIAPI integrations

A collection of tools useful for integrating the Checkmarx Malicious Package Identification API (MPIAPI)into CI/CD and other automated build processes. These tools require an active API key for the commercial MPIAPI. This API was previously known as "SCS Threat Intel API" (hence the repo name).

These tools can be used as-is, but are intended as templates for modification and use. These tools were written by Darren P Meyer while employed by Checkmarx, but are not officially supported by Checkmarx -- they're shared as a form of education and guidance.

* [`npm-checker`](npm-checker/) checks NPM-based projects for indicators of supply-chain risks (except known vulenrabilities)
    - [`npm-check.bash`](npm-checker/README.md#npm-check) can be run in an npm project anywhere `npm install` would work; it will use `npm` to determine what would be installed and exits non-zero if any of those package versions have supply-chain risks (other than known vulnerabilities) or are known to be malicious / malware.
    - [`npm-check-lockfile.bash`](npm-checker/README.md#npm-check-lockfile) is similar to `npm-check.bash` but it trusts the `package-lock.json`; this makes it much faster, but in exchange it is less complete and potentially less accurate
* [`pip3-checker`](pip3-checker/) checks PyPI-based projects that are installable with `pip3` for indicators of supply-chain risks (except known vulenrabilities)
    - [`pip3-check.bash`](pip3-checker/README.md) can be run for the installation of any `pip3`-based module; you can use a `requirements.txt`, a local module with a 
    `pyproject.toml`, or a PyPI spec like `requests==2.32.3` -- basically anything that `pip3 install` will accept. It uses `pip3` to determine what would be installed and exits non-zero if any of those package versions have supply-chain risks (other than known vulnerabilities) or are known to be malicious / malware.
* [`httpie-template.sh`](http-template.sh) is a simple example script for using the [HTTPie command-line tool](https://httpie.io/cli) to query the API; it is run as `bash httpie-template.sh ECOSYSTEM PACKAGE_NAME VERSION` and checks a single package. It's in the repo to help implementors and researchers with a starting point to write their own simple scripts.


Note that the `basis` directory is intended as development-only; it's strongly recommended not to use any scripts there directly.

## Verification

Each "shipped" script has two verification files -- a SHA-512 hash in `${SCRIPT_NAME}.sha512` and a GnuPG signature in `${SCRIPT_NAME}.asc`. The signature uses the public key associated with the signature on the commit that last created the script.

## CI integration notes

All these tools provide a simple way to provide a Threat Intel API key during run; we strongly recommend using your organization's secrets manager to store that API key. Our examples will generally showcase using a well-known secrets manager (like Hashicorp's Vault or GitHub Action Secrets), and we definitely encourage you to follow that pattern as adapted for your systems.

These examples are pretty agressive about returning non-zero; when they do so, most CI systems will fail the job immediately without additional configuration. This is by design, as we believe the default for security tools should be "fail secure". We recommend responding to non-zero exit codes with an error handler that more closely examines the output and makes a policy decision, however. For example, you may note the exit code indicates risks are present, then examine the JSON output provided and only fail the build only if at least one risk is a 9 or 10 out of a possible 10. You should determine your risk tolerance and act accordingly.

## License notes

They are provided under the GNU Affero General Public License (AGPL) unless otherwise specified (see the LICENSE file in each tool directory); this license permits you to modify and distribute the code as long as you share the source _with the people to whom you distribute it_, whether as a service or not. 

The AGPL was chosen to discourage people from incorporating these components into proprietary software, because making them part of an application would require people to share that code; however, **simply using them as part of your build process does not count as distribution or make these components part of your applications**, so regular customer use should be unencumbered.


## No Warranty

**This software is provided by the copyright holders and contributors “AS IS” and any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the copyright owner or contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.**