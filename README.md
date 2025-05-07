# Checkmarx Threat Intel API integrations

A collection of tools useful for integrating the Checkmarx SCS Threat Intel API into CI/CD and other automated build processes.

These tools can be used as-is, but are intended as templates for modification and use. These tools were written by Darren P Meyer while employed by Checkmarx, but are not officially supported by Checkmarx -- they're shared as a form of education and guidance.

- [`npm-check.bash`](npm-checker/README.md) can be run in an npm project anywhere `npm install` would work; it will use `npm` to determine what would be installed and exits non-zero if any of those package versions have supply-chain risks (other than known vulnerabilities) or are known to be malicious / malware.

## CI integration notes

All these tools provide a simple way to provide a Threat Intel API key during run; we strongly recommend using your organization's secrets manager to store that API key. Our examples will generally showcase using a well-known secrets manager (like Hashicorp's Vault or GitHub Action Secrets), and we definitely encourage you to follow that pattern as adapted for your systems.

These examples are pretty agressive about returning non-zero; when they do so, most CI systems will fail the job immediately without additional configuration. This is by design, as we believe the default for security tools should be "fail secure". We recommend responding to non-zero exit codes with an error handler that more closely examines the output and makes a policy decision, however. For example, you may note the exit code indicates risks are present, then examine the JSON output provided and only fail the build only if at least one risk is a 9 or 10 out of a possible 10. You should determine your risk tolerance and act accordingly.

## License notes

They are provided under the GNU Affero General Public License (AGPL) unless otherwise specified (see the LICENSE file in each tool directory); this license permits you to modify and distribute the code as long as you share the source _with the people to whom you distribute it_, whether as a service or not. 

The AGPL was chosen to discourage people from incorporating these components into proprietary software, because making them part of an application would require people to share that code; however, **simply using them as part of your build process does not count as distribution or make these components part of your applications**, so regular customer use should be free of problems.