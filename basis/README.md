# Checkmarx Malicious Package Identification API integrations BASIS area

This directory is where initial development and testing occurs. Essentially, we want to make each integration/utility as self-contained and easy to deploy as possible. To do that, each integration contains its own copy of common functions. But that's a recipe for getting out of sync.

So we build things in a modular way inside the BASIS area, and then automatically "de-modularize" for ease of use/deployment.

**TL;DR** use the tools from the directories at repo root for prod, develop changes here, and make sure you compile the scripts and commit the results before merging to `main`

## No Warranty

**This software is provided by the copyright holders and contributors “AS IS” and any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the copyright owner or contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.**