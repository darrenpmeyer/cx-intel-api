# Checkmarx Threat Intel API integrations BASIS area

This directory is where initial development and testing occurs. Essentially, we want to make each integration/utility as self-contained and easy to deploy as possible. To do that, each integration contains its own copy of common functions. But that's a recipe for getting out of sync.

So we build things in a modular way inside the BASIS area, and then automatically "de-modularize" for ease of use/deployment.

**TL;DR** use the tools from the directories at repo root for prod, develop changes here
