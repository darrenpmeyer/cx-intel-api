#!/usr/bin/env bash
set -eu
./_compile-scripts.py npm-check-base.bash:../npm-checker/npm-check.bash --clean
./_compile-scripts.py npm-package-lock-checker.bash:../npm-checker/npm-check-lockfile.bash --clean
./_compile-scripts.py pip3-check-base.bash:../pip3-checker/pip3-check.bash --clean
