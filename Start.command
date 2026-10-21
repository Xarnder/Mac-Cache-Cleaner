#!/bin/bash
# Double-click this file in Finder to start Mac Cache Cleaner.
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"
exec /bin/bash ./cleanup.command "$@"
