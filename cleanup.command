#!/bin/bash
# Double-click this file, or run ./cleanup.command from Terminal.
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

if ! /usr/bin/python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)'; then
  echo "Python 3.9 or newer is required. macOS includes python3."
  echo "Press Return to close."
  read -r _
  exit 1
fi

/usr/bin/python3 -m cleaner "$@"
status=$?
if [[ $status -ne 0 ]]; then
  echo
  echo "Exited with status ${status}. Press Return to close."
  read -r _
fi
exit "$status"
