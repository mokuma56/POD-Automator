#!/bin/bash
# Launch all PODs from the dashboard DB
set -e
cd "$(dirname "$0")/.."
uv run python3 docker/generate.py --db --up
