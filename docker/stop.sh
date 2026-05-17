#!/bin/bash
# Teardown all PODs from the dashboard DB
cd "$(dirname "$0")/.."
uv run python3 docker/generate.py --db --down
