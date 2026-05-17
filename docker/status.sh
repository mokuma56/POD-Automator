#!/bin/bash
# Show status of all PODs from the dashboard DB
cd "$(dirname "$0")/.."
uv run python3 docker/generate.py --db --status
