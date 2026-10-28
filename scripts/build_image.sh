#!/usr/bin/env bash
# Build the sandbox image used by both the author and the verifier.
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE="${EGA_IMAGE:-ega-sandbox:dev}"

docker build -t "$IMAGE" -f sandbox/Dockerfile sandbox/
echo "built $IMAGE"