#!/usr/bin/env bash
# The project's own gate: build the image, run the whole suite, print counts,
# and refuse to be a false green (see SPEC §10).
set -uo pipefail

cd "$(dirname "$0")/.."
mkdir -p runs

echo "== [1/4] build sandbox image =="
if ! bash scripts/build_image.sh; then
  echo "FAIL: could not build the sandbox image"
  exit 1
fi

echo
echo "== [2/4] full pytest =="
uv run pytest -q --junitxml=runs/check-junit.xml 2>&1 | tee runs/check.log
pytest_status=${PIPESTATUS[0]}
echo "pytest exit status: ${pytest_status}"

echo
echo "== [3/4] docker-marked pytest =="
if docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then
  uv run pytest -q -m docker --junitxml=runs/check-docker-junit.xml 2>&1 | tee runs/check-docker.log
  docker_status=${PIPESTATUS[0]}
  echo "docker-marked pytest exit status: ${docker_status}"
  docker_junit=runs/check-docker-junit.xml
else
  echo "docker is NOT available; docker-marked tests will be skipped with a named reason"
  docker_status=0
  docker_junit=""
fi

echo
echo "== [4/4] counts gate =="
if [ -n "${docker_junit}" ]; then
  uv run python scripts/check_counts.py \
    --junit runs/check-junit.xml \
    --pytest-status "${pytest_status}" \
    --docker-junit "${docker_junit}"
else
  uv run python scripts/check_counts.py \
    --junit runs/check-junit.xml \
    --pytest-status "${pytest_status}"
fi
gate_status=$?

if [ "${docker_status}" -ne 0 ] && [ "${gate_status}" -eq 0 ]; then
  echo "FAIL: docker-marked pytest exited ${docker_status}"
  gate_status=1
fi

echo
echo "== last 12 lines of the full log =="
tail -n 12 runs/check.log

exit "${gate_status}"