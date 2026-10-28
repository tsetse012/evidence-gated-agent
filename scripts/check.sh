#!/usr/bin/env bash
# The project's own gate: build the image, run the whole suite, print counts,
# and refuse to be a false green (see SPEC §10).
#
# PYTEST_ADDOPTS is unset for every pytest call: an outside `-k`/`-m` filter
# would otherwise shrink the run and still look green. The required node ids in
# scripts/expected_tests.txt are then checked against the junit reports.
set -uo pipefail

cd "$(dirname "$0")/.."
mkdir -p runs

# Temp-dir leak check: a verifier run owns every ega-* directory it creates, so
# the number of them in TMPDIR must not grow across the whole suite.
tmp_root="${TMPDIR:-/tmp}"
ega_tmp_before=runs/ega-tmp-before.txt
find "${tmp_root}" -maxdepth 1 -name 'ega-*' -print | sort > "${ega_tmp_before}"

echo "== [1/4] build sandbox image =="
if ! bash scripts/build_image.sh; then
  echo "FAIL: could not build the sandbox image"
  exit 1
fi

echo
echo "== [2/4] full pytest =="
env -u PYTEST_ADDOPTS uv run pytest -q --junitxml=runs/check-junit.xml 2>&1 | tee runs/check.log
pytest_status=${PIPESTATUS[0]}
echo "pytest exit status: ${pytest_status}"

echo
echo "== [3/4] docker-marked pytest =="
if docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then
  env -u PYTEST_ADDOPTS uv run pytest -q -m docker --junitxml=runs/check-docker-junit.xml 2>&1 | tee runs/check-docker.log
  docker_status=${PIPESTATUS[0]}
  echo "docker-marked pytest exit status: ${docker_status}"
  docker_junit=runs/check-docker-junit.xml
else
  echo "docker is NOT available; docker-marked tests will be skipped with a named reason"
  docker_status=0
  docker_junit=""
fi

echo
echo "== [4/4] counts + required node ids gate =="
if [ -n "${docker_junit}" ]; then
  uv run python scripts/check_counts.py \
    --junit runs/check-junit.xml \
    --pytest-status "${pytest_status}" \
    --docker-junit "${docker_junit}" \
    --expected-tests scripts/expected_tests.txt
else
  uv run python scripts/check_counts.py \
    --junit runs/check-junit.xml \
    --pytest-status "${pytest_status}" \
    --expected-tests scripts/expected_tests.txt
fi
gate_status=$?

if [ "${docker_status}" -ne 0 ] && [ "${gate_status}" -eq 0 ]; then
  echo "FAIL: docker-marked pytest exited ${docker_status}"
  gate_status=1
fi

# Exit 3 is check_counts' "degraded": it only happens with EGA_ALLOW_NO_DOCKER=1,
# and it must never be reported as a pass.
if [ "${gate_status}" -eq 3 ]; then
  echo "DEGRADED: the gate accepted a run without Docker (EGA_ALLOW_NO_DOCKER=1)"
fi

echo
echo "== temp dir leak check =="
ega_tmp_after=runs/ega-tmp-after.txt
find "${tmp_root}" -maxdepth 1 -name 'ega-*' -print | sort > "${ega_tmp_after}"
leaked=$(comm -13 "${ega_tmp_before}" "${ega_tmp_after}")
before_count=$(wc -l < "${ega_tmp_before}" | tr -d ' ')
after_count=$(wc -l < "${ega_tmp_after}" | tr -d ' ')
echo "ega-* under ${tmp_root}: before=${before_count} after=${after_count}"
if [ -n "${leaked}" ]; then
  echo "FAIL: the run leaked ega-* temp directories:"
  echo "${leaked}" | head -n 20
  [ "${gate_status}" -eq 0 ] && gate_status=1
else
  echo "OK: no ega-* temp directories leaked"
fi

echo
echo "== last 40 lines of the full log =="
tail -n 40 runs/check.log

exit "${gate_status}"