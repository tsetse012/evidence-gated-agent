# Sandbox image for both the author run and the independent verifier run.
# Non-root uid 1000. No network is available at runtime (`--network none`).
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir "pytest==8.3.4" \
    && useradd --uid 1000 --create-home --shell /bin/bash runner

USER 1000:1000
WORKDIR /work

CMD ["python", "-m", "pytest", "-q"]