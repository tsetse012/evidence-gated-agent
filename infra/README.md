# infra — Vultr VM provisioning (written now, executed after kickoff)

Nothing here has been run. It is checked in so that kickoff day is one boot,
not a provisioning project.

## What a fresh host ends up with

| Component | Source |
| --- | --- |
| Ubuntu 24.04 | Vultr Cloud Compute, 4 vCPU / 8 GB |
| Docker CE | official apt repo (`download.docker.com`) |
| gVisor `runsc` | `storage.googleapis.com/gvisor/releases/release/latest/<arch>/runsc` |
| runtime registration | `/etc/docker/daemon.json` → `runtimes.runsc.path` |
| host firewall | `ufw`: 22, 80, 443 only |
| app | `/opt/evidence-gated-agent`, `uv sync`, `ega-sandbox:dev` image built |
| process supervision | systemd unit `ega.service` (uvicorn on 127.0.0.1:8000) |
| TLS / reverse proxy | Caddy from the official Cloudsmith repo |

## Steps

1. Create the VM (Ubuntu 24.04, 4 vCPU / 8 GB, open 22/80/443 in the Vultr
   firewall group as well as on the host).
2. Replace `REPLACE_ME` in `cloud-init.yaml` with the real git remote, and
   replace `:80` in the Caddyfile block with your domain if you have one.
3. Paste the file into the Vultr "Cloud-Init User-Data" field at deploy time
   (or `vultr-cli instance create ... --userdata "$(cat infra/cloud-init.yaml)"`).
4. Watch the boot log: `cloud-init status --wait --long` on the VM.

## Smoke tests (run after the first boot)

```bash
# gVisor is registered and usable
docker info --format '{{json .Runtimes}}'
# -> {"runsc":{"path":"/usr/local/bin/runsc",...},"runc":{...}}

docker run --runtime=runsc --rm hello-world

# the sandbox image exists
docker images ega-sandbox:dev

# the app answers
curl -s localhost:80/api/fixtures | head

# containment, out of the process, on the real host
cd /opt/evidence-gated-agent
uv run python -c "from ega.probes import run_probes; [print(p.name, p.blocked, p.evidence) for p in run_probes()]"
```

Expected: all six probes `True` (blocked), and `EGA_RUNTIME=runsc` is already
set for `ega.service`, so every run records `isolation: gvisor`.

## Notes / known traps

- Docker Desktop on the development Mac has no `runsc`, so local runs record
  `isolation: runc`. The gVisor path is only exercised on the VM.
- `daemon.json` is written as a whole file. On a *fresh* VM that is correct;
  on a host that already has settings, merge instead of overwrite.
- The systemd unit points at `.venv/bin/uvicorn` created by `uv sync
  --frozen`. If `uv.lock` changes, re-run `uv sync --frozen` before restarting.