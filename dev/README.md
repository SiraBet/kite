# dev/

Scripts for working **on** kite, not for running it.

Nothing in here is part of an install. These exist to shorten the
edit-deploy-test loop on a machine you already control, and they make
trade-offs a real deployment must not make.

| Script | What it does | Why it is not an install path |
|---|---|---|
| `deploy-to-opt.sh` | Pushes the current checkout to a systemd install at `/opt/kite-controller` and restarts it | Serves **plain HTTP on `0.0.0.0:8000`** — no Caddy, no TLS. Enrolment secrets and agent credentials cross the network in the clear. |

## To actually install kite

Use `controller/controller-install.sh`, which puts Caddy in front with TLS
on 443 (self-signed by default, `--domain` for Let's Encrypt) and binds
uvicorn to localhost. See [`controller/INSTALL.md`](../controller/INSTALL.md).

Docker is easier still — see the [root README](../README.md).
