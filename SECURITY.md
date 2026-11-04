# Security policy

kite agents run as root/SYSTEM across every enrolled host. Treat
anything that could let an untrusted party influence what an agent
executes, forge enrollment, or read another host's credentials as a
security issue, not a regular bug.

## Reporting a vulnerability

Do not open a public issue. Instead, use GitHub's private vulnerability
reporting: go to the repo's **Security** tab → **Report a vulnerability**.

Include:
- What's affected (controller, agent-linux, agent-windows, or the
  install/packaging scripts)
- Steps to reproduce, or a proof of concept
- What you think the impact is (e.g. "any authenticated operator can
  read another team's enrollment secret," "an unauthenticated request
  can queue a job")

## Scope

In scope: the controller API and frontend, both agents, the install/
enrollment scripts, and the OS-scripts execution path (scripts uploaded
to the controller run as root/SYSTEM on every matching host — see
`controller/README.md`'s "OS Scripts" section for the trust model
that's supposed to hold there).

Out of scope: vulnerabilities that require an attacker to already have
the enrollment secret or root/SYSTEM on a managed host, or that only
manifest in a deliberately misconfigured deployment (no TLS, default
credentials left unchanged). `controller/ROADMAP.md` lists the known
gaps; they are tracked openly rather than hidden.
