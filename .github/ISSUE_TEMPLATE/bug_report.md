---
name: Bug report
about: Something in the controller, an agent, or the install scripts isn't working right
title: ""
labels: bug
---

**Component**
controller / agent-linux / agent-windows / install scripts

**What happened**
A clear description of the actual behavior.

**What you expected**
What should have happened instead.

**Steps to reproduce**
1. ...
2. ...

**Environment**
- kite version/commit:
- Controller OS:
- Agent OS (if relevant), e.g. rocky9, win2022:
- Deployed via: controller-install.sh / Docker / manual

**Logs**
Relevant lines from `journalctl -u kite-controller` (or
`kite-agent` / the agent.log on Windows) and, if this is an agent
issue, the stage output from the Progress screen or `/runs/{id}`.

**Anything else**
