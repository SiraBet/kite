# Installer payload

`build.sh` writes `kite-agent.exe.gz` here — the agent binary the
setup program installs — and the setup binary embeds whatever it finds.

The file is not committed: it is a build artifact, and a stale copy in
git would mean shipping an installer that quietly deploys an old agent.
This README exists so the directory is never empty, because `go:embed`
fails to compile against a pattern that matches nothing.
