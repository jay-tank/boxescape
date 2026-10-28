# Changelog

## 0.1.0 - Initial release

- Eleven rules for dev containers, Docker Compose services and agent `docker run` lines: BE001
  privileged container, BE002 host Docker socket shared, BE003 host network / PID / IPC / user
  namespace, BE004 dangerous capability, BE005 seccomp / AppArmor / SELinux turned off, BE006 host
  credentials, `$HOME` or system paths mounted, BE007 workspace parent mounted, BE008 SSH or GPG
  agent forwarded, BE009 host device passed through, BE010 agent firewall missing, ignored or
  without `NET_ADMIN`, BE011 agent running as root.
- Containers that run an AI coding agent (Claude Code, Codex, Aider, OpenCode, OpenHands, Cline,
  Cursor Agent, Gemini CLI, or your own patterns) are recognised from the name, Features,
  extensions, lifecycle commands, environment, image, command and Dockerfile, and get stricter
  severities for exposed secrets and the Docker socket.
- Quick Fixes: remove `privileged`, a capability, a security option, the docker.sock mount or the
  docker-outside-of-docker Feature; make a mount read-only.
- Container escape checks view in its own activity bar container, grouped by file, with rows that
  name the setting, the path and the container, an inline Quick Fix button and a findings badge.
  Status bar `BoxEscape: N`.
- JSONC, YAML and shell parsing built in, no dependencies. No network, no telemetry, no child
  processes. Works in untrusted workspaces.
