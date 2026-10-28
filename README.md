# BoxEscape: Dev Container and Agent Sandbox Escape Checker

You put the coding agent in a dev container so it can run with fewer prompts, maybe with
`--dangerously-skip-permissions`. It is in a box, so it is safe. Then you look at what the box
was built with:

```jsonc
{
  "name": "claude",
  "features": {
    "ghcr.io/anthropics/devcontainer-features/claude-code:1.0": {},
    "ghcr.io/devcontainers/features/docker-outside-of-docker:1": {}   // the host's docker.sock
  },
  "privileged": true,                                                   // "needed for docker"
  "runArgs": ["--network=host"],                                        // "needed for the dev server"
  "mounts": [
    "source=${localEnv:HOME}/.aws,target=/home/node/.aws,type=bind",    // "needed for the deploy script"
    "source=${localEnv:HOME}/.ssh,target=/home/node/.ssh,type=bind"     // "needed for git"
  ],
  "postStartCommand": "sudo /usr/local/bin/init-firewall.sh || true"   // and if it fails, nobody knows
}
```

Each line was added for a good reason, and together they hand the agent your host: a mounted
Docker socket is root on the machine, `privileged` turns off every kernel protection, and your
cloud and SSH keys are one prompt injection away from being sent somewhere.

BoxEscape reads your `devcontainer.json`, your Docker Compose services and the `docker run` lines
in scripts that start an agent CLI, and shows every setting that lets the container reach the
host. When the container runs an AI agent (Claude Code, Codex, Aider, OpenCode, OpenHands, Cline,
Cursor Agent, Gemini CLI), the findings that expose secrets or the host are errors.

## What you see

- **Problems and squiggles** on the exact setting, with a message that says what it gives the
  container, and why the container counts as an agent container
  (`It runs an AI agent (feature claude-code) ...`).
- **Quick Fixes** (lightbulb): remove `privileged`, remove a dangerous `capAdd` / `cap_add` entry or
  `--cap-add` argument, remove a `securityOpt` entry, remove the docker.sock mount or the
  docker-outside-of-docker Feature, make a mount read-only (`,readonly` for mount strings, `:ro` for
  `-v` and Compose volumes).
- **Activity bar**: a BoxEscape icon opens the **Container escape checks** view. Findings are
  grouped by file, and each row names the setting, what it brings in and which container:
  `mounts: ~/.aws into the "claude" container`, `runArgs --network: host network shared with the
  "claude" container`, `privileged: true runs the "agent" service privileged`. Click a row to jump to
  it, or use the inline lightbulb button to apply its Quick Fix. A badge on the icon shows the
  number of findings.
- **Status bar**: `BoxEscape: N`. Click it to open the view.

Open files are checked as you type. The rest of the workspace is scanned in the background.

## Rules

| ID | Rule | Default | Examples | Quick Fix |
| --- | --- | --- | --- | --- |
| BE001 | Privileged container | Error | `"privileged": true`, `runArgs` `--privileged`, the docker-in-docker Feature, Compose `privileged: true`, `docker run --privileged` | Remove it |
| BE002 | Host Docker socket shared | Warning, **error in an agent container** | `/var/run/docker.sock` (also `/run/docker.sock`, Docker Desktop, rootless, Podman and containerd sockets, `/var/run` itself) in `mounts`, `-v`, Compose `volumes`; the docker-outside-of-docker Feature; `docker run --use-api-socket` | Remove the mount or the Feature |
| BE003 | Host namespace shared | Warning | `--network=host`, `--pid=host`, `--ipc=host`, `--userns=host`, `--cgroupns=host`; Compose `network_mode: host`, `pid`, `ipc`, `userns_mode`, `cgroup` | - |
| BE004 | Dangerous capability added | Error for `ALL`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`, `DAC_READ_SEARCH`; warning for `NET_ADMIN`, `BPF`, `PERFMON`, `SYS_TIME` | `capAdd`, `--cap-add`, Compose `cap_add`. `NET_ADMIN` is not reported when the container runs an egress firewall script (the documented reason for it) | Remove the entry |
| BE005 | Confinement turned off | Error; warning for `label=disable` | `seccomp=unconfined`, `apparmor=unconfined`, `systempaths=unconfined` in `securityOpt`, `--security-opt`, Compose `security_opt` | Remove the entry (devcontainer.json, block lists) |
| BE006 | Host credentials or system path mounted | Warning, **error in an agent container**; one step lower when the mount is read-only | `~/.ssh`, `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`, `~/.docker`, `~/.gnupg`, `~/.config/gh`, `~/.git-credentials`, `~/.netrc`, `~/.npmrc`, `~/.pypirc` and others, your whole `$HOME`, `/`, `/etc`, `/proc`, `/sys`, `/home` ... in every home form: `${localEnv:HOME}`, `${localEnv:USERPROFILE}`, `$HOME`, `${HOME}`, `~`, `/home/<you>`, `/Users/<you>`, `C:\Users\<you>` | Make the mount read-only |
| BE007 | Workspace parent mounted | Warning | `${localWorkspaceFolder}/..`, Compose `../..:/workspaces` in `.devcontainer/` (resolved against the Compose file), `$(pwd)/..` | - |
| BE008 | SSH or GPG agent forwarded | Warning, **error in an agent container** | `${localEnv:SSH_AUTH_SOCK}`, `$SSH_AUTH_SOCK`, Docker Desktop's `/run/host-services/ssh-auth.sock`, `S.gpg-agent` sockets mounted in | Remove the mount |
| BE009 | Host device passed through | Warning | `--device=/dev/sda`, `/dev/mem`, `/dev/nvme0n1`, Compose `devices`, `device_cgroup_rules: ['a *:* rwm']`. GPUs (`/dev/dri`, `/dev/nvidia*`), `/dev/fuse`, `/dev/net/tun`, `/dev/kvm`, sound, video and USB serial devices are not reported | - |
| BE010 | Agent firewall not effective | Information | A lifecycle command runs `init-firewall.sh` (or any `*firewall*.sh`) that is not in the repository; its failure is ignored (`\|\| true`); it runs without the `NET_ADMIN` capability iptables needs; or a firewall script sits next to an agent's `devcontainer.json` and nothing runs it | - |
| BE011 | Agent runs as root | Warning | `remoteUser` / `containerUser` `root` in an agent container, Compose `user: root` / `"0:0"`, `docker run -u 0` | - |

Set any rule to another severity or `off` with `boxEscape.rules`.

### When is a container an agent container?

When BoxEscape sees one of these, the message says which:

- **devcontainer.json**: its `name` (`claude`, `Codex sandbox`, `ai-agent` ...), a Feature
  (`ghcr.io/anthropics/devcontainer-features/claude-code`, codex, aider, gemini-cli, opencode), an
  extension in `customizations.vscode.extensions` (`anthropic.claude-code`, `openai.chatgpt`, Cline,
  Roo Code, Kilo Code), a lifecycle command that installs or runs an agent CLI
  (`npm i -g @openai/codex`, `curl -fsSL https://claude.ai/install.sh | bash`, `aider ...`),
  `containerEnv` like `CLAUDE_CONFIG_DIR` or `CODEX_HOME`, or a Dockerfile (`build.dockerfile`)
  that installs one.
- **Docker Compose**: the service named in an agent `devcontainer.json` (`dockerComposeFile` +
  `service`), or a service whose name, `container_name`, image, `command` / `entrypoint`,
  `environment` or build Dockerfile shows an agent.
- **Scripts** (`*.sh`, `*.bash`): only `docker run` / `podman run` / `nerdctl run` lines that start an
  agent (`... image claude -p`, an agent image, `--name codex-sandbox`, `-e CLAUDE_CODE_...`) are
  checked. Every other `docker run` in your scripts is left alone.
- Your own agent tools: add a pattern to `boxEscape.extraAgentPatterns`.

### What it leaves alone

- `SYS_PTRACE` (the documented capability for debuggers) and `NET_RAW` (in Docker's default set).
- Named volumes (`source=claude-code-config,target=/home/node/.claude,type=volume`), the workspace
  itself, and folders inside your home that are not credential folders (`~/projects/app`).
- `NET_ADMIN` / `NET_RAW` next to an egress firewall that runs at start, as in the Claude Code
  reference container, which BoxEscape reports nothing for.
- Comments, heredoc bodies and quoted text in scripts.

The checks follow the [devcontainer.json reference](https://containers.dev/implementors/json_reference/),
the [Claude Code dev container docs](https://code.claude.com/docs/en/devcontainer) ("avoid mounting
host secrets such as `~/.ssh` or cloud credential files", the reference firewall and its
capabilities) and [Docker Engine security](https://docs.docker.com/engine/security/) ("only trusted
users should be allowed to control your Docker daemon").

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `boxEscape.enabled` | `true` | Turn all checks on or off. |
| `boxEscape.rules` | `{}` | Severity per rule (`error`, `warning`, `information`, `hint`) or `off`, e.g. `{ "BE007": "off" }`. Rules not set here use the per-finding defaults above. |
| `boxEscape.extraAgentPatterns` | `[]` | Extra regular expressions (case-insensitive, up to 200 characters each, 20 patterns) that mark a container as an agent container. |
| `boxEscape.checkScripts` | `true` | Also check `docker run` lines in shell scripts that start an agent CLI. |
| `boxEscape.maxFiles` | `2000` | Maximum number of files scanned. Files open in an editor are always checked. Files over 1 MB are skipped. |
| `boxEscape.exclude` | `node_modules`, `.git`, `dist`, `build`, `out`, `vendor`, `venv`, `.venv`, `__pycache__`, `coverage`, `site-packages` | Glob patterns that are never scanned. `node_modules`, `.git`, `vendor`, `venv` and `.venv` are always excluded. |

Settings apply immediately, without a reload.

## Commands

- **BoxEscape: Rescan Workspace** (also the refresh button in the view title)
- **BoxEscape: Show Container Escape Checks**
- **BoxEscape: Open Settings** (gear button in the view title)
- **Apply Quick Fix** (inline button on each fixable row)

## Files checked

`devcontainer.json` and `.devcontainer.json` anywhere in the workspace, Compose files
(`compose.yaml`, `docker-compose.yml`, `docker-compose.dev.yml` and other `*compose*.yml` /
`*.yaml` names, plus any file a `devcontainer.json` names in `dockerComposeFile`), and `*.sh` /
`*.bash` scripts. Dockerfiles are read only to see whether they install an agent or run a firewall
script.

## Privacy and safety

- No network, no telemetry. Nothing leaves your machine.
- BoxEscape only reads files inside the workspace. Symlinks that lead outside are ignored, and
  files over 1 MB are skipped. It never runs Docker or any other process.
- It works in untrusted workspaces. There, all `boxEscape.*` settings (including `enabled`,
  `rules` and `exclude`) are taken only from your user settings, never from the repository.

## Limitations

- BoxEscape reads configuration, not the running container. Settings added by a Feature's own
  metadata are known only for the docker-in-docker and docker-outside-of-docker Features, and the
  base image's default user is not known, so BE011 needs an explicit `root`.
- Read-only mounts are still reported (one severity lower): a read-only `~/.ssh` can not be
  changed, but the keys in it can still be read and sent out. Removing the mount and passing a
  short-lived, repository-scoped token is the real fix.
- VS Code's Dev Containers extension forwards your SSH agent and reuses your git credential helper
  on its own when they are set up on the host. That is not visible in `devcontainer.json`, so
  BE008 only reports agent sockets that are mounted explicitly.
- Flags hidden in shell variables (`docker run $FLAGS ...`) and Compose `extends` from other files
  are not followed. Compose `${VAR}` values are not substituted, except the home forms above.

## License

MIT - included with the extension.
