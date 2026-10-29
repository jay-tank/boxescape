"use strict";

// Shared fixtures for the unit tests and the in-editor tests.

const AGENT_DEVCONTAINER = `{
  // Sandbox for the coding agent
  "name": "claude",
  "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
  "features": {
    "ghcr.io/anthropics/devcontainer-features/claude-code:1.0": {},
    "ghcr.io/devcontainers/features/docker-outside-of-docker:1": {}
  },
  "privileged": true,
  "capAdd": ["SYS_ADMIN", "SYS_PTRACE"],
  "securityOpt": ["seccomp=unconfined"],
  "runArgs": ["--network=host", "--pid", "host", "-v", "\${localEnv:HOME}/.ssh:/home/node/.ssh", "--device=/dev/sda"],
  "mounts": [
    "source=\${localEnv:HOME}/.aws,target=/home/node/.aws,type=bind",
    "source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind",
    "source=\${localEnv:SSH_AUTH_SOCK},target=/ssh-agent,type=bind",
    "source=\${localWorkspaceFolder}/..,target=/all,type=bind",
    "source=claude-config,target=/home/node/.claude,type=volume",
  ],
  "remoteUser": "root",
  "postStartCommand": "sudo /usr/local/bin/init-firewall.sh || true"
}
`;

// [rule, severity, line] in order.
const AGENT_DEVCONTAINER_EXPECT = [
  ["BE001", "error", 8],
  ["BE002", "error", 6],
  ["BE004", "error", 9],
  ["BE005", "error", 10],
  ["BE003", "warning", 11],
  ["BE003", "warning", 11],
  ["BE006", "error", 11],
  ["BE009", "warning", 11],
  ["BE006", "error", 13],
  ["BE002", "error", 14],
  ["BE008", "error", 15],
  ["BE007", "warning", 16],
  ["BE011", "warning", 19],
  ["BE010", "information", 20],
];

const AGENT_COMPOSE = `services:
  agent:
    image: ghcr.io/acme/claude-runner:latest
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    security_opt: ["apparmor:unconfined"]
    network_mode: host
    pid: host
    user: root
    volumes:
      - ~/.kube:/root/.kube
      - /var/run/docker.sock:/var/run/docker.sock
      - ../..:/workspaces:cached
      - type: bind
        source: \${HOME}
        target: /host-home
  db:
    image: postgres:16
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./init:/docker-entrypoint-initdb.d:ro
volumes:
  pgdata: {}
`;

const AGENT_COMPOSE_EXPECT = [
  ["BE001", "error", 3],
  ["BE004", "warning", 5],
  ["BE004", "error", 6],
  ["BE005", "error", 7],
  ["BE003", "warning", 8],
  ["BE003", "warning", 9],
  ["BE011", "warning", 10],
  ["BE006", "error", 12],
  ["BE002", "error", 13],
  ["BE007", "warning", 14],
  ["BE006", "error", 16],
];

const AGENT_SCRIPT = `#!/usr/bin/env bash
set -euo pipefail
# Start the agent sandbox
docker run --rm -it \\
  --privileged \\
  -v "$HOME/.ssh:/root/.ssh" \\
  -v "$(pwd):/work" \\
  --cap-add SYS_ADMIN \\
  ghcr.io/acme/sandbox:1 claude --dangerously-skip-permissions
docker run --privileged -v /:/host busybox ls
echo "docker run --privileged claude"
cat <<EOF > run-agent.sh
docker run --privileged codex
EOF
`;

const AGENT_SCRIPT_EXPECT = [
  ["BE001", "error", 4],
  ["BE006", "error", 5],
  ["BE004", "error", 7],
];

// The Claude Code reference container (anthropics/claude-code .devcontainer), with init-firewall.sh present.
const REFERENCE_DEVCONTAINER = `{
  "name": "Claude Code Sandbox",
  "build": {
    "dockerfile": "Dockerfile",
    "args": { "TZ": "\${localEnv:TZ:America/Los_Angeles}", "CLAUDE_CODE_VERSION": "latest" }
  },
  "runArgs": [
    "--cap-add=NET_ADMIN",
    "--cap-add=NET_RAW"
  ],
  "customizations": {
    "vscode": {
      "extensions": ["anthropic.claude-code", "dbaeumer.vscode-eslint"]
    }
  },
  "remoteUser": "node",
  "mounts": [
    "source=claude-code-bashhistory-\${devcontainerId},target=/commandhistory,type=volume",
    "source=claude-code-config-\${devcontainerId},target=/home/node/.claude,type=volume"
  ],
  "containerEnv": {
    "NODE_OPTIONS": "--max-old-space-size=4096",
    "CLAUDE_CONFIG_DIR": "/home/node/.claude"
  },
  "workspaceMount": "source=\${localWorkspaceFolder},target=/workspace,type=bind,consistency=delegated",
  "workspaceFolder": "/workspace",
  "postStartCommand": "sudo /usr/local/bin/init-firewall.sh",
  "waitFor": "postStartCommand"
}
`;

const REFERENCE_DOCKERFILE = `FROM node:20
RUN npm install -g @anthropic-ai/claude-code@\${CLAUDE_CODE_VERSION}
COPY init-firewall.sh /usr/local/bin/
USER node
`;

// Ordinary dev setups that must stay clean.
const PLAIN_DEVCONTAINER = `{
  "name": "Python 3",
  "image": "mcr.microsoft.com/devcontainers/python:3.12",
  "capAdd": ["SYS_PTRACE"],
  "securityOpt": ["no-new-privileges:true"],
  "runArgs": ["--init", "--network=bridge", "--gpus", "all", "--device=/dev/dri", "-v", "\${localWorkspaceFolder}/data:/data"],
  "mounts": [
    "source=pip-cache,target=/root/.cache/pip,type=volume",
    "source=\${localWorkspaceFolder}/.cache,target=/cache,type=bind",
    { "source": "node_modules", "target": "/work/node_modules", "type": "volume" }
  ],
  "features": { "ghcr.io/devcontainers/features/node:1": {} },
  "privileged": false,
  "remoteUser": "vscode",
  "postCreateCommand": "pip install -r requirements.txt && eval $(ssh-agent)"
}
`;

const PLAIN_COMPOSE = `services:
  web:
    build: .
    ports: ["8000:8000"]
    privileged: false
    network_mode: bridge
    cap_add: [SYS_PTRACE]
    volumes:
      - .:/app
      - ./data:/data:ro
      - static:/static
    devices:
      - /dev/dri:/dev/dri
  worker:
    image: redis:7
    user: "1000:1000"
volumes:
  static:
`;

const PLAIN_SCRIPT = `#!/bin/sh
# docker run --privileged claude   (comment)
docker build -t app .
docker run --rm -v "$PWD:/src" -w /src node:20 npm test
docker run --rm --network host --privileged busybox true
docker run --rm -v "$PWD:/work" ghcr.io/acme/claude-sandbox:1 claude -p "hi"
`;

module.exports = {
  AGENT_DEVCONTAINER,
  AGENT_DEVCONTAINER_EXPECT,
  AGENT_COMPOSE,
  AGENT_COMPOSE_EXPECT,
  AGENT_SCRIPT,
  AGENT_SCRIPT_EXPECT,
  REFERENCE_DEVCONTAINER,
  REFERENCE_DOCKERFILE,
  PLAIN_DEVCONTAINER,
  PLAIN_COMPOSE,
  PLAIN_SCRIPT,
};
