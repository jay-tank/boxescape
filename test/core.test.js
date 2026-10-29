"use strict";

// Unit tests for core.js: node test/core.test.js

const assert = require("assert");
const core = require("../core");
const fx = require("./fixtures");

let passed = 0;
let failed = 0;
function test(name, fn) {
  try {
    fn();
    passed++;
  } catch (e) {
    failed++;
    console.log("FAIL " + name + "\n  " + (e && e.message ? e.message.split("\n").join("\n  ") : e));
  }
}

function applyFix(text, f) {
  assert.ok(f.fix, "finding has a fix: " + f.label);
  let out = text;
  for (const ed of f.fix.edits.slice().sort((a, b) => b.start - a.start)) {
    assert.strictEqual(out.slice(ed.start, ed.end), ed.expect, "edit expect matches");
    out = out.slice(0, ed.start) + ed.text + out.slice(ed.end);
  }
  return out;
}

/** Analyse one file (plus extra files for context). */
function run(rel, text, extra, opts) {
  const files = [{ rel, text }, ...(extra || [])];
  const known = new Map(files.map((f) => [f.rel, f.text]));
  const r = core.analyzeWorkspace(Object.assign({ files, read: (p) => (known.has(p) ? known.get(p) : null), exists: (p) => known.has(p) }, opts || {}));
  return r.get(rel) || [];
}
const shape = (F) => F.map((f) => [f.rule, f.defaultSeverity, f.line]);
const rules = (F) => F.map((f) => f.rule).sort();
const dev = (t, extra, o) => run(".devcontainer/devcontainer.json", t, extra, o);
const comp = (t, extra, o) => run("compose.yaml", t, extra, o);
const sh = (t, o) => run("scripts/agent.sh", t, [], o);

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

test("agent devcontainer: exact findings", () => {
  assert.deepStrictEqual(shape(dev(fx.AGENT_DEVCONTAINER)), fx.AGENT_DEVCONTAINER_EXPECT);
});
test("agent compose: exact findings", () => {
  assert.deepStrictEqual(shape(run(".devcontainer/compose.yml", fx.AGENT_COMPOSE)), fx.AGENT_COMPOSE_EXPECT);
});
test("agent script: exact findings (non-agent runs, echo, heredoc ignored)", () => {
  assert.deepStrictEqual(shape(sh(fx.AGENT_SCRIPT)), fx.AGENT_SCRIPT_EXPECT);
});
test("reference Claude Code container is clean when init-firewall.sh is in the repo", () => {
  const F = dev(fx.REFERENCE_DEVCONTAINER, [{ rel: ".devcontainer/Dockerfile", text: fx.REFERENCE_DOCKERFILE }, { rel: ".devcontainer/init-firewall.sh", text: "#!/bin/bash\n" }]);
  assert.deepStrictEqual(rules(F), []);
});
test("reference container without init-firewall.sh: BE010 information only", () => {
  const F = dev(fx.REFERENCE_DEVCONTAINER, [{ rel: ".devcontainer/Dockerfile", text: fx.REFERENCE_DOCKERFILE }]);
  assert.deepStrictEqual(shape(F), [["BE010", "information", 26]]);
  assert.ok(/init-firewall\.sh is not in the repository/.test(F[0].label));
});
test("plain devcontainer: nothing reported", () => {
  assert.deepStrictEqual(rules(dev(fx.PLAIN_DEVCONTAINER)), []);
});
test("plain compose: nothing reported", () => {
  assert.deepStrictEqual(rules(comp(fx.PLAIN_COMPOSE)), []);
});
test("plain script: only agent docker runs are checked, safe agent run is clean", () => {
  assert.deepStrictEqual(rules(sh(fx.PLAIN_SCRIPT)), []);
});

// ---------------------------------------------------------------------------------------------
// Labels and messages name the exact setting and container
// ---------------------------------------------------------------------------------------------

test("labels name setting, path and container", () => {
  const F = dev(fx.AGENT_DEVCONTAINER);
  const L = F.map((f) => f.label);
  for (const want of [
    'privileged: true runs the "claude" container privileged',
    'mounts: ~/.aws into the "claude" container',
    'mounts: /var/run/docker.sock into the "claude" container',
    'runArgs -v: ~/.ssh into the "claude" container',
    'runArgs --network: host network shared with the "claude" container',
    'runArgs --pid: host PID shared with the "claude" container',
    'capAdd: SYS_ADMIN in the "claude" container',
    'securityOpt: seccomp=unconfined in the "claude" container',
    'mounts: the SSH agent socket into the "claude" container',
    'remoteUser: root for the agent in the "claude" container',
  ]) assert.ok(L.includes(want), "missing label: " + want + "\n" + L.join("\n"));
});
test("messages give the agent reason and the doc advice", () => {
  const f = dev(fx.AGENT_DEVCONTAINER).find((x) => x.label.startsWith("mounts: ~/.aws"));
  assert.ok(/It runs an AI agent \(name "claude"\)/.test(f.message), f.message);
  assert.ok(/avoid mounting host secrets/.test(f.message));
  assert.strictEqual(f.agent, 'name "claude"');
  assert.strictEqual(f.container, "claude");
});
test("compose labels", () => {
  const L = run(".devcontainer/compose.yml", fx.AGENT_COMPOSE).map((f) => f.label);
  assert.ok(L.includes('volumes: ~/.kube into the "agent" service'), L.join("\n"));
  assert.ok(L.includes('network_mode: host network shared with the "agent" service'));
  assert.ok(L.includes('security_opt: apparmor:unconfined in the "agent" service'));
  assert.ok(L.includes('volumes: ../.. into the "agent" service'));
  assert.ok(L.includes('volumes: ~ (home) into the "agent" service'));
});
test("ranges cover the value", () => {
  const t = fx.AGENT_DEVCONTAINER;
  const f = dev(t).find((x) => x.label.startsWith("mounts: ~/.aws"));
  assert.strictEqual(t.slice(f.start, f.end), '"source=${localEnv:HOME}/.aws,target=/home/node/.aws,type=bind"');
  const c = dev(t).find((x) => x.rule === "BE004");
  assert.strictEqual(t.slice(c.start, c.end), '"SYS_ADMIN"');
});

// ---------------------------------------------------------------------------------------------
// Agent detection and severity
// ---------------------------------------------------------------------------------------------

const MOUNT_AWS = '"mounts": ["source=${localEnv:HOME}/.aws,target=/root/.aws,type=bind"]';
test("non-agent container: BE006 is a warning", () => {
  const F = dev(`{ "name": "web", ${MOUNT_AWS} }`);
  assert.deepStrictEqual(shape(F), [["BE006", "warning", 0]]);
  assert.strictEqual(F[0].agent, null);
});
for (const [what, json] of [
  ["name", '"name": "Codex sandbox"'],
  ["feature", '"features": { "ghcr.io/anthropics/devcontainer-features/claude-code:1": {} }'],
  ["extension", '"customizations": { "vscode": { "extensions": ["openai.chatgpt"] } }'],
  ["postCreate install", '"postCreateCommand": "npm i -g @openai/codex"'],
  ["postCreate install (object form)", '"postCreateCommand": { "agent": ["bash", "-c", "curl -fsSL https://claude.ai/install.sh | bash"] }'],
  ["postStart run", '"postStartCommand": "aider --yes"'],
  ["containerEnv", '"containerEnv": { "CLAUDE_CONFIG_DIR": "/home/node/.claude" }'],
  ["ai-agent name", '"name": "ai-agent"'],
]) {
  test(`agent detected by ${what}: BE006 error`, () => {
    const F = dev(`{ ${json}, ${MOUNT_AWS} }`);
    assert.deepStrictEqual(shape(F), [["BE006", "error", 0]]);
    assert.ok(F[0].agent, "agent reason");
  });
}
for (const [what, json] of [
  ["ssh-agent in a command", '"postCreateCommand": "eval $(ssh-agent) && ssh-add"'],
  ["user-agent name", '"name": "user-agent parser"'],
  ["datadog agent name", '"name": "datadog-agent"'],
  [".claude path", '"postCreateCommand": "mkdir -p /home/node/.claude"'],
  ["build agent", '"name": "build agent"'],
]) {
  test(`not an agent: ${what}`, () => {
    const F = dev(`{ ${json}, ${MOUNT_AWS} }`);
    assert.deepStrictEqual(shape(F), [["BE006", "warning", 0]]);
  });
}
test("agent detected through the Dockerfile", () => {
  const F = dev(`{ "build": { "dockerfile": "Dockerfile" }, ${MOUNT_AWS} }`, [{ rel: ".devcontainer/Dockerfile", text: "FROM node:20\nRUN npm install -g @anthropic-ai/claude-code\n" }]);
  assert.strictEqual(F[0].defaultSeverity, "error");
  assert.ok(/Dockerfile installs @anthropic-ai\/claude-code/.test(F[0].agent));
});
test("Dockerfile outside the workspace is never read", () => {
  let asked = [];
  core.analyzeWorkspace({ files: [{ rel: ".devcontainer/devcontainer.json", text: '{ "build": { "dockerfile": "../../../etc/Dockerfile" } }' }], read: (p) => (asked.push(p), null), exists: () => false });
  assert.deepStrictEqual(asked, []);
  core.analyzeWorkspace({ files: [{ rel: "devcontainer.json", text: '{ "build": { "dockerfile": "/etc/Dockerfile" } }' }], read: (p) => (asked.push(p), null), exists: () => false });
  assert.deepStrictEqual(asked, []);
});
test("extraAgentPatterns raise the severity", () => {
  const pats = core.compileAgentPatterns(["my-bot-cli"]);
  const F = dev(`{ "postCreateCommand": "npm i -g my-bot-cli", ${MOUNT_AWS} }`, [], { agentPatterns: pats });
  assert.strictEqual(F[0].defaultSeverity, "error");
  assert.strictEqual(F[0].agent, "matches boxEscape.extraAgentPatterns");
});
test("compileAgentPatterns caps length and count, drops invalid", () => {
  assert.strictEqual(core.compileAgentPatterns(["x".repeat(201)]).length, 0);
  assert.strictEqual(core.compileAgentPatterns(["(", "ok"]).length, 1);
  assert.strictEqual(core.compileAgentPatterns(new Array(50).fill("a")).length, 20);
  assert.strictEqual(core.compileAgentPatterns("nope").length, 0);
  assert.strictEqual(core.compileAgentPatterns([1, null, ""]).length, 0);
});
test("compose service inherits agent status from devcontainer service", () => {
  const dc = '{ "name": "Claude box", "dockerComposeFile": ["../docker-compose.yml"], "service": "app" }';
  const yml = "services:\n  app:\n    image: node:20\n    volumes:\n      - ~/.ssh:/root/.ssh\n  db:\n    image: postgres\n    volumes:\n      - ~/.ssh:/x\n";
  const r = core.analyzeWorkspace({ files: [{ rel: ".devcontainer/devcontainer.json", text: dc }, { rel: "docker-compose.yml", text: yml }], read: () => null, exists: () => false });
  const F = r.get("docker-compose.yml");
  assert.deepStrictEqual(shape(F), [["BE006", "error", 4], ["BE006", "warning", 8]]);
  assert.ok(/name "Claude box" in \.devcontainer\/devcontainer\.json/.test(F[0].agent), F[0].agent);
});
test("referenced compose file with another name is read and checked", () => {
  const dc = '{ "dockerComposeFile": "stack.yml", "service": "app" }';
  const yml = "services:\n  app:\n    image: x\n    privileged: true\n";
  const r = core.analyzeWorkspace({ files: [{ rel: ".devcontainer/devcontainer.json", text: dc }], read: (p) => (p === ".devcontainer/stack.yml" ? yml : null), exists: () => false });
  assert.deepStrictEqual(rules(r.get(".devcontainer/stack.yml")), ["BE001"]);
});
test("compose agent by environment / command / image", () => {
  assert.strictEqual(comp("services:\n  s:\n    image: x\n    environment:\n      CLAUDE_CODE_USE_BEDROCK: '1'\n    volumes: ['~/.aws:/root/.aws']\n")[0].defaultSeverity, "error");
  assert.strictEqual(comp("services:\n  s:\n    image: x\n    command: [\"codex\", \"exec\"]\n    volumes: ['~/.aws:/root/.aws']\n")[0].defaultSeverity, "error");
  assert.strictEqual(comp("services:\n  s:\n    image: acme/opencode:1\n    volumes: ['~/.aws:/root/.aws']\n")[0].defaultSeverity, "error");
  assert.strictEqual(comp("services:\n  s:\n    image: nginx\n    environment:\n      - ANTHROPIC_API_KEY\n    volumes: ['~/.aws:/root/.aws']\n")[0].defaultSeverity, "warning");
});

// ---------------------------------------------------------------------------------------------
// Rule details
// ---------------------------------------------------------------------------------------------

test("BE001: docker-in-docker feature, runArgs --privileged, --privileged=false ignored", () => {
  assert.deepStrictEqual(rules(dev('{ "features": { "ghcr.io/devcontainers/features/docker-in-docker:2": {} } }')), ["BE001"]);
  assert.deepStrictEqual(rules(dev('{ "runArgs": ["--privileged"] }')), ["BE001"]);
  assert.deepStrictEqual(rules(dev('{ "runArgs": ["--privileged=false"] }')), []);
  assert.deepStrictEqual(rules(comp("services:\n  a:\n    image: x\n    privileged: yes\n")), ["BE001"]);
  assert.deepStrictEqual(rules(comp("services:\n  a:\n    image: x\n    privileged: \"false\"\n")), []);
});
test("BE002: sockets in many forms", () => {
  for (const src of ["/var/run/docker.sock", "/run/docker.sock", "//var/run/docker.sock", "${localEnv:HOME}/.docker/run/docker.sock", "/run/user/1000/podman/podman.sock", "/var/run", "/run/containerd/containerd.sock"]) {
    assert.deepStrictEqual(rules(dev(`{ "mounts": ["source=${src},target=/var/run/docker.sock,type=bind"] }`)), ["BE002"], src);
  }
  assert.deepStrictEqual(rules(dev('{ "features": { "ghcr.io/devcontainers/features/docker-from-docker:1": {} } }')), ["BE002"]);
  assert.deepStrictEqual(rules(sh("docker run --use-api-socket img claude\n")), ["BE002"]);
  assert.deepStrictEqual(rules(comp("services:\n  a:\n    image: x\n    volumes:\n      - type: bind\n        source: /var/run/docker.sock\n        target: /var/run/docker.sock\n")), ["BE002"]);
});
test("BE002 message: read-only socket still dangerous", () => {
  const f = dev('{ "mounts": ["source=/var/run/docker.sock,target=/s,type=bind,readonly"] }')[0];
  assert.ok(/read-only mount does not help/.test(f.message));
});
test("BE003: namespaces", () => {
  assert.deepStrictEqual(rules(dev('{ "runArgs": ["--net=host", "--ipc=host", "--userns=host", "--uts=host", "--network", "bridge"] }')), ["BE003", "BE003", "BE003"]);
  assert.deepStrictEqual(rules(comp("services:\n  a:\n    image: x\n    ipc: host\n    userns_mode: host\n    network_mode: \"service:db\"\n")), ["BE003", "BE003"]);
});
test("BE004: capability names and severities", () => {
  const F = dev('{ "capAdd": ["ALL", "CAP_SYS_MODULE", "dac_read_search", "NET_ADMIN", "BPF", "SYS_PTRACE", "NET_RAW", "CHOWN"] }');
  assert.deepStrictEqual(F.map((f) => [f.label.split(" ")[1], f.defaultSeverity]), [["ALL", "error"], ["SYS_MODULE", "error"], ["DAC_READ_SEARCH", "error"], ["NET_ADMIN", "warning"], ["BPF", "warning"]]);
});
test("BE004: NET_ADMIN not reported when a firewall script runs", () => {
  const F = dev('{ "capAdd": ["NET_ADMIN"], "postStartCommand": "sudo /usr/local/bin/init-firewall.sh" }', [{ rel: ".devcontainer/init-firewall.sh", text: "" }]);
  assert.deepStrictEqual(rules(F), []);
});
test("BE005: security options", () => {
  const F = dev('{ "securityOpt": ["apparmor=unconfined", "seccomp:unconfined", "systempaths=unconfined", "label=disable", "no-new-privileges", "seccomp=/path/profile.json"] }');
  assert.deepStrictEqual(F.map((f) => f.defaultSeverity), ["error", "error", "error", "warning"]);
  assert.deepStrictEqual(rules(dev('{ "runArgs": ["--security-opt", "seccomp=unconfined"] }')), ["BE005"]);
});
test("BE006: home and credential forms", () => {
  const forms = ["${localEnv:HOME}", "${localEnv:USERPROFILE}", "${env:HOME}", "$HOME", "${HOME}", "~", "/home/jay", "/Users/jay", "C:\\\\Users\\\\jay", "/root"];
  for (const h of forms) {
    for (const d of ["", "/.ssh", "/.aws/credentials", "/.config/gcloud", "/.kube", "/.docker", "/.gnupg", "/.azure"]) {
      const F = dev(`{ "mounts": ["source=${h}${d},target=/x,type=bind"] }`);
      assert.deepStrictEqual(rules(F), ["BE006"], h + d);
    }
  }
  for (const src of ["/", "/etc", "/proc", "/home"]) assert.deepStrictEqual(rules(dev(`{ "mounts": ["source=${src},target=/x,type=bind"] }`)), ["BE006"], src);
});
test("BE006: harmless paths not reported", () => {
  for (const src of ["${localEnv:HOME}/projects/app", "/home/jay/src", "/tmp/x", "/opt/data", "/etc2", "~/.sshx", "${localWorkspaceFolder}", "${localWorkspaceFolder}/sub", "${localEnv:SECRETS}", "~bob/.ssh"]) {
    assert.deepStrictEqual(rules(dev(`{ "mounts": ["source=${src},target=/x,type=bind"] }`)), [], src);
  }
  assert.deepStrictEqual(rules(dev('{ "mounts": ["source=${localEnv:HOME}/.ssh,target=/x,type=volume"] }')), []);
});
test("BE006: read-only lowers the severity one step and has no fix", () => {
  const F = dev(`{ "name": "claude", "mounts": ["source=\${localEnv:HOME}/.ssh,target=/x,type=bind,readonly"] }`);
  assert.deepStrictEqual(shape(F), [["BE006", "warning", 0]]);
  assert.strictEqual(F[0].fix, null);
  assert.ok(/read-only/.test(F[0].label) && /can still be read/.test(F[0].message));
  const G = dev(`{ "mounts": [{ "source": "\${localEnv:HOME}/.ssh", "target": "/x", "type": "bind" }] }`);
  assert.deepStrictEqual(shape(G), [["BE006", "warning", 0]]);
  assert.deepStrictEqual(shape(comp("services:\n  a:\n    image: x\n    volumes:\n      - ~/.ssh:/x:ro\n")), [["BE006", "information", 4]]);
});
test("BE007: workspace parent, not siblings", () => {
  assert.deepStrictEqual(rules(dev('{ "workspaceMount": "source=${localWorkspaceFolder}/..,target=/w,type=bind" }')), ["BE007"]);
  assert.deepStrictEqual(rules(dev('{ "workspaceMount": "source=${localWorkspaceFolder}/../..,target=/w,type=bind" }')), ["BE007"]);
  assert.deepStrictEqual(rules(dev('{ "workspaceMount": "source=${localWorkspaceFolder}/../shared,target=/w,type=bind" }')), []);
  assert.deepStrictEqual(rules(run(".devcontainer/docker-compose.yml", "services:\n  a:\n    image: x\n    volumes:\n      - ..:/workspace\n")), []);
  assert.deepStrictEqual(rules(run(".devcontainer/docker-compose.yml", "services:\n  a:\n    image: x\n    volumes:\n      - ../..:/workspaces:cached\n")), ["BE007"]);
  assert.deepStrictEqual(rules(run("docker-compose.yml", "services:\n  a:\n    image: x\n    volumes:\n      - ..:/w\n")), ["BE007"]);
  assert.deepStrictEqual(rules(sh("docker run -v $(pwd)/..:/all img claude\n")), ["BE007"]);
});
test("BE008: SSH and GPG agent sockets", () => {
  assert.deepStrictEqual(rules(dev('{ "mounts": ["source=/run/host-services/ssh-auth.sock,target=/ssh.sock,type=bind"] }')), ["BE008"]);
  assert.deepStrictEqual(rules(dev('{ "runArgs": ["-v", "${localEnv:HOME}/.gnupg/S.gpg-agent:/root/.gnupg/S.gpg-agent"] }')), ["BE008"]);
  assert.deepStrictEqual(rules(sh('docker run -v "$SSH_AUTH_SOCK:/ssh-agent" -e SSH_AUTH_SOCK=/ssh-agent img claude\n')), ["BE008"]);
});
test("BE009: devices", () => {
  assert.deepStrictEqual(rules(dev('{ "runArgs": ["--device=/dev/mem", "--device", "/dev/nvme0n1", "--device=/dev/fuse", "--device=/dev/net/tun", "--device=/dev/nvidia0"] }')), ["BE009", "BE009"]);
  assert.deepStrictEqual(rules(comp("services:\n  a:\n    image: x\n    devices:\n      - /dev/sda:/dev/xvda:rwm\n      - /dev/kvm\n    device_cgroup_rules:\n      - 'a *:* rwm'\n      - 'c 1:3 mr'\n")), ["BE009", "BE009"]);
});
test("BE010: firewall cases", () => {
  const ex = [{ rel: ".devcontainer/init-firewall.sh", text: "" }];
  // run without NET_ADMIN
  const a = dev('{ "name": "claude", "postStartCommand": "sudo /usr/local/bin/init-firewall.sh" }', ex);
  assert.deepStrictEqual(rules(a), ["BE010"]);
  assert.ok(/without NET_ADMIN/.test(a[0].label));
  // failure ignored
  const b = dev('{ "name": "claude", "runArgs": ["--cap-add=NET_ADMIN"], "postStartCommand": "sudo /usr/local/bin/init-firewall.sh || true" }', ex);
  assert.ok(/failure is ignored/.test(b[0].label) && b.length === 1);
  // script present but never run
  const c = dev('{ "name": "claude", "runArgs": ["--cap-add=NET_ADMIN"] }', ex);
  assert.deepStrictEqual(rules(c), ["BE004", "BE010"]);
  assert.ok(c.some((f) => /init-firewall\.sh is never run/.test(f.label)));
  // not an agent: unused firewall script is not reported
  assert.deepStrictEqual(rules(dev('{ "name": "web" }', ex)), []);
  // ENTRYPOINT runs it
  const d = dev('{ "name": "claude", "build": { "dockerfile": "Dockerfile" }, "capAdd": ["NET_ADMIN"] }', [...ex, { rel: ".devcontainer/Dockerfile", text: 'FROM x\nENTRYPOINT ["/usr/local/bin/init-firewall.sh"]\n' }]);
  assert.deepStrictEqual(rules(d), []);
});
test("BE011: root agent only", () => {
  assert.deepStrictEqual(rules(dev('{ "name": "claude", "containerUser": "root" }')), ["BE011"]);
  assert.deepStrictEqual(rules(dev('{ "name": "web", "remoteUser": "root" }')), []);
  assert.deepStrictEqual(rules(dev('{ "name": "claude", "remoteUser": "node" }')), []);
  assert.deepStrictEqual(rules(comp("services:\n  codex:\n    image: x\n    user: \"0:0\"\n")), ["BE011"]);
  assert.deepStrictEqual(rules(sh("docker run -u 0 img claude\n")), ["BE011"]);
  assert.deepStrictEqual(rules(sh("docker run --user=1000 img claude\n")), []);
});

// ---------------------------------------------------------------------------------------------
// Quick Fixes
// ---------------------------------------------------------------------------------------------

test("fix: remove privileged property keeps valid JSONC", () => {
  const t = fx.AGENT_DEVCONTAINER;
  const f = dev(t).find((x) => x.rule === "BE001");
  const out = applyFix(t, f);
  assert.ok(!/"privileged"/.test(out));
  assert.ok(!dev(out).some((x) => x.rule === "BE001"));
  assert.strictEqual(core.parseJsonc(out).errors.length, 0);
  assert.strictEqual(dev(out).length, dev(t).length - 1);
});
test("fix: privileged as the last property", () => {
  const t = '{\n  "name": "a",\n  "privileged": true\n}\n';
  const out = applyFix(t, dev(t)[0]);
  assert.strictEqual(out, '{\n  "name": "a"\n}\n');
  const t2 = '{ "privileged": true }';
  assert.strictEqual(applyFix(t2, dev(t2)[0]), "{  }");
  const t3 = '{ "privileged": true, }';
  assert.strictEqual(core.parseJsonc(applyFix(t3, dev(t3)[0])).errors.length, 0);
});
test("fix: remove a capAdd entry (first, middle, last, only)", () => {
  const cases = [
    ['{ "capAdd": ["SYS_ADMIN", "SYS_PTRACE"] }', '{ "capAdd": ["SYS_PTRACE"] }'],
    ['{ "capAdd": ["SYS_PTRACE", "SYS_ADMIN"] }', '{ "capAdd": ["SYS_PTRACE"] }'],
    ['{ "capAdd": ["A", "SYS_ADMIN", "B"] }', '{ "capAdd": ["A", "B"] }'],
    ['{ "capAdd": ["SYS_ADMIN"] }', '{ "capAdd": [] }'],
    ['{ "capAdd": ["SYS_ADMIN",] }', '{ "capAdd": [] }'],
    ['{ "capAdd": [\n    "SYS_ADMIN", // needed?\n    "SYS_PTRACE"\n  ] }', '{ "capAdd": [\n    "SYS_PTRACE"\n  ] }'],
  ];
  for (const [t, want] of cases) {
    const f = dev(t).find((x) => x.rule === "BE004");
    assert.strictEqual(applyFix(t, f), want);
  }
});
test("fix: remove runArgs --cap-add pair and --privileged", () => {
  const t = '{ "runArgs": ["--init", "--cap-add", "SYS_ADMIN", "--privileged"] }';
  const F = dev(t);
  const out = applyFix(t, F.find((f) => f.rule === "BE004"));
  assert.strictEqual(out, '{ "runArgs": ["--init", "--privileged"] }');
  const out2 = applyFix(t, F.find((f) => f.rule === "BE001"));
  assert.strictEqual(out2, '{ "runArgs": ["--init", "--cap-add", "SYS_ADMIN"] }');
});
test("fix: mount read-only with ,readonly, then severity drops", () => {
  const t = '{ "name": "claude", "mounts": ["source=${localEnv:HOME}/.aws,target=/root/.aws,type=bind"] }';
  const f = dev(t)[0];
  assert.strictEqual(f.fix.title, "Make the mount read-only (,readonly)");
  const out = applyFix(t, f);
  assert.ok(out.includes('type=bind,readonly"'));
  assert.deepStrictEqual(shape(dev(out)), [["BE006", "warning", 0]]);
});
test("fix: runArgs -v gets :ro / ,ro; rw mode gets no fix", () => {
  const t = '{ "runArgs": ["-v", "/etc:/host-etc"] }';
  assert.ok(applyFix(t, dev(t)[0]).includes('"/etc:/host-etc:ro"'));
  const t2 = '{ "runArgs": ["--volume=/etc:/host-etc:z"] }';
  assert.ok(applyFix(t2, dev(t2)[0]).includes('"--volume=/etc:/host-etc:z,ro"'));
  assert.strictEqual(dev('{ "runArgs": ["-v", "/etc:/x:rw"] }')[0].fix, null);
});
test("fix: remove docker.sock mount and docker-outside-of-docker feature", () => {
  const t = fx.AGENT_DEVCONTAINER;
  for (const f of dev(t).filter((x) => x.rule === "BE002")) {
    const out = applyFix(t, f);
    assert.strictEqual(core.parseJsonc(out).errors.length, 0);
    assert.strictEqual(dev(out).filter((x) => x.rule === "BE002").length, 1);
  }
});
test("fix: compose privileged, cap_add item, last cap_add, volume :ro, volume removal", () => {
  const t = fx.AGENT_COMPOSE;
  const rel = ".devcontainer/compose.yml";
  const F = run(rel, t);
  const priv = applyFix(t, F.find((f) => f.rule === "BE001"));
  assert.ok(!/privileged/.test(priv));
  assert.strictEqual(run(rel, priv).length, F.length - 1);
  const cap = applyFix(t, F.find((f) => f.label.startsWith("cap_add: SYS_ADMIN")));
  assert.ok(cap.includes("    cap_add:\n      - NET_ADMIN\n    security_opt"), cap);
  const kube = applyFix(t, F.find((f) => f.label.startsWith("volumes: ~/.kube")));
  assert.ok(kube.includes("- ~/.kube:/root/.kube:ro\n"));
  assert.ok(run(rel, kube).some((f) => f.label === 'volumes: ~/.kube (read-only) into the "agent" service' && f.defaultSeverity === "warning"));
  const sock = applyFix(t, F.find((f) => f.rule === "BE002"));
  assert.ok(!sock.includes("docker.sock"));
  assert.strictEqual(run(rel, sock).length, F.length - 1);
  const one = "services:\n  a:\n    image: x\n    cap_add:\n      - SYS_ADMIN\n    user: app\n";
  assert.strictEqual(applyFix(one, comp(one)[0]), "services:\n  a:\n    image: x\n    user: app\n");
  const flow = "services:\n  a:\n    image: x\n    cap_add: [SYS_ADMIN, SYS_PTRACE]\n";
  assert.strictEqual(applyFix(flow, comp(flow)[0]), "services:\n  a:\n    image: x\n    cap_add: [SYS_PTRACE]\n");
  const q = "services:\n  a:\n    image: x\n    volumes:\n      - \"/etc:/e\"\n";
  assert.ok(applyFix(q, comp(q)[0]).includes('- "/etc:/e:ro"'));
});
test("fix: shell --privileged and -v read-only", () => {
  const t = fx.AGENT_SCRIPT;
  const F = sh(t);
  const p = applyFix(t, F.find((f) => f.rule === "BE001"));
  assert.ok(!sh(p).some((f) => f.rule === "BE001"));
  assert.ok(p.includes("docker run --rm -it \\\n \\\n"));
  const v = applyFix(t, F.find((f) => f.rule === "BE006"));
  assert.ok(v.includes('-v "$HOME/.ssh:/root/.ssh:ro"'));
});
test("no fix for anchors / merged keys", () => {
  const t = "x-base: &base\n  privileged: true\nservices:\n  a:\n    <<: *base\n    image: x\n";
  const F = comp(t);
  assert.deepStrictEqual(rules(F), ["BE001"]);
  assert.strictEqual(F[0].fix, null);
});

// ---------------------------------------------------------------------------------------------
// Parsers and robustness
// ---------------------------------------------------------------------------------------------

test("parseJsonc: comments, trailing commas, escapes, positions", () => {
  const r = core.parseJsonc('// c\n{ /* a */ "a\\"b": [1, true, null, "x\\u0041",], }');
  assert.strictEqual(r.errors.length, 0);
  assert.strictEqual(r.root.entries[0].key, 'a"b');
  assert.deepStrictEqual(r.root.entries[0].value.items.map((n) => n.value), [1, true, null, "xA"]);
});
test("broken and hostile inputs never throw", () => {
  const inputs = ["", "{", "[", '{"a":', '{"mounts": [', "{".repeat(5000), "[".repeat(5000), '"\\', "services:\n  a: [", "services:\n" + "  a:\n".repeat(3000), "\u0000\u0001", "docker run " + "-v ".repeat(10000), "docker run $(" + "(".repeat(5000), "<<EOF\n", 'docker run "unterminated'];
  for (const t of inputs) {
    for (const rel of ["devcontainer.json", "compose.yaml", "a.sh"]) {
      assert.doesNotThrow(() => core.analyzeWorkspace({ files: [{ rel, text: t }] }));
    }
  }
  // random fuzz
  let seed = 7;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const alpha = '{}[]":,/\\*-\n #$()\'`<EOF;|&truefalse privileged mounts source=/var/run/docker.sock ~/.ssh docker run claude';
  for (let n = 0; n < 300; n++) {
    let s = "";
    const len = Math.floor(rnd() * 400);
    for (let i = 0; i < len; i++) s += alpha[Math.floor(rnd() * alpha.length)];
    for (const rel of ["devcontainer.json", "compose.yaml", "a.sh"]) core.analyzeWorkspace({ files: [{ rel, text: s }] });
  }
});
test("callbacks that throw are contained", () => {
  const r = core.analyzeWorkspace({ files: [{ rel: ".devcontainer/devcontainer.json", text: '{ "build": { "dockerfile": "Dockerfile" }, "postStartCommand": "init-firewall.sh" }' }], read: () => { throw new Error("x"); }, exists: () => { throw new Error("y"); } });
  assert.ok(Array.isArray(r.get(".devcontainer/devcontainer.json")));
});
test("large input is fast", () => {
  const big = "services:\n" + Array.from({ length: 2000 }, (_, i) => `  s${i}:\n    image: x\n    volumes:\n      - ./a:/a\n`).join("");
  const t0 = Date.now();
  comp(big);
  sh("docker run -v a:b img claude\n".repeat(5000));
  assert.ok(Date.now() - t0 < 4000, "took " + (Date.now() - t0));
});
test("shellCommands: continuations, quotes, comments, heredocs", () => {
  const c = core.shellCommands('a "b c" \'d\' \\\n  e # f\ng $(h i) ${J:-k}\ncat <<-X\n\tdocker run --privileged claude\n\tX\nz\n');
  assert.deepStrictEqual(c.map((w) => w.map((x) => x.value)), [["a", "b c", "d", "e"], ["g", "$(h i)", "${J:-k}"], ["cat"], ["z"]]);
});
test("interpretFlags: short clusters, inline values, image position", () => {
  const toks = ["-itv", "/a:/b", "--rm", "-e", "X=1", "--name=n", "img", "cmd"].map((value, i) => ({ value, start: i, end: i + 1 }));
  const r = core.interpretFlags(toks, true);
  assert.strictEqual(r.positional, 6);
  assert.deepStrictEqual(r.flags.map((f) => [f.name, f.value]), [["interactive", "true"], ["tty", "true"], ["volume", "/a:/b"], ["rm", "true"], ["env", "X=1"], ["name", "n"]]);
});
test("splitVolume keeps ${localEnv:HOME} and drive letters", () => {
  assert.deepStrictEqual(core.splitVolume("${localEnv:HOME}/.ssh:/root/.ssh:ro"), ["${localEnv:HOME}/.ssh", "/root/.ssh", "ro"]);
  assert.deepStrictEqual(core.splitVolume("C:\\Users\\me\\.aws:/root/.aws"), ["C:\\Users\\me\\.aws", "/root/.aws"]);
});
test("classifyHost", () => {
  assert.strictEqual(core.classifyHost("C:\\Users\\me\\.aws").cat, "cred");
  assert.strictEqual(core.classifyHost("\\\\.\\pipe\\docker_engine").cat, "socket");
  assert.strictEqual(core.classifyHost("${localEnv:HOME:/tmp}").cat, "home");
  assert.strictEqual(core.classifyHost("pgdata"), null);
  assert.strictEqual(core.classifyHost("./src", ""), null);
});
test("fileKind", () => {
  assert.strictEqual(core.fileKind(".devcontainer/devcontainer.json"), "devcontainer");
  assert.strictEqual(core.fileKind(".devcontainer.json"), "devcontainer");
  assert.strictEqual(core.fileKind("deploy/docker-compose.prod.yml"), "compose");
  assert.strictEqual(core.fileKind("compose.yaml"), "compose");
  assert.strictEqual(core.fileKind("x/run.sh"), "shell");
  assert.strictEqual(core.fileKind("package.json"), null);
});
test("checkScripts=false skips scripts", () => {
  assert.deepStrictEqual(sh(fx.AGENT_SCRIPT, { checkScripts: false }), []);
});
test("resolveSeverities / severityOf", () => {
  const o = core.resolveSeverities({ BE006: "hint", BE001: "bogus", XX: "error" });
  assert.deepStrictEqual(o, { BE006: "hint" });
  assert.strictEqual(core.severityOf({ rule: "BE006", defaultSeverity: "error" }, o), "hint");
  assert.strictEqual(core.severityOf({ rule: "BE001", defaultSeverity: "error" }, o), "error");
});
test("every rule has a title and default severity; every message free of en/em dashes", () => {
  for (const id of core.RULE_IDS) assert.ok(core.RULES[id].title && core.SEVERITIES.includes(core.RULES[id].severity));
  const all = [...dev(fx.AGENT_DEVCONTAINER), ...run(".devcontainer/compose.yml", fx.AGENT_COMPOSE), ...sh(fx.AGENT_SCRIPT)];
  for (const f of all) assert.ok(!/[\u2013\u2014]/.test(f.message + f.label));
  assert.deepStrictEqual([...new Set(all.map((f) => f.rule))].sort().length, 11);
});

// ---------------------------------------------------------------------------------------------
// Glob hardening
// ---------------------------------------------------------------------------------------------

test("globToRegExp basics", () => {
  const ex = core.makeExcluder(["**/node_modules/**", "*.bak", "gen/{a,b}/**", "x[0-9].sh"]);
  assert.ok(ex("a/node_modules/b/c.sh"));
  assert.ok(ex("deep/f.bak"));
  assert.ok(ex("gen/a/z.yml"));
  assert.ok(ex("x1.sh"));
  assert.ok(!ex("src/app.sh"));
});
test("globToRegExp: collapses **/ runs and *** runs, refuses huge patterns", () => {
  assert.strictEqual(core.globToRegExp("**/**/**/a").source, core.globToRegExp("**/a").source);
  assert.strictEqual(core.globToRegExp("a/****/b").source, core.globToRegExp("a/**/b").source);
  assert.strictEqual(core.globToRegExp("x".repeat(301)), null);
  assert.strictEqual(core.globToRegExp("a**b**c**d**e**f"), null);
  const re = core.globToRegExp("**/*a**/*a**/*a**/*a");
  const t0 = Date.now();
  if (re) re.test("a".repeat(50) + "/b".repeat(30) + "!");
  assert.ok(Date.now() - t0 < 500);
});
test("globToRegExp: brackets escape \\, [ and ]", () => {
  const re = core.globToRegExp("f[\\]x");
  assert.ok(re, "compiles");
  assert.ok(core.globToRegExp("a[[]b").test("a[b"));
  assert.ok(!core.globToRegExp("a[!x]b").test("axb"));
  assert.ok(core.globToRegExp("a[!x]b").test("ayb"));
});

test("firewall script detection is linear and matches the old regex (ReDoS)", () => {
  const OLD = /[\w.\-/]*firewall[\w.\-]*\.sh/i;
  const samples = ["sudo /usr/local/bin/init-firewall.sh", "bash .devcontainer/init-FIREWALL.SH && x", "a/firewall/b.sh", "x/firewall-a.sh/y/firewall.sh.bak.sh z", "firewall.sh", "nofw.sh", "init-firewall.bash", "a firewall .sh", "pre/x.firewall.sh/post", "/a/b/firewallfirewall.shfirewall", "\"bash ./init-firewall.sh\"", "run firewall.s h", ""];
  for (const t of samples) {
    const m = OLD.exec(t);
    assert.strictEqual(core.firewallScript(t), m ? m[0] : null, JSON.stringify(t));
  }
  for (const bomb of ["a".repeat(100000), "firewall".repeat(12500), "a/".repeat(50000), ("firewall" + "a".repeat(50)).repeat(1700) + "/x"]) {
    const t0 = Date.now();
    core.firewallScript(bomb);
    core.dfEntrypointHas("CMD " + bomb + "\n" + "\n".repeat(100000), (rest) => core.firewallScript(rest) !== null);
    run(".devcontainer/devcontainer.json", JSON.stringify({ name: "claude", postStartCommand: bomb, build: { dockerfile: "Dockerfile" } }), [{ rel: ".devcontainer/Dockerfile", text: "FROM x\n" + "\n".repeat(100000) + "CMD " + bomb + "\n" }]);
    run("compose.yaml", "services:\n  claude:\n    image: x\n    command: " + bomb + "\n");
    assert.ok(Date.now() - t0 < 200, "took " + (Date.now() - t0) + " ms");
  }
  assert.ok(core.dfEntrypointHas("FROM x\n\n  cmd [\"/usr/local/bin/init-firewall.sh\"]\n", (rest) => core.firewallScript(rest) !== null));
  assert.ok(!core.dfEntrypointHas("FROM x\nRUN init-firewall.sh\nCMDX firewall.sh\n", (rest) => core.firewallScript(rest) !== null));
});

test("whitespace runs and newline-bearing image names stay linear (ReDoS)", () => {
  for (const u of [" ", "\t", ":", "@", "a:"]) {
    const t = u.repeat(Math.ceil(100000 / u.length)) + "x\"";
    const t0 = Date.now();
    core.parseYaml(t);
    run("compose.yaml", "services:\n  claude:\n    image: x\n    command: " + t + "\n");
    run("compose.yaml", "services:\n  a:\n    image: \"" + t + "\\n\"\n");
    sh("docker run " + t + " claude\n");
    dev(JSON.stringify({ features: { ["ghcr.io/x/claude-code:" + t + "\n"]: {} } }));
    assert.ok(Date.now() - t0 < 200, JSON.stringify(u) + " took " + (Date.now() - t0) + " ms");
  }
  for (const u of ["../", "./.", "/.."]) {
    const t0 = Date.now();
    core.normHostPath(u.repeat(140000) + "x", "");
    core.normHostPath("./" + u.repeat(140000), null);
    comp("services:\n  a:\n    image: x\n    volumes:\n      - " + u.repeat(140000) + ":/x\n");
    assert.ok(Date.now() - t0 < 200, JSON.stringify(u) + " path took " + (Date.now() - t0) + " ms");
  }
  assert.strictEqual(core.normHostPath("${localEnv:HOME}/.ssh"), "~/.ssh");
  // Image names are still cut at the tag or digest.
  assert.ok(comp("services:\n  a:\n    image: ghcr.io/acme/claude:1@sha256:abc\n    privileged: true\n").some((f) => f.agent));
});

console.log(`core tests: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
