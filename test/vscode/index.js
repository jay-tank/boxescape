"use strict";

// In-editor test, loaded by VS Code through --extensionTestsPath. Expects the workspace built by
// test/run-vscode.js and its JSON config in BE_TEST_CONFIG.

const vscode = require("vscode");
const fs = require("fs");
const path = require("path");
const fx = require("../fixtures");

const results = [];
function check(name, cond, detail) {
  results.push({ name, ok: !!cond, detail: cond ? undefined : detail });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, timeoutMs, label) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (_) {
      /* retry */
    }
    await sleep(200);
  }
  throw new Error("timeout waiting for " + label);
}
async function expectWait(name, fn, timeoutMs) {
  try {
    await waitFor(fn, timeoutMs || 15000, name);
    check(name, true);
  } catch (e) {
    check(name, false, String(e));
  }
}

async function run() {
  const cfg = JSON.parse(fs.readFileSync(process.env.BE_TEST_CONFIG, "utf8"));
  const { mode, root, outsideDir, resultFile, markerDir } = cfg;
  const trusted = mode === "trusted";
  const M = (s) => `${mode}: ${s}`;
  const P = (rel) => path.join(root, ...rel.split("/"));
  const weirdRel = "weird dir/na\u00efve (1)/devcontainer.json";
  const EXPECTED = {
    ".devcontainer/devcontainer.json": fx.AGENT_DEVCONTAINER_EXPECT.length,
    ".devcontainer/compose.yml": fx.AGENT_COMPOSE_EXPECT.length,
    "scripts/agent.sh": fx.AGENT_SCRIPT_EXPECT.length,
    "fix/.devcontainer/devcontainer.json": 2,
    "panel/docker-compose.yml": 1,
    [weirdRel]: 1,
    "dep/.devcontainer/devcontainer.json": 1,
    "gen/compose.yaml": 1,
  };
  const TOTAL = Object.values(EXPECTED).reduce((a, b) => a + b, 0);
  const conf = () => vscode.workspace.getConfiguration("boxEscape");
  const count = () => vscode.languages.getDiagnostics().reduce((n, [, ds]) => n + ds.filter((d) => d.source === "BoxEscape").length, 0);

  try {
    check(M("workspace trust state"), vscode.workspace.isTrusted === trusted);
    const ext = vscode.extensions.getExtension("jaytankdev.boxescape");
    check(M("extension found"), !!ext);
    const api = ext.isActive ? ext.exports : await ext.activate();
    check(M("activate() returns the test API"), api && typeof api.getTreeItems === "function");
    await api.ready();
    await expectWait(M(`initial scan finds ${TOTAL} findings`), () => api.getFindings().length === TOTAL, 30000);
    const F = api.getFindings();

    for (const [rel, n] of Object.entries(EXPECTED)) check(M(`${rel}: ${n} findings`), F.filter((f) => f.rel === rel).length === n, JSON.stringify(F.filter((f) => f.rel === rel).map((f) => f.rule + ":" + f.label)));
    for (const [rule, sev, line] of fx.AGENT_DEVCONTAINER_EXPECT) check(M(`devcontainer ${rule} ${sev} line ${line + 1}`), F.some((f) => f.rel === ".devcontainer/devcontainer.json" && f.rule === rule && f.severity === sev && f.line === line));
    for (const [rule, sev, line] of fx.AGENT_COMPOSE_EXPECT) check(M(`compose ${rule} ${sev} line ${line + 1}`), F.some((f) => f.rel === ".devcontainer/compose.yml" && f.rule === rule && f.severity === sev && f.line === line));
    for (const rel of ["ref/.devcontainer/devcontainer.json", "plain/.devcontainer/devcontainer.json", "plain/compose.yaml", "plain/run.sh", "node_modules/pkg/devcontainer.json", "big/devcontainer.json", "link/devcontainer.json", "nofinding/devcontainer.json", "live/.devcontainer.json"]) {
      check(M(`no findings in ${rel}`), !F.some((f) => f.rel === rel));
    }
    check(M("nothing reported outside the workspace"), !F.some((f) => f.uri.fsPath.startsWith(outsideDir)));
    check(M("dep: non-agent mount is a warning"), F.some((f) => f.rel === "dep/.devcontainer/devcontainer.json" && f.severity === "warning"));

    // Contributions.
    const pkg = ext.packageJSON;
    const ac = (pkg.contributes.viewsContainers || {}).activitybar || [];
    check(M("activity bar container contributed"), ac.some((c) => c.id === "boxescape" && c.icon === "media/activity.svg"));
    check(M("activity bar icon file exists"), fs.existsSync(path.join(ext.extensionPath, "media", "activity.svg")));
    check(M("view named Container escape checks"), (pkg.contributes.views.boxescape || []).some((v) => v.id === "boxEscape.view" && v.name === "Container escape checks"));
    check(M("inline Quick Fix menu contributed"), pkg.contributes.menus["view/item/context"].some((m) => m.command === "boxEscape.applyFix" && m.group.startsWith("inline") && /finding\.fixable/.test(m.when)));
    check(M("three empty states contributed"), pkg.contributes.viewsWelcome.length === 3);
    check(M("untrustedWorkspaces supported: true"), pkg.capabilities.untrustedWorkspaces.supported === true);

    // Diagnostics, badge, status bar.
    const diag = vscode.languages.getDiagnostics(vscode.Uri.file(P(".devcontainer/devcontainer.json"))).filter((d) => d.source === "BoxEscape");
    check(M("diagnostics published for devcontainer.json"), diag.length === EXPECTED[".devcontainer/devcontainer.json"], String(diag.length));
    check(M("BE006 diagnostic is an error in the agent container"), diag.some((d) => d.code === "BE006" && d.severity === vscode.DiagnosticSeverity.Error && d.range.start.line === 13));
    check(M("BE003 is a warning"), diag.some((d) => d.code === "BE003" && d.severity === vscode.DiagnosticSeverity.Warning));
    check(M("BE010 is information"), diag.some((d) => d.code === "BE010" && d.severity === vscode.DiagnosticSeverity.Information));
    check(M("no diagnostics for excluded node_modules"), vscode.languages.getDiagnostics(vscode.Uri.file(P("node_modules/pkg/devcontainer.json"))).length === 0);
    check(M("badge equals finding count"), api.getBadge() === TOTAL, `badge=${api.getBadge()}`);
    check(M("total diagnostics equal finding count"), count() === TOTAL, String(count()));
    check(M("status bar shows BoxEscape: N"), api.getStatusText().endsWith(`BoxEscape: ${TOTAL}`), api.getStatusText());

    // Open the view container.
    let opened = true;
    try {
      await vscode.commands.executeCommand("workbench.view.extension.boxescape");
    } catch (e) {
      opened = String(e);
    }
    check(M("workbench.view.extension.boxescape opens"), opened === true, opened);
    let focused = true;
    try {
      await vscode.commands.executeCommand("boxEscape.focusView");
    } catch (e) {
      focused = String(e);
    }
    check(M("boxEscape.focusView works"), focused === true, focused);

    // Tree rows: file -> findings.
    const top = await api.getTreeItems();
    check(M("one row per file with findings"), top.length === Object.keys(EXPECTED).length && top.every((t) => t.contextValue === "file"), JSON.stringify(top.map((t) => t.label)));
    const devRow = top.find((t) => t.resourceUri && t.resourceUri.fsPath === P(".devcontainer/devcontainer.json"));
    check(M("file row label is the file name, description has folder and count"), devRow && devRow.label === "devcontainer.json" && devRow.description === `.devcontainer  ${EXPECTED[".devcontainer/devcontainer.json"]}`, devRow && JSON.stringify([devRow.label, devRow.description]));
    const weirdRow = top.find((t) => t.resourceUri && t.resourceUri.fsPath === P(weirdRel));
    check(M("weird folder name row"), weirdRow && weirdRow.description.startsWith("weird dir/na\u00efve (1)"));
    const rows = await api.getTreeItems(devRow.node);
    check(M("finding rows equal the file's findings"), rows.length === EXPECTED[".devcontainer/devcontainer.json"]);
    check(M("row label names setting, path and container"), rows.some((r) => r.label === 'mounts: ~/.aws into the "claude" container' && r.description === "BE006 Host credentials or system path mounted  :14" && r.tooltip.includes("(AI agent container)")), JSON.stringify(rows.map((r) => [r.label, r.description])));
    check(M("row labels distinguishable"), new Set(rows.map((r) => r.label + "@" + r.command.arguments[1])).size === rows.length);
    check(M("rows have icon, tooltip with file:line, open command"), rows.every((r) => r.iconPath && /\.devcontainer\/devcontainer\.json:\d+/.test(r.tooltip) && r.command && r.command.command === "boxEscape.openFinding"));
    check(M("fixable rows marked for the inline button"), rows.some((r) => r.contextValue === "finding.fixable") && rows.some((r) => r.contextValue === "finding"));
    check(M("fixable row tooltip names the Quick Fix"), rows.filter((r) => r.contextValue === "finding.fixable").every((r) => /Quick Fix: /.test(r.tooltip)));

    // Open a finding at the right line.
    const sockRow = rows.find((r) => r.label.startsWith("mounts: /var/run/docker.sock"));
    const [uri, line, ch] = sockRow.command.arguments;
    const ok = await vscode.commands.executeCommand("boxEscape.openFinding", uri, line, ch);
    let ed = vscode.window.activeTextEditor;
    check(M("openFinding opens the file"), ok === true && ed && ed.document.uri.fsPath === P(".devcontainer/devcontainer.json"), ed && ed.document.uri.fsPath);
    check(M("openFinding selects the docker.sock line"), ed && ed.selection.active.line === line && ed.document.lineAt(line).text.includes("docker.sock"));
    const wr = (await api.getTreeItems(weirdRow.node))[0];
    check(M("openFinding opens the weird-named file"), (await vscode.commands.executeCommand("boxEscape.openFinding", ...wr.command.arguments)) === true && vscode.window.activeTextEditor.document.uri.fsPath === P(weirdRel));
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");

    // Forged arguments.
    check(M("openFinding refuses a plain object"), (await vscode.commands.executeCommand("boxEscape.openFinding", { fsPath: P(".devcontainer/devcontainer.json"), scheme: "file" }, line)) === false);
    check(M("openFinding refuses a file outside the workspace"), (await vscode.commands.executeCommand("boxEscape.openFinding", vscode.Uri.file(path.join(outsideDir, "devcontainer.json")), 0)) === false);
    check(M("openFinding refuses a symlink leading outside"), (await vscode.commands.executeCommand("boxEscape.openFinding", vscode.Uri.file(P("link/devcontainer.json")), 0)) === false);
    check(M("openFinding refuses a workspace file without findings"), (await vscode.commands.executeCommand("boxEscape.openFinding", vscode.Uri.file(P("nofinding/devcontainer.json")), 0)) === false);
    check(M("openFinding refuses a line without a finding"), (await vscode.commands.executeCommand("boxEscape.openFinding", uri, 999)) === false);
    check(M("no editor opened for refused arguments"), !vscode.window.activeTextEditor);
    check(M("applyFix refuses a forged node"), (await vscode.commands.executeCommand("boxEscape.applyFix", { type: "finding", key: uri.toString(), id: "BE001:0:1" })) === false);
    check(M("applyFix refuses junk"), (await vscode.commands.executeCommand("boxEscape.applyFix", "x")) === false);

    // Visual check (trusted run): view container open with the agent devcontainer.
    if (trusted) {
      const ddoc = await vscode.workspace.openTextDocument(P(".devcontainer/devcontainer.json"));
      await vscode.window.showTextDocument(ddoc, { preview: false });
      const r0 = rows.find((r) => r.label.startsWith("mounts: ~/.aws"));
      await vscode.commands.executeCommand("boxEscape.openFinding", ...r0.command.arguments);
      await vscode.commands.executeCommand("workbench.view.extension.boxescape");
      for (const cmd of ["workbench.action.closeAuxiliaryBar", "notifications.clearAll", "workbench.action.closePanel"]) {
        try {
          await vscode.commands.executeCommand(cmd);
        } catch (_) {
          /* not available in this version */
        }
      }
      await vscode.commands.executeCommand("workbench.action.focusActiveEditorGroup");
      for (let i = 0; i < 11; i++) {
        try {
          await vscode.commands.executeCommand("workbench.action.decreaseViewWidth");
        } catch (_) {
          break;
        }
      }
      await sleep(6000);
      fs.writeFileSync(path.join(markerDir, "shot-" + mode), "1");
      await expectWait(M("screenshot taken"), () => fs.existsSync(path.join(markerDir, "shot-done-" + mode)), 40000);
    }
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");

    // Quick Fixes through the code action provider (lightbulb path).
    const fdoc = await vscode.workspace.openTextDocument(P("fix/.devcontainer/devcontainer.json"));
    await vscode.window.showTextDocument(fdoc);
    await sleep(600);
    const acts = await vscode.commands.executeCommand("vscode.executeCodeActionProvider", fdoc.uri, new vscode.Range(2, 13, 2, 24), vscode.CodeActionKind.QuickFix.value);
    const a1 = (acts || []).find((a) => /\(BE004\)/.test(a.title));
    check(M("code action offered for BE004"), !!a1 && a1.title === "Remove SYS_ADMIN from capAdd (BE004)", JSON.stringify((acts || []).map((a) => a.title)));
    if (a1) await vscode.workspace.applyEdit(a1.edit);
    check(M("BE004 Quick Fix removes the capAdd entry"), fdoc.lineAt(2).text === '  "capAdd": ["SYS_PTRACE"],', fdoc.lineAt(2).text);
    await expectWait(M("BE004 gone after the fix, BE006 remains"), () => {
      const G = api.getFindings().filter((f) => f.rel === "fix/.devcontainer/devcontainer.json");
      return G.length === 1 && G[0].rule === "BE006" && G[0].severity === "error";
    });
    const acts2 = await vscode.commands.executeCommand("vscode.executeCodeActionProvider", fdoc.uri, new vscode.Range(3, 14, 3, 20), vscode.CodeActionKind.QuickFix.value);
    const a2 = (acts2 || []).find((a) => /\(BE006\)/.test(a.title));
    check(M("code action offered for BE006"), !!a2 && a2.title === "Make the mount read-only (,readonly) (BE006)", JSON.stringify((acts2 || []).map((a) => a.title)));
    if (a2) await vscode.workspace.applyEdit(a2.edit);
    check(M("BE006 Quick Fix appends ,readonly"), fdoc.lineAt(3).text.includes('type=bind,readonly"]'), fdoc.lineAt(3).text);
    await expectWait(M("read-only mount drops to a warning, no fix left"), () => {
      const G = api.getFindings().filter((f) => f.rel === "fix/.devcontainer/devcontainer.json");
      return G.length === 1 && G[0].severity === "warning" && !G[0].fix && /\(read-only\)/.test(G[0].label);
    });
    await fdoc.save();

    // Quick Fix from the panel's inline button (file not open).
    const topNow = await api.getTreeItems();
    const panelRow = topNow.find((t) => t.resourceUri && t.resourceUri.fsPath === P("panel/docker-compose.yml"));
    const prow = (await api.getTreeItems(panelRow.node))[0];
    check(M("panel row names the setting and the agent service, fixable"), prow.label === 'privileged: true runs the "agent" service privileged' && prow.contextValue === "finding.fixable", prow.label);
    const applied = await vscode.commands.executeCommand("boxEscape.applyFix", prow.node);
    const pdoc = await vscode.workspace.openTextDocument(P("panel/docker-compose.yml"));
    check(M("panel applyFix removes privileged"), applied === true && pdoc.getText() === "services:\n  agent:\n    image: ghcr.io/acme/claude-runner:1\n", pdoc.getText());
    const T2 = TOTAL - 2;
    await expectWait(M("panel row gone and badge updated"), () => !api.getFindings().some((f) => f.rel === "panel/docker-compose.yml") && api.getBadge() === T2);
    check(M("applying the same (now stale) node again is refused"), (await vscode.commands.executeCommand("boxEscape.applyFix", prow.node)) === false);
    await pdoc.save();

    // Live: unsaved edits are checked.
    const ldoc = await vscode.workspace.openTextDocument(P("live/.devcontainer.json"));
    await vscode.window.showTextDocument(ldoc);
    const we = new vscode.WorkspaceEdit();
    we.insert(ldoc.uri, new vscode.Position(1, 0), '  "runArgs": ["--pid=host"],\n');
    await vscode.workspace.applyEdit(we);
    await expectWait(M("unsaved edit is checked live"), () => api.getFindings().some((f) => f.rel === "live/.devcontainer.json" && f.rule === "BE003"));
    await vscode.commands.executeCommand("workbench.action.files.revert");
    await expectWait(M("revert removes the live finding"), () => !api.getFindings().some((f) => f.rel === "live/.devcontainer.json"));
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");

    // Disk changes to closed files: Rescan, and the focused-window poll (watchers may not fire here).
    fs.writeFileSync(P("gen/compose.yaml"), "services:\n  a:\n    image: x\n    privileged: true\n    pid: host\n");
    await vscode.commands.executeCommand("boxEscape.rescan");
    await expectWait(M("rescan picks up a disk change to a closed compose file"), () => api.getFindings().filter((f) => f.rel === "gen/compose.yaml").length === 2);
    await sleep(1100);
    fs.writeFileSync(P("gen/compose.yaml"), "services:\n  a:\n    image: x\n    privileged: true\n");
    await api.poll();
    await expectWait(M("poll fallback picks up the change back"), () => api.getFindings().filter((f) => f.rel === "gen/compose.yaml").length === 1);

    // A referenced Dockerfile changes on disk: the container becomes an agent container.
    await api.poll();
    await sleep(1100);
    fs.writeFileSync(P("dep/.devcontainer/Dockerfile"), "FROM node:20\nRUN npm install -g @anthropic-ai/claude-code\n");
    await api.poll();
    await expectWait(M("Dockerfile change re-checks the devcontainer (warning to error)"), async () => {
      await api.poll();
      return api.getFindings().some((f) => f.rel === "dep/.devcontainer/devcontainer.json" && f.severity === "error" && /Dockerfile installs/.test(f.agent || ""));
    }, 20000);

    // Settings apply live.
    await conf().update("rules", { BE003: "off", BE006: "hint" }, vscode.ConfigurationTarget.Global);
    const n003 = api.getFindings().filter((f) => f.rule === "BE003").length;
    await expectWait(M("rules: BE003 off removes BE003"), () => !api.getFindings().some((f) => f.rule === "BE003") && api.getFindings().length === T2 - n003, 15000);
    const d2 = vscode.languages.getDiagnostics(vscode.Uri.file(P(".devcontainer/devcontainer.json"))).filter((d) => d.code === "BE006");
    check(M("rules: BE006 severity hint applied"), d2.length === 2 && d2.every((d) => d.severity === vscode.DiagnosticSeverity.Hint), String(d2.length));
    await conf().update("rules", undefined, vscode.ConfigurationTarget.Global);
    await expectWait(M("rules reset restores the findings"), () => api.getFindings().length === T2);

    await conf().update("checkScripts", false, vscode.ConfigurationTarget.Global);
    await expectWait(M("checkScripts=false drops script findings"), () => !api.getFindings().some((f) => f.rel === "scripts/agent.sh") && api.getFindings().length === T2 - 3);
    await conf().update("checkScripts", undefined, vscode.ConfigurationTarget.Global);
    await expectWait(M("checkScripts reset"), () => api.getFindings().length === T2);

    // extraAgentPatterns: the gen service becomes an agent; privileged stays error, but a mount would change.
    fs.writeFileSync(P("gen/compose.yaml"), "services:\n  a:\n    image: acme/helperbot\n    volumes:\n      - ~/.ssh:/root/.ssh\n");
    await vscode.commands.executeCommand("boxEscape.rescan");
    await expectWait(M("gen: non-agent mount is a warning"), () => api.getFindings().some((f) => f.rel === "gen/compose.yaml" && f.severity === "warning"));
    await conf().update("extraAgentPatterns", ["helperbot"], vscode.ConfigurationTarget.Global);
    await expectWait(M("extraAgentPatterns (user setting) marks the agent"), () => api.getFindings().some((f) => f.rel === "gen/compose.yaml" && f.severity === "error"));
    await conf().update("extraAgentPatterns", undefined, vscode.ConfigurationTarget.Global);
    await expectWait(M("extraAgentPatterns reset"), () => api.getFindings().some((f) => f.rel === "gen/compose.yaml" && f.severity === "warning"));

    await conf().update("exclude", ["**/gen/**"], vscode.ConfigurationTarget.Global);
    await expectWait(M("exclude setting drops gen/compose.yaml"), () => !api.getFindings().some((f) => f.rel === "gen/compose.yaml") && api.getFindings().length === T2 - 1);
    check(M("mandatory excludes still apply with a custom exclude list"), !api.getFindings().some((f) => /node_modules/.test(f.rel)));
    await conf().update("exclude", undefined, vscode.ConfigurationTarget.Global);
    await expectWait(M("exclude reset"), () => api.getFindings().length === T2);

    await conf().update("maxFiles", 1, vscode.ConfigurationTarget.Global);
    await expectWait(M("maxFiles caps the workspace scan"), () => new Set(api.getFindings().map((f) => f.rel)).size <= 1);
    await conf().update("maxFiles", undefined, vscode.ConfigurationTarget.Global);
    await expectWait(M("maxFiles reset"), () => api.getFindings().length === T2);

    // Workspace-level settings: honoured when trusted, ignored when untrusted (only the user value counts).
    let wsWrite = true;
    try {
      await conf().update("exclude", ["**/gen/**"], vscode.ConfigurationTarget.Workspace);
    } catch (e) {
      wsWrite = String(e);
    }
    if (wsWrite === true) {
      if (trusted) await expectWait(M("workspace exclude honoured when trusted"), () => !api.getFindings().some((f) => f.rel === "gen/compose.yaml"));
      else {
        await sleep(1500);
        await vscode.commands.executeCommand("boxEscape.rescan");
        check(M("workspace exclude ignored when untrusted"), api.getFindings().some((f) => f.rel === "gen/compose.yaml"));
      }
      await conf().update("exclude", undefined, vscode.ConfigurationTarget.Workspace);
      await conf().update("extraAgentPatterns", ["helperbot"], vscode.ConfigurationTarget.Workspace);
      if (trusted) await expectWait(M("workspace extraAgentPatterns honoured when trusted"), () => api.getFindings().some((f) => f.rel === "gen/compose.yaml" && f.severity === "error"));
      else {
        await sleep(1500);
        await vscode.commands.executeCommand("boxEscape.rescan");
        check(M("workspace extraAgentPatterns ignored when untrusted"), api.getFindings().some((f) => f.rel === "gen/compose.yaml" && f.severity === "warning"));
      }
      await conf().update("extraAgentPatterns", undefined, vscode.ConfigurationTarget.Workspace);
      await expectWait(M("workspace settings reset"), () => api.getFindings().length === T2);
      // A repository must not switch the checker off or silence rules in Restricted Mode.
      await conf().update("enabled", false, vscode.ConfigurationTarget.Workspace);
      await conf().update("rules", { BE001: "off", BE002: "off", BE003: "off", BE004: "off", BE005: "off", BE006: "off", BE007: "off", BE008: "off", BE009: "off", BE010: "off", BE011: "off" }, vscode.ConfigurationTarget.Workspace);
      if (trusted) await expectWait(M("workspace enabled=false honoured when trusted"), () => api.getFindings().length === 0);
      else {
        await sleep(1500);
        await vscode.commands.executeCommand("boxEscape.rescan");
        check(M("workspace enabled/rules ignored when untrusted"), api.getFindings().length === T2, `${api.getFindings().length} vs ${T2}`);
      }
      await conf().update("enabled", undefined, vscode.ConfigurationTarget.Workspace);
      await conf().update("rules", undefined, vscode.ConfigurationTarget.Workspace);
      await expectWait(M("workspace enabled/rules reset"), () => api.getFindings().length === T2);
    } else check(M("workspace settings writable"), false, wsWrite);

    await conf().update("enabled", false, vscode.ConfigurationTarget.Global);
    await expectWait(M("enabled=false empties view, badge, diagnostics"), async () => api.getBadge() === 0 && (await api.getTreeItems()).length === 0 && count() === 0);
    await conf().update("enabled", undefined, vscode.ConfigurationTarget.Global);
    await expectWait(M("re-enabled restores the badge"), () => api.getBadge() === T2);

    const cmds = await vscode.commands.getCommands(true);
    for (const c of ["boxEscape.rescan", "boxEscape.applyFix", "boxEscape.openFinding", "boxEscape.focusView", "boxEscape.openSettings"]) check(M(`command ${c} registered`), cmds.includes(c));
    await vscode.commands.executeCommand("boxEscape.rescan");
    check(M("rescan keeps the same findings"), api.getFindings().length === T2);
  } catch (e) {
    check(M("unexpected exception"), false, String(e && e.stack ? e.stack : e));
  }

  await vscode.commands.executeCommand("workbench.action.files.saveAll");
  await vscode.commands.executeCommand("workbench.action.closeAllEditors");
  const passed = results.filter((r) => r.ok).length;
  const failed = results.length - passed;
  fs.writeFileSync(resultFile, JSON.stringify({ passed, failed, results }, null, 2));
  if (failed) throw new Error(`${failed} in-editor checks failed`);
}

module.exports = { run };
