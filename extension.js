"use strict";

// BoxEscape: finds dev container, Compose and agent docker run settings that reach the host.
// UI layer only: all analysis lives in core.js.

const vscode = require("vscode");
const fs = require("fs");
const path = require("path");
const core = require("./core");

const SOURCE = "BoxEscape";
const VIEW_ID = "boxEscape.view";
const CONTAINER_ID = "boxescape";
const FILE_GLOB = "**/{devcontainer.json,.devcontainer.json,*compose*.yml,*compose*.yaml,*.sh,*.bash}";
const MANDATORY_EXCLUDES = ["**/node_modules/**", "**/.git/**", "**/vendor/**", "**/venv/**", "**/.venv/**"];
const MAX_BYTES = 1024 * 1024;
const POLL_MS = 20000;
const SELECTOR = [{ scheme: "file", pattern: "**/*.{json,yml,yaml,sh,bash}" }];

let diagnostics;
let treeView;
let treeProvider;
let statusBar;
/** uri string -> { uri, rel, findings, version } (only files with findings) */
let results = new Map();
/** uri string -> { uri, folder, folderRel, rel, text, mtime } for the scanned candidate files */
let files = new Map();
/** uri strings of files read through the core's callbacks (Dockerfiles, referenced compose files) */
let deps = new Map();
let scanSeq = 0;
let fullScanTimer;
let analyzeTimer;
let pollTimer;
let polling = false;

// ---------------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------------

/**
 * A setting value. In an untrusted workspace only the user's own (global) value counts, never the
 * repository's: otherwise a repository could switch the checker off, silence rules or exclude
 * its own files in Restricted Mode.
 */
function setting(c, key) {
  if (vscode.workspace.isTrusted) return c.get(key);
  const info = c.inspect(key) || {};
  return info.globalValue !== undefined ? info.globalValue : info.defaultValue;
}

function readSettings() {
  const c = vscode.workspace.getConfiguration("boxEscape");
  let maxFiles = Number(setting(c, "maxFiles"));
  if (!Number.isFinite(maxFiles) || maxFiles < 1) maxFiles = 2000;
  const rawExclude = setting(c, "exclude");
  const userExclude = Array.isArray(rawExclude) ? rawExclude.filter((g) => typeof g === "string") : [];
  const excludes = [...new Set([...MANDATORY_EXCLUDES, ...userExclude])];
  const rawPatterns = setting(c, "extraAgentPatterns");
  return {
    enabled: setting(c, "enabled") !== false,
    overrides: core.resolveSeverities(setting(c, "rules")),
    agentPatterns: core.compileAgentPatterns(rawPatterns),
    checkScripts: setting(c, "checkScripts") !== false,
    maxFiles: Math.min(Math.floor(maxFiles), 100000),
    excludes,
    isExcluded: core.makeExcluder(excludes),
  };
}

/** findFiles exclude glob: brace-free patterns only; the rest is post-filtered. */
function findFilesExclude(s) {
  const simple = s.excludes.filter((g) => !/[{}]/.test(g));
  return simple.length ? `{${simple.join(",")}}` : null;
}

// ---------------------------------------------------------------------------------------------
// Workspace confinement
// ---------------------------------------------------------------------------------------------

function realpathOrNull(p) {
  try {
    return fs.realpathSync.native(p);
  } catch (_) {
    return null;
  }
}

function inside(root, real) {
  const r = path.relative(root, real);
  return !!r && !r.startsWith("..") && !path.isAbsolute(r);
}

/**
 * For a file Uri whose realpath lies inside a workspace folder (so a symlink can not lead
 * outside), return { folder, rel, folderRel }, else null.
 */
function confine(uri) {
  if (!(uri instanceof vscode.Uri) || uri.scheme !== "file") return null;
  const real = realpathOrNull(uri.fsPath);
  if (!real) return null;
  const folders = vscode.workspace.workspaceFolders || [];
  for (const folder of folders) {
    if (folder.uri.scheme !== "file") continue;
    const root = realpathOrNull(folder.uri.fsPath);
    if (!root || !inside(root, real)) continue;
    const shown = path.relative(folder.uri.fsPath, uri.fsPath);
    if (!shown || shown.startsWith("..") || path.isAbsolute(shown)) continue;
    const folderRel = shown.split(path.sep).join("/");
    return { folder, folderRel, rel: folders.length > 1 ? `${folder.name}/${folderRel}` : folderRel };
  }
  return null;
}

function openDoc(uri) {
  const key = uri.toString();
  return vscode.workspace.textDocuments.find((d) => d.uri.toString() === key);
}

function tabUris() {
  const out = [];
  for (const g of vscode.window.tabGroups.all) {
    for (const t of g.tabs) {
      if (t.input instanceof vscode.TabInputText && t.input.uri.scheme === "file") out.push(t.input.uri);
    }
  }
  return out;
}

/** Synchronous, confined read used by the core for Dockerfiles and referenced compose files. */
function makeReader(folder, s) {
  const root = realpathOrNull(folder.uri.fsPath);
  const resolve = (rel) => {
    if (!root || typeof rel !== "string" || !rel || rel.length > 1000 || path.isAbsolute(rel) || rel.split("/").includes("..")) return null;
    if (s.isExcluded(rel)) return null;
    const p = path.join(folder.uri.fsPath, ...rel.split("/"));
    const real = realpathOrNull(p);
    if (!real || !inside(root, real)) return null;
    return { p, uri: vscode.Uri.file(p) };
  };
  return {
    read(rel) {
      const r = resolve(rel);
      if (!r) return null;
      deps.set(r.uri.toString(), true);
      const d = openDoc(r.uri);
      if (d) return d.getText().length > MAX_BYTES ? null : d.getText();
      try {
        const st = fs.statSync(r.p);
        if (!st.isFile() || st.size > MAX_BYTES) return null;
        const text = fs.readFileSync(r.p, "utf8");
        return text.includes("\u0000") ? null : text;
      } catch (_) {
        return null;
      }
    },
    exists(rel) {
      const r = resolve(rel);
      if (!r) return false;
      try {
        return fs.statSync(r.p).isFile();
      } catch (_) {
        return false;
      }
    },
  };
}

async function readCapped(uri) {
  try {
    const st = await vscode.workspace.fs.stat(uri);
    if (st.size > MAX_BYTES || (st.type & vscode.FileType.File) === 0) return null;
    const buf = await vscode.workspace.fs.readFile(uri);
    const text = new TextDecoder("utf-8").decode(buf);
    if (text.includes("\u0000")) return null;
    return { text, mtime: st.mtime };
  } catch (_) {
    return null;
  }
}

/** Text of a confined workspace file: the open (possibly unsaved) document, or disk. */
async function textOf(uri) {
  const d = openDoc(uri);
  if (d) {
    const t = d.getText();
    let mtime;
    try {
      mtime = (await vscode.workspace.fs.stat(uri)).mtime;
    } catch (_) {
      mtime = undefined;
    }
    return t.length > MAX_BYTES ? null : { text: t, mtime };
  }
  return readCapped(uri);
}

function isCandidate(uri, s) {
  const kind = core.fileKind(uri.fsPath.split(path.sep).join("/"));
  if (!kind) return false;
  return kind !== "shell" || s.checkScripts;
}

// ---------------------------------------------------------------------------------------------
// Analysis: the whole set is re-analysed on every change (cross-file: devcontainer -> compose,
// Dockerfile), which is cheap for config files.
// ---------------------------------------------------------------------------------------------

function toSeverity(sev) {
  const S = vscode.DiagnosticSeverity;
  return sev === "error" ? S.Error : sev === "information" ? S.Information : sev === "hint" ? S.Hint : S.Warning;
}

function analyzeAll() {
  const s = readSettings();
  const next = new Map();
  deps = new Map();
  if (s.enabled) {
    const byFolder = new Map();
    for (const f of files.values()) {
      if (!byFolder.has(f.folder.uri.toString())) byFolder.set(f.folder.uri.toString(), { folder: f.folder, list: [] });
      byFolder.get(f.folder.uri.toString()).list.push(f);
    }
    const multi = (vscode.workspace.workspaceFolders || []).length > 1;
    for (const { folder, list } of byFolder.values()) {
      const reader = makeReader(folder, s);
      const out = core.analyzeWorkspace({
        files: list.map((f) => ({ rel: f.folderRel, text: f.text })),
        read: reader.read,
        exists: reader.exists,
        checkScripts: s.checkScripts,
        agentPatterns: s.agentPatterns,
      });
      for (const [folderRel, findings] of out) {
        if (!findings.length) continue;
        const uri = vscode.Uri.file(path.join(folder.uri.fsPath, ...folderRel.split("/")));
        const known = files.get(uri.toString());
        const info = known || confine(uri);
        if (!info) continue;
        const kept = [];
        for (const f of findings) {
          const sev = core.severityOf(f, s.overrides);
          if (sev === "off") continue;
          kept.push(Object.assign({}, f, { severity: sev }));
        }
        if (!kept.length) continue;
        const d = openDoc(uri);
        next.set(uri.toString(), { uri, rel: multi ? `${folder.name}/${folderRel}` : folderRel, findings: kept, version: d ? d.version : undefined });
      }
    }
  }
  results = next;
  diagnostics.clear();
  for (const fr of results.values()) {
    diagnostics.set(
      fr.uri,
      fr.findings.map((f) => {
        const d = new vscode.Diagnostic(new vscode.Range(f.line, f.character, f.endLine, f.endCharacter), f.message, toSeverity(f.severity));
        d.source = SOURCE;
        d.code = f.rule;
        return d;
      })
    );
  }
  refreshUi();
}

function scheduleAnalyze(ms) {
  clearTimeout(analyzeTimer);
  analyzeTimer = setTimeout(() => {
    try {
      analyzeAll();
    } catch (_) {
      /* never surface analysis errors */
    }
  }, ms);
}

/** Refresh one file's cached text (open document or disk), then re-analyse. */
async function updateUri(uri) {
  const s = readSettings();
  if (!s.enabled) return;
  const key = uri.toString();
  if (!isCandidate(uri, s)) {
    if (deps.has(key)) scheduleAnalyze(50);
    return;
  }
  const info = confine(uri);
  if (!info || s.isExcluded(info.folderRel)) {
    if (files.delete(key)) scheduleAnalyze(50);
    return;
  }
  if (!files.has(key)) {
    const inTab = tabUris().some((u) => u.toString() === key);
    if (!inTab && files.size >= s.maxFiles) return;
  }
  const t = await textOf(uri);
  if (t === null) files.delete(key);
  else files.set(key, Object.assign({ uri, text: t.text, mtime: t.mtime }, info));
  scheduleAnalyze(50);
}

async function fullScan() {
  const seq = ++scanSeq;
  const s = readSettings();
  vscode.commands.executeCommand("setContext", "boxEscape.enabled", s.enabled);
  if (!s.enabled) {
    files = new Map();
    results = new Map();
    diagnostics.clear();
    stopPolling();
    refreshUi();
    return;
  }
  const uris = await vscode.workspace.findFiles(FILE_GLOB, findFilesExclude(s), s.maxFiles);
  if (seq !== scanSeq) return;
  const seen = new Set(uris.map((u) => u.toString()));
  for (const u of tabUris()) {
    if (!seen.has(u.toString())) {
      uris.push(u);
      seen.add(u.toString());
    }
  }
  const next = new Map();
  for (const uri of uris) {
    if (!isCandidate(uri, s)) continue;
    const info = confine(uri);
    if (!info || s.isExcluded(info.folderRel)) continue;
    const t = await textOf(uri);
    if (seq !== scanSeq) return;
    if (t === null) continue;
    next.set(uri.toString(), Object.assign({ uri, text: t.text, mtime: t.mtime }, info));
  }
  files = next;
  analyzeAll();
  if (vscode.window.state.focused) startPolling();
}

function scheduleFullScan(ms) {
  clearTimeout(fullScanTimer);
  fullScanTimer = setTimeout(() => fullScan().catch(() => {}), ms);
}

// ---------------------------------------------------------------------------------------------
// Polling fallback: file watchers do not fire on every file system. While the window is
// focused, closed files from the last scan (and files they reference) are re-read when their
// mtime changes.
// ---------------------------------------------------------------------------------------------

const depMtimes = new Map();

async function pollOnce() {
  if (polling || !readSettings().enabled) return;
  polling = true;
  try {
    let changed = false;
    for (const [key, f] of [...files]) {
      if (openDoc(f.uri)) continue;
      let st;
      try {
        st = await vscode.workspace.fs.stat(f.uri);
      } catch (_) {
        files.delete(key);
        changed = true;
        continue;
      }
      if (st.mtime !== f.mtime) {
        const t = await readCapped(f.uri);
        if (t === null) files.delete(key);
        else files.set(key, Object.assign({}, f, { text: t.text, mtime: t.mtime }));
        changed = true;
      }
    }
    for (const key of [...deps.keys()]) {
      const uri = vscode.Uri.parse(key);
      let m = null;
      try {
        m = (await vscode.workspace.fs.stat(uri)).mtime;
      } catch (_) {
        m = -1;
      }
      if (depMtimes.has(key) && depMtimes.get(key) !== m) changed = true;
      depMtimes.set(key, m);
    }
    if (changed) analyzeAll();
  } finally {
    polling = false;
  }
}

function startPolling() {
  if (pollTimer || !readSettings().enabled) return;
  pollTimer = setInterval(() => {
    if (!vscode.window.state.focused) {
      stopPolling();
      return;
    }
    pollOnce().catch(() => {});
  }, POLL_MS);
}

function stopPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = undefined;
}

// ---------------------------------------------------------------------------------------------
// Tree view, badge and status bar
// ---------------------------------------------------------------------------------------------

function allFindings() {
  const out = [];
  for (const fr of results.values()) for (const f of fr.findings) out.push(Object.assign({ rel: fr.rel, uri: fr.uri }, f));
  return out;
}

function refreshUi() {
  const s = readSettings();
  vscode.commands.executeCommand("setContext", "boxEscape.enabled", s.enabled);
  const all = s.enabled ? allFindings() : [];
  const n = all.length;
  const errors = all.filter((f) => f.severity === "error").length;
  if (treeProvider) treeProvider.refresh();
  if (treeView) treeView.badge = n ? { value: n, tooltip: `${n} container escape finding${n === 1 ? "" : "s"}` } : undefined;
  if (statusBar) {
    if (!s.enabled) statusBar.hide();
    else {
      statusBar.text = `$(shield) BoxEscape: ${n}`;
      statusBar.tooltip = n ? `${n} container escape finding${n === 1 ? "" : "s"} (${errors} error${errors === 1 ? "" : "s"}). Click to open Container escape checks.` : "No container escape found. Click to open Container escape checks.";
      statusBar.show();
    }
  }
}

const ICONS = { error: ["error", "list.errorForeground"], warning: ["warning", "list.warningForeground"], information: ["info", "notificationsInfoIcon.foreground"], hint: ["lightbulb", "notificationsInfoIcon.foreground"] };

class EscapeTreeProvider {
  constructor() {
    this._emitter = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._emitter.event;
  }
  refresh() {
    this._emitter.fire();
  }
  dispose() {
    this._emitter.dispose();
  }
  getChildren(node) {
    if (!readSettings().enabled) return [];
    if (!node) return [...results.values()].sort((a, b) => a.rel.localeCompare(b.rel)).map((fr) => ({ type: "file", key: fr.uri.toString() }));
    if (node.type === "file") {
      const fr = results.get(node.key);
      return fr ? fr.findings.map((f) => ({ type: "finding", key: node.key, id: f.id })) : [];
    }
    return [];
  }
  getTreeItem(node) {
    const C = vscode.TreeItemCollapsibleState;
    const fr = results.get(node.key);
    if (!fr) return new vscode.TreeItem("(stale)", C.None);
    if (node.type === "file") {
      const item = new vscode.TreeItem(path.posix.basename(fr.rel), C.Expanded);
      const dir = path.posix.dirname(fr.rel);
      item.description = `${dir === "." ? "" : dir + "  "}${fr.findings.length}`;
      item.resourceUri = fr.uri;
      item.iconPath = vscode.ThemeIcon.File;
      item.tooltip = `${fr.rel}\n${fr.findings.length} finding${fr.findings.length === 1 ? "" : "s"}`;
      item.contextValue = "file";
      item.id = "file:" + node.key;
      return item;
    }
    const f = fr.findings.find((x) => x.id === node.id);
    if (!f) return new vscode.TreeItem("(stale)", C.None);
    const item = new vscode.TreeItem(f.label, C.None);
    item.description = `${f.rule} ${f.title}  :${f.line + 1}`;
    const [icon, color] = ICONS[f.severity] || ICONS.warning;
    item.iconPath = new vscode.ThemeIcon(icon, new vscode.ThemeColor(color));
    item.tooltip = `${f.rule} ${f.title}${f.agent ? " (AI agent container)" : ""}\n${fr.rel}:${f.line + 1}\n\n${f.message}${f.fix ? "\n\nQuick Fix: " + f.fix.title : ""}`;
    item.contextValue = f.fix ? "finding.fixable" : "finding";
    item.id = `finding:${node.key}:${f.id}`;
    item.command = { command: "boxEscape.openFinding", title: "Go to finding", arguments: [fr.uri, f.line, f.character] };
    return item;
  }
}

// ---------------------------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------------------------

/** Open a finding: only a live finding's file, realpath-confined to the workspace. */
async function openFindingCmd(uri, line, character) {
  const fr = uri instanceof vscode.Uri ? results.get(uri.toString()) : undefined;
  const n = Number(line);
  const ch = Number(character);
  const f = fr && Number.isInteger(n) ? fr.findings.find((x) => x.line === n) : undefined;
  if (!fr || !f || !confine(uri)) {
    vscode.window.showWarningMessage("BoxEscape: refusing to open something that is not a current finding inside the workspace.");
    return false;
  }
  const doc = await vscode.workspace.openTextDocument(fr.uri);
  const ed = await vscode.window.showTextDocument(doc, { preview: true });
  const pos = new vscode.Position(Math.min(n, doc.lineCount - 1), Number.isInteger(ch) && ch >= 0 ? ch : 0);
  ed.selection = new vscode.Selection(pos, pos);
  ed.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
  return true;
}

function findingForNode(node) {
  if (!node || typeof node !== "object" || node.type !== "finding" || typeof node.key !== "string" || typeof node.id !== "string") return null;
  const fr = results.get(node.key);
  if (!fr) return null;
  const f = fr.findings.find((x) => x.id === node.id);
  return f && f.fix ? { fr, f } : null;
}

/** The fix's edits as a WorkspaceEdit, or null when the document no longer has the expected text. */
function fixEdit(doc, f) {
  const edit = new vscode.WorkspaceEdit();
  for (const e of f.fix.edits) {
    const range = new vscode.Range(doc.positionAt(e.start), doc.positionAt(e.end));
    if (doc.getText(range) !== e.expect) return null;
    edit.replace(doc.uri, range, e.text);
  }
  return edit;
}

/** Apply the Quick Fix of a panel row, after checking the text is still what was analysed. */
async function applyFixCmd(node) {
  const hit = findingForNode(node);
  if (!hit || !confine(hit.fr.uri)) {
    vscode.window.showWarningMessage("BoxEscape: that finding is no longer current.");
    return false;
  }
  const { fr, f } = hit;
  const doc = await vscode.workspace.openTextDocument(fr.uri);
  const edit = fixEdit(doc, f);
  if (!edit) {
    await updateUri(fr.uri);
    vscode.window.showWarningMessage("BoxEscape: the file changed since it was checked; rescanned, try again.");
    return false;
  }
  const ok = await vscode.workspace.applyEdit(edit);
  if (ok) {
    const ed = await vscode.window.showTextDocument(doc, { preview: true });
    const pos = doc.positionAt(Math.min(...f.fix.edits.map((e) => e.start)));
    ed.selection = new vscode.Selection(pos, pos);
    ed.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
    await updateUri(fr.uri);
  }
  return ok;
}

// ---------------------------------------------------------------------------------------------
// Quick Fixes
// ---------------------------------------------------------------------------------------------

class FixProvider {
  provideCodeActions(doc, _range, context) {
    const fr = results.get(doc.uri.toString());
    if (!fr || (fr.version !== undefined && fr.version !== doc.version)) return [];
    const out = [];
    for (const diag of context.diagnostics) {
      if (diag.source !== SOURCE) continue;
      const f = fr.findings.find((x) => x.rule === diag.code && x.message === diag.message && x.line === diag.range.start.line && x.character === diag.range.start.character && x.endLine === diag.range.end.line && x.endCharacter === diag.range.end.character);
      if (!f || !f.fix) continue;
      const edit = fixEdit(doc, f);
      if (!edit) continue;
      const action = new vscode.CodeAction(`${f.fix.title} (${f.rule})`, vscode.CodeActionKind.QuickFix);
      action.diagnostics = [diag];
      action.isPreferred = true;
      action.edit = edit;
      out.push(action);
    }
    return out;
  }
}

// ---------------------------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------------------------

function activate(context) {
  diagnostics = vscode.languages.createDiagnosticCollection("boxescape");
  treeProvider = new EscapeTreeProvider();
  treeView = vscode.window.createTreeView(VIEW_ID, { treeDataProvider: treeProvider, showCollapseAll: true });
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusBar.command = "boxEscape.focusView";
  statusBar.name = "BoxEscape";

  const watcher = vscode.workspace.createFileSystemWatcher("**/*");
  const onDisk = (uri) => {
    if (uri.scheme !== "file") return;
    const key = uri.toString();
    if (files.has(key) || deps.has(key) || isCandidate(uri, readSettings())) {
      if (!openDoc(uri)) updateUri(uri).catch(() => {});
    }
  };
  const relevant = (uri) => uri.scheme === "file" && (files.has(uri.toString()) || deps.has(uri.toString()) || isCandidate(uri, readSettings()));
  const docTimers = new Map();
  const scheduleDoc = (uri, ms) => {
    const key = uri.toString();
    clearTimeout(docTimers.get(key));
    docTimers.set(key, setTimeout(() => {
      docTimers.delete(key);
      updateUri(uri).catch(() => {});
    }, ms));
  };

  context.subscriptions.push(
    diagnostics,
    treeProvider,
    treeView,
    statusBar,
    watcher,
    vscode.languages.registerCodeActionsProvider(SELECTOR, new FixProvider(), { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    vscode.commands.registerCommand("boxEscape.rescan", () => fullScan()),
    vscode.commands.registerCommand("boxEscape.openFinding", (uri, line, character) => openFindingCmd(uri, line, character)),
    vscode.commands.registerCommand("boxEscape.applyFix", (node) => applyFixCmd(node)),
    vscode.commands.registerCommand("boxEscape.focusView", () => vscode.commands.executeCommand(`workbench.view.extension.${CONTAINER_ID}`)),
    vscode.commands.registerCommand("boxEscape.openSettings", () => vscode.commands.executeCommand("workbench.action.openSettings", "boxEscape")),
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (relevant(e.document.uri)) scheduleDoc(e.document.uri, 250);
    }),
    vscode.workspace.onDidOpenTextDocument((d) => {
      if (relevant(d.uri)) scheduleDoc(d.uri, 50);
    }),
    vscode.workspace.onDidCloseTextDocument((d) => {
      if (relevant(d.uri)) scheduleDoc(d.uri, 100);
    }),
    vscode.workspace.onDidSaveTextDocument((d) => {
      if (relevant(d.uri)) scheduleDoc(d.uri, 50);
    }),
    watcher.onDidCreate(onDisk),
    watcher.onDidChange(onDisk),
    watcher.onDidDelete((uri) => {
      const key = uri.toString();
      if (files.delete(key) || deps.has(key)) scheduleAnalyze(50);
    }),
    vscode.window.onDidChangeWindowState((st) => {
      if (st.focused) {
        startPolling();
        pollOnce().catch(() => {});
      } else stopPolling();
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("boxEscape")) scheduleFullScan(50);
    }),
    vscode.workspace.onDidChangeWorkspaceFolders(() => scheduleFullScan(200)),
    vscode.workspace.onDidGrantWorkspaceTrust(() => scheduleFullScan(200)),
    { dispose: () => { clearTimeout(fullScanTimer); clearTimeout(analyzeTimer); stopPolling(); for (const t of docTimers.values()) clearTimeout(t); } }
  );

  refreshUi();
  const ready = fullScan().catch(() => {});

  // Small API used by the in-editor tests.
  return {
    ready: () => ready,
    rescan: () => fullScan(),
    poll: () => pollOnce(),
    getFindings: () => allFindings(),
    getTreeItems: async (node) => {
      const out = [];
      for (const child of treeProvider.getChildren(node)) out.push(Object.assign({ node: child }, treeProvider.getTreeItem(child)));
      return out;
    },
    getBadge: () => (treeView && treeView.badge ? treeView.badge.value : 0),
    getStatusText: () => (statusBar ? statusBar.text : ""),
  };
}

function deactivate() {}

module.exports = { activate, deactivate };
