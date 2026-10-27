"use strict";

// BoxEscape core: finds the settings that let a dev container, a Compose service or a
// `docker run` sandbox reach the host, with a stricter severity when the container runs an AI
// coding agent. Pure logic, no vscode import. Paths are workspace-relative POSIX paths; reading
// other files (Dockerfiles, referenced compose files) goes through callbacks supplied by the
// caller, which confines them to the workspace.
//
// Sources (read 2026-10-24):
// - Dev Container spec, devcontainer.json reference (containers.dev/implementors/json_reference):
//   runArgs, mounts (Docker --mount syntax), privileged, capAdd, securityOpt, remoteUser,
//   containerUser, workspaceMount, dockerComposeFile, service, lifecycle commands, ${localEnv:..}.
// - devcontainers/features docker-outside-of-docker: bind-mounts /var/run/docker.sock and sets
//   securityOpt label=disable; docker-in-docker runs the container privileged.
// - Docker docs: docker run --privileged ("not a securely sandboxed process", all capabilities,
//   seccomp and AppArmor off, all host devices), --pid host, --ipc host, seccomp=unconfined;
//   bind mounts are writable by default, `readonly` / `ro` makes them read-only; Docker Engine
//   security: only trusted users should control the daemon, a container can be started with the
//   host's / mounted.
// - Claude Code dev container docs (code.claude.com/docs/en/devcontainer): avoid mounting host
//   secrets such as ~/.ssh or cloud credential files; the reference container adds NET_ADMIN and
//   NET_RAW for init-firewall.sh, run from postStartCommand; --dangerously-skip-permissions is
//   rejected as root.
// - Codex agent approvals and security docs: inside a dev container, Docker is the isolation
//   boundary; a malicious project can exfiltrate anything available inside it.

const path = require("path");
const P = path.posix;

const SEVERITIES = ["error", "warning", "information", "hint", "off"];

const RULES = {
  BE001: { title: "Privileged container", severity: "error" },
  BE002: { title: "Host Docker socket shared", severity: "warning", agentSeverity: "error" },
  BE003: { title: "Host namespace shared", severity: "warning" },
  BE004: { title: "Dangerous capability added", severity: "error" },
  BE005: { title: "Confinement turned off", severity: "error" },
  BE006: { title: "Host credentials or system path mounted", severity: "warning", agentSeverity: "error" },
  BE007: { title: "Workspace parent mounted", severity: "warning" },
  BE008: { title: "SSH or GPG agent forwarded", severity: "warning", agentSeverity: "error" },
  BE009: { title: "Host device passed through", severity: "warning" },
  BE010: { title: "Agent firewall not effective", severity: "information" },
  BE011: { title: "Agent runs as root", severity: "warning" },
};
const RULE_IDS = Object.keys(RULES);

const MAX_DEPTH = 64;
const MAX_FINDINGS_PER_FILE = 500;

// =============================================================================================
// File kinds
// =============================================================================================

const COMPOSE_NAME_RE = /^(docker-)?compose([.\-_][^/\\]*)?\.ya?ml$/i;

function fileKind(rel) {
  const base = P.basename(String(rel || "").replace(/\\/g, "/"));
  if (base === "devcontainer.json" || base === ".devcontainer.json") return "devcontainer";
  if (COMPOSE_NAME_RE.test(base)) return "compose";
  if (/\.(sh|bash)$/i.test(base)) return "shell";
  return null;
}


// =============================================================================================
// JSONC parser with offsets (comments, trailing commas). Never throws.
// Nodes: { kind: "object", entries: [{ key, keyStart, keyEnd, value, start, end }], start, end }
//        { kind: "array", items: [node], start, end }
//        { kind: "string", value, start, end }   (start/end include the quotes)
//        { kind: "literal", value, start, end }  (true, false, null, numbers)
// =============================================================================================

function parseJsonc(text) {
  const s = String(text == null ? "" : text);
  const errors = [];
  let i = 0;
  let stop = false;
  function fail(msg) {
    if (errors.length < 20) errors.push({ message: msg, offset: i });
    stop = true;
  }
  function ws() {
    for (;;) {
      while (i < s.length && (s[i] === " " || s[i] === "\t" || s[i] === "\n" || s[i] === "\r" || s[i] === "﻿")) i++;
      if (s[i] === "/" && s[i + 1] === "/") {
        while (i < s.length && s[i] !== "\n") i++;
        continue;
      }
      if (s[i] === "/" && s[i + 1] === "*") {
        const e = s.indexOf("*/", i + 2);
        i = e < 0 ? s.length : e + 2;
        continue;
      }
      break;
    }
  }
  function str() {
    const start = i;
    i++;
    let out = "";
    while (i < s.length) {
      const c = s[i];
      if (c === "\\") {
        const n = s[i + 1];
        const map = { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", '"': '"', "\\": "\\", "/": "/" };
        if (n === "u" && /^[0-9a-fA-F]{4}$/.test(s.slice(i + 2, i + 6))) {
          out += String.fromCharCode(parseInt(s.slice(i + 2, i + 6), 16));
          i += 6;
          continue;
        }
        out += n in map ? map[n] : n || "";
        i += 2;
        continue;
      }
      if (c === '"') {
        i++;
        return { kind: "string", value: out, start, end: i };
      }
      if (c === "\n") break;
      out += c;
      i++;
    }
    fail("unterminated string");
    return { kind: "string", value: out, start, end: i };
  }
  function value(d) {
    ws();
    const start = i;
    if (d > MAX_DEPTH) {
      fail("nesting too deep");
      return { kind: "literal", value: null, start, end: i };
    }
    const c = s[i];
    if (c === "{") {
      const node = { kind: "object", entries: [], start, end: start };
      i++;
      while (!stop) {
        ws();
        if (i >= s.length) {
          fail("unterminated object");
          break;
        }
        if (s[i] === "}") {
          i++;
          break;
        }
        if (s[i] === ",") {
          i++;
          continue;
        }
        if (s[i] !== '"') {
          fail("expected a property name");
          break;
        }
        const k = str();
        ws();
        if (s[i] !== ":") {
          fail("expected ':'");
          break;
        }
        i++;
        const v = value(d + 1);
        node.entries.push({ key: k.value, keyStart: k.start, keyEnd: k.end, value: v, start: k.start, end: v.end });
        ws();
        if (s[i] === ",") i++;
        else if (s[i] !== "}") {
          fail("expected ',' or '}'");
          break;
        }
      }
      node.end = i;
      return node;
    }
    if (c === "[") {
      const node = { kind: "array", items: [], start, end: start };
      i++;
      while (!stop) {
        ws();
        if (i >= s.length) {
          fail("unterminated array");
          break;
        }
        if (s[i] === "]") {
          i++;
          break;
        }
        if (s[i] === ",") {
          i++;
          continue;
        }
        const before = i;
        node.items.push(value(d + 1));
        ws();
        if (i === before) {
          fail("unexpected character");
          break;
        }
        if (s[i] === ",") i++;
        else if (s[i] !== "]") {
          fail("expected ',' or ']'");
          break;
        }
      }
      node.end = i;
      return node;
    }
    if (c === '"') return str();
    const m = /^(true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(s.slice(i, i + 64));
    if (m) {
      i += m[0].length;
      const v = m[1] === "true" ? true : m[1] === "false" ? false : m[1] === "null" ? null : Number(m[1]);
      return { kind: "literal", value: v, start, end: i };
    }
    fail("unexpected character");
    return { kind: "literal", value: undefined, start, end: i };
  }
  let root = null;
  try {
    root = value(0);
    if (root && root.value === undefined && root.kind === "literal") root = null;
  } catch (e) {
    errors.push({ message: "parse failure: " + (e && e.message), offset: i });
    root = null;
  }
  return { root, errors };
}

function jprop(obj, key) {
  if (!obj || obj.kind !== "object") return null;
  let found = null;
  for (const e of obj.entries) if (e.key === key) found = e; // last one wins, like JSON.parse
  return found;
}

function jstr(node) {
  return node && node.kind === "string" ? node.value : null;
}

/** Strings of a string, an array of strings, or an object of those (lifecycle command forms). */
function commandTexts(node) {
  if (!node) return [];
  if (node.kind === "string") return [node.value];
  if (node.kind === "array") return [node.items.filter((n) => n.kind === "string").map((n) => n.value).join(" ")];
  if (node.kind === "object") {
    const out = [];
    for (const e of node.entries) out.push(...commandTexts(e.value));
    return out;
  }
  return [];
}

// =============================================================================================
// YAML (Compose) parser: shared with ProfileFit
// =============================================================================================
//
// Supports what Compose files use: block maps and sequences (incl. "- key: v" items), flow
// [..] / {..} (also over several lines), single / double quoted and plain scalars, block
// scalars (| and >, skipped), comments, anchors (&a), aliases (*a), merge keys (<<) and tags
// (!reset, !override). Never throws: problems are collected in `errors`.
//
// Nodes: { kind: "map", entries: [{ key, keyStart, keyEnd, value }], start, end }
//        { kind: "seq", items: [node], start, end, flow }
//        { kind: "scalar", value, quoted, start, end }
//        { kind: "alias", name, start, end }
//        { kind: "null", start, end }
// Every node may carry .tag and .anchor.

function parseYaml(text) {
  const src = String(text == null ? "" : text);
  const errors = [];
  const anchors = new Map();
  const L = [];
  let docs = 0;
  let pos = 0;
  let lineNo = 0;
  while (pos <= src.length) {
    let nl = src.indexOf("\n", pos);
    if (nl < 0) nl = src.length;
    let raw = src.slice(pos, nl);
    if (raw.endsWith("\r")) raw = raw.slice(0, -1);
    let indent = 0;
    while (indent < raw.length && raw[indent] === " ") indent++;
    const body = stripComment(raw.slice(indent));
    if (body.length) {
      if (indent === 0 && (body === "---" || body.startsWith("--- ") || body === "...")) {
        if (body === "...") break;
        docs++;
        if (docs > 1 && L.length) break;
        const rest = body.slice(3).trim();
        if (rest) L.push({ no: lineNo, indent: 4, start: pos + 4, text: rest });
      } else {
        L.push({ no: lineNo, indent, start: pos + indent, text: body });
      }
    }
    if (nl >= src.length) break;
    pos = nl + 1;
    lineNo++;
  }

  let idx = 0;
  let depth = 0;

  function err(msg, line) {
    if (errors.length < 50) errors.push({ message: msg, line });
  }

  function skipLinesBefore(offset) {
    while (idx < L.length && L[idx].start < offset) idx++;
  }

  function parseBlock(minIndent) {
    if (idx >= L.length || L[idx].indent < minIndent) return null;
    if (++depth > MAX_DEPTH) {
      depth--;
      err("nesting too deep", L[idx].no);
      const n = L[idx].indent;
      while (idx < L.length && L[idx].indent >= n) idx++;
      return null;
    }
    let out;
    const ln = L[idx];
    if (isSeqLine(ln.text)) out = parseSeq(ln.indent);
    else if (findKeyColon(ln.text) >= 0) out = parseMap(ln.indent);
    else out = inlineValue(ln.text, ln.start, ln.indent - 1, ln.no, true);
    depth--;
    return out;
  }

  function parseMap(n) {
    const node = { kind: "map", entries: [], start: L[idx].start, end: L[idx].start };
    while (idx < L.length) {
      const ln = L[idx];
      if (ln.indent < n) break;
      if (ln.indent > n) {
        err("unexpected indentation", ln.no);
        idx++;
        continue;
      }
      if (isSeqLine(ln.text)) break;
      const c = findKeyColon(ln.text);
      if (c < 0) {
        err("expected a key", ln.no);
        idx++;
        continue;
      }
      const rawKey = ln.text.slice(0, c).trimEnd();
      const keyStart = ln.start;
      const keyEnd = ln.start + rawKey.length;
      let rest = ln.text.slice(c + 1);
      const lead = rest.length - rest.replace(/^\s+/, "").length;
      rest = rest.trim();
      const value = inlineValue(rest, ln.start + c + 1 + lead, n, ln.no, true);
      node.entries.push({ key: unquote(rawKey), keyStart, keyEnd, value, line: ln.no });
      node.end = Math.max(node.end, value && value.end != null ? value.end : keyEnd);
    }
    return node;
  }

  function parseSeq(n) {
    const node = { kind: "seq", items: [], start: L[idx].start, end: L[idx].start, flow: false };
    while (idx < L.length) {
      const ln = L[idx];
      if (ln.indent !== n || !isSeqLine(ln.text)) {
        if (ln.indent > n) {
          err("unexpected indentation", ln.no);
          idx++;
          continue;
        }
        break;
      }
      const after = ln.text.slice(1);
      const rest = after.replace(/^\s+/, "");
      const col = n + 1 + (after.length - rest.length);
      const restStart = ln.start + 1 + (after.length - rest.length);
      let item;
      if (!rest.length) {
        idx++;
        item = idx < L.length && L[idx].indent > n ? parseBlock(n + 1) : { kind: "null", start: ln.start + 1, end: ln.start + 1 };
      } else if (isSeqLine(rest) || (findKeyColon(rest) >= 0 && !/^[[{]/.test(rest))) {
        L[idx] = { no: ln.no, indent: col, start: restStart, text: rest };
        item = parseBlock(col);
      } else {
        item = inlineValue(rest, restStart, n, ln.no, true);
      }
      if (!item) item = { kind: "null", start: restStart, end: restStart };
      node.items.push(item);
      node.end = Math.max(node.end, item.end != null ? item.end : restStart);
    }
    return node;
  }

  /**
   * Value text on a line (after "key:" or "- "), at absolute offset `at`. When `advance` is set
   * the current line is consumed here (and a block value below it parsed).
   */
  function inlineValue(textIn, at, parentIndent, no, advance) {
    let t = textIn;
    let off = at;
    let anchor;
    let tag;
    for (let guard = 0; guard < 4; guard++) {
      const m = /^([&!])([^\s,\[\]{}]*)\s*/.exec(t);
      if (!m) break;
      if (m[1] === "&") anchor = m[2];
      else tag = "!" + m[2];
      off += m[0].length;
      t = t.slice(m[0].length);
    }
    let node;
    if (!t.length) {
      if (advance) idx++;
      if (idx < L.length && L[idx].indent > parentIndent) node = parseBlock(parentIndent + 1);
      else if (idx < L.length && L[idx].indent === parentIndent && isSeqLine(L[idx].text) && advance) node = parseSeq(parentIndent);
      if (!node) node = { kind: "null", start: off, end: off };
    } else if (t[0] === "|" || t[0] === ">") {
      if (advance) idx++;
      while (idx < L.length && L[idx].indent > parentIndent) idx++;
      node = { kind: "scalar", value: "", quoted: false, block: true, start: off, end: off + t.length };
    } else if (t[0] === "[" || t[0] === "{") {
      const r = parseFlow(src, off, 0);
      node = r.node;
      if (advance) {
        idx++;
        skipLinesBefore(r.end);
      }
    } else if (t[0] === "*") {
      const m = /^\*([^\s,\[\]{}]+)/.exec(t);
      node = { kind: "alias", name: m ? m[1] : "", start: off, end: off + (m ? m[0].length : 1) };
      if (advance) idx++;
    } else if (t[0] === '"' || t[0] === "'") {
      const r = readQuoted(src, off);
      node = { kind: "scalar", value: r.value, quoted: true, start: off, end: r.end };
      if (advance) {
        idx++;
        skipLinesBefore(r.end);
      }
    } else {
      node = { kind: "scalar", value: t.trim(), quoted: false, start: off, end: off + t.trim().length };
      if (advance) {
        idx++;
        // Plain multi-line continuation.
        while (idx < L.length && L[idx].indent > parentIndent && !isSeqLine(L[idx].text) && findKeyColon(L[idx].text) < 0) {
          node.value += " " + L[idx].text.trim();
          node.end = L[idx].start + L[idx].text.length;
          idx++;
        }
      }
    }
    if (tag) node.tag = tag;
    if (anchor) {
      node.anchor = anchor;
      anchors.set(anchor, node);
    }
    return node;
  }

  function parseFlow(s, start, d) {
    let i = start;
    const ws = () => {
      for (;;) {
        while (i < s.length && /\s/.test(s[i])) i++;
        if (s[i] === "#" && (i === 0 || /\s/.test(s[i - 1]))) {
          while (i < s.length && s[i] !== "\n") i++;
          continue;
        }
        break;
      }
    };
    if (d > MAX_DEPTH) {
      err("flow nesting too deep");
      return { node: { kind: "null", start, end: s.length }, end: s.length };
    }
    function value(inMap) {
      ws();
      let tag;
      let anchor;
      for (let g = 0; g < 4; g++) {
        const m = /^([&!])([^\s,\[\]{}]*)\s*/.exec(s.slice(i, i + 200));
        if (!m) break;
        if (m[1] === "&") anchor = m[2];
        else tag = "!" + m[2];
        i += m[0].length;
      }
      let node;
      const c = s[i];
      if (c === "[" || c === "{") {
        const r = parseFlow(s, i, d + 1);
        node = r.node;
        i = r.end;
      } else if (c === '"' || c === "'") {
        const r = readQuoted(s, i);
        node = { kind: "scalar", value: r.value, quoted: true, start: i, end: r.end };
        i = r.end;
      } else if (c === "*") {
        const m = /^\*([^\s,\[\]{}]+)/.exec(s.slice(i, i + 200));
        node = { kind: "alias", name: m ? m[1] : "", start: i, end: i + (m ? m[0].length : 1) };
        i = node.end;
      } else {
        const b = i;
        while (i < s.length && !/[,\]\}\n]/.test(s[i]) && !(inMap && s[i] === ":" && /[\s,\]\}]/.test(s[i + 1] || " ")) && !(s[i] === "#" && /\s/.test(s[i - 1] || ""))) i++;
        const raw = s.slice(b, i).trimEnd();
        node = raw.length ? { kind: "scalar", value: raw, quoted: false, start: b, end: b + raw.length } : { kind: "null", start: b, end: b };
      }
      if (tag) node.tag = tag;
      if (anchor) {
        node.anchor = anchor;
        anchors.set(anchor, node);
      }
      return node;
    }
    if (s[i] === "[") {
      const node = { kind: "seq", items: [], start, end: start, flow: true };
      i++;
      for (let guard = 0; guard < 100000; guard++) {
        ws();
        if (i >= s.length) {
          err("unterminated [");
          break;
        }
        if (s[i] === "]") {
          i++;
          break;
        }
        if (s[i] === ",") {
          i++;
          continue;
        }
        const before = i;
        node.items.push(value(false));
        ws();
        if (i === before) i++;
      }
      node.end = i;
      return { node, end: i };
    }
    const node = { kind: "map", entries: [], start, end: start, flow: true };
    i++;
    for (let guard = 0; guard < 100000; guard++) {
      ws();
      if (i >= s.length) {
        err("unterminated {");
        break;
      }
      if (s[i] === "}") {
        i++;
        break;
      }
      if (s[i] === ",") {
        i++;
        continue;
      }
      const before = i;
      const k = value(true);
      ws();
      let v = { kind: "null", start: i, end: i };
      if (s[i] === ":") {
        i++;
        v = value(false);
        ws();
      }
      if (k.kind === "scalar") node.entries.push({ key: k.value, keyStart: k.start, keyEnd: k.end, value: v });
      if (i === before) i++;
    }
    node.end = i;
    return { node, end: i };
  }

  let root = null;
  try {
    root = parseBlock(0);
    while (idx < L.length) {
      err("content after the document root", L[idx].no);
      idx++;
    }
  } catch (e) {
    err("parse failure: " + (e && e.message));
    root = null;
  }
  return { root, errors, anchors };
}

function stripComment(s) {
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (c === "\\" && q === '"') i++;
      else if (c === q) {
        if (q === "'" && s[i + 1] === "'") i++;
        else q = null;
      }
      continue;
    }
    if ((c === '"' || c === "'") && (i === 0 || /[\s:\[{,\-]/.test(s[i - 1]))) q = c;
    else if (c === "#" && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i).trimEnd();
  }
  return s.trimEnd();
}

function isSeqLine(t) {
  return t === "-" || /^-[ \t]/.test(t);
}

/** Index of the ":" that ends a mapping key on this line, or -1. */
function findKeyColon(t) {
  if (!t.length) return -1;
  if (t[0] === '"' || t[0] === "'") {
    const r = readQuoted(t, 0);
    let i = r.end;
    while (t[i] === " ") i++;
    return t[i] === ":" && (i + 1 >= t.length || /\s/.test(t[i + 1])) ? i : -1;
  }
  if (/^[[{|>*&!%@`]/.test(t)) return -1;
  for (let i = 0; i < t.length; i++) {
    if (t[i] === ":" && (i + 1 >= t.length || /\s/.test(t[i + 1]))) return i;
  }
  return -1;
}

function readQuoted(s, start) {
  const q = s[start];
  let i = start + 1;
  let out = "";
  while (i < s.length) {
    const c = s[i];
    if (q === "'") {
      if (c === "'") {
        if (s[i + 1] === "'") {
          out += "'";
          i += 2;
          continue;
        }
        return { value: out, end: i + 1 };
      }
    } else {
      if (c === "\\") {
        const n = s[i + 1];
        const map = { n: "\n", t: "\t", r: "\r", '"': '"', "\\": "\\", "/": "/", "0": "\0", " ": " " };
        if (n === "u" && /^[0-9a-fA-F]{4}$/.test(s.slice(i + 2, i + 6))) {
          out += String.fromCharCode(parseInt(s.slice(i + 2, i + 6), 16));
          i += 6;
          continue;
        }
        out += n in map ? map[n] : n || "";
        i += 2;
        continue;
      }
      if (c === '"') return { value: out, end: i + 1 };
    }
    out += c === "\n" || c === "\r" ? " " : c;
    i++;
  }
  return { value: out, end: s.length };
}

function unquote(raw) {
  const t = String(raw).trim();
  if ((t[0] === '"' || t[0] === "'") && t.length >= 2) return readQuoted(t, 0).value;
  return t;
}

// ---------------------------------------------------------------------------------------------
// Node helpers (aliases, merge keys)
// ---------------------------------------------------------------------------------------------

function resolveNode(doc, node) {
  let n = node;
  for (let g = 0; g < 10 && n && n.kind === "alias"; g++) {
    const t = doc.anchors.get(n.name);
    const keep = n.tag;
    n = t || null;
    if (n && keep && !n.tag) n = Object.assign({}, n, { tag: keep });
  }
  return n && n.kind === "alias" ? null : n;
}

/** Own entries first, then entries pulled in by "<<" (marked viaMerge). Own keys win. */
function mapEntries(doc, node, d) {
  const m = resolveNode(doc, node);
  if (!m || m.kind !== "map") return [];
  const out = [];
  const seen = new Set();
  const merges = [];
  for (const e of m.entries) {
    if (e.key === "<<") {
      merges.push(e.value);
      continue;
    }
    if (seen.has(e.key)) continue;
    seen.add(e.key);
    out.push(e);
  }
  if ((d || 0) > 8) return out;
  for (const mv of merges) {
    const r = resolveNode(doc, mv);
    const srcs = r && r.kind === "seq" ? r.items : [mv];
    for (const s of srcs) {
      for (const e of mapEntries(doc, s, (d || 0) + 1)) {
        if (seen.has(e.key)) continue;
        seen.add(e.key);
        out.push(Object.assign({}, e, { viaMerge: true }));
      }
    }
  }
  return out;
}

function scalarOf(doc, node) {
  const n = resolveNode(doc, node);
  if (!n || n.kind !== "scalar" || n.block) return null;
  return n;
}

function isFalse(v) {
  return /^(false|False|FALSE|no|No|NO|off|Off|OFF)$/.test(String(v).trim());
}


function ymap(doc, node, key) {
  for (const e of mapEntries(doc, node)) if (e.key === key) return e;
  return null;
}

function yscalar(doc, node) {
  const n = scalarOf(doc, node);
  return n ? String(n.value) : null;
}

/** Scalars of a scalar or a sequence of scalars. */
function yitems(doc, node) {
  const n = resolveNode(doc, node);
  if (!n) return [];
  if (n.kind === "scalar") return n.block ? [] : [n];
  if (n.kind === "seq") return n.items.map((x) => scalarOf(doc, x)).filter(Boolean);
  return [];
}

function isTrue(v) {
  return /^(true|True|TRUE|yes|Yes|YES|on|On|ON)$/.test(String(v).trim());
}

// =============================================================================================
// Text helpers
// =============================================================================================

function lineStarts(text) {
  const out = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === "\n") out.push(i + 1);
  return out;
}

function posOf(starts, off) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= off) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo, character: off - starts[lo] };
}

function lineStartOf(text, off) {
  return text.lastIndexOf("\n", off - 1) + 1;
}

function nextLineStart(text, off) {
  const nl = text.indexOf("\n", off);
  return nl < 0 ? text.length : nl + 1;
}

function edit(text, start, end, repl) {
  return { start, end, expect: text.slice(start, end), text: repl };
}

/** Remove items i..j (inclusive) of a JSON array, or entries i..j of an object, keeping commas valid. */
function jsonRemove(text, list, i, j) {
  const first = list[i];
  const last = list[j];
  if (j + 1 < list.length) return edit(text, first.start, list[j + 1].start, "");
  if (i > 0) return edit(text, list[i - 1].end, last.end, "");
  // Only element(s): remove them and a trailing comma.
  let e = last.end;
  const m = /^\s*,/.exec(text.slice(e, e + 200));
  if (m) e += m[0].length;
  return edit(text, first.start, e, "");
}

/** Append text inside a JSON string node, before its closing quote. */
function jsonAppend(text, node, add) {
  return edit(text, node.end - 1, node.end, add + '"');
}

/** Remove a YAML block-map entry that fits on whole lines (key line through the value's last line). */
function yamlRemoveEntry(text, entry) {
  const start = lineStartOf(text, entry.keyStart);
  if (text.slice(start, entry.keyStart).trim() !== "") return null;
  const v = entry.value;
  const endOff = v && v.end != null ? v.end : entry.keyEnd;
  if (v && v.kind === "map" && v.flow !== true) return null;
  return edit(text, start, nextLineStart(text, Math.max(endOff - 1, entry.keyEnd)), "");
}

/** Remove item i of a YAML sequence (block "- x" line, or flow [a, b]). */
function yamlRemoveItem(text, seq, i) {
  const it = seq.items[i];
  if (!it) return null;
  if (seq.flow) {
    const list = seq.items;
    if (list.length === 1) return null;
    if (i + 1 < list.length) return edit(text, it.start, list[i + 1].start, "");
    return edit(text, list[i - 1].end, it.end, "");
  }
  if (it.kind !== "scalar" || it.block) return null;
  const ls = lineStartOf(text, it.start);
  if (!/^\s*-\s*$/.test(text.slice(ls, it.start))) return null;
  const le = text.indexOf("\n", it.end);
  const rest = text.slice(it.end, le < 0 ? text.length : le);
  if (!/^\s*(#.*)?\r?$/.test(rest)) return null;
  return edit(text, ls, le < 0 ? text.length : le + 1, "");
}

// =============================================================================================
// Agent detection
// =============================================================================================

const AGENT_INSTALL_RE = /@anthropic-ai\/claude-code|claude\.ai\/install\.(?:sh|ps1|cmd)|@openai\/codex\b|\baider-chat\b|\baider-install\b|@google\/gemini-cli|\bopencode-ai\b|opencode\.ai\/install|cursor\.com\/install|\bopenhands-ai\b/i;
const AGENT_RUN_RE = /(?:^|[\s;&|(`'"/])(claude|codex|aider|opencode|cursor-agent|openhands)(?=$|[\s;&|)`'"])/i;
const AGENT_FEATURE_RE = /(?:^|\/)(claude-code|codex|codex-cli|aider|gemini-cli|opencode)(?::|$)/i;
const AGENT_EXTENSIONS = new Set(["anthropic.claude-code", "openai.chatgpt", "saoudrizwan.claude-dev", "rooveterinaryinc.roo-cline", "kilocode.kilo-code"]);
const AGENT_ENV_RE = /^(CLAUDE_CODE_[A-Z0-9_]*|CLAUDE_CONFIG_DIR|CODEX_HOME|CODEX_SANDBOX[A-Z0-9_]*)$/;
const AGENT_NAME_WORDS = new Set(["claude", "codex", "aider", "opencode", "openhands", "cline"]);
const AGENT_QUALIFIERS = new Set(["ai", "coding", "llm", "sandbox", "swe", "cursor", "code"]);

/** s up to the first of chars (a loop: /[:@].*$/ was quadratic when s held a newline). */
function cutAt(s, chars) {
  for (let i = 0; i < s.length; i++) if (chars.includes(s[i])) return s.slice(0, i);
  return s;
}

function nameIsAgent(name) {
  const s = String(name || "").toLowerCase();
  if (!s) return false;
  const words = s.split(/[^a-z0-9]+/).filter(Boolean);
  if (words.some((w) => AGENT_NAME_WORDS.has(w))) return true;
  if (words.length === 1 && (words[0] === "agent" || words[0] === "agents")) return true;
  if (words.some((w) => w === "agent" || w === "agents") && words.some((w) => AGENT_QUALIFIERS.has(w))) return true;
  return false;
}

/** Compile user patterns: strings of at most 200 chars, at most 20, invalid ones dropped. */
function compileAgentPatterns(list) {
  const out = [];
  if (!Array.isArray(list)) return out;
  for (const p of list.slice(0, 20)) {
    if (typeof p !== "string" || !p.trim() || p.length > 200) continue;
    try {
      out.push(new RegExp(p, "i"));
    } catch (_) {
      /* invalid pattern: ignored */
    }
  }
  return out;
}

function extraMatch(patterns, text) {
  if (!patterns || !patterns.length || !text) return false;
  const t = String(text).slice(0, 4000);
  return patterns.some((re) => re.test(t));
}

function installReason(text) {
  const m = AGENT_INSTALL_RE.exec(String(text || ""));
  return m ? m[0] : null;
}

function runReason(text) {
  const m = AGENT_RUN_RE.exec(String(text || ""));
  return m ? m[1] : null;
}

// =============================================================================================
// Host paths
// =============================================================================================

const CRED_DIRS = [".ssh", ".aws", ".azure", ".config/gcloud", ".kube", ".docker", ".gnupg", ".config/gh", ".git-credentials", ".netrc", ".npmrc", ".pypirc", ".terraform.d", ".config/op", ".password-store", ".oci"];
const SYSTEM_PATHS = ["/etc", "/proc", "/sys", "/boot", "/dev", "/home", "/Users", "/var/lib/docker", "/lib/modules", "/usr", "/var/log"];
const SOCKET_RE = /(?:^|\/)(docker|podman|containerd|dockershim|crio)\.sock$|\/pipe\/docker_engine$/i;
const AGENT_SOCK_RE = /SSH_AUTH_SOCK|ssh-auth\.sock|\/ssh-[^/]+\/agent\.|S\.gpg-agent|gnupg\/S\./i;

/**
 * Normalise a host path from a mount source: home forms become "~", the workspace "@ws".
 * Returns null for a named volume or something unknown.
 */
function normHostPath(raw, baseDir) {
  let s = String(raw == null ? "" : raw).trim().replace(/^['"]|['"]$/g, "");
  // path.posix.normalize is quadratic on long "../" chains: no real host path is this long.
  if (!s || s.length > 4096) return null;
  s = s.replace(/\\/g, "/");
  s = s
    .replace(/^\$\{localEnv:(?:HOME|USERPROFILE)(?::[^}]*)?\}/i, "~")
    .replace(/^\$\{env:(?:HOME|USERPROFILE)\}/i, "~")
    .replace(/^\$\{HOME(?::?[-=][^}]*)?\}/, "~")
    .replace(/^\$HOME(?=\/|$)/, "~")
    .replace(/^%USERPROFILE%/i, "~")
    .replace(/^\$\{localWorkspaceFolder\}/, "@ws")
    .replace(/^\$\{PWD\}|^\$PWD(?=\/|$)|^\$\(pwd\)|^`pwd`/, "@ws")
    .replace(/^\/(?:home|Users)\/[^/$]+(?=\/|$)/, "~")
    .replace(/^[A-Za-z]:\/Users\/[^/]+(?=\/|$)/i, "~")
    .replace(/^\/root(?=\/|$)/, "~");
  if (/^~[^/]/.test(s)) return null; // ~otheruser
  if (s[0] === "." && baseDir != null) {
    // Compose: relative to the compose file's folder, workspace-relative result.
    const j = P.normalize(P.join(baseDir === "" ? "." : baseDir, s));
    return j === "." ? "@ws" : j.startsWith("..") ? "@ws/" + j : "@ws/" + j;
  }
  if (s[0] === ".") s = "@ws/" + s;
  if (!/^[~/@]/.test(s) && !/^[A-Za-z]:\//.test(s)) return null;
  if (s.startsWith("@ws")) {
    if (s.length > 3 && s[3] !== "/") return null;
    const r = P.normalize(s.slice(3).replace(/^\/+/, "") || ".");
    return r === "." ? "@ws" : "@ws/" + r.replace(/\/+$/, "");
  }
  s = s.replace(/\/{2,}/g, "/").replace(/\/\.(?=\/|$)/g, "");
  if (s.length > 1) s = s.replace(/\/+$/, "");
  return s;
}

/**
 * Classify a mount source. Returns { cat, shown } with cat one of socket, agentsock, cred,
 * home, root, system, parent, or null when harmless / unknown.
 */
function classifyHost(raw, baseDir) {
  const r = String(raw == null ? "" : raw);
  if (AGENT_SOCK_RE.test(r)) return { cat: "agentsock", shown: /gpg/i.test(r) ? "the GPG agent socket" : "the SSH agent socket" };
  const s = normHostPath(r, baseDir);
  if (s == null) return null;
  if (SOCKET_RE.test(s)) return { cat: "socket", shown: s };
  if (s === "/var/run" || s === "/run") return { cat: "socket", shown: s + " (with docker.sock)" };
  if (s === "/" || /^[A-Za-z]:\/?$/.test(s)) return { cat: "root", shown: "/" };
  if (s === "~") return { cat: "home", shown: "~ (home)" };
  if (s.startsWith("~/")) {
    const rest = s.slice(2);
    for (const d of CRED_DIRS) if (rest === d || rest.startsWith(d + "/")) return { cat: "cred", shown: "~/" + d };
    return null;
  }
  for (const p of SYSTEM_PATHS) if (s === p) return { cat: "system", shown: s };
  // Workspace parent: the workspace folder's ancestors only (not siblings).
  if (/^@ws(\/\.\.)+$/.test(s)) return { cat: "parent", shown: r.trim().replace(/^['"]|['"]$/g, "") };
  return null;
}

/** Split "src:dst:mode" (docker -v / compose short syntax), keeping ${a:b} and C:\ together. */
function splitVolume(spec) {
  const s = String(spec);
  const parts = [];
  let cur = "";
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "$" && s[i + 1] === "{") depth++;
    if (c === "}" && depth > 0) depth--;
    if (c === ":" && depth === 0 && !(i === 1 && /^[A-Za-z]$/.test(s[0]) && /[\\/]/.test(s[2] || ""))) {
      parts.push(cur);
      cur = "";
      continue;
    }
    cur += c;
  }
  parts.push(cur);
  return parts;
}

/** Parse a Docker --mount / devcontainer mount string. */
function parseMountSpec(spec) {
  const out = { type: null, source: null, target: null, readonly: false };
  for (const part of String(spec).split(",")) {
    const eq = part.indexOf("=");
    const k = (eq < 0 ? part : part.slice(0, eq)).trim().toLowerCase();
    const v = eq < 0 ? "" : part.slice(eq + 1).trim();
    if (k === "type") out.type = v.toLowerCase();
    else if (k === "source" || k === "src") out.source = v;
    else if (k === "target" || k === "destination" || k === "dst") out.target = v;
    else if ((k === "readonly" || k === "ro") && (eq < 0 || /^(true|1)$/i.test(v))) out.readonly = true;
  }
  return out;
}

function looksLikePath(s) {
  return /^[~/.$%\\]|^[A-Za-z]:[\\/]/.test(String(s || ""));
}

// =============================================================================================
// Docker CLI flags (runArgs and docker run in scripts)
// =============================================================================================

const LONG_VALUE = new Set(("add-host annotation attach blkio-weight blkio-weight-device cap-add cap-drop cgroup-parent cgroupns cidfile cpu-count cpu-percent cpu-period cpu-quota cpu-rt-period cpu-rt-runtime cpu-shares cpus cpuset-cpus cpuset-mems detach-keys device device-cgroup-rule device-read-bps device-read-iops device-write-bps device-write-iops dns dns-option dns-search domainname entrypoint env env-file expose gpus group-add health-cmd health-interval health-retries health-start-interval health-start-period health-timeout hostname io-maxbandwidth io-maxiops ip ip6 ipc isolation kernel-memory label label-file link link-local-ip log-driver log-opt mac-address memory memory-reservation memory-swap memory-swappiness mount name network net network-alias net-alias oom-score-adj pid pids-limit platform publish pull restart runtime security-opt shm-size stop-signal stop-timeout storage-opt sysctl tmpfs ulimit user userns uts volume volume-driver volumes-from workdir arch os variant secret hooks-dir pod requires uidmap gidmap subuidname subgidname").split(" "));
const SHORT_NAMES = { a: "attach", c: "cpu-shares", e: "env", h: "hostname", l: "label", m: "memory", p: "publish", u: "user", v: "volume", w: "workdir", d: "detach", i: "interactive", t: "tty", P: "publish-all", q: "quiet" };
const SHORT_VALUE = new Set(["a", "c", "e", "h", "l", "m", "p", "u", "v", "w"]);

/**
 * Interpret docker run flags. toks: [{ value, start, end, node? }]. Returns
 * { flags: [{ name, value, toks: [tok..], valueTok }], positional } where positional is the
 * index of the first non-flag token (the image), or -1.
 */
function interpretFlags(toks, stopAtPositional) {
  const flags = [];
  let positional = -1;
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    const v = String(t.value);
    if (v === "--") {
      positional = k + 1 < toks.length ? k + 1 : -1;
      break;
    }
    if (v.startsWith("--") && v.length > 2) {
      const eq = v.indexOf("=");
      const name = (eq < 0 ? v.slice(2) : v.slice(2, eq)).toLowerCase();
      if (eq >= 0) flags.push({ name, value: v.slice(eq + 1), toks: [t], valueTok: t, inline: true });
      else if (LONG_VALUE.has(name) && k + 1 < toks.length) {
        flags.push({ name, value: String(toks[k + 1].value), toks: [t, toks[k + 1]], valueTok: toks[k + 1] });
        k++;
      } else flags.push({ name, value: "true", toks: [t], valueTok: null });
      continue;
    }
    if (v.startsWith("-") && v.length > 1) {
      for (let c = 1; c < v.length; c++) {
        const ch = v[c];
        const name = SHORT_NAMES[ch] || ch;
        if (SHORT_VALUE.has(ch)) {
          let rest = v.slice(c + 1);
          if (rest.startsWith("=")) rest = rest.slice(1);
          if (rest) flags.push({ name, value: rest, toks: [t], valueTok: t, inline: true });
          else if (k + 1 < toks.length) {
            flags.push({ name, value: String(toks[k + 1].value), toks: [t, toks[k + 1]], valueTok: toks[k + 1] });
            k++;
          }
          break;
        }
        flags.push({ name, value: "true", toks: [t], valueTok: null, cluster: v.length > 2 });
      }
      continue;
    }
    if (stopAtPositional) {
      positional = k;
      break;
    }
  }
  return { flags, positional };
}

// =============================================================================================
// Shell: commands with word offsets
// =============================================================================================

/** Split a shell script into commands of words { value, start, end } (quotes removed). */
function shellCommands(text) {
  const s = String(text);
  const cmds = [];
  let cur = [];
  let i = 0;
  let pendingHeredocs = [];
  const flush = () => {
    if (cur.length) cmds.push(cur);
    cur = [];
  };
  let guard = 0;
  while (i < s.length && guard++ < 5000000) {
    const c = s[i];
    if (c === "\\" && s[i + 1] === "\n") {
      i += 2;
      continue;
    }
    if (c === "\\" && s[i + 1] === "\r" && s[i + 2] === "\n") {
      i += 3;
      continue;
    }
    if (c === " " || c === "\t" || c === "\r") {
      i++;
      continue;
    }
    if (c === "\n") {
      flush();
      i++;
      // Skip heredoc bodies.
      for (const h of pendingHeredocs) {
        for (;;) {
          if (i >= s.length) break;
          const nl = s.indexOf("\n", i);
          const line = s.slice(i, nl < 0 ? s.length : nl).replace(/\r$/, "");
          i = nl < 0 ? s.length : nl + 1;
          if ((h.strip ? line.replace(/^\t+/, "") : line) === h.word) break;
        }
      }
      pendingHeredocs = [];
      continue;
    }
    if (c === "#") {
      while (i < s.length && s[i] !== "\n") i++;
      continue;
    }
    if (c === ";" || c === "&" || c === "|" || c === "(" || c === ")" || c === "{" && /[\s]/.test(s[i + 1] || " ") || c === "}" && cur.length === 0) {
      flush();
      i++;
      continue;
    }
    if (c === "<" && s[i + 1] === "<" && s[i + 2] !== "<") {
      const m = /^<<(-?)\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/.exec(s.slice(i, i + 200));
      if (m) {
        pendingHeredocs.push({ word: m[3], strip: m[1] === "-" });
        i += m[0].length;
        continue;
      }
    }
    // A word.
    const start = i;
    let value = "";
    while (i < s.length) {
      const ch = s[i];
      if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r" || ch === ";" || ch === "&" || ch === "|" || ch === "(" || ch === ")" || ch === "<" || ch === ">") {
        if (ch === "(" && value.endsWith("$")) {
          // $( ... ) command substitution kept in the word
          let depth = 0;
          const b = i;
          while (i < s.length) {
            if (s[i] === "(") depth++;
            else if (s[i] === ")") {
              depth--;
              if (depth === 0) {
                i++;
                break;
              }
            } else if (s[i] === "\n" && depth > 20) break;
            i++;
          }
          value += s.slice(b, i);
          continue;
        }
        if (ch === "\\" ) break;
        break;
      }
      if (ch === "\\") {
        if (s[i + 1] === "\n") {
          i += 2;
          break;
        }
        value += s[i + 1] || "";
        i += 2;
        continue;
      }
      if (ch === "'") {
        const e = s.indexOf("'", i + 1);
        const end = e < 0 ? s.length : e;
        value += s.slice(i + 1, end);
        i = end + 1;
        continue;
      }
      if (ch === '"') {
        i++;
        while (i < s.length && s[i] !== '"') {
          if (s[i] === "\\" && i + 1 < s.length) {
            value += /["\\$`]/.test(s[i + 1]) ? s[i + 1] : s[i] + s[i + 1];
            i += 2;
            continue;
          }
          value += s[i];
          i++;
        }
        i++;
        continue;
      }
      if (ch === "`") {
        const e = s.indexOf("`", i + 1);
        const end = e < 0 ? s.length : e + 1;
        value += s.slice(i, end);
        i = end;
        continue;
      }
      if (ch === "$" && s[i + 1] === "{") {
        const e = s.indexOf("}", i);
        const end = e < 0 ? s.length : e + 1;
        value += s.slice(i, end);
        i = end;
        continue;
      }
      value += ch;
      i++;
    }
    if (i === start) {
      i++;
      continue;
    }
    cur.push({ value, start, end: Math.min(i, s.length), raw: s.slice(start, Math.min(i, s.length)) });
    if (cur.length > 2000) flush();
  }
  flush();
  return cmds;
}

const CMD_PREFIX_RE = /^(sudo|exec|command|nohup|time|env|doas|-\S*|[A-Za-z_][A-Za-z0-9_]*=.*)$/;

/** docker/podman run|create commands: { words, runIdx } (runIdx = index of the first flag). */
function dockerRuns(cmds) {
  const out = [];
  for (const words of cmds) {
    for (let k = 0; k < words.length && k < 12; k++) {
      const b = P.basename(words[k].value);
      if (b !== "docker" && b !== "podman" && b !== "nerdctl") {
        if (!CMD_PREFIX_RE.test(words[k].value)) break;
        continue;
      }
      let j = k + 1;
      // global flags like --context x / -H host
      while (j < words.length && /^-/.test(words[j].value)) j += /^(--context|-c|-H|--host|--config|--log-level|-l)$/.test(words[j].value) ? 2 : 1;
      if (words[j] && words[j].value === "container") j++;
      if (words[j] && (words[j].value === "run" || words[j].value === "create")) out.push({ words, runIdx: j + 1, tool: b });
      break;
    }
  }
  return out;
}

// =============================================================================================
// Findings
// =============================================================================================

function lowerSev(sev) {
  return sev === "error" ? "warning" : sev === "warning" ? "information" : "hint";
}

class FileCtx {
  constructor(rel, text) {
    this.rel = rel;
    this.text = text;
    this.starts = lineStarts(text);
    this.out = [];
    this.seen = new Set();
  }
  add(rule, start, end, severity, label, message, cont, fix) {
    if (this.out.length >= MAX_FINDINGS_PER_FILE) return;
    const key = `${rule}:${start}:${end}:${label}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    const a = posOf(this.starts, start);
    const b = posOf(this.starts, Math.max(start, end));
    this.out.push({
      id: `${rule}:${start}:${this.out.length}`,
      rule,
      title: RULES[rule].title,
      label,
      message,
      defaultSeverity: severity,
      container: cont ? cont.name : null,
      agent: cont ? cont.agent : null,
      start,
      end,
      line: a.line,
      character: a.character,
      endLine: b.line,
      endCharacter: b.character,
      fix: fix || null,
    });
  }
}

function agentNote(cont) {
  return cont.agent ? ` It runs an AI agent (${cont.agent}), so whatever the agent is talked into doing by a prompt injection, it can do there.` : "";
}

function sevFor(rule, cont) {
  const r = RULES[rule];
  return cont.agent && r.agentSeverity ? r.agentSeverity : r.severity;
}

// --- individual checks, shared by devcontainer / compose / docker run ---------------------

const PRIV_MSG = "Privileged mode turns on every Linux capability, turns off seccomp and AppArmor, and gives the container all host devices: Docker calls such a container \"not a securely sandboxed process\". Root in it can mount the host disk and leave the container.";

function checkPrivileged(fc, cont, setting, start, end, fix, extra) {
  fc.add("BE001", start, end, "error", `${setting} runs ${cont.label} privileged`, `${cont.Label} runs privileged (${setting}). ${PRIV_MSG}${extra || ""}${agentNote(cont)}`, cont, fix);
}

const CAP_ERRORS = {
  ALL: "every Linux capability, almost the same as --privileged",
  SYS_ADMIN: "mount, namespaces and most of root's powers: the classic container escape (mount the host disk, cgroup release_agent)",
  SYS_MODULE: "loading kernel modules into the host kernel",
  SYS_RAWIO: "raw I/O on host memory and devices",
  DAC_READ_SEARCH: "open_by_handle_at, which reads any file on the host file system (the Shocker escape)",
};
const CAP_WARNINGS = {
  NET_ADMIN: "changing network interfaces, routes and firewall rules, so code in the container can turn off an egress firewall",
  BPF: "loading eBPF programs into the host kernel",
  PERFMON: "kernel performance monitoring of host processes",
  SYS_TIME: "setting the host clock",
};

function normCap(v) {
  return String(v || "").trim().toUpperCase().replace(/^CAP_/, "");
}

function checkCap(fc, cont, setting, value, start, end, fix) {
  const cap = normCap(value);
  if (CAP_ERRORS[cap]) {
    fc.add("BE004", start, end, "error", `${setting}: ${cap} in ${cont.label}`, `${cont.Label} adds the ${cap} capability (${setting}), which allows ${CAP_ERRORS[cap]}.${agentNote(cont)}`, cont, fix);
  } else if (CAP_WARNINGS[cap]) {
    if (cap === "NET_ADMIN" && cont.firewall) return; // the documented reason: the agent firewall needs it
    fc.add("BE004", start, end, "warning", `${setting}: ${cap} in ${cont.label}`, `${cont.Label} adds the ${cap} capability (${setting}), which allows ${CAP_WARNINGS[cap]}.${cap === "NET_ADMIN" ? " If it is for an egress firewall script, run that script from postStartCommand so it is in place before the agent starts." : ""}${agentNote(cont)}`, cont, fix);
  }
}

function checkSecOpt(fc, cont, setting, value, start, end, fix) {
  const v = String(value || "").trim().toLowerCase().replace(/\s+/g, "");
  const m = /^(seccomp|apparmor|systempaths|label)[=:](.*)$/.exec(v);
  if (!m) return;
  if ((m[1] === "seccomp" || m[1] === "apparmor" || m[1] === "systempaths") && m[2] === "unconfined") {
    const what = m[1] === "seccomp" ? "the seccomp filter that blocks dangerous system calls (mount, kexec, bpf, keyctl ...)" : m[1] === "apparmor" ? "the AppArmor profile that blocks writes to /proc and /sys and mounts" : "the masking of sensitive /proc and /sys paths";
    fc.add("BE005", start, end, "error", `${setting}: ${String(value).trim()} in ${cont.label}`, `${cont.Label} turns off ${what} (${setting} ${value}). That is one of the layers that keeps a root process from reaching the host kernel.${agentNote(cont)}`, cont, fix);
  } else if (m[1] === "label" && m[2] === "disable") {
    fc.add("BE005", start, end, "warning", `${setting}: ${String(value).trim()} in ${cont.label}`, `${cont.Label} turns off SELinux labelling (${setting} ${value}), so on SELinux hosts the container is no longer kept away from host files it can see through mounts.${agentNote(cont)}`, cont, fix);
  }
}

const NS_TEXT = {
  network: "the host network: it reaches every service bound to the host's localhost (databases, the Docker API on tcp, cloud metadata proxies), and an egress firewall set up inside the container edits the host's rules or is bypassed",
  pid: "the host PID namespace: it sees every host process, can signal them and read their command lines and environment through /proc",
  ipc: "the host IPC namespace: shared memory and message queues of host processes",
  userns: "the host user namespace, turning off user namespace remapping: root in the container is root on the host",
  cgroupns: "the host cgroup namespace",
};

function checkNamespace(fc, cont, setting, kind, value, start, end, fix) {
  if (String(value || "").trim().toLowerCase() !== "host") return;
  fc.add("BE003", start, end, "warning", `${setting}: host ${kind === "userns" ? "user namespace" : kind === "cgroupns" ? "cgroup namespace" : kind === "pid" || kind === "ipc" ? kind.toUpperCase() : kind} shared with ${cont.label}`, `${cont.Label} shares ${NS_TEXT[kind]} (${setting}).${agentNote(cont)}`, cont, fix);
}

const SAFE_DEVICE_RE = /^\/dev\/(dri(\/.*)?|nvidia[^/]*|snd(\/.*)?|fuse|net\/tun|kvm|video\d*|ttyUSB\d*|ttyACM\d*|bus\/usb(\/.*)?|hidraw\d*|vhost-net|vhost-vsock|null|zero|urandom|random)$/;

function checkDevice(fc, cont, setting, value, start, end) {
  const src = splitVolume(String(value || "").trim())[0];
  if (!src || SAFE_DEVICE_RE.test(src)) return;
  if (!src.startsWith("/dev")) return;
  fc.add("BE009", start, end, "warning", `${setting}: ${src} into ${cont.label}`, `${cont.Label} gets the host device ${src} (${setting}). By default a container can read, write and mknod a device it is given; a disk or memory device is the host's data.${agentNote(cont)}`, cont, null);
}

function checkDeviceRule(fc, cont, setting, value, start, end) {
  if (!/^\s*a\b|\*:\*\s*r?w?m?/.test(String(value || ""))) return;
  fc.add("BE009", start, end, "warning", `${setting}: "${value}" in ${cont.label}`, `${cont.Label} may create and use any host device (${setting} "${value}").${agentNote(cont)}`, cont, null);
}

function isRootUser(v) {
  return /^(root|0)(:(root|0))?$/.test(String(v || "").trim());
}

function checkRoot(fc, cont, setting, value, start, end) {
  if (!cont.agent || !isRootUser(value)) return;
  fc.add("BE011", start, end, "warning", `${setting}: ${value} for the agent in ${cont.label}`, `The AI agent in ${cont.label} runs as root (${setting}: ${value}). Claude Code refuses --dangerously-skip-permissions as root, and with root every other weakness here (capabilities, mounts, the Docker socket) is fully usable. Use a non-root user, as the reference agent containers do.`, cont, null);
}

/**
 * A mount. m: { src, readonly, setting, start, end, baseDir, readonlyFix, removeFix }.
 */
function checkMount(fc, cont, m) {
  const c = classifyHost(m.src, m.baseDir);
  if (!c) return;
  const rw = m.readonly ? "read-only" : "writable";
  if (c.cat === "socket") {
    fc.add("BE002", m.start, m.end, sevFor("BE002", cont), `${m.setting}: ${c.shown} into ${cont.label}`, `${cont.Label} gets the host's container engine socket (${m.src}). Whoever can talk to it can start a privileged container with the host's / mounted, so this is root on the host${m.readonly ? " (a read-only mount does not help: the socket still accepts connections)" : ""}. Docker: only trusted users should control the daemon.${agentNote(cont)}`, cont, m.removeFix || null);
    return;
  }
  if (c.cat === "agentsock") {
    fc.add("BE008", m.start, m.end, sevFor("BE008", cont), `${m.setting}: ${c.shown} into ${cont.label}`, `${cont.Label} gets ${c.shown} (${m.src}). Anything in the container can then use your loaded keys to push to every repository and log in to every server they open, for as long as it runs.${agentNote(cont)}`, cont, m.removeFix || null);
    return;
  }
  if (c.cat === "parent") {
    fc.add("BE007", m.start, m.end, "warning", `${m.setting}: ${c.shown} into ${cont.label}`, `${cont.Label} mounts the folder above the workspace (${m.src}, ${rw}), so it sees every sibling project and file there, not only this repository.${agentNote(cont)}`, cont, null);
    return;
  }
  let sev = sevFor("BE006", cont);
  if (m.readonly) sev = lowerSev(sev);
  const what = c.cat === "cred" ? `your ${c.shown} credentials` : c.cat === "home" ? "your whole home directory (SSH keys, cloud credentials, shell startup files)" : c.cat === "root" ? "the host's root file system" : `the host path ${c.shown}`;
  const how = m.readonly ? " It is read-only, so files can not be changed, but every secret in it can still be read and sent out." : c.cat === "cred" ? " It is writable too." : " It is writable, so code in the container can change host files (a line in ~/.bashrc or /etc runs on the host next time).";
  const fix = !m.readonly && m.readonlyFix ? m.readonlyFix : null;
  fc.add("BE006", m.start, m.end, sev, `${m.setting}: ${c.shown}${m.readonly ? " (read-only)" : ""} into ${cont.label}`, `${cont.Label} mounts ${what} from the host (${m.src}).${how} Claude Code's dev container docs: avoid mounting host secrets such as ~/.ssh or cloud credential files; prefer repository-scoped or short-lived tokens.${agentNote(cont)}`, cont, fix);
}

/** Apply the docker CLI flag checks (runArgs or a docker run line). */
function checkDockerFlags(fc, cont, flags, settingOf, fixes) {
  for (const f of flags) {
    const vt = f.valueTok || f.toks[0];
    const setting = settingOf(f);
    const s0 = f.toks[0].start;
    const e1 = f.toks[f.toks.length - 1].end;
    const remove = f.cluster ? null : fixes.remove(f);
    switch (f.name) {
      case "privileged":
        if (!/^(false|0)$/i.test(f.value)) checkPrivileged(fc, cont, setting, s0, e1, remove ? Object.assign({ title: "Remove --privileged" }, remove) : null);
        break;
      case "use-api-socket":
        if (!/^(false|0)$/i.test(f.value)) fc.add("BE002", s0, e1, sevFor("BE002", cont), `${setting} gives ${cont.label} the Docker API`, `${cont.Label} gets the Docker API socket (--use-api-socket). Whoever can talk to it can start a privileged container with the host's / mounted, so this is root on the host.${agentNote(cont)}`, cont, null);
        break;
      case "cap-add":
        checkCap(fc, cont, setting, f.value, vt.start, vt.end, remove ? Object.assign({ title: `Remove ${normCap(f.value)} from the added capabilities` }, remove) : null);
        break;
      case "security-opt":
        checkSecOpt(fc, cont, setting, f.value, vt.start, vt.end, remove ? Object.assign({ title: `Remove ${f.value}` }, remove) : null);
        break;
      case "network":
      case "net":
        checkNamespace(fc, cont, setting, "network", f.value, s0, e1, null);
        break;
      case "pid":
      case "ipc":
      case "userns":
      case "cgroupns":
        checkNamespace(fc, cont, setting, f.name, f.value, s0, e1, null);
        break;
      case "device":
        checkDevice(fc, cont, setting, f.value, vt.start, vt.end);
        break;
      case "device-cgroup-rule":
        checkDeviceRule(fc, cont, setting, f.value, vt.start, vt.end);
        break;
      case "user":
        checkRoot(fc, cont, setting, f.value, vt.start, vt.end);
        break;
      case "volume": {
        const parts = splitVolume(f.value);
        if (parts.length < 2 || !looksLikePath(parts[0])) break;
        const mode = parts.length > 2 ? parts[parts.length - 1] : "";
        const ro = /(^|,)(ro|readonly)(,|$)/.test(mode);
        let roFix = null;
        if (!ro && !/(^|,)rw(,|$)/.test(mode) && fixes.append) {
          const ap = fixes.append(vt, parts.length > 2 ? ",ro" : ":ro");
          if (ap) roFix = Object.assign({ title: "Make the mount read-only" }, ap);
        }
        checkMount(fc, cont, { src: parts[0], readonly: ro, setting, start: vt.start, end: vt.end, baseDir: null, readonlyFix: roFix, removeFix: remove ? Object.assign({ title: "Remove the mount" }, remove) : null });
        break;
      }
      case "mount": {
        const m = parseMountSpec(f.value);
        if (!m.source || (m.type && m.type !== "bind") || (!m.type && !looksLikePath(m.source))) break;
        const ap = !m.readonly && fixes.append ? fixes.append(vt, ",readonly") : null;
        checkMount(fc, cont, { src: m.source, readonly: m.readonly, setting, start: vt.start, end: vt.end, baseDir: null, readonlyFix: ap ? Object.assign({ title: "Make the mount read-only (,readonly)" }, ap) : null, removeFix: remove ? Object.assign({ title: "Remove the mount" }, remove) : null });
        break;
      }
      default:
        break;
    }
  }
}

// =============================================================================================
// devcontainer.json
// =============================================================================================

const LIFECYCLE = ["onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"];
/**
 * The firewall script a command runs (like the old /[\w.\-/]*firewall[\w.\-]*\.sh/i match), or null.
 * Linear time: the unanchored regex backtracked quadratically on long word runs.
 */
function firewallScript(text) {
  const s = String(text || "");
  const tokRe = /[\w.\-/]+/g;
  let m;
  while ((m = tokRe.exec(s))) {
    const tok = m[0];
    const low = tok.toLowerCase();
    if (!low.includes("firewall")) continue;
    // The last "/"-free segment with "firewall" followed by ".sh" (the greedy regex's choice).
    let end = tok.length;
    while (end > 0) {
      const segStart = low.lastIndexOf("/", end - 1) + 1;
      const seg = low.slice(segStart, end);
      const j = seg.lastIndexOf(".sh");
      const i = seg.indexOf("firewall");
      if (i >= 0 && j >= i + 8) return tok.slice(0, segStart + j + 3);
      end = segStart - 1;
    }
  }
  return null;
}

/** True when a Dockerfile ENTRYPOINT/CMD line satisfies test(rest of line). Line by line, linear. */
function dfEntrypointHas(dfText, test) {
  if (!dfText) return false;
  for (const line of String(dfText).split(/\r\n|[\n\r\u2028\u2029]/)) {
    const m = /^\s*(?:ENTRYPOINT|CMD)\b/i.exec(line);
    if (m && test(line.slice(m[0].length))) return true;
  }
  return false;
}

function safeJoin(dir, rel) {
  if (typeof rel !== "string" || !rel || rel.length > 500 || P.isAbsolute(rel) || /^[A-Za-z]:/.test(rel)) return null;
  const j = P.normalize(P.join(dir || ".", rel.replace(/\\/g, "/")));
  if (j.startsWith("..") || j === "." ) return null;
  return j;
}

function dockerfileAgent(text) {
  if (!text) return null;
  const inst = installReason(text);
  if (inst) return `Dockerfile installs ${inst}`;
  return null;
}

function analyzeDevcontainer(ws, rel, text) {
  const fc = new FileCtx(rel, text);
  const doc = parseJsonc(text);
  const root = doc.root;
  if (!root || root.kind !== "object") return fc.out;
  const dir = P.dirname(rel) === "." ? "" : P.dirname(rel);
  const g = (k) => jprop(root, k);
  const nameE = g("name");
  const name = jstr(nameE && nameE.value);

  // Agent detection.
  const lifecycle = [];
  for (const k of LIFECYCLE) {
    const e = g(k);
    if (e) for (const t of commandTexts(e.value)) lifecycle.push({ key: k, text: t, entry: e });
  }
  const featuresE = g("features");
  const features = featuresE && featuresE.value.kind === "object" ? featuresE.value.entries : [];
  let dockerfileRel = null;
  const buildE = g("build");
  const dfNode = buildE && buildE.value.kind === "object" ? jprop(buildE.value, "dockerfile") : null;
  const legacyDf = g("dockerFile");
  const df = jstr(dfNode && dfNode.value) || jstr(legacyDf && legacyDf.value);
  if (df) dockerfileRel = safeJoin(dir, df);
  const dfText = dockerfileRel ? ws.read(dockerfileRel) : null;

  let agent = null;
  if (name && nameIsAgent(name)) agent = `name "${name}"`;
  if (!agent) for (const f of features) if (AGENT_FEATURE_RE.test(f.key)) agent = `feature ${cutAt(f.key.replace(/^.*\//, ""), ":")}`;
  if (!agent) {
    const cust = g("customizations");
    const vs = cust && cust.value.kind === "object" ? jprop(cust.value, "vscode") : null;
    const ex = vs && vs.value.kind === "object" ? jprop(vs.value, "extensions") : null;
    if (ex && ex.value.kind === "array") for (const n of ex.value.items) if (n.kind === "string" && AGENT_EXTENSIONS.has(n.value.toLowerCase())) agent = `extension ${n.value}`;
  }
  if (!agent) {
    for (const l of lifecycle) {
      const r = installReason(l.text);
      if (r) {
        agent = `${l.key} installs ${r}`;
        break;
      }
      const run = runReason(l.text);
      if (run) {
        agent = `${l.key} runs ${run}`;
        break;
      }
    }
  }
  if (!agent) {
    const env = g("containerEnv") || g("remoteEnv");
    if (env && env.value.kind === "object") for (const e of env.value.entries) if (AGENT_ENV_RE.test(e.key)) agent = `containerEnv ${e.key}`;
  }
  if (!agent) agent = dockerfileAgent(dfText);
  if (!agent && ws.patterns.length) {
    const hay = [name, ...features.map((f) => f.key), ...lifecycle.map((l) => l.text), dfText || ""].join("\n");
    if (extraMatch(ws.patterns, hay)) agent = "matches boxEscape.extraAgentPatterns";
  }

  // Firewall script run at start?
  const fwRuns = lifecycle.filter((l) => firewallScript(l.text) !== null);
  const dfEntrypointFw = dfEntrypointHas(dfText, (rest) => firewallScript(rest) !== null);
  const cont = {
    name: name || "dev container",
    label: name ? `the "${name}" container` : "the dev container",
    Label: name ? `The "${name}" container` : "The dev container",
    agent,
    firewall: fwRuns.length > 0 || !!dfEntrypointFw,
  };

  // privileged
  const priv = g("privileged");
  if (priv && priv.value.kind === "literal" && priv.value.value === true) {
    checkPrivileged(fc, cont, "privileged: true", priv.keyStart, priv.value.end, Object.assign({ title: 'Remove "privileged": true' }, { edits: [jsonRemove(text, root.entries, root.entries.indexOf(priv), root.entries.indexOf(priv))] }));
  }
  // features
  features.forEach((f, idx) => {
    const id = f.key.toLowerCase();
    if (/(^|\/)docker-in-docker(:|$)/.test(id)) {
      checkPrivileged(fc, cont, "features: docker-in-docker", f.keyStart, f.keyEnd, null, " The docker-in-docker Feature needs it to run its own Docker daemon.");
    } else if (/(^|\/)docker-(outside-of|from)-docker(:|$)/.test(id)) {
      fc.add("BE002", f.keyStart, f.keyEnd, sevFor("BE002", cont), `features: docker-outside-of-docker shares the host Docker socket with ${cont.label}`, `${cont.Label} uses the docker-outside-of-docker Feature, which bind-mounts the host's /var/run/docker.sock (and sets label=disable). Whoever can talk to the socket can start a privileged container with the host's / mounted, so this is root on the host.${agentNote(cont)}`, cont, { title: "Remove the docker-outside-of-docker Feature", edits: [jsonRemove(text, featuresE.value.entries, idx, idx)] });
    }
  });
  // capAdd
  const capE = g("capAdd");
  if (capE && capE.value.kind === "array") {
    capE.value.items.forEach((n, idx) => {
      if (n.kind !== "string") return;
      checkCap(fc, cont, "capAdd", n.value, n.start, n.end, { title: `Remove ${normCap(n.value)} from capAdd`, edits: [jsonRemove(text, capE.value.items, idx, idx)] });
    });
  }
  // securityOpt
  const secE = g("securityOpt");
  if (secE && secE.value.kind === "array") {
    secE.value.items.forEach((n, idx) => {
      if (n.kind !== "string") return;
      checkSecOpt(fc, cont, "securityOpt", n.value, n.start, n.end, { title: `Remove ${n.value} from securityOpt`, edits: [jsonRemove(text, secE.value.items, idx, idx)] });
    });
  }
  // runArgs
  const runE = g("runArgs");
  if (runE && runE.value.kind === "array") {
    const items = runE.value.items;
    const toks = items.filter((n) => n.kind === "string").map((n) => ({ value: n.value, start: n.start, end: n.end, node: n }));
    const { flags } = interpretFlags(toks, false);
    checkDockerFlags(fc, cont, flags, (f) => `runArgs ${flagText(f)}`, {
      remove: (f) => {
        const i0 = items.indexOf(f.toks[0].node);
        const i1 = items.indexOf(f.toks[f.toks.length - 1].node);
        return i0 < 0 || i1 < 0 ? null : { edits: [jsonRemove(text, items, i0, i1)] };
      },
      append: (tok, add) => ({ edits: [jsonAppend(text, tok.node, add)] }),
    });
  }
  // mounts
  const mountsE = g("mounts");
  if (mountsE && mountsE.value.kind === "array") {
    const items = mountsE.value.items;
    items.forEach((n, idx) => {
      const removeFix = { title: "Remove the mount", edits: [jsonRemove(text, items, idx, idx)] };
      if (n.kind === "string") {
        const m = parseMountSpec(n.value);
        if (!m.source || (m.type && m.type !== "bind") || (!m.type && !looksLikePath(m.source))) return;
        checkMount(fc, cont, { src: m.source, readonly: m.readonly, setting: "mounts", start: n.start, end: n.end, baseDir: null, readonlyFix: { title: "Make the mount read-only (,readonly)", edits: [jsonAppend(text, n, ",readonly")] }, removeFix });
      } else if (n.kind === "object") {
        const src = jstr((jprop(n, "source") || {}).value);
        const type = jstr((jprop(n, "type") || {}).value);
        const roE = jprop(n, "readonly") || jprop(n, "readOnly");
        if (!src || (type && type !== "bind") || (!type && !looksLikePath(src))) return;
        checkMount(fc, cont, { src, readonly: !!(roE && roE.value.value === true), setting: "mounts", start: n.start, end: n.end, baseDir: null, readonlyFix: null, removeFix });
      }
    });
  }
  // workspaceMount
  const wmE = g("workspaceMount");
  if (wmE && wmE.value.kind === "string") {
    const m = parseMountSpec(wmE.value.value);
    if (m.source && (!m.type || m.type === "bind")) checkMount(fc, cont, { src: m.source, readonly: m.readonly, setting: "workspaceMount", start: wmE.value.start, end: wmE.value.end, baseDir: null, readonlyFix: null, removeFix: null });
  }
  // users
  for (const k of ["remoteUser", "containerUser"]) {
    const e = g(k);
    if (e && e.value.kind === "string") checkRoot(fc, cont, k, e.value.value, e.value.start, e.value.end);
  }
  // Firewall (agent containers).
  checkFirewall(fc, ws, cont, { dir, lifecycle, fwRuns, dfText, dockerfileRel, root, text, capE, runE, priv });

  // Compose: hand agent status to the service.
  const dcf = g("dockerComposeFile");
  const svc = jstr((g("service") || {}).value);
  if (dcf && svc) {
    const files = dcf.value.kind === "string" ? [dcf.value.value] : dcf.value.kind === "array" ? dcf.value.items.filter((n) => n.kind === "string").map((n) => n.value) : [];
    for (const f of files) {
      const r = safeJoin(dir, f);
      if (!r) continue;
      if (!ws.composeRefs.has(r)) ws.composeRefs.set(r, []);
      ws.composeRefs.get(r).push({ service: svc, agent: agent ? `${agent} in ${rel}` : null, firewall: cont.firewall });
    }
  }
  return fc.out;
}

/** The flag as written, without its value: "--cap-add", "-v". */
function flagText(f) {
  const v = String(f.toks[0].value);
  if (v.startsWith("--")) return v.split("=")[0];
  return f.valueTok ? v.slice(0, 2) : v;
}

function shortArg(a) {
  return a.length > 70 ? a.slice(0, 67) + "..." : a;
}

function grantsNetAdmin(capE, runE, priv) {
  if (priv && priv.value.kind === "literal" && priv.value.value === true) return true;
  if (capE && capE.value.kind === "array" && capE.value.items.some((n) => n.kind === "string" && /^(NET_ADMIN|ALL)$/.test(normCap(n.value)))) return true;
  if (runE && runE.value.kind === "array") {
    const toks = runE.value.items.filter((n) => n.kind === "string").map((n) => ({ value: n.value, start: n.start, end: n.end }));
    for (const f of interpretFlags(toks, false).flags) {
      if (f.name === "cap-add" && /^(NET_ADMIN|ALL)$/.test(normCap(f.value))) return true;
      if (f.name === "privileged" && !/^(false|0)$/i.test(f.value)) return true;
    }
  }
  return false;
}

function checkFirewall(fc, ws, cont, c) {
  const { dir, lifecycle, fwRuns, dfText, dockerfileRel, root, text, capE, runE, priv } = c;
  const dfDir = dockerfileRel ? (P.dirname(dockerfileRel) === "." ? "" : P.dirname(dockerfileRel)) : dir;
  const exists = (base) => ws.exists(dir ? `${dir}/${base}` : base) || ws.exists(dfDir ? `${dfDir}/${base}` : base) || ws.shellBasenames.has(base);
  for (const l of fwRuns) {
    const m = [firewallScript(l.text)];
    const base = P.basename(m[0]);
    const v = l.entry.value;
    const s = v.start;
    const e = v.end;
    if (!exists(base)) {
      fc.add("BE010", s, e, "information", `${l.key}: ${base} is not in the repository`, `${l.key} runs ${m[0]}, but no ${base} was found next to devcontainer.json, next to the Dockerfile or anywhere else in the workspace. If the image does not bring it, the egress firewall never comes up and ${cont.label} has open network access.${agentNote(cont)}`, cont, null);
      continue;
    }
    const after = l.text.slice(m.index);
    if (/\|\|\s*(true|:|exit\s+0|echo\b)/.test(after) || /;\s*(true|exit\s+0)\s*$/.test(after)) {
      fc.add("BE010", s, e, "information", `${l.key}: ${base} failure is ignored`, `${l.key} runs ${base} but ignores its failure (${after.trim().slice(0, 80)}). If the firewall can not be set up, ${cont.label} starts with open network access and nobody notices.${agentNote(cont)}`, cont, null);
      continue;
    }
    if (!grantsNetAdmin(capE, runE, priv)) {
      fc.add("BE010", s, e, "information", `${l.key}: ${base} without NET_ADMIN`, `${l.key} runs ${base}, but ${cont.label} does not get the NET_ADMIN capability that iptables needs (the Claude Code reference container adds --cap-add=NET_ADMIN and --cap-add=NET_RAW in runArgs), so the firewall script fails.`, cont, null);
    }
  }
  if (!cont.agent || fwRuns.length) return;
  // A firewall script next to devcontainer.json that nothing runs.
  const local = [...ws.allRels].filter((r) => (P.dirname(r) === (dir || ".")) && /firewall[\w.\-]*\.sh$/i.test(P.basename(r)));
  if (!local.length) return;
  const base = P.basename(local[0]);
  if (dfText && dfText.includes(base) && dfEntrypointHas(dfText, (rest) => rest.includes(base))) return;
  const anchor = jprop(root, "postStartCommand") || jprop(root, "name") || root.entries[0];
  if (!anchor) return;
  void lifecycle;
  void text;
  fc.add("BE010", anchor.keyStart, anchor.keyEnd, "information", `${base} is never run in ${cont.label}`, `${base} is in ${dir || "the workspace root"}, but no lifecycle command (postStartCommand in the reference container) runs it, so ${cont.label} has open network access.${agentNote(cont)}`, cont, null);
}

// =============================================================================================
// Docker Compose
// =============================================================================================

function analyzeCompose(ws, rel, text) {
  const fc = new FileCtx(rel, text);
  const doc = parseYaml(text);
  const root = resolveNode(doc, doc.root);
  if (!root || root.kind !== "map") return fc.out;
  const servicesE = ymap(doc, root, "services");
  if (!servicesE) return fc.out;
  const dir = P.dirname(rel) === "." ? "" : P.dirname(rel);
  const refs = ws.composeRefs.get(rel) || [];
  for (const se of mapEntries(doc, servicesE.value)) {
    const svc = resolveNode(doc, se.value);
    if (!svc || svc.kind !== "map") continue;
    const sname = se.key;
    const get = (k) => ymap(doc, svc, k);
    const ref = refs.find((r) => r.service === sname);
    const image = yscalar(doc, (get("image") || {}).value);
    const cname = yscalar(doc, (get("container_name") || {}).value);
    const cmdText = ["command", "entrypoint"].map((k) => yitems(doc, (get(k) || {}).value).map((n) => n.value).join(" ")).join(" ");
    let envKeys = [];
    const envE = get("environment");
    if (envE) {
      const en = resolveNode(doc, envE.value);
      if (en && en.kind === "map") envKeys = mapEntries(doc, en).map((e) => e.key);
      else envKeys = yitems(doc, envE.value).map((n) => String(n.value).split("=")[0]);
    }
    // Build Dockerfile.
    let dfText = null;
    const b = get("build");
    if (b) {
      const bn = resolveNode(doc, b.value);
      let ctx = null;
      let dfn = "Dockerfile";
      if (bn && bn.kind === "scalar") ctx = bn.value;
      else if (bn && bn.kind === "map") {
        ctx = yscalar(doc, (ymap(doc, bn, "context") || {}).value) || ".";
        dfn = yscalar(doc, (ymap(doc, bn, "dockerfile") || {}).value) || "Dockerfile";
      }
      if (ctx && !/^[a-z]+:\/\//i.test(ctx)) {
        const c = safeJoin(dir, ctx) || (ctx === "." ? dir : null);
        const r = c !== null ? safeJoin(c === "" ? "." : c, dfn) : null;
        if (r) dfText = ws.read(r);
      }
    }
    let agent = ref && ref.agent ? ref.agent : null;
    if (!agent && nameIsAgent(sname)) agent = `service name "${sname}"`;
    if (!agent && cname && nameIsAgent(cname)) agent = `container_name "${cname}"`;
    if (!agent && image && nameIsAgent(cutAt(image.replace(/^.*\//, ""), ":@"))) agent = `image ${image}`;
    if (!agent) {
      const r = installReason(cmdText) || runReason(cmdText);
      if (r) agent = `command runs ${r}`;
    }
    if (!agent) {
      const k = envKeys.find((x) => AGENT_ENV_RE.test(x));
      if (k) agent = `environment ${k}`;
    }
    if (!agent) agent = dockerfileAgent(dfText);
    if (!agent && ws.patterns.length && extraMatch(ws.patterns, [sname, cname, image, cmdText, dfText || ""].join("\n"))) agent = "matches boxEscape.extraAgentPatterns";
    const cont = {
      name: sname,
      label: `the "${sname}" service`,
      Label: `The "${sname}" service`,
      agent,
      firewall: (ref && ref.firewall) || firewallScript(cmdText) !== null || dfEntrypointHas(dfText, (rest) => firewallScript(rest) !== null),
    };

    const priv = get("privileged");
    if (priv && isTrue(yscalar(doc, priv.value) || "")) {
      const ed = priv.viaMerge ? null : yamlRemoveEntry(text, priv);
      checkPrivileged(fc, cont, "privileged: true", priv.keyStart, priv.value.end, ed ? { title: "Remove privileged: true", edits: [ed] } : null);
    }
    const capE = get("cap_add");
    if (capE) {
      const seq = resolveNode(doc, capE.value);
      const items = yitems(doc, capE.value);
      items.forEach((n, idx) => {
        let ed = null;
        if (!capE.viaMerge && seq && seq.kind === "seq" && seq.items[idx] === n) ed = seq.items.length === 1 && !seq.flow ? yamlRemoveEntry(text, capE) : yamlRemoveItem(text, seq, idx);
        checkCap(fc, cont, "cap_add", n.value, n.start, n.end, ed ? { title: `Remove ${normCap(n.value)} from cap_add`, edits: [ed] } : null);
      });
    }
    const secE = get("security_opt");
    if (secE) {
      const seq = resolveNode(doc, secE.value);
      yitems(doc, secE.value).forEach((n, idx) => {
        let ed = null;
        if (!secE.viaMerge && seq && seq.kind === "seq" && seq.items[idx] === n) ed = seq.items.length === 1 && !seq.flow ? yamlRemoveEntry(text, secE) : yamlRemoveItem(text, seq, idx);
        checkSecOpt(fc, cont, "security_opt", n.value, n.start, n.end, ed ? { title: `Remove ${n.value} from security_opt`, edits: [ed] } : null);
      });
    }
    for (const [key, kind] of [["network_mode", "network"], ["pid", "pid"], ["ipc", "ipc"], ["userns_mode", "userns"], ["cgroup", "cgroupns"]]) {
      const e = get(key);
      const v = e && scalarOf(doc, e.value);
      if (v) checkNamespace(fc, cont, key, kind, v.value, e.keyStart, v.end, null);
    }
    const devE = get("devices");
    if (devE) {
      const dn = resolveNode(doc, devE.value);
      if (dn && dn.kind === "seq") {
        for (const it of dn.items) {
          const r = resolveNode(doc, it);
          if (r && r.kind === "scalar") checkDevice(fc, cont, "devices", r.value, r.start, r.end);
          else if (r && r.kind === "map") {
            const src = scalarOf(doc, (ymap(doc, r, "source") || {}).value);
            if (src) checkDevice(fc, cont, "devices", src.value, src.start, src.end);
          }
        }
      }
    }
    const dcr = get("device_cgroup_rules");
    if (dcr) for (const n of yitems(doc, dcr.value)) checkDeviceRule(fc, cont, "device_cgroup_rules", n.value, n.start, n.end);
    const userE = get("user");
    const uv = userE && scalarOf(doc, userE.value);
    if (uv) checkRoot(fc, cont, "user", uv.value, uv.start, uv.end);
    const volE = get("volumes");
    if (volE) {
      const vn = resolveNode(doc, volE.value);
      if (vn && vn.kind === "seq") {
        vn.items.forEach((it, idx) => {
          const r = resolveNode(doc, it);
          const canRemove = !volE.viaMerge && r === it && vn.items.length > 1;
          const removeEd = canRemove ? yamlRemoveItem(text, vn, idx) : null;
          const removeFix = removeEd ? { title: "Remove the volume", edits: [removeEd] } : null;
          if (r && r.kind === "scalar" && !r.block) {
            const parts = splitVolume(r.value);
            if (parts.length < 2 || !looksLikePath(parts[0])) return;
            const mode = parts.length > 2 ? parts[parts.length - 1] : "";
            const ro = /(^|,)(ro|readonly)(,|$)/.test(mode);
            let roFix = null;
            if (!ro && !/(^|,)rw(,|$)/.test(mode) && r === it) {
              const add = parts.length > 2 ? ",ro" : ":ro";
              const ed = r.quoted ? edit(text, r.end - 1, r.end, add + text[r.end - 1]) : edit(text, r.end, r.end, add);
              roFix = { title: "Make the volume read-only (:ro)", edits: [ed] };
            }
            checkMount(fc, cont, { src: parts[0], readonly: ro, setting: "volumes", start: r.start, end: r.end, baseDir: dir, readonlyFix: roFix, removeFix });
          } else if (r && r.kind === "map") {
            const type = yscalar(doc, (ymap(doc, r, "type") || {}).value);
            const src = scalarOf(doc, (ymap(doc, r, "source") || {}).value);
            const roV = yscalar(doc, (ymap(doc, r, "read_only") || {}).value);
            if (!src || (type && type !== "bind")) return;
            if (!type && !looksLikePath(src.value)) return;
            checkMount(fc, cont, { src: src.value, readonly: roV != null && isTrue(roV), setting: "volumes", start: src.start, end: src.end, baseDir: dir, readonlyFix: null, removeFix: null });
          }
        });
      }
    }
  }
  return fc.out;
}

// =============================================================================================
// Shell scripts: docker run lines that launch an agent CLI
// =============================================================================================

function analyzeShell(ws, rel, text) {
  const fc = new FileCtx(rel, text);
  if (!/\b(docker|podman|nerdctl)\b/.test(text)) return fc.out;
  for (const run of dockerRuns(shellCommands(text))) {
    const toks = run.words.slice(run.runIdx);
    const { flags, positional } = interpretFlags(toks, true);
    if (positional < 0) continue;
    const image = toks[positional].value;
    const rest = toks.slice(positional + 1).map((t) => P.basename(t.value)).join(" ");
    const nameF = flags.find((f) => f.name === "name");
    const entry = flags.find((f) => f.name === "entrypoint");
    let agent = null;
    const cmdRun = runReason(" " + rest + " ") || (entry ? runReason(" " + P.basename(entry.value) + " ") : null) || (/(^|\s)gemini(\s|$)/.test(rest) ? "gemini" : null);
    if (cmdRun) agent = `runs ${cmdRun}`;
    else if (nameIsAgent(cutAt(image.replace(/^.*\//, ""), ":@"))) agent = `image ${image}`;
    else if (nameF && nameIsAgent(nameF.value)) agent = `--name ${nameF.value}`;
    else {
      const envF = flags.find((f) => f.name === "env" && AGENT_ENV_RE.test(String(f.value).split("=")[0]));
      if (envF) agent = `-e ${String(envF.value).split("=")[0]}`;
    }
    if (!agent && extraMatch(ws.patterns, [image, rest, nameF ? nameF.value : ""].join(" "))) agent = "matches boxEscape.extraAgentPatterns";
    if (!agent) continue; // only agent sandboxes are checked in scripts
    const shown = image.length > 60 ? image.slice(0, 57) + "..." : image;
    const cont = { name: image, label: `the ${shown} container`, Label: `The ${shown} container`, agent, firewall: /firewall/i.test(rest) };
    checkDockerFlags(fc, cont, flags, (f) => `${run.tool} run ${flagText(f)}`, {
      remove: (f) => {
        const first = f.toks[0];
        const last = f.toks[f.toks.length - 1];
        let s = first.start;
        while (s > 0 && (text[s - 1] === " " || text[s - 1] === "\t")) s--;
        if (s === first.start) return null;
        return { edits: [edit(text, s, last.end, "")] };
      },
      append: (tok, add) => {
        const raw = text.slice(tok.start, tok.end);
        const q = raw[raw.length - 1];
        if ((q === '"' || q === "'") && raw.length > 1) return { edits: [edit(text, tok.end - 1, tok.end, add + q)] };
        if (/[\\$`]$/.test(raw)) return null;
        return { edits: [edit(text, tok.end, tok.end, add)] };
      },
    });
  }
  return fc.out;
}

// =============================================================================================
// Workspace
// =============================================================================================

/**
 * opts: {
 *   files: [{ rel, text }]  candidate files (devcontainer.json, compose files, shell scripts),
 *   read(rel) -> string|null  read another workspace file (Dockerfiles, referenced compose files),
 *   exists(rel) -> boolean,
 *   checkScripts: boolean (default true),
 *   agentPatterns: [RegExp] (from compileAgentPatterns),
 *   allRels: [rel]  every scanned path (optional; used to find firewall scripts)
 * }
 * Returns Map rel -> findings.
 */
function analyzeWorkspace(opts) {
  const o = opts || {};
  const files = Array.isArray(o.files) ? o.files : [];
  const byRel = new Map(files.map((f) => [f.rel, f.text]));
  const ws = {
    read: (rel) => {
      if (byRel.has(rel)) return byRel.get(rel);
      try {
        const t = typeof o.read === "function" ? o.read(rel) : null;
        return typeof t === "string" ? t : null;
      } catch (_) {
        return null;
      }
    },
    exists: (rel) => {
      if (byRel.has(rel)) return true;
      try {
        return typeof o.exists === "function" ? !!o.exists(rel) : false;
      } catch (_) {
        return false;
      }
    },
    patterns: Array.isArray(o.agentPatterns) ? o.agentPatterns : [],
    composeRefs: new Map(),
    shellBasenames: new Set(),
    allRels: new Set([...(Array.isArray(o.allRels) ? o.allRels : []), ...files.map((f) => f.rel)]),
  };
  for (const r of ws.allRels) if (/\.(sh|bash)$/i.test(r)) ws.shellBasenames.add(P.basename(r));
  const out = new Map();
  const safe = (fn, rel, text) => {
    try {
      return fn(ws, rel, String(text));
    } catch (_) {
      return [];
    }
  };
  for (const f of files) if (fileKind(f.rel) === "devcontainer") out.set(f.rel, safe(analyzeDevcontainer, f.rel, f.text));
  const composeDone = new Set();
  for (const f of files) {
    if (fileKind(f.rel) === "compose") {
      out.set(f.rel, safe(analyzeCompose, f.rel, f.text));
      composeDone.add(f.rel);
    }
  }
  for (const rel of ws.composeRefs.keys()) {
    if (composeDone.has(rel)) continue;
    const t = ws.read(rel);
    if (t != null) out.set(rel, safe(analyzeCompose, rel, t));
  }
  if (o.checkScripts !== false) for (const f of files) if (fileKind(f.rel) === "shell") out.set(f.rel, safe(analyzeShell, f.rel, f.text));
  return out;
}

/** Convenience for a single file without cross-file context. */
function analyzeFile(rel, text, opts) {
  const r = analyzeWorkspace(Object.assign({}, opts || {}, { files: [{ rel, text }] }));
  return r.get(rel) || [];
}

// =============================================================================================
// Settings helpers
// =============================================================================================

/** User severity overrides: rule -> severity, only for valid values. */
function resolveSeverities(userRules) {
  const out = {};
  for (const id of RULE_IDS) {
    const v = userRules && typeof userRules === "object" ? userRules[id] : undefined;
    if (typeof v === "string" && SEVERITIES.includes(v)) out[id] = v;
  }
  return out;
}

function severityOf(f, overrides) {
  return (overrides && overrides[f.rule]) || f.defaultSeverity;
}

/**
 * Compile a glob into a matcher { source, test(path) }, or null when the pattern is refused.
 * No RegExp is built: matching is a memoised walk over (pattern token, path index), so its cost is
 * bounded by pattern length x path length whatever the pattern ("*a*a*a*b" cannot backtrack).
 * Repeated "**\/" and runs of "*" are collapsed first; patterns over 300 characters or with more
 * than 4 "**" are refused. Inside [...] a backslash escapes the next character, so "\\", "[" and "]"
 * are always literal there.
 */
function globToRegExp(glob) {
  const g = String(glob).replace(/(?:\*\*\/)+/g, "**/").replace(/\*{3,}/g, "**");
  if (g.length > 300 || (g.match(/\*\*/g) || []).length > 4) return null;
  const alts = expandBraces(g, 0);
  if (!alts) return null;
  const programs = [];
  for (const a of alts) {
    const p = globTokens(a);
    if (!p) return null;
    programs.push(p);
  }
  return {
    source: g,
    test(path) {
      const s = String(path);
      if (s.length > 4096) return false;
      return programs.some((p) => globMatch(p, s));
    },
  };
}

/** Expand {a,b} groups (nested allowed), at most 64 alternatives; null when that is exceeded. */
function expandBraces(g, depth) {
  if (depth > 8) return null;
  let open = -1;
  let level = 0;
  let close = -1;
  for (let i = 0; i < g.length; i++) {
    if (g[i] === "\\") {
      i++;
      continue;
    }
    if (g[i] === "{") {
      if (level === 0) open = i;
      level++;
    } else if (g[i] === "}" && level > 0) {
      level--;
      if (level === 0) {
        close = i;
        break;
      }
    }
  }
  if (open < 0 || close < 0) return [g];
  const parts = [];
  let cur = "";
  level = 0;
  for (let i = open + 1; i < close; i++) {
    const c = g[i];
    if (c === "{") level++;
    if (c === "}") level--;
    if (c === "," && level === 0) {
      parts.push(cur);
      cur = "";
    } else cur += c;
  }
  parts.push(cur);
  const out = [];
  for (const part of parts) {
    const sub = expandBraces(g.slice(0, open) + part + g.slice(close + 1), depth + 1);
    if (!sub) return null;
    out.push(...sub);
    if (out.length > 64) return null;
  }
  return out;
}

function globTokens(g) {
  const toks = [];
  for (let i = 0; i < g.length; ) {
    const c = g[i];
    if (c === "*" && g[i + 1] === "*") {
      if (g[i + 2] === "/") {
        toks.push({ t: "dirs" });
        i += 3;
      } else {
        toks.push({ t: "any" });
        i += 2;
      }
      continue;
    }
    if (c === "*") {
      toks.push({ t: "star" });
      i++;
      continue;
    }
    if (c === "?") {
      toks.push({ t: "one" });
      i++;
      continue;
    }
    if (c === "[") {
      const cls = parseClass(g, i);
      if (cls) {
        toks.push(cls.tok);
        i = cls.next;
        continue;
      }
    }
    if (c === "\\" && i + 1 < g.length) {
      toks.push({ t: "lit", c: g[i + 1] });
      i += 2;
      continue;
    }
    toks.push({ t: "lit", c });
    i++;
  }
  return toks;
}

/** [...] / [!...] / [^...] with ranges; a backslash escapes the next character. */
function parseClass(g, start) {
  let i = start + 1;
  let neg = false;
  if (g[i] === "!" || g[i] === "^") {
    neg = true;
    i++;
  }
  const items = [];
  let first = true;
  while (i < g.length) {
    let c = g[i];
    if (c === "]" && !first) return { tok: { t: "cls", neg, items }, next: i + 1 };
    first = false;
    if (c === "\\" && i + 1 < g.length) c = g[++i];
    let hi = c;
    if (g[i + 1] === "-" && i + 2 < g.length && g[i + 2] !== "]") {
      hi = g[i + 2] === "\\" && i + 3 < g.length ? g[i + 3] : g[i + 2];
      i += g[i + 2] === "\\" ? 4 : 3;
    } else i++;
    if (hi < c) return null;
    items.push([c, hi]);
  }
  return null;
}

function globMatch(toks, s) {
  const P = toks.length;
  const S = s.length;
  const memo = new Uint8Array((P + 1) * (S + 1));
  const m = (pi, si) => {
    const key = pi * (S + 1) + si;
    if (memo[key]) return memo[key] === 1;
    let r;
    if (pi === P) r = si === S;
    else {
      const t = toks[pi];
      const ch = s[si];
      if (t.t === "lit") r = si < S && ch === t.c && m(pi + 1, si + 1);
      else if (t.t === "one") r = si < S && ch !== "/" && m(pi + 1, si + 1);
      else if (t.t === "cls") r = si < S && ch !== "/" && t.items.some(([a, b]) => ch >= a && ch <= b) !== t.neg && m(pi + 1, si + 1);
      else if (t.t === "star") r = m(pi + 1, si) || (si < S && ch !== "/" && m(pi, si + 1));
      else if (t.t === "any") r = m(pi + 1, si) || (si < S && m(pi, si + 1));
      else {
        // "**/": zero or more whole directories.
        r = m(pi + 1, si);
        if (!r) {
          const j = s.indexOf("/", si);
          r = j >= 0 && m(pi, j + 1);
        }
      }
    }
    memo[key] = r ? 1 : 2;
    return r;
  };
  return m(0, 0);
}

function makeExcluder(globs) {
  const res = (globs || []).filter((g) => typeof g === "string" && g.trim()).map((g) => ({ g: g.trim(), re: globToRegExp(g.trim()) })).filter((x) => x.re);
  return (rel) => {
    const p = String(rel).replace(/\\/g, "/");
    const base = p.split("/").pop();
    return res.some((x) => x.re.test(p) || (!x.g.includes("/") && x.re.test(base)));
  };
}

module.exports = {
  RULES,
  RULE_IDS,
  SEVERITIES,
  fileKind,
  parseJsonc,
  parseYaml,
  shellCommands,
  interpretFlags,
  normHostPath,
  classifyHost,
  splitVolume,
  parseMountSpec,
  nameIsAgent,
  compileAgentPatterns,
  analyzeWorkspace,
  analyzeFile,
  resolveSeverities,
  severityOf,
  globToRegExp,
  makeExcluder,
  firewallScript,
  dfEntrypointHas,
};
