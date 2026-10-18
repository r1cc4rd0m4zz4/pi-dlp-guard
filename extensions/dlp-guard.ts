/**
 * pi-dlp-guard: path protection and secret redaction for Pi.
 *
 * - tool_call:   blocks access to protected paths (structured tools + bash writes)
 * - tool_result: redacts secrets from tool output before it enters the transcript
 * - context:     redacts secrets from the messages sent to the model provider
 *
 * This is defense in depth, not a sandbox: bash is analysed lexically and cannot
 * be made airtight. Use an OS-level sandbox as the real boundary.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as cp from "node:child_process";
import { fileURLToPath } from "node:url";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export interface DlpGuardConfig {
  /** Blocked for read and write. */
  protectedPaths: string[];
  /** Blocked for write only (the agent may still read them). */
  integrityPaths: string[];
  enableGitleaks: boolean;
  gitleaksMinBytes: number;
  gitleaksTimeoutMs: number;
}

export const DEFAULT_CONFIG: DlpGuardConfig = {
  protectedPaths: [
    ".env",
    ".env.*",
    "**/.git/**",
    "~/.ssh/**",
    "~/.aws/**",
    "~/.gnupg/**",
    "~/.netrc",
    "~/.zshrc*",
    "~/.bashrc*",
    "~/.bash_profile",
    "~/.profile",
    "**/*rc.local",
    "**/*.pem",
    "**/*.key",
    "**/id_rsa*",
    "**/id_ed25519*",
    "~/.pi/agent/auth.json",
  ],
  integrityPaths: ["~/.pi/agent/**"],
  enableGitleaks: true,
  gitleaksMinBytes: 4096,
  gitleaksTimeoutMs: 500,
};

const HOME = (() => {
  try {
    return fs.realpathSync(os.homedir());
  } catch {
    return os.homedir();
  }
})();
const CONFIG_FILE = path.join(HOME, ".pi", "agent", "dlp-guard.json");
const TEMPLATE_ENV = /^\.env\.(?:example|sample|template)$/i;

let packageDir = "";
try {
  packageDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
} catch {
  // Unknown location: only the configured integrityPaths apply.
}

export function loadConfig(): DlpGuardConfig {
  try {
    const parsed = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf-8"));
    const list = (v: unknown, d: string[]) => (Array.isArray(v) && v.every((s) => typeof s === "string") ? (v as string[]) : d);
    const num = (v: unknown, d: number) => (typeof v === "number" && v >= 0 ? v : d);
    return {
      protectedPaths: list(parsed.protectedPaths, DEFAULT_CONFIG.protectedPaths),
      integrityPaths: list(parsed.integrityPaths, DEFAULT_CONFIG.integrityPaths),
      enableGitleaks: typeof parsed.enableGitleaks === "boolean" ? parsed.enableGitleaks : DEFAULT_CONFIG.enableGitleaks,
      gitleaksMinBytes: num(parsed.gitleaksMinBytes, DEFAULT_CONFIG.gitleaksMinBytes),
      gitleaksTimeoutMs: num(parsed.gitleaksTimeoutMs, DEFAULT_CONFIG.gitleaksTimeoutMs),
    };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

// -----------------------------------------------------------------------------
// Secret redaction
// -----------------------------------------------------------------------------

const secretToToken = new Map<string, string>();
const categoryCounters = new Map<string, number>();

export function resetSessionState(): void {
  secretToToken.clear();
  categoryCounters.clear();
}

/** The same secret always maps to the same token within a session. */
function tokenFor(secret: string, category: string): string {
  let token = secretToToken.get(secret);
  if (!token) {
    const n = (categoryCounters.get(category) ?? 0) + 1;
    categoryCounters.set(category, n);
    token = `[REDACTED_${category}_#${n}]`;
    secretToToken.set(secret, token);
  }
  return token;
}

// Each rule captures the secret in group 1. Specific rules run before SECRET.
const RULES: { category: string; rx: RegExp }[] = [
  { category: "PRIVATE_KEY", rx: /(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)/g },
  { category: "AWS_KEY", rx: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g },
  { category: "GITHUB_TOKEN", rx: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})(?![\w])/g },
  { category: "SLACK_TOKEN", rx: /\b(xox[baprs]-[0-9a-zA-Z-]{10,48})\b/g },
  { category: "API_KEY", rx: /\b(sk-ant-[\w-]{20,}|sk-proj-[\w-]{20,}|sk-[A-Za-z0-9]{32,}|AIza[\w-]{35}|[rs]k_live_[0-9A-Za-z]{24,})(?![\w-])/g },
  { category: "URL_CREDENTIAL", rx: /:\/\/[^\s:/@]+:([^\s@/]+)@/g },
  {
    // NAME=value / NAME: value / "name": "value", where a NAME segment is a secret word.
    category: "SECRET",
    rx: /(?:^|[\s;,{("'])(?:export\s+)?(?:[A-Za-z0-9]+[_-])*(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|PASS|AUTH|PRIVATE)(?:[_-][A-Za-z0-9]+)*["']?\s*[=:]\s*(?:"([^"\r\n]{8,})"|'([^'\r\n]{8,})'|([^\s"',;]{8,}))/gi,
  },
];

let gitleaksAvailable: boolean | null = null;
function hasGitleaks(): boolean {
  if (gitleaksAvailable === null) {
    gitleaksAvailable = cp.spawnSync("gitleaks", ["version"], { timeout: 500, stdio: "ignore" }).status === 0;
  }
  return gitleaksAvailable;
}

export function scanWithGitleaks(text: string, timeoutMs = 500): string[] {
  if (!hasGitleaks()) return [];
  try {
    const res = cp.spawnSync(
      "gitleaks",
      ["stdin", "--no-banner", "--log-level", "error", "--report-format", "json", "--report-path", "-"],
      { input: text, timeout: timeoutMs, encoding: "utf-8", maxBuffer: 5 * 1024 * 1024 },
    );
    const found = JSON.parse(res.stdout || "[]");
    return Array.isArray(found) ? found.map((f: { Secret?: string }) => f.Secret ?? "").filter((s: string) => s.length >= 8) : [];
  } catch {
    return [];
  }
}

/** Replaces secrets with stable tokens. gitleaks (optional) only runs on large inputs. */
export function redactSecrets(text: string, config: DlpGuardConfig = DEFAULT_CONFIG, useGitleaks = false): string {
  if (typeof text !== "string" || !text) return text;
  let out = text;
  for (const { category, rx } of RULES) {
    out = out.replace(rx, (match, ...groups: unknown[]) => {
      const secret = groups.slice(0, 3).find((g) => typeof g === "string" && g) as string | undefined;
      if (!secret || /^(?:\[REDACTED_|[$<{(])/.test(secret)) return match;
      const i = match.lastIndexOf(secret);
      return match.slice(0, i) + tokenFor(secret, category) + match.slice(i + secret.length);
    });
  }
  if (useGitleaks && config.enableGitleaks && out.length >= config.gitleaksMinBytes) {
    for (const secret of scanWithGitleaks(out, config.gitleaksTimeoutMs)) {
      out = out.split(secret).join(tokenFor(secret, "SECRET"));
    }
  }
  return out;
}

// -----------------------------------------------------------------------------
// Path protection
// -----------------------------------------------------------------------------

function expandHome(p: string): string {
  return p.replace(/^(?:~|\$HOME|\$\{HOME\})(?=\/|$)/, HOME);
}

/** Glob to RegExp: `**` crosses directories, `*` does not; `**\/` may match nothing. */
function globToRegExp(glob: string): RegExp {
  let s = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*" && glob[i + 1] === "*") {
      if (glob[i + 2] === "/") {
        s += "(?:.*/)?";
        i += 2;
      } else {
        s += ".*";
        i += 1;
      }
    } else if (c === "*") s += "[^/]*";
    else s += c.replace(/[.+^${}()|[\]\\?]/g, "\\$&");
  }
  return new RegExp(`^${s}$`, "i");
}

/** Does an absolute path match a pattern? A bare name matches any basename. */
function matches(pattern: string, abs: string, cwd: string): boolean {
  let g = expandHome(pattern.replace(/\\/g, "/"));
  if (!g.includes("/")) return globToRegExp(g).test(path.basename(abs));
  if (!g.startsWith("/") && !g.startsWith("**")) g = `${cwd}/${g}`;
  if (globToRegExp(g).test(abs)) return true;
  if (g.endsWith("/**") && globToRegExp(g.slice(0, -3)).test(abs)) return true;

  // On macOS /var is a symlink to /private/var: check pattern with canonical prefix as well.
  const prefix = g.replace(/\/\*\*?.*$/, "");
  const canonPrefix = canonical(prefix);
  if (canonPrefix !== prefix) {
    const gCanon = canonPrefix + g.slice(prefix.length);
    if (globToRegExp(gCanon).test(abs)) return true;
    if (gCanon.endsWith("/**") && globToRegExp(gCanon.slice(0, -3)).test(abs)) return true;
  }
  return false;
}

/** Follows symlinks, including dangling ones, and ancestors of files that do not exist yet. */
function canonical(p: string, depth = 0): string {
  try {
    return fs.realpathSync(p);
  } catch {
    // not resolvable as-is
  }
  try {
    if (depth < 8 && fs.lstatSync(p).isSymbolicLink()) return canonical(path.resolve(path.dirname(p), fs.readlinkSync(p)), depth + 1);
  } catch {
    // does not exist
  }
  const parent = path.dirname(p);
  return parent === p ? p : path.join(canonical(parent, depth), path.basename(p));
}

export function isPathProtected(
  targetPath: string,
  config: DlpGuardConfig = DEFAULT_CONFIG,
  cwd: string = process.cwd(),
  op: "read" | "write" = "read",
): { protected: boolean; reason?: string } {
  if (typeof targetPath !== "string" || !targetPath.trim()) return { protected: false };
  const lexical = path.resolve(cwd, expandHome(targetPath.trim()));
  if (TEMPLATE_ENV.test(path.basename(lexical)) && canonical(lexical) === lexical) return { protected: false };

  const integrity = op === "write" ? [...config.integrityPaths, ...(packageDir ? [`${packageDir}/**`] : [])] : [];
  for (const abs of new Set([lexical, canonical(lexical)])) {
    const hit = config.protectedPaths.find((p) => matches(p, abs, cwd));
    if (hit) return { protected: true, reason: `percorso protetto "${hit}"` };
    const own = integrity.find((p) => matches(p, abs, cwd));
    if (own) return { protected: true, reason: `integrità del guardiano: scrittura vietata su "${own}"` };
  }
  return { protected: false };
}

// -----------------------------------------------------------------------------
// Bash analysis: split chained commands, track `cd`, check write targets
// -----------------------------------------------------------------------------

type Segment = { words: string[]; redirects: string[] };

/** Splits on ; && || | & and newlines outside quotes. Redirect targets are collected apart. */
function parseSegments(cmd: string): Segment[] {
  const segments: Segment[] = [];
  let seg: Segment = { words: [], redirects: [] };
  let word = "";
  let inWord = false;
  let quote = "";
  let redirect = false; // the next word is a write redirect target

  const endWord = () => {
    if (inWord) (redirect ? seg.redirects : seg.words).push(word);
    if (inWord) redirect = false;
    word = "";
    inWord = false;
  };
  const endSegment = () => {
    endWord();
    redirect = false;
    if (seg.words.length || seg.redirects.length) segments.push(seg);
    seg = { words: [], redirects: [] };
  };

  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (quote) {
      if (c === quote) quote = "";
      else if (c === "\\" && quote === '"' && i + 1 < cmd.length) word += cmd[++i];
      else word += c;
    } else if (c === "'" || c === '"') {
      quote = c;
      inWord = true;
    } else if (c === "\\" && i + 1 < cmd.length) {
      word += cmd[++i];
      inWord = true;
    } else if (c === ";" || c === "\n" || c === "|") {
      endSegment();
    } else if (c === "&" && cmd[i - 1] !== ">" && cmd[i + 1] !== ">") {
      endSegment();
    } else if (c === ">") {
      endWord();
      if (cmd[i + 1] === ">") i++;
      redirect = true;
    } else if (c === "<") {
      endWord(); // input redirection is a read: not checked here
      if (cmd[i + 1] === "<") i++;
    } else if (/\s/.test(c)) {
      endWord();
    } else {
      word += c;
      inWord = true;
    }
  }
  endSegment();
  return segments;
}

const WRAPPERS = new Set(["sudo", "env", "command", "nohup", "time", "exec", "nice", "builtin", "xargs"]);
const MUTATORS = new Set(["rm", "rmdir", "mv", "cp", "ln", "install", "rsync", "touch", "truncate", "dd", "chmod", "chown", "chgrp", "tee", "shred", "unlink", "mkdir", "patch"]);
const IN_PLACE_EDITORS = new Set(["sed", "perl", "ruby"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh"]);

export function checkBashCommand(
  cmd: string,
  config: DlpGuardConfig = DEFAULT_CONFIG,
  cwd: string = process.cwd(),
  depth = 0,
): { block: boolean; reason?: string } {
  if (typeof cmd !== "string" || !cmd.trim() || depth > 3) return { block: false };
  const deny = (target: string, reason?: string) => ({ block: true, reason: `scrittura vietata su "${target}" (${reason})` });
  let here = cwd;

  // Nested code: $(...), `...`, sh -c "...", eval "..."
  const nested = [...cmd.matchAll(/\$\(([^()]*)\)|`([^`]*)`/g)].map((m) => m[1] ?? m[2]);

  for (const { words, redirects } of parseSegments(cmd)) {
    let i = 0;
    while (i < words.length && (/^[A-Za-z_]\w*=/.test(words[i]) || WRAPPERS.has(path.basename(words[i])))) i++;
    const name = path.basename(words[i] ?? "");
    const args = words.slice(i + 1);

    if (name === "cd" || name === "pushd") {
      if (args[0]) here = path.resolve(here, expandHome(args[0]));
      continue;
    }
    if (SHELLS.has(name) && args.includes("-c")) nested.push(args[args.indexOf("-c") + 1] ?? "");
    if (name === "eval") nested.push(args.join(" "));

    const inPlace = IN_PLACE_EDITORS.has(name) && args.some((a) => /^-[A-Za-z]*i|^--in-place/.test(a));
    const targets = MUTATORS.has(name) || inPlace ? [...args.filter((a) => !a.startsWith("-")), ...redirects] : redirects;
    for (const target of targets) {
      const check = isPathProtected(target, config, here, "write");
      if (check.protected) return deny(target, check.reason);
    }
  }

  for (const inner of nested) {
    const res = checkBashCommand(inner, config, here, depth + 1);
    if (res.block) return res;
  }
  return { block: false };
}

// -----------------------------------------------------------------------------
// Extension entry point
// -----------------------------------------------------------------------------

const PATH_KEYS = ["path", "file", "file_path", "filePath", "notebook_path", "paths"];
const WRITE_TOOL = /write|edit|replace|patch|create|delete|move|rename/i;

function pathsOf(input: Record<string, unknown>): string[] {
  return PATH_KEYS.flatMap((k) => (Array.isArray(input[k]) ? (input[k] as unknown[]) : [input[k]])).filter((v): v is string => typeof v === "string");
}

type Part = { type?: string; text?: string };

function redactParts(content: unknown, redact: (s: string) => string): unknown {
  if (typeof content === "string") return redact(content);
  if (!Array.isArray(content)) return content;
  return content.map((p: Part) => (p?.type === "text" && typeof p.text === "string" ? { ...p, text: redact(p.text) } : p));
}

export default function (pi: ExtensionAPI) {
  let config = loadConfig();
  let enabled = true;

  pi.on("tool_call", async (event, ctx) => {
    if (!enabled) return undefined;
    const input = (event.input || {}) as Record<string, unknown>;
    let reason: string | undefined;

    if (event.toolName === "bash") {
      if (typeof input.command === "string") reason = checkBashCommand(input.command, config, process.cwd()).reason;
    } else {
      const op = WRITE_TOOL.test(event.toolName) ? "write" : "read";
      for (const target of pathsOf(input)) {
        const check = isPathProtected(target, config, process.cwd(), op);
        if (check.protected) {
          reason = `${target}: ${check.reason}`;
          break;
        }
      }
    }
    if (!reason) return undefined;
    if (ctx.hasUI) ctx.ui.notify(`🛑 [DLP Guard] ${reason}`, "error");
    return { block: true, reason: `🛑 [DLP Guard] ${reason}` };
  });

  // Tool output: regex + optional gitleaks on large payloads.
  pi.on("tool_result", async (event) => {
    if (!enabled || !Array.isArray(event.content)) return undefined;
    const content = redactParts(event.content, (s) => redactSecrets(s, config, true));
    return JSON.stringify(content) === JSON.stringify(event.content) ? undefined : { content: content as typeof event.content };
  });

  // Outbound messages: regex only, so every turn stays fast.
  pi.on("context", async (event) => {
    if (!enabled || !Array.isArray(event.messages)) return undefined;
    let changed = false;
    const messages = event.messages.map((m) => {
      const content = redactParts((m as { content?: unknown }).content, (s) => redactSecrets(s, config));
      if (JSON.stringify(content) === JSON.stringify((m as { content?: unknown }).content)) return m;
      changed = true;
      return { ...m, content };
    });
    return changed ? { messages: messages as typeof event.messages } : undefined;
  });

  pi.registerCommand("dlp", {
    description: "DLP guard: /dlp [status|on|off|reload]",
    handler: async (args, ctx) => {
      const arg = (args || "").trim().toLowerCase();
      if (arg === "off") enabled = false;
      else if (arg === "on") enabled = true;
      else if (arg === "reload") config = loadConfig();
      if (arg === "off" || arg === "on" || arg === "reload") {
        ctx.ui.notify(`[DLP Guard] ${arg === "reload" ? "configurazione ricaricata" : enabled ? "ATTIVO" : "DISATTIVATO"}`, enabled ? "info" : "warning");
        return;
      }
      ctx.ui.notify(
        [
          `[DLP Guard] ${enabled ? "ATTIVO" : "DISATTIVATO"}`,
          `gitleaks: ${config.enableGitleaks ? (hasGitleaks() ? "attivo" : "non trovato nel PATH") : "disabilitato"}`,
          `segreti mascherati in sessione: ${secretToToken.size}`,
          `percorsi protetti: ${config.protectedPaths.length}, di integrità: ${config.integrityPaths.length}`,
        ].join("\n"),
        "info",
      );
    },
  });
}
