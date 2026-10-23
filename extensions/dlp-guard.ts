/**
 * pi-dlp-guard: Zero-dependency DLP, Path Protection, Deep Shell Guard & Secret Redaction for Pi.
 *
 * - tool_call:   blocks protected/integrity paths, deep bash obfuscation/reads/writes, and secret leaks
 * - tool_result: redacts secrets from tool output with stable relational tokens (+ optional Gitleaks)
 * - context:     redacts secrets from LLM context messages at zero latency
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as cp from "node:child_process";
import { fileURLToPath } from "node:url";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export interface DlpGuardConfig {
  enabled: boolean;
  /** Blocked for both read and write. */
  protectedPaths: string[];
  /** Blocked for write/mutation only (read is allowed). */
  integrityPaths: string[];
  enableGitleaks: boolean;
  gitleaksMinBytes: number;
  gitleaksTimeoutMs: number;
  blockInlineSecretsInCommands: boolean;
  blockReaderCommandsOnProtected: boolean;
  blockWriteSecrets: boolean;
}

const BASE_HOME = (() => {
  try {
    return fs.realpathSync(os.homedir());
  } catch {
    return os.homedir();
  }
})();

export function getHome(): string {
  return process.env.HOME || BASE_HOME;
}

let packageDir = "";
try {
  packageDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
} catch {
  // Fallback when import.meta.url is unavailable
}

export const DEFAULT_CONFIG: DlpGuardConfig = {
  enabled: true,
  protectedPaths: [
    ".env",
    ".env.*",
    "*.env",
    ".envrc",
    "**/.git/**",
    "~/.ssh/**",
    "/etc/ssh/**",
    "/etc/shadow*",
    "/etc/gshadow*",
    "/etc/sudoers*",
    "~/.aws/**",
    "~/.config/gcloud/**",
    "~/.gcp/**",
    "~/.azure/**",
    "~/.oci/**",
    "~/.gnupg/**",
    "~/.password-store/**",
    "~/.local/share/keyrings/**",
    "~/Library/Keychains/**",
    "~/.config/gh/**",
    "~/.config/glab-cli/**",
    "~/.config/op/**",
    "~/.op/**",
    "~/.config/sops/**",
    "~/.config/age/**",
    "~/.kube/**",
    "~/.docker/config.json",
    "~/.terraform.d/**",
    "**/*.tfstate",
    "**/*.tfstate.*",
    "**/*.tfvars",
    "~/.vault-token",
    "~/.netrc",
    "~/.git-credentials",
    "~/.npmrc",
    "~/.pypirc",
    "~/.gem/credentials",
    "~/.cargo/credentials*",
    "~/.composer/auth.json",
    "~/.zshrc*",
    "~/.zprofile",
    "~/.zshenv",
    "~/.zsh_history",
    "~/.bashrc*",
    "~/.bash_profile",
    "~/.bash_history",
    "~/.profile",
    "**/*rc.local",
    "**/*.pem",
    "**/*.key",
    "**/*.pkcs12",
    "**/*.pfx",
    "**/*.p12",
    "**/*.jks",
    "**/*.keystore",
    "**/*.age",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/id_ecdsa*",
    "**/id_dsa*",
    "~/.pi/agent/auth.json",
    "~/.claude/.credentials.json",
  ],
  integrityPaths: [
    "~/.pi/agent/**",
    "**/.pi/agent/**",
    ".pi/**",
    "~/.gemini/config/**",
    "**/.gemini/config/**",
    "~/.gemini/antigravity-cli/**",
    "~/.gemini/antigravity/**",
    "~/.gemini/antigravity-ide/**",
    ".agents/**",
    ".agent/**",
    "_agents/**",
    "_agent/**",
    "**/dlp-guard.json",
    ...(packageDir ? [`${packageDir}/**`] : []),
  ],
  enableGitleaks: true,
  gitleaksMinBytes: 4096,
  gitleaksTimeoutMs: 500,
  blockInlineSecretsInCommands: true,
  blockReaderCommandsOnProtected: true,
  blockWriteSecrets: true,
};

export function loadConfig(cwd: string = process.cwd()): DlpGuardConfig {
  const home = getHome();
  const candidates = [
    { file: path.join(cwd, ".pi", "dlp-guard.json"), trusted: false },
    { file: path.join(cwd, ".agents", "dlp-guard.json"), trusted: false },
    { file: path.join(cwd, ".agent", "dlp-guard.json"), trusted: false },
    { file: path.join(home, ".pi", "agent", "dlp-guard.json"), trusted: true },
    { file: path.join(home, ".gemini", "config", "dlp-guard.json"), trusted: true },
  ];
  const list = (v: unknown, d: string[]) => (Array.isArray(v) && v.every((s) => typeof s === "string") ? (v as string[]) : d);
  const num = (v: unknown, d: number) => (typeof v === "number" && v >= 0 ? v : d);
  const bool = (v: unknown, d: boolean) => (typeof v === "boolean" ? v : d);

  for (const { file, trusted } of candidates) {
    try {
      if (!fs.existsSync(file)) continue;
      const parsed = JSON.parse(fs.readFileSync(file, "utf-8"));
      const userProtected = list(parsed.protectedPaths, DEFAULT_CONFIG.protectedPaths);
      const userIntegrity = list(parsed.integrityPaths, DEFAULT_CONFIG.integrityPaths);
      return {
        // Untrusted workspace configs cannot disable the guard or weaken built-in protections
        enabled: trusted ? bool(parsed.enabled, DEFAULT_CONFIG.enabled) : true,
        protectedPaths: trusted ? userProtected : Array.from(new Set([...DEFAULT_CONFIG.protectedPaths, ...userProtected])),
        integrityPaths: Array.from(
          new Set([
            ...(trusted ? userIntegrity : [...DEFAULT_CONFIG.integrityPaths, ...userIntegrity]),
            "**/dlp-guard.json",
            ...(packageDir ? [`${packageDir}/**`] : []),
          ]),
        ),
        enableGitleaks: trusted ? bool(parsed.enableGitleaks, DEFAULT_CONFIG.enableGitleaks) : true,
        gitleaksMinBytes: num(parsed.gitleaksMinBytes, DEFAULT_CONFIG.gitleaksMinBytes),
        gitleaksTimeoutMs: num(parsed.gitleaksTimeoutMs, DEFAULT_CONFIG.gitleaksTimeoutMs),
        blockInlineSecretsInCommands: trusted ? bool(parsed.blockInlineSecretsInCommands, DEFAULT_CONFIG.blockInlineSecretsInCommands) : true,
        blockReaderCommandsOnProtected: trusted ? bool(parsed.blockReaderCommandsOnProtected, DEFAULT_CONFIG.blockReaderCommandsOnProtected) : true,
        blockWriteSecrets: trusted ? bool(parsed.blockWriteSecrets, DEFAULT_CONFIG.blockWriteSecrets) : true,
      };
    } catch {
      // Try next candidate
    }
  }
  return { ...DEFAULT_CONFIG };
}

// -----------------------------------------------------------------------------
// Secret Detection & Relational Redaction
// -----------------------------------------------------------------------------

const secretToToken = new Map<string, string>();
const categoryCounters = new Map<string, number>();

export function resetSessionState(): void {
  secretToToken.clear();
  categoryCounters.clear();
}

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

const SEC_WORDS = "SECRET|KEY|TOKEN|PASSWORD|PASSWD|PASS|PW|AUTH|PRIVATE|CREDENTIAL";

const RULES: { category: string; rx: RegExp }[] = [
  { category: "PRIVATE_KEY", rx: /(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----)/g },
  { category: "AGE_SECRET_KEY", rx: /\b(AGE-SECRET-KEY-1[A-Z0-9]{58})\b/g },
  { category: "AWS_KEY", rx: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g },
  { category: "GITHUB_TOKEN", rx: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})(?![\w])/g },
  { category: "GITLAB_TOKEN", rx: /\b(glpat-[0-9a-zA-Z_-]{20,})\b/g },
  { category: "SLACK_TOKEN", rx: /\b(xox[baprs]-[0-9a-zA-Z-]{10,48})\b/g },
  { category: "NPM_TOKEN", rx: /\b(npm_[A-Za-z0-9]{36})(?![\w])/g },
  { category: "PYPI_TOKEN", rx: /\b(pypi-[A-Za-z0-9_-]{50,})(?![\w-])/g },
  {
    category: "API_KEY",
    rx: /\b(sk-ant-[\w-]{20,}|sk-proj-[\w-]{20,}|sk-[A-Za-z0-9]{32,}|AIza[0-9A-Za-z_-]{35}|[rs]k_live_[0-9A-Za-z]{24,}|hf_[a-zA-Z0-9]{34}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|do[po]_v1_[a-f0-9]{64})(?![\w-])/g,
  },
  { category: "JWT_TOKEN", rx: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g },
  { category: "BEARER_TOKEN", rx: /Authorization["']?\s*:\s*["']?Bearer\s+([A-Za-z0-9_\-.~+/]{16,}=*)/gi },
  { category: "URL_CREDENTIAL", rx: /[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s:/@]+:([^\s@/]{3,})@/g },
  {
    category: "SECRET",
    rx: new RegExp(
      `(?:^|[\\s;,{("'])(?:export\\s+)?(?:[A-Za-z0-9]+[_-])*(?:${SEC_WORDS})(?:[_-][A-Za-z0-9]+)*["']?\\s*[=:]\\s*(?:"([^"\\r\\n]{8,})"|'([^'\\r\\n]{8,})'|([A-Za-z0-9_~%+=-]{8,})(?![A-Za-z0-9_~%+=-]|[.(]))`,
      "gi",
    ),
  },
];

const BENIGN_SET = new Set([
  "true",
  "false",
  "null",
  "undefined",
  "none",
  "unknown",
  "example",
  "changeme",
  "dummy",
  "placeholder",
  "password",
  "secret",
  "token",
]);

function isBenign(val: string | undefined): boolean {
  if (!val || typeof val !== "string") return true;
  if (BENIGN_SET.has(val.trim().toLowerCase())) return true;
  return /^(?:\[REDACTED_.*\]|\$\{[^}]+\}|\$[A-Za-z_]\w*|<[^>]+>|\*+|\.+|[$<{(].*)$/.test(val);
}

let gitleaksAvailable: boolean | null = null;
export function hasGitleaks(): boolean {
  if (gitleaksAvailable === null) {
    try {
      gitleaksAvailable = cp.spawnSync("gitleaks", ["version"], { timeout: 500, stdio: "ignore" }).status === 0;
    } catch {
      gitleaksAvailable = false;
    }
  }
  return gitleaksAvailable;
}

export function scanWithGitleaks(text: string, timeoutMs = 500): string[] {
  if (!hasGitleaks()) return [];
  try {
    const res = cp.spawnSync(
      "gitleaks",
      ["stdin", "--no-banner", "--log-level", "error", "--report-format", "json", "--report-path", "-"],
      { input: text, timeout: timeoutMs, encoding: "utf-8", maxBuffer: 10 * 1024 * 1024 },
    );
    const found = JSON.parse(res.stdout || "[]");
    return Array.isArray(found)
      ? found.map((f: { Secret?: string }) => f.Secret ?? "").filter((s: string) => s.length >= 8 && !isBenign(s))
      : [];
  } catch {
    return [];
  }
}

export function detectSecrets(
  text: string,
  config: DlpGuardConfig = DEFAULT_CONFIG,
  useGitleaks = true,
): { category: string; detected: string; sample: string } | null {
  if (typeof text !== "string" || !text) return null;
  for (const { category, rx } of RULES) {
    rx.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rx.exec(text)) !== null) {
      const captured = m.slice(1, 4).find((g) => typeof g === "string" && g);
      if (captured && !isBenign(captured)) {
        return {
          category,
          detected: captured,
          sample: captured.length > 8 ? `${captured.slice(0, 4)}...${captured.slice(-4)}` : "[SECRET]",
        };
      }
    }
  }
  if (useGitleaks && config.enableGitleaks && text.length >= config.gitleaksMinBytes) {
    const leaks = scanWithGitleaks(text, config.gitleaksTimeoutMs);
    if (leaks.length > 0) {
      const first = leaks[0];
      return {
        category: "GITLEAKS_DETECTED",
        detected: first,
        sample: first.length > 8 ? `${first.slice(0, 4)}...${first.slice(-4)}` : "[SECRET]",
      };
    }
  }
  return null;
}

export function redactSecrets(text: string, config: DlpGuardConfig = DEFAULT_CONFIG, useGitleaks = false): string {
  if (typeof text !== "string" || !text) return text;
  let out = text;
  for (const { category, rx } of RULES) {
    rx.lastIndex = 0;
    out = out.replace(rx, (match, ...groups: unknown[]) => {
      const secret = groups.slice(0, 3).find((g) => typeof g === "string" && g) as string | undefined;
      if (!secret || isBenign(secret)) return match;
      const i = match.lastIndexOf(secret);
      return i === -1 ? match : match.slice(0, i) + tokenFor(secret, category) + match.slice(i + secret.length);
    });
  }
  if (useGitleaks && config.enableGitleaks && out.length >= config.gitleaksMinBytes) {
    for (const secret of scanWithGitleaks(out, config.gitleaksTimeoutMs)) {
      if (!isBenign(secret)) out = out.split(secret).join(tokenFor(secret, "SECRET"));
    }
  }
  return out;
}

// -----------------------------------------------------------------------------
// Path Protection (Null-byte, URL-decoding, Braces, Wildcards, Symlinks)
// -----------------------------------------------------------------------------

const TEMPLATE_ENV = /^\.env\.(?:example|sample|template|dist|default|schema)$/i;
const SAMPLE_SENSITIVE_BASENAMES = [
  ".env",
  ".env.local",
  ".env.production",
  ".envrc",
  "id_rsa",
  "id_ed25519",
  "id_ecdsa",
  "id_dsa",
  "private.key",
  "server.pem",
  "cert.p12",
  "cert.pfx",
  ".netrc",
  ".git-credentials",
  ".bashrc",
  ".zshrc",
  "auth.json",
];

function expandHome(p: string, cwd: string = process.cwd()): string {
  if (typeof p !== "string") return "";
  const home = getHome();
  return p
    .replace(/^(?:~|\$HOME|\$\{HOME\})(?=\/|$)/, home)
    .replace(/\$\{HOME\}|\$HOME\b/g, home)
    .replace(/^(?:~\+|\$PWD|\$\{PWD\})(?=\/|$)/, cwd)
    .replace(/\$\{PWD\}|\$PWD\b/g, cwd);
}

function expandBraces(input: string, depth = 0): string[] {
  if (typeof input !== "string" || depth > 4) return [input];
  const m = input.match(/^(.*?)\{([^{}]+)\}(.*)$/);
  if (!m || !m[2].includes(",")) return [input];
  return m[2]
    .split(",")
    .slice(0, 16)
    .flatMap((part) => expandBraces(m[1] + part + m[3], depth + 1));
}

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

function shellWildcardToRegExp(pat: string): RegExp {
  let s = "";
  for (let i = 0; i < pat.length; i++) {
    const c = pat[i];
    if (c === "*") s += "[^/]*";
    else if (c === "?") s += "[^/]";
    else if (c === "[") {
      const close = pat.indexOf("]", i + 1);
      if (close !== -1) {
        s += `[${pat.slice(i + 1, close).replace(/\\/g, "\\\\")}]`;
        i = close;
      } else s += "\\[";
    } else s += c.replace(/[.+^${}()|\\]/g, "\\$&");
  }
  return new RegExp(`^${s}$`, "i");
}

function canonical(p: string, depth = 0): string {
  try {
    return fs.realpathSync(p);
  } catch {
    // Not resolvable as-is
  }
  try {
    if (depth < 8 && fs.lstatSync(p).isSymbolicLink()) {
      const target = fs.readlinkSync(p);
      return canonical(path.isAbsolute(target) ? target : path.resolve(path.dirname(p), target), depth + 1);
    }
  } catch {
    // Does not exist
  }
  const parent = path.dirname(p);
  return parent === p ? p : path.join(canonical(parent, depth), path.basename(p));
}

function matches(pattern: string, abs: string, cwd: string): boolean {
  let g = expandHome(pattern.replace(/\\/g, "/"), cwd);
  const norm = abs.replace(/\\/g, "/");
  if (!g.includes("/")) return globToRegExp(g).test(path.basename(norm));
  if (!g.startsWith("/") && !g.startsWith("**")) g = `${cwd.replace(/\\/g, "/")}/${g}`;
  if (globToRegExp(g).test(norm)) return true;
  if (g.endsWith("/**") && globToRegExp(g.slice(0, -3)).test(norm)) return true;

  const prefix = g.replace(/\/\*\*?.*$/, "");
  const canonPrefix = canonical(prefix).replace(/\\/g, "/");
  if (canonPrefix !== prefix) {
    const gCanon = canonPrefix + g.slice(prefix.length);
    if (globToRegExp(gCanon).test(norm)) return true;
    if (gCanon.endsWith("/**") && globToRegExp(gCanon.slice(0, -3)).test(norm)) return true;
  }
  return false;
}

function checkSinglePath(
  cleaned: string,
  config: DlpGuardConfig,
  cwd: string,
  op: "read" | "write",
  allowWildcardExpand = true,
): { protected: boolean; reason?: string } {
  const lexical = path.resolve(cwd, expandHome(cleaned, cwd));
  const canon = canonical(lexical);
  const isEnvTemplate = TEMPLATE_ENV.test(path.basename(lexical)) && TEMPLATE_ENV.test(path.basename(canon));

  const protectedList = isEnvTemplate ? [] : config.protectedPaths;
  const integrityList =
    op === "write" ? [...config.integrityPaths, ...(packageDir ? [`${packageDir}/**`] : [])] : [];

  for (const abs of new Set([lexical, canon])) {
    const hit = protectedList.find((p) => matches(p, abs, cwd));
    if (hit) return { protected: true, reason: `percorso protetto "${hit}"` };
    const own = integrityList.find((p) => matches(p, abs, cwd));
    if (own) return { protected: true, reason: `integrità del guardiano: scrittura vietata su "${own}"` };
  }

  const base = path.basename(lexical);
  if (allowWildcardExpand && /[*?[\]]/.test(base)) {
    const wildRx = shellWildcardToRegExp(base);
    const parentDir = path.dirname(lexical);
    try {
      if (fs.existsSync(parentDir) && fs.statSync(parentDir).isDirectory()) {
        for (const entry of fs.readdirSync(parentDir)) {
          if (wildRx.test(entry)) {
            const sub = checkSinglePath(path.join(parentDir, entry), config, cwd, op, false);
            if (sub.protected) return sub;
          }
        }
      }
    } catch {
      // Ignore unreadable dir
    }
    const nonWild = base.replace(/[*?[\]]/g, "");
    if (nonWild.length >= 2 || base.startsWith(".")) {
      for (const sample of SAMPLE_SENSITIVE_BASENAMES) {
        if (wildRx.test(sample)) {
          const sub = checkSinglePath(path.join(parentDir, sample), config, cwd, op, false);
          if (sub.protected) return sub;
        }
      }
    }
  }
  return { protected: false };
}

export function isPathProtected(
  targetPath: string,
  config: DlpGuardConfig = DEFAULT_CONFIG,
  cwd: string = process.cwd(),
  op: "read" | "write" = "read",
): { protected: boolean; reason?: string } {
  if (typeof targetPath !== "string" || !targetPath.trim()) return { protected: false };
  if (targetPath.includes("\0")) return { protected: true, reason: "rilevato carattere nullo (null-byte injection)" };

  let cleaned = targetPath.trim();
  for (let pass = 0; pass < 2; pass++) {
    try {
      if (!/%[0-9a-fA-F]{2}/.test(cleaned)) break;
      const decoded = decodeURIComponent(cleaned);
      if (decoded === cleaned) break;
      cleaned = decoded;
    } catch {
      break;
    }
  }
  if (cleaned.includes("\0")) return { protected: true, reason: "rilevato carattere nullo (null-byte injection)" };

  for (const variant of expandBraces(cleaned)) {
    const res = checkSinglePath(variant, config, cwd, op, true);
    if (res.protected) return res;
  }
  return { protected: false };
}

// -----------------------------------------------------------------------------
// Deep Bash Analysis & Anti-Obfuscation Engine
// -----------------------------------------------------------------------------

type Segment = { words: string[]; redirects: string[]; inputRedirects: string[]; pipedToNext: boolean };

function decodeAnsiC(str: string): string {
  return str
    .replace(/\\x([0-9a-fA-F]{1,2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\u([0-9a-fA-F]{1,4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\0?([0-7]{1,3})/g, (_, o) => String.fromCharCode(parseInt(o, 8)))
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t")
    .replace(/\\(['"\\])/g, "$1");
}

function parseSegments(cmd: string): Segment[] {
  const segments: Segment[] = [];
  let seg: Segment = { words: [], redirects: [], inputRedirects: [], pipedToNext: false };
  let word = "";
  let inWord = false;
  let quote = "";
  let ansiC = false;
  let ansiBuf = "";
  let redirMode: "write" | "read" | null = null;

  const endWord = () => {
    if (!inWord) return;
    if (redirMode === "write") seg.redirects.push(word);
    else if (redirMode === "read") seg.inputRedirects.push(word);
    else seg.words.push(word);
    redirMode = null;
    word = "";
    inWord = false;
  };

  const endSegment = (isPipe = false) => {
    endWord();
    redirMode = null;
    while (seg.words[0] === "{") seg.words.shift();
    while (seg.words[seg.words.length - 1] === "}") seg.words.pop();
    if (seg.words.length || seg.redirects.length || seg.inputRedirects.length) {
      seg.pipedToNext = isPipe;
      segments.push(seg);
    }
    seg = { words: [], redirects: [], inputRedirects: [], pipedToNext: false };
  };

  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (quote) {
      if (c === quote) {
        if (ansiC) {
          word += decodeAnsiC(ansiBuf);
          ansiBuf = "";
          ansiC = false;
        }
        quote = "";
      } else if (ansiC) {
        ansiBuf += c === "\\" && i + 1 < cmd.length ? c + cmd[++i] : c;
      } else if (c === "\\" && quote === '"' && i + 1 < cmd.length) {
        word += cmd[++i];
      } else {
        word += c;
      }
    } else if (c === "$" && (cmd[i + 1] === "'" || cmd[i + 1] === '"')) {
      quote = cmd[++i];
      ansiC = quote === "'";
      ansiBuf = "";
      inWord = true;
    } else if (c === "$" && cmd[i + 1] === "(") {
      let depth = 1;
      word += "$(";
      inWord = true;
      i += 2;
      while (i < cmd.length && depth > 0) {
        if (cmd[i] === "(") depth++;
        else if (cmd[i] === ")") depth--;
        word += cmd[i++];
      }
      i--;
    } else if (c === "'" || c === '"') {
      quote = c;
      inWord = true;
    } else if (c === "\\" && i + 1 < cmd.length) {
      word += cmd[++i];
      inWord = true;
    } else if (c === "(" || c === ")") {
      endSegment(false);
    } else if (c === "|" && cmd[i + 1] !== "|") {
      endSegment(true);
    } else if (c === "|" && cmd[i + 1] === "|") {
      i++;
      endSegment(false);
    } else if (c === ";" || c === "\n") {
      endSegment(false);
    } else if (c === "&") {
      const prev = cmd[i - 1];
      const next = cmd[i + 1];
      if (next === "&") {
        i++;
        endSegment(false);
      } else if (next === ">") {
        endWord();
        i++;
        if (cmd[i + 1] === ">") i++;
        redirMode = "write";
      } else if (prev === ">" || prev === "<") {
        if (/[0-9-]/.test(next || "")) {
          word += c;
          inWord = true;
        } else {
          redirMode = "write";
        }
      } else {
        endSegment(false);
      }
    } else if (c === ">") {
      if (inWord && /^[0-9]+$/.test(word)) {
        word = "";
        inWord = false;
      } else {
        endWord();
      }
      if (cmd[i + 1] === ">" || cmd[i + 1] === "|") i++;
      if (cmd[i + 1] === "(") endSegment(false);
      else redirMode = "write";
    } else if (c === "<") {
      if (inWord && /^[0-9]+$/.test(word)) {
        word = "";
        inWord = false;
      } else {
        endWord();
      }
      if (cmd[i + 1] === "<") {
        i++;
        if (cmd[i + 1] === "<") i++;
        redirMode = null;
      } else if (cmd[i + 1] === ">") {
        i++;
        redirMode = "write";
      } else if (cmd[i + 1] === "(") {
        endSegment(false);
      } else {
        redirMode = "read";
      }
    } else if (/\s/.test(c)) {
      endWord();
    } else {
      word += c;
      inWord = true;
    }
  }
  endSegment(false);
  return segments;
}

function extractSubshells(cmd: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < cmd.length) {
    if (cmd[i] === "$" && cmd[i + 1] === "(") {
      let depth = 1;
      const start = i + 2;
      i += 2;
      while (i < cmd.length && depth > 0) {
        if (cmd[i] === "(") depth++;
        else if (cmd[i] === ")") depth--;
        i++;
      }
      out.push(cmd.slice(start, depth === 0 ? i - 1 : i));
    } else {
      i++;
    }
  }
  for (const m of cmd.matchAll(/`([^`]+)`/g)) {
    if (m[1]) out.push(m[1]);
  }
  return out;
}

const WRAPPERS = new Set(["sudo", "env", "command", "nohup", "time", "exec", "nice", "builtin", "xargs", "doas", "su", "timeout", "strace", "ltrace"]);
const OPTS_WITH_ARG = new Set(["-u", "-g", "-C", "-U", "-r", "-t", "-D", "-n", "-d", "-I"]);
const MUTATORS = new Set(["rm", "rmdir", "mv", "cp", "ln", "install", "rsync", "touch", "truncate", "chmod", "chown", "chgrp", "tee", "shred", "unlink", "mkdir", "patch", "srm", "wipe", "chattr"]);
const READERS = new Set(["cat", "head", "tail", "more", "less", "base64", "xxd", "hexdump", "strings", "bat", "view", "nl", "tac", "od", "rev", "shuf", "sort", "uniq", "cut", "paste", "column", "fmt", "pr", "fold", "expand", "unexpand", "wc", "diff", "cmp", "comm", "zcat", "bzcat", "xzcat", "source", "."]);
const ARCHIVERS = new Set(["tar", "zip", "7z", "gzip", "bzip2", "xz", "zstd", "cpio"]);
const GREP_CMDS = new Set(["grep", "egrep", "fgrep", "rg", "ag", "ack"]);
const AWK_CMDS = new Set(["awk", "gawk", "mawk", "nawk"]);
const JQ_CMDS = new Set(["jq", "yq"]);
const INTERPRETERS = new Set(["python", "python3", "python2", "node", "bun", "deno", "ruby", "perl", "php", "lua"]);
const IN_PLACE_EDITORS = new Set(["sed", "perl", "ruby"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh"]);
const VAR_DECL_CMDS = new Set(["export", "local", "declare", "typeset", "readonly"]);

const isFdOrSafe = (t: string) =>
  /^&?[0-9-]+$/.test(t) ||
  t === "-" ||
  /^\/dev\/(?:null|zero|u?random|std(?:out|err|in))$/.test(t);

function applyVars(str: string, vars: Map<string, string>): string {
  if (!vars.size || !str) return str;
  return str.replace(/\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)/g, (m, g1, g2) => {
    const k = g1 || g2;
    return vars.has(k) ? (vars.get(k) as string) : m;
  });
}

function resolveTargetCandidates(raw: string, vars: Map<string, string>): string[] {
  if (!raw) return [];
  const withVars = applyVars(raw, vars);
  const out = new Set([raw, withVars]);
  for (const base of [raw, withVars]) {
    const sub = base
      .replace(/\$\(\s*echo\s+(?:-[neE]+\s+)?(["']?)([^()"']*)\1\s*\)/g, "$2")
      .replace(/`\s*echo\s+(?:-[neE]+\s+)?(["']?)([^`"']*)\1\s*`/g, "$2")
      .replace(/\$\(\s*printf\s+(?:["']%s["']\s+)?(["']?)([^()"']*)\1\s*\)/g, "$2")
      .replace(/\$\{[A-Za-z_]\w*:[=-]([^}]*)\}/g, "$1");
    out.add(sub);
    const stripped = sub.replace(/\$\{(?!HOME\b|PWD\b)[A-Za-z_]\w*\}|\$(?!HOME\b|PWD\b)[A-Za-z_]\w*/g, "");
    if (stripped && stripped !== "/") out.add(stripped);
  }
  return [...out];
}

function unwrapWords(words: string[]): { cmdName: string; args: string[]; usedXargs: boolean } {
  let i = 0;
  let usedXargs = false;
  while (i < words.length) {
    const w = words[i];
    if (/^[A-Za-z_]\w*=/.test(w)) {
      i++;
      continue;
    }
    const base = path.basename(w);
    if (WRAPPERS.has(base)) {
      if (base === "xargs") usedXargs = true;
      i++;
      if (base === "timeout" && i < words.length && /^[0-9]/.test(words[i])) i++;
      while (i < words.length && words[i].startsWith("-")) {
        const next = words[i + 1];
        if (OPTS_WITH_ARG.has(words[i]) && next && !next.startsWith("-") && !MUTATORS.has(next) && !READERS.has(next) && !WRAPPERS.has(next)) {
          i += 2;
        } else {
          i++;
        }
      }
      continue;
    }
    break;
  }
  return { cmdName: words[i] ? path.basename(words[i]) : "", args: words.slice(i + 1), usedXargs };
}

function extractStringLiterals(code: string): string[] {
  let folded = code;
  for (let pass = 0; pass < 4; pass++) {
    const next = folded
      .replace(/"([^"\\]*)"\s*\+\s*"([^"\\]*)"/g, '"$1$2"')
      .replace(/'([^'\\]*)'\s*\+\s*'([^'\\]*)'/g, "'$1$2'");
    if (next === folded) break;
    folded = next;
  }
  const literals: string[] = [];
  const rx = /"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'|`([^`\\]*(?:\\.[^`\\]*)*)`/g;
  for (const src of new Set([code, folded])) {
    let m: RegExpExecArray | null;
    while ((m = rx.exec(src)) !== null) {
      const lit = (m[1] ?? m[2] ?? m[3] ?? "").trim();
      if (lit) literals.push(lit);
    }
  }
  return literals;
}

export function checkBashCommand(
  cmd: string,
  config: DlpGuardConfig = DEFAULT_CONFIG,
  cwd: string = process.cwd(),
  depth = 0,
): { block: boolean; reason?: string } {
  if (typeof cmd !== "string" || !cmd.trim() || depth > 5) return { block: false };

  if (config.blockInlineSecretsInCommands) {
    const hit = detectSecrets(cmd, config);
    if (hit) return { block: true, reason: `rilevata credenziale/segreto in chiaro nella riga di comando (${hit.category})` };
  }

  let here = cwd;
  const vars = new Map<string, string>();
  const deny = (target: string, reason?: string) => ({ block: true, reason: `operazione shell vietata su "${target}" (${reason})` });
  const checkTarget = (raw: string, op: "read" | "write", prefix = "") => {
    for (const c of resolveTargetCandidates(raw, vars)) {
      if (!c || isFdOrSafe(c)) continue;
      const check = isPathProtected(c, config, here, op);
      if (check.protected) return deny(raw, prefix ? `${prefix}: ${check.reason}` : check.reason);
    }
    return null;
  };

  const nested = extractSubshells(cmd);
  let pipedArgs: string[] = [];
  let pipedFromDecoder = false;

  for (const { words, redirects, inputRedirects, pipedToNext } of parseSegments(cmd)) {
    if (!words.length && !redirects.length && !inputRedirects.length) {
      pipedArgs = [];
      pipedFromDecoder = false;
      continue;
    }

    for (const tok of words) {
      if (VAR_DECL_CMDS.has(tok) || tok.startsWith("-")) continue;
      const eq = tok.match(/^([A-Za-z_]\w*)=(.*)$/);
      if (eq) vars.set(eq[1], applyVars(eq[2], vars));
      else break;
    }

    const expanded = words.map((w) => applyVars(w, vars));
    const { cmdName, args: rawArgs, usedXargs } = unwrapWords(expanded);
    const args = usedXargs && pipedArgs.length ? [...rawArgs, ...pipedArgs] : rawArgs;

    // Anti-tampering CLI defense (agy-dlp & pi package manager)
    if (cmdName === "agy-dlp" || cmdName === "agy-dlp-guard" || words.some((w) => /agy-dlp(?:-guard)?(?:\.mjs)?$/.test(w))) {
      const tIdx = args.findIndex((a) => /^toggle$/i.test(a));
      if (
        args.some((a) => /^(?:uninstall|off|disable)$/i.test(a)) ||
        (tIdx !== -1 && /^(?:off|false|0|disable)$/i.test(args[tIdx + 1] || ""))
      ) {
        return deny(cmdName || "agy-dlp", "integrità del guardiano: disattivazione non consentita dall'agente");
      }
    }
    if (cmdName === "pi" && args.some((a) => /^(?:uninstall|remove|disable)$/i.test(a)) && args.some((a) => /dlp-guard/i.test(a))) {
      return deny("pi", "integrità del guardiano: rimozione di pi-dlp-guard non consentita dall'agente");
    }

    if (pipedFromDecoder && (SHELLS.has(cmdName) || cmdName === "eval" || cmdName === "source" || cmdName === ".")) {
      return deny(cmdName, "esecuzione di payload decodificato in pipe verso shell vietata");
    }

    if (cmdName === "cd" || cmdName === "pushd") {
      if (args[0]) {
        const resolved = resolveTargetCandidates(args[0], vars).pop() || args[0];
        here = path.resolve(here, expandHome(resolved, here));
      }
      pipedArgs = [];
      pipedFromDecoder = false;
      continue;
    }

    if (SHELLS.has(cmdName)) {
      const cIdx = args.indexOf("-c");
      if (cIdx !== -1 && args[cIdx + 1]) nested.push(args[cIdx + 1]);
      else if (config.blockReaderCommandsOnProtected) {
        for (const a of args.filter((x) => !x.startsWith("-"))) {
          const hit = checkTarget(a, "read", `esecuzione/lettura tramite ${cmdName}`);
          if (hit) return hit;
        }
      }
    }
    if (cmdName === "eval") nested.push(args.join(" "));

    for (const t of redirects) {
      const hit = checkTarget(t, "write");
      if (hit) return hit;
    }
    if (config.blockReaderCommandsOnProtected) {
      for (const t of inputRedirects) {
        const hit = checkTarget(t, "read", "redirezione di lettura non autorizzata");
        if (hit) return hit;
      }
    }

    if (cmdName === "dd") {
      for (const a of args) {
        if (a.startsWith("if=") && config.blockReaderCommandsOnProtected) {
          const hit = checkTarget(a.slice(3), "read", "lettura tramite dd");
          if (hit) return hit;
        } else if (a.startsWith("of=")) {
          const hit = checkTarget(a.slice(3), "write");
          if (hit) return hit;
        }
      }
    }

    const inPlace = IN_PLACE_EDITORS.has(cmdName) && args.some((a) => /^-[A-Za-z]*i|^--in-place/.test(a));
    if (MUTATORS.has(cmdName) || inPlace) {
      const targets = cmdName === "sed" ? args.filter((a, idx) => !a.startsWith("-") && idx > 0) : args.filter((a) => !a.startsWith("-"));
      for (const t of targets) {
        const hit = checkTarget(t, "write");
        if (hit) return hit;
      }
    }

    if (config.blockReaderCommandsOnProtected && READERS.has(cmdName)) {
      for (const t of args.filter((a) => !a.startsWith("-"))) {
        const hit = checkTarget(t, "read", `lettura non autorizzata tramite ${cmdName}`);
        if (hit) return hit;
      }
    }

    if (config.blockReaderCommandsOnProtected && GREP_CMDS.has(cmdName)) {
      let hasPat = false;
      const pos: string[] = [];
      const optArg = new Set(["-m", "-A", "-B", "-C", "-g", "-t", "--max-count", "--after-context", "--before-context", "--context", "--glob", "--type", "--include", "--exclude", "--exclude-dir", "--color"]);
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        if (a === "-e" || a === "--regexp") {
          hasPat = true;
          j++;
        } else if (a.startsWith("--regexp=")) hasPat = true;
        else if (a === "-f" || a === "--file") {
          hasPat = true;
          if (args[j + 1]) {
            const hit = checkTarget(args[++j], "read", `lettura file pattern tramite ${cmdName}`);
            if (hit) return hit;
          }
        } else if (a.startsWith("--file=")) {
          hasPat = true;
          const hit = checkTarget(a.slice(7), "read", `lettura file pattern tramite ${cmdName}`);
          if (hit) return hit;
        } else if (optArg.has(a)) j++;
        else if (!a.startsWith("-")) pos.push(a);
      }
      for (const t of hasPat ? pos : pos.slice(1)) {
        const hit = checkTarget(t, "read", `ricerca/lettura tramite ${cmdName}`);
        if (hit) return hit;
      }
    }

    if (config.blockReaderCommandsOnProtected && (cmdName === "sed" || AWK_CMDS.has(cmdName) || JQ_CMDS.has(cmdName))) {
      let hasExpr = false;
      const pos: string[] = [];
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        if (a === "-f" || a === "--file" || a === "--from-file") {
          hasExpr = true;
          if (args[j + 1]) {
            const hit = checkTarget(args[++j], "read", `lettura tramite ${cmdName}`);
            if (hit) return hit;
          }
        } else if (a.startsWith("--file=")) {
          hasExpr = true;
          const hit = checkTarget(a.slice(7), "read", `lettura tramite ${cmdName}`);
          if (hit) return hit;
        } else if (a === "-e" || a === "--expression") {
          hasExpr = true;
          j++;
        } else if (a === "-F" || a === "-v") j++;
        else if ((a === "--slurpfile" || a === "--rawfile") && j + 2 < args.length) {
          const hit = checkTarget(args[j + 2], "read", `lettura tramite ${cmdName}`);
          if (hit) return hit;
          j += 2;
        } else if ((a === "--arg" || a === "--argjson") && j + 2 < args.length) j += 2;
        else if (!a.startsWith("-")) pos.push(a);
      }
      for (const t of hasExpr ? pos : pos.slice(1)) {
        const hit = checkTarget(t, "read", `lettura non autorizzata tramite ${cmdName}`);
        if (hit) return hit;
      }
    }

    if (ARCHIVERS.has(cmdName)) {
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        if ((a === "-C" || a === "--directory" || a === "-f" || a === "--file") && args[j + 1]) {
          const hit = checkTarget(args[++j], "write");
          if (hit) return hit;
        } else if (!a.startsWith("-")) {
          if (config.blockReaderCommandsOnProtected) {
            const hitR = checkTarget(a, "read", `archiviazione tramite ${cmdName}`);
            if (hitR) return hitR;
          }
          const hitW = checkTarget(a, "write");
          if (hitW) return hitW;
        }
      }
    }

    if (cmdName === "find") {
      const hasDel = args.includes("-delete");
      const execIdx = args.findIndex((a) => a === "-exec" || a === "-execdir" || a === "-ok");
      const targets: string[] = [];
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        if (a === "-exec" || a === "-execdir" || a === "-ok") break;
        if ((a === "-name" || a === "-iname" || a === "-path" || a === "-wholename") && args[j + 1]) targets.push(args[++j]);
        else if (!a.startsWith("-") && a !== "!" && a !== ";") targets.push(a);
      }
      for (const t of targets) {
        if (hasDel) {
          const hit = checkTarget(t, "write");
          if (hit) return hit;
        }
        if (config.blockReaderCommandsOnProtected && (execIdx !== -1 || t !== ".")) {
          const hit = checkTarget(t, "read", "ricerca find su percorso protetto");
          if (hit) return hit;
        }
      }
      if (execIdx !== -1) {
        const execTokens = args
          .slice(execIdx + 1)
          .filter((a) => a !== ";" && a !== "\\;" && a !== "+")
          .map((a) => (a === "{}" && targets[0] ? targets[0] : a));
        if (execTokens.length) nested.push(execTokens.join(" "));
      }
    }

    if (cmdName === "git" && config.blockReaderCommandsOnProtected) {
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        let cand: string | null = null;
        if (a.startsWith("--file=")) cand = a.slice(7);
        else if ((a === "-f" || a === "--file") && args[0] === "config" && args[j + 1]) cand = args[++j];
        else if (!a.startsWith("-") && j > 0) cand = a.includes(":") && !a.includes("://") ? (a.split(":").pop() ?? a) : a;
        if (cand) {
          const hit = checkTarget(cand, "read", "accesso git a percorso protetto");
          if (hit) return hit;
        }
      }
    }

    if (cmdName === "openssl") {
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        if ((a === "-in" || a === "-inkey" || a === "-certin") && args[j + 1] && config.blockReaderCommandsOnProtected) {
          const hit = checkTarget(args[++j], "read", "lettura tramite openssl");
          if (hit) return hit;
        } else if (a.startsWith("file:") && config.blockReaderCommandsOnProtected) {
          const hit = checkTarget(a.slice(5), "read", "lettura tramite openssl");
          if (hit) return hit;
        } else if ((a === "-out" || a === "-keyout") && args[j + 1]) {
          const hit = checkTarget(args[++j], "write");
          if (hit) return hit;
        }
      }
    }

    if (cmdName === "scp" || cmdName === "sftp") {
      for (const a of args.filter((x) => !x.startsWith("-"))) {
        const local = a.includes(":") && !a.includes("://") ? (a.split(":").pop() ?? a) : a;
        if (config.blockReaderCommandsOnProtected) {
          const hitR = checkTarget(local, "read", `trasferimento tramite ${cmdName}`);
          if (hitR) return hitR;
        }
        const hitW = checkTarget(local, "write");
        if (hitW) return hitW;
      }
    }

    if (INTERPRETERS.has(cmdName)) {
      const codeFlags = new Set(["-c", "-e", "-p", "-r", "--eval", "--print", "eval"]);
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        if (codeFlags.has(a) && args[j + 1]) {
          const code = args[++j];
          const mut = /\b(?:write|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|unlinkSync|rm|rmSync|rmdir|remove|removedirs|rmtree|rename|replace|chmod|chown|truncate|copyFile|cpSync|shutil)\b/i.test(code);
          for (const lit of extractStringLiterals(code)) {
            if (config.blockReaderCommandsOnProtected) {
              const hitR = checkTarget(lit, "read", `accesso tramite script inline ${cmdName}`);
              if (hitR) return hitR;
            }
            if (mut) {
              const hitW = checkTarget(lit, "write", `modifica tramite script inline ${cmdName}`);
              if (hitW) return hitW;
            }
          }
        } else if (!a.startsWith("-") && config.blockReaderCommandsOnProtected) {
          const hit = checkTarget(a, "read", `esecuzione/lettura tramite ${cmdName}`);
          if (hit) return hit;
        }
      }
    }

    if (cmdName === "curl") {
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        let rT: string | null = null;
        let wT: string | null = null;
        if (a.startsWith("@")) rT = a.slice(1);
        else if (a.includes("=@")) rT = a.split("=@")[1];
        else if ((a === "-T" || a === "--upload-file") && args[j + 1]) rT = args[++j];
        else if ((a === "-o" || a === "--output") && args[j + 1]) wT = args[++j];
        else if (a.startsWith("--output=")) wT = a.slice(9);
        if (rT) {
          const hit = checkTarget(rT, "read", "esfiltrazione tramite curl");
          if (hit) return hit;
        }
        if (wT) {
          const hit = checkTarget(wT, "write");
          if (hit) return hit;
        }
      }
    }

    if (cmdName === "wget") {
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        let rT: string | null = null;
        let wT: string | null = null;
        if (a.startsWith("--post-file=")) rT = a.slice(12);
        else if (a === "--post-file" && args[j + 1]) rT = args[++j];
        else if ((a === "-O" || a === "--output-document" || a === "-P" || a === "--directory-prefix") && args[j + 1]) wT = args[++j];
        else if (a.startsWith("--output-document=")) wT = a.slice(18);
        else if (a.startsWith("--directory-prefix=")) wT = a.slice(19);
        if (rT) {
          const hit = checkTarget(rT, "read", "esfiltrazione tramite wget");
          if (hit) return hit;
        }
        if (wT) {
          const hit = checkTarget(wT, "write");
          if (hit) return hit;
        }
      }
    }

    if (pipedToNext) {
      if (cmdName === "echo" || cmdName === "printf") {
        pipedArgs = args.filter((a) => !a.startsWith("-"));
        pipedFromDecoder = false;
      } else if ((cmdName === "base64" && args.some((a) => /^-(?:d|D|-decode)$/.test(a))) || (cmdName === "xxd" && args.includes("-r"))) {
        pipedFromDecoder = true;
        for (const cand of pipedArgs) {
          try {
            const dec = Buffer.from(cand, "base64").toString("utf-8");
            if (dec && /^[\x20-\x7e\s]+$/.test(dec)) nested.push(dec);
          } catch {
            // Ignore invalid base64
          }
        }
      } else {
        pipedArgs = [];
        pipedFromDecoder = false;
      }
    } else {
      pipedArgs = [];
      pipedFromDecoder = false;
    }
  }

  for (const inner of nested) {
    const res = checkBashCommand(inner, config, here, depth + 1);
    if (res.block) return res;
  }
  return { block: false };
}

// -----------------------------------------------------------------------------
// Extension Entry Point
// -----------------------------------------------------------------------------

const PATH_KEYS = [
  "path",
  "Path",
  "file",
  "File",
  "file_path",
  "filePath",
  "FilePath",
  "target_file",
  "targetFile",
  "TargetFile",
  "target_path",
  "targetPath",
  "TargetPath",
  "notebook_path",
  "NotebookPath",
  "source",
  "Source",
  "destination",
  "Destination",
  "directory",
  "Directory",
  "dir_path",
  "dirPath",
  "DirPath",
  "search_path",
  "searchPath",
  "SearchPath",
  "paths",
  "Paths",
  "files",
  "Files",
];

const WRITE_TOOL = /write|edit|replace|patch|create|delete|remove|move|rename|update/i;
const OUTBOUND_TOOL = /search|web|fetch|http|url|curl|request|send|post|mcp/i;

function pathsOf(input: Record<string, unknown>): string[] {
  return PATH_KEYS.flatMap((k) => (Array.isArray(input[k]) ? (input[k] as unknown[]) : [input[k]]))
    .filter((v): v is string => typeof v === "string" && v.trim().length > 0)
    .map((v) => v.trim());
}

function extractWriteTexts(input: Record<string, unknown>): string {
  const chunks: string[] = [];
  for (const k of ["content", "Content", "replacement", "Replacement", "replacementContent", "ReplacementContent", "newText", "new_str"]) {
    if (typeof input[k] === "string" && input[k]) chunks.push(input[k] as string);
  }
  const list = input.edits || input.Edits || input.replacementChunks || input.ReplacementChunks;
  if (Array.isArray(list)) {
    for (const item of list) {
      if (item && typeof item === "object") {
        const rec = item as Record<string, unknown>;
        const txt = rec.newText || rec.new_str || rec.replacement || rec.Replacement || rec.replacementContent || rec.ReplacementContent || rec.content || "";
        if (typeof txt === "string" && txt) chunks.push(txt);
      }
    }
  }
  return chunks.join("\n");
}

function extractOutboundTexts(input: Record<string, unknown>): string {
  const pathSet = new Set(PATH_KEYS);
  const out: string[] = [];
  for (const [k, v] of Object.entries(input)) {
    if (pathSet.has(k)) continue;
    if (typeof v === "string" && v) out.push(v);
  }
  return out.join(" ");
}

type Part = { type?: string; text?: string };

function redactParts(content: unknown, redact: (s: string) => string): unknown {
  if (typeof content === "string") return redact(content);
  if (!Array.isArray(content)) return content;
  return content.map((p: Part) => (p?.type === "text" && typeof p.text === "string" ? { ...p, text: redact(p.text) } : p));
}

export default function (pi: ExtensionAPI) {
  let config = loadConfig();
  let enabled = config.enabled;

  pi.on("tool_call", async (event, ctx) => {
    if (!enabled) return undefined;
    const input = (event.input || {}) as Record<string, unknown>;
    const toolName = String(event.toolName || "");
    const cwd = process.cwd();
    let reason: string | undefined;

    if (toolName === "bash" || toolName === "run_command") {
      const cmd = (input.command ?? input.CommandLine ?? input.cmd) as string | undefined;
      if (typeof cmd === "string") reason = checkBashCommand(cmd, config, cwd).reason;
    } else {
      const isWrite = WRITE_TOOL.test(toolName);
      const op = isWrite ? "write" : "read";
      const targets = pathsOf(input);
      for (const target of targets) {
        const check = isPathProtected(target, config, cwd, op);
        if (check.protected) {
          reason = `${target}: ${check.reason}`;
          break;
        }
      }
      if (!reason && isWrite && config.blockWriteSecrets) {
        const hit = detectSecrets(extractWriteTexts(input), config, true);
        if (hit) reason = `${targets[0] || toolName}: rilevata credenziale o segreto in chiaro (${hit.category})`;
      }
      if (!reason && (OUTBOUND_TOOL.test(toolName) || (!isWrite && targets.length === 0))) {
        const hit = detectSecrets(extractOutboundTexts(input), config, false);
        if (hit) reason = `${toolName}: esfiltrazione bloccata, rilevato segreto nella richiesta (${hit.category})`;
      }
    }

    if (!reason) return undefined;
    if (ctx?.hasUI) ctx.ui.notify(`🛑 [DLP Guard] ${reason}`, "error");
    return { block: true, reason: `🛑 [DLP Guard] ${reason}` };
  });

  pi.on("tool_result", async (event) => {
    if (!enabled || !Array.isArray(event.content)) return undefined;
    const content = redactParts(event.content, (s) => redactSecrets(s, config, true));
    return JSON.stringify(content) === JSON.stringify(event.content) ? undefined : { content: content as typeof event.content };
  });

  pi.on("context", async (event) => {
    if (!enabled || !Array.isArray(event.messages)) return undefined;
    let changed = false;
    const messages = event.messages.map((m) => {
      const content = redactParts((m as { content?: unknown }).content, (s) => redactSecrets(s, config, false));
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
      else if (arg === "reload") {
        config = loadConfig();
        enabled = config.enabled;
      }
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
