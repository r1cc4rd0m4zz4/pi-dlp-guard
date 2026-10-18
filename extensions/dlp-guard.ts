/**
 * pi-dlp-guard: Zero-dependency DLP, Path Protection & Secret Redaction Guard
 *
 * Architecture:
 * 1. Path Guard: Dual-layer lexical + canonical realpath (anti-traversal & anti-symlinks).
 * 2. Bash Tool Guard: Lexer scanning arguments and shell redirections (<, >, >>).
 * 3. Hawking Black Hole Redaction: Deterministic, irreversible redaction with relational
 *    preservation ([REDACTED_<CATEGORY>_#<ID>]) on tool_result and wire context.
 * 4. Dual-Core Engine: Ultra-fast in-process regex (<0.05ms) + optional gitleaks via pipe
 *    for pre-commit staged diffs and large buffers.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as cp from "node:child_process";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export interface DlpGuardConfig {
  protectedPaths: string[];
  enableGitleaks: boolean;
  gitleaksMinBytes: number;
  gitleaksTimeoutMs: number;
}

export const DEFAULT_CONFIG: DlpGuardConfig = {
  protectedPaths: [
    ".env*",
    ".git",
    "**/.git/**",
    "~/.ssh",
    "~/.ssh/**",
    "~/.aws",
    "~/.aws/**",
    "~/.gnupg",
    "~/.gnupg/**",
    "~/.netrc",
    "**/*.pem",
    "**/*.key",
    "**/id_rsa*",
    "**/id_ed25519*",
  ],
  enableGitleaks: true,
  gitleaksMinBytes: 4096,
  gitleaksTimeoutMs: 500,
};

const CONFIG_FILE_PATH = path.join(os.homedir(), ".pi", "agent", "dlp-guard.json");

export function loadConfig(): DlpGuardConfig {
  try {
    if (fs.existsSync(CONFIG_FILE_PATH)) {
      const raw = fs.readFileSync(CONFIG_FILE_PATH, "utf-8");
      const parsed = JSON.parse(raw);
      return {
        protectedPaths: Array.isArray(parsed.protectedPaths) ? parsed.protectedPaths : DEFAULT_CONFIG.protectedPaths,
        enableGitleaks: typeof parsed.enableGitleaks === "boolean" ? parsed.enableGitleaks : DEFAULT_CONFIG.enableGitleaks,
        gitleaksMinBytes: typeof parsed.gitleaksMinBytes === "number" ? parsed.gitleaksMinBytes : DEFAULT_CONFIG.gitleaksMinBytes,
        gitleaksTimeoutMs: typeof parsed.gitleaksTimeoutMs === "number" ? parsed.gitleaksTimeoutMs : DEFAULT_CONFIG.gitleaksTimeoutMs,
      };
    }
    // Auto-create default configuration file if absent
    fs.mkdirSync(path.dirname(CONFIG_FILE_PATH), { recursive: true, mode: 0o700 });
    fs.writeFileSync(CONFIG_FILE_PATH, JSON.stringify(DEFAULT_CONFIG, null, 2), { mode: 0o600 });
  } catch {
    // Non-blocking fallback to defaults
  }
  return { ...DEFAULT_CONFIG };
}

// -----------------------------------------------------------------------------
// Hawking Relational Redaction Engine
// -----------------------------------------------------------------------------

// Session maps for relational preservation (A == A)
const secretToToken = new Map<string, string>();
const categoryCounters = new Map<string, number>();

export function resetSessionState(): void {
  secretToToken.clear();
  categoryCounters.clear();
}

function getRelationalToken(secret: string, category: string): string {
  const existing = secretToToken.get(secret);
  if (existing) {
    return existing;
  }
  const currentCount = (categoryCounters.get(category) || 0) + 1;
  categoryCounters.set(category, currentCount);
  const token = `[REDACTED_${category}_#${currentCount}]`;
  secretToToken.set(secret, token);
  return token;
}

interface SecretCategoryRule {
  category: string;
  regex: RegExp;
  extractSecret?: (match: RegExpExecArray) => string;
}

const CATEGORY_RULES: SecretCategoryRule[] = [
  {
    category: "AWS_KEY",
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    extractSecret: (m) => m[1],
  },
  {
    category: "GITHUB_TOKEN",
    regex: /\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b/g,
    extractSecret: (m) => m[1],
  },
  {
    category: "PRIVATE_KEY",
    regex: /(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)/g,
    extractSecret: (m) => m[1],
  },
  {
    category: "SLACK_TOKEN",
    regex: /\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b/g,
    extractSecret: (m) => m[1],
  },
  {
    category: "OPENAI_KEY",
    regex: /\b(sk-[a-zA-Z0-9]{20,T3BlbkFJ[a-zA-Z0-9]{20,})\b|\b(sk-proj-[a-zA-Z0-9_\-]{40,})\b/g,
    extractSecret: (m) => m[1] || m[2] || m[0],
  },
  {
    category: "STRIPE_KEY",
    regex: /\b([rs]k_live_[0-9a-zA-Z]{24,})\b/g,
    extractSecret: (m) => m[1],
  },
  {
    category: "ENV_SECRET",
    regex: /(?:^|[\r\n])\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|AUTH|PRIVATE)[A-Za-z0-9_]*)\s*=\s*(["']?)([^\r\n"']+)\2/gi,
    extractSecret: (m) => m[3],
  },
  {
    category: "GENERIC_SECRET",
    regex: /(?:api[_-]?key|secret[_-]?token|auth[_-]?token|bearer[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9\-_./+=]{16,})["']?/gi,
    extractSecret: (m) => m[1],
  },
];

let gitleaksAvailable: boolean | null = null;
function isGitleaksAvailable(): boolean {
  if (gitleaksAvailable !== null) return gitleaksAvailable;
  try {
    const res = cp.spawnSync("gitleaks", ["version"], { timeout: 500, stdio: "ignore" });
    gitleaksAvailable = res.status === 0;
  } catch {
    gitleaksAvailable = false;
  }
  return gitleaksAvailable;
}

export function scanWithGitleaks(text: string, timeoutMs = 500): string[] {
  if (!isGitleaksAvailable()) return [];
  try {
    const child = cp.spawnSync("gitleaks", ["detect", "--pipe", "--report-format", "json", "--report-path", "/dev/stdout"], {
      input: text,
      timeout: timeoutMs,
      encoding: "utf-8",
      maxBuffer: 5 * 1024 * 1024,
    });
    // Gitleaks returns exit code 1 when leaks are detected
    if (child.stdout) {
      const parsed = JSON.parse(child.stdout);
      if (Array.isArray(parsed)) {
        return parsed.map((item: any) => item.Secret || item.Match).filter(Boolean);
      }
    }
  } catch {
    // Non-blocking fallback
  }
  return [];
}

export function redactSecrets(text: string, config: DlpGuardConfig = DEFAULT_CONFIG): string {
  if (!text || typeof text !== "string") return text;
  let result = text;

  // 1. In-process deterministic regex replacement
  for (const rule of CATEGORY_RULES) {
    result = result.replace(rule.regex, (...args) => {
      const match = args[0];
      const matchArray = [match, ...args.slice(1, -2)] as unknown as RegExpExecArray;
      const secret = rule.extractSecret ? rule.extractSecret(matchArray) : match;
      if (!secret || secret.trim().length === 0) return match;

      const token = getRelationalToken(secret, rule.category);
      return match.replace(secret, token);
    });
  }

  // 2. Optional gitleaks pipe on large buffers
  if (config.enableGitleaks && result.length >= config.gitleaksMinBytes) {
    const gitleaksSecrets = scanWithGitleaks(result, config.gitleaksTimeoutMs);
    for (const secret of gitleaksSecrets) {
      if (secret && secret.length >= 8) {
        const token = getRelationalToken(secret, "GITLEAKS");
        result = result.split(secret).join(token);
      }
    }
  }

  return result;
}

// -----------------------------------------------------------------------------
// Path Canonicalization & Protection Engine (Mitnick Vector: Traversal & Symlinks)
// -----------------------------------------------------------------------------

function expandTilde(p: string): string {
  if (p === "~" || p.startsWith("~/") || p.startsWith("~\\")) {
    return path.join(os.homedir(), p.slice(1));
  }
  return p;
}

const INTRINSIC_PROTECTED_PATTERNS = [
  /(?:^|[\/\\])\.env(?:[\.\-_].*)?$/i,
  /(?:^|[\/\\])\.git(?:[\/\\]|$)/i,
  /(?:^|[\/\\])(?:\.ssh|\.aws|\.gnupg|\.netrc)(?:[\/\\]|$)/i,
  /\.(?:pem|key)$/i,
  /(?:^|[\/\\])id_(?:rsa|ed25519)(?:[\.\-_].*)?$/i,
];

export function isPathProtected(
  targetPath: string,
  config: DlpGuardConfig = DEFAULT_CONFIG,
  cwd: string = process.cwd()
): { protected: boolean; reason?: string } {
  if (!targetPath || typeof targetPath !== "string") {
    return { protected: false };
  }

  const rawNormalized = targetPath.trim().replace(/\\/g, "/");
  const expanded = expandTilde(rawNormalized);
  const resolved = path.resolve(cwd, expanded);

  // Layer 1: Lexical check on raw string, expanded string, and resolved path
  for (const pattern of INTRINSIC_PROTECTED_PATTERNS) {
    if (pattern.test(rawNormalized) || pattern.test(expanded) || pattern.test(resolved)) {
      return {
        protected: true,
        reason: `Percorso riservato intercettato da regola di sicurezza intrinseca (${path.basename(resolved)})`,
      };
    }
  }

  // Check against configured protected paths
  const homeDir = os.homedir();
  for (const configured of config.protectedPaths) {
    const cfgExpanded = expandTilde(configured.replace(/\\/g, "/"));
    const cfgResolved = path.resolve(cwd, cfgExpanded);

    // Exact or prefix match
    if (resolved === cfgResolved || resolved.startsWith(cfgResolved + path.sep)) {
      return {
        protected: true,
        reason: `Percorso protetto configurato in dlp-guard.json: "${configured}"`,
      };
    }

    // Basename / wildcards match
    const base = path.basename(resolved);
    if (configured.startsWith(".env") && base.startsWith(".env")) {
      return {
        protected: true,
        reason: `File d'ambiente protetto: "${base}"`,
      };
    }
  }

  // Layer 2: Canonical realpath check (Mitnick traversal & symlink defense)
  try {
    if (fs.existsSync(resolved)) {
      const canonical = fs.realpathSync(resolved);
      const canonicalNorm = canonical.replace(/\\/g, "/");

      // Check if canonical target lands inside ~/.ssh, ~/.aws, .git, or matches .env
      const canonicalHome = homeDir.replace(/\\/g, "/");
      if (
        canonicalNorm.startsWith(canonicalHome + "/.ssh") ||
        canonicalNorm.startsWith(canonicalHome + "/.aws") ||
        canonicalNorm.startsWith(canonicalHome + "/.gnupg") ||
        /(?:^|[\/\\])\.env(?:[\.\-_].*)?$/i.test(canonicalNorm) ||
        /(?:^|[\/\\])\.git(?:[\/\\]|$)/i.test(canonicalNorm) ||
        /\.(?:pem|key)$/i.test(canonicalNorm)
      ) {
        return {
          protected: true,
          reason: `Risoluzione symlink/canonica punta a un percorso protetto (${canonical})`,
        };
      }
    }
  } catch {
    // If realpath resolution fails, lexical check already guarded the operation
  }

  return { protected: false };
}

// -----------------------------------------------------------------------------
// Bash Lexer & Redirection Inspection Guard
// -----------------------------------------------------------------------------

export function checkBashCommand(
  cmd: string,
  config: DlpGuardConfig = DEFAULT_CONFIG,
  cwd: string = process.cwd()
): { block: boolean; reason?: string } {
  if (!cmd || typeof cmd !== "string") {
    return { block: false };
  }

  const trimmed = cmd.trim();

  // 1. Redirection inspection: < file, > file, >> file, | tee file
  const redirectionRegex = /(?:<|>|>>|\|\s*tee\s+(?:-a\s+)?)\s*([^\s;&|]+)/g;
  let match: RegExpExecArray | null;
  while ((match = redirectionRegex.exec(trimmed)) !== null) {
    const rawTarget = match[1].replace(/["']/g, "");
    const check = isPathProtected(rawTarget, config, cwd);
    if (check.protected) {
      return {
        block: true,
        reason: `Redirezione shell non consentita verso percorso protetto: ${rawTarget} (${check.reason})`,
      };
    }
  }

  // 2. Token / Argument inspection: split on whitespace ignoring quoted regions
  const tokens = trimmed.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
  for (const token of tokens) {
    const cleanToken = token.replace(/^["']|["']$/g, "");
    if (!cleanToken || cleanToken.startsWith("-")) continue;

    // Check if token resolves to a protected file
    if (
      cleanToken.includes(".env") ||
      cleanToken.includes(".ssh") ||
      cleanToken.includes(".aws") ||
      cleanToken.includes(".git") ||
      cleanToken.endsWith(".pem") ||
      cleanToken.endsWith(".key") ||
      cleanToken.includes("id_rsa") ||
      cleanToken.includes("id_ed25519")
    ) {
      const check = isPathProtected(cleanToken, config, cwd);
      if (check.protected) {
        return {
          block: true,
          reason: `Comando shell bloccato: argomento "${cleanToken}" punta a percorso protetto (${check.reason})`,
        };
      }
    }
  }

  // 3. Staged diff pre-commit scan
  if (/\bgit\s+commit\b/i.test(trimmed)) {
    try {
      const stagedDiff = cp.execSync("git diff --cached", {
        cwd,
        encoding: "utf-8",
        timeout: 2000,
        stdio: ["ignore", "pipe", "ignore"],
      });

      if (stagedDiff) {
        // Run regex checks
        const hasSecret = CATEGORY_RULES.some((rule) => {
          rule.regex.lastIndex = 0;
          return rule.regex.test(stagedDiff);
        });

        if (hasSecret) {
          return {
            block: true,
            reason: "🔒 [DLP Alert] Commit bloccato: rilevata una chiave o token segreto nei file in staging. 👉 Rimuovi il file con 'git reset <file>' prima di committare.",
          };
        }

        // Run gitleaks if enabled
        if (config.enableGitleaks && isGitleaksAvailable()) {
          const leaks = scanWithGitleaks(stagedDiff, config.gitleaksTimeoutMs);
          if (leaks.length > 0) {
            return {
              block: true,
              reason: `🔒 [DLP Alert] Gitleaks ha rilevato ${leaks.length} credenziali o token nei file in staging. Commit rifiutato.`,
            };
          }
        }
      }
    } catch {
      // Non-blocking if git diff fails (e.g. not a git repo)
    }
  }

  return { block: false };
}

// -----------------------------------------------------------------------------
// Extension Main Entrypoint
// -----------------------------------------------------------------------------

export default function (pi: ExtensionAPI) {
  let config = loadConfig();
  let isEnabled = true;

  // 1. Tool Call Guard: Read/Write/Edit & Bash
  pi.on("tool_call", async (event, ctx) => {
    if (!isEnabled) return undefined;
    const toolName = event.toolName;
    const input = (event.input || {}) as Record<string, unknown>;

    // Intercept File Operations (read, write, edit)
    if (toolName === "read" || toolName === "write" || toolName === "edit") {
      const targetPath = String(input.path || input.file || "");
      const check = isPathProtected(targetPath, config, process.cwd());
      if (check.protected) {
        if (ctx.hasUI) {
          ctx.ui.notify(`🛑 [DLP Guard] Bloccato accesso al percorso: ${targetPath}`, "error");
        }
        return {
          block: true,
          reason: `🛑 [DLP Guard] Operazione non consentita su percorso protetto: ${targetPath}. ${check.reason}`,
        };
      }
    }

    // Intercept Bash Shell Commands
    if (toolName === "bash" && typeof input.command === "string") {
      const check = checkBashCommand(input.command, config, process.cwd());
      if (check.block) {
        if (ctx.hasUI) {
          ctx.ui.notify(`🛑 [DLP Guard] Comando shell bloccato: ${check.reason}`, "error");
        }
        return {
          block: true,
          reason: `🛑 [DLP Guard] ${check.reason}`,
        };
      }
    }

    return undefined;
  });

  // 2. Dual Horizon - Horizon 1: Immediate Transcript & Tool Output Sanitization
  pi.on("tool_result", async (event) => {
    if (!isEnabled || !Array.isArray(event.content)) return undefined;

    let modified = false;
    const sanitizedContent = event.content.map((part) => {
      if (part.type === "text" && typeof part.text === "string") {
        const redacted = redactSecrets(part.text, config);
        if (redacted !== part.text) {
          modified = true;
          return { ...part, text: redacted };
        }
      }
      return part;
    });

    if (modified) {
      return { content: sanitizedContent };
    }
    return undefined;
  });

  // 3. Dual Horizon - Horizon 2: Outbound Context / Wire Sanitization
  pi.on("context", async (event) => {
    if (!isEnabled || !Array.isArray(event.messages)) return undefined;

    let modified = false;
    const sanitizedMessages = event.messages.map((msg) => {
      if (typeof msg.content === "string") {
        const redacted = redactSecrets(msg.content, config);
        if (redacted !== msg.content) {
          modified = true;
          return { ...msg, content: redacted };
        }
      } else if (Array.isArray(msg.content)) {
        let partsModified = false;
        const newParts = msg.content.map((part) => {
          if (part.type === "text" && typeof part.text === "string") {
            const redacted = redactSecrets(part.text, config);
            if (redacted !== part.text) {
              partsModified = true;
              return { ...part, text: redacted };
            }
          }
          return part;
        });
        if (partsModified) {
          modified = true;
          return { ...msg, content: newParts };
        }
      }
      return msg;
    });

    if (modified) {
      return { messages: sanitizedMessages };
    }
    return undefined;
  });

  // 4. Interactive Command: /dlp
  pi.registerCommand("dlp", {
    description: "Gestisci la protezione DLP (/dlp on | off | reload | status)",
    handler: async (args, ctx) => {
      const arg = (args || "").trim().toLowerCase();
      if (arg === "off" || arg === "disable") {
        isEnabled = false;
        ctx.ui.notify("⚠️ [DLP Guard] Protezione DLP DISATTIVATA temporaneamente per questa sessione.", "warning");
        return;
      }
      if (arg === "on" || arg === "enable") {
        isEnabled = true;
        ctx.ui.notify("🛡️ [DLP Guard] Protezione DLP ATTIVATA.", "info");
        return;
      }
      if (arg === "reload") {
        config = loadConfig();
        ctx.ui.notify("🔄 [DLP Guard] Configurazione ricaricata da dlp-guard.json.", "info");
        return;
      }

      config = loadConfig();
      const status = [
        "🛡️ **pi-dlp-guard Status**:",
        `- Stato protezione: ${isEnabled ? "✅ ATTIVA" : "⚠️ DISATTIVATA"}`,
        `- Gitleaks integration: ${config.enableGitleaks ? (isGitleaksAvailable() ? "✅ Attivo" : "⚠️ Non trovato nel PATH") : "Disabilitato"}`,
        `- Segreti tracciati in sessione: ${secretToToken.size}`,
        `- Percorsi protetti (${config.protectedPaths.length}):`,
        ...config.protectedPaths.slice(0, 10).map((p) => `  • ${p}`),
        config.protectedPaths.length > 10 ? `  ... altri ${config.protectedPaths.length - 10} percorsi` : "",
        "",
        "💡 Comandi disponibili: /dlp on | /dlp off | /dlp reload | /dlp status",
      ]
        .filter(Boolean)
        .join("\n");

      ctx.ui.notify(status, "info");
    },
  });
}
