/**
 * Deterministic Test Suite for pi-dlp-guard
 * Covers all 4 Acceptance Groups:
 * Group 1: Path Traversal, Symlinks & Protected Paths
 * Group 2: Bash Shell Lexer, Redirections & Commands
 * Group 3: DLP Redaction, Semantic Types & Relational Preservation (A == A)
 * Group 4: Gitleaks Dual-Core & Graceful Fallback
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  isPathProtected,
  checkBashCommand,
  redactSecrets,
  scanWithGitleaks,
  resetSessionState,
  DEFAULT_CONFIG,
} from "../extensions/dlp-guard.ts";

console.log("🚀 Starting deterministic regression suite for pi-dlp-guard...\n");

let passed = 0;
let total = 0;

function test(name, fn) {
  total++;
  try {
    fn();
    passed++;
    console.log(`  ✅ [PASS] ${name}`);
  } catch (err) {
    console.error(`  ❌ [FAIL] ${name}`);
    console.error(err);
    process.exitCode = 1;
  }
}

// =============================================================================
// Group 1: Path Guard (Traversal, Symlinks, Protected Targets)
// =============================================================================
console.log("--- Group 1: Path Guard & Traversal Defense ---");

test("Direct .env protection", () => {
  assert.equal(isPathProtected(".env").protected, true);
  assert.equal(isPathProtected(".env.local").protected, true);
  assert.equal(isPathProtected(".env.production").protected, true);
});

test("Directory traversal on .env", () => {
  assert.equal(isPathProtected("./.env").protected, true);
  assert.equal(isPathProtected("../../.env").protected, true);
  assert.equal(isPathProtected("sub/dir/../../.env").protected, true);
});

test("Critical credentials & key paths", () => {
  assert.equal(isPathProtected("~/.ssh/id_rsa").protected, true);
  assert.equal(isPathProtected("~/.aws/credentials").protected, true);
  assert.equal(isPathProtected(".git/config").protected, true);
  assert.equal(isPathProtected("certs/server.pem").protected, true);
  assert.equal(isPathProtected("keys/private.key").protected, true);
});

test("Symlink resolution to protected file (Mitnick Vector)", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-dlp-test-"));
  try {
    const realEnv = path.join(tmpDir, ".env");
    const fakeLink = path.join(tmpDir, "innocent.txt");
    fs.writeFileSync(realEnv, "SECRET=xyz\n");
    fs.symlinkSync(realEnv, fakeLink);

    const check = isPathProtected(fakeLink, DEFAULT_CONFIG, tmpDir);
    assert.equal(check.protected, true, "Symlink pointing to .env must be blocked");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Normal benign files flow freely (Negative branch)", () => {
  assert.equal(isPathProtected("src/index.ts").protected, false);
  assert.equal(isPathProtected("package.json").protected, false);
  assert.equal(isPathProtected("README.md").protected, false);
  assert.equal(isPathProtected("tests/unit.test.js").protected, false);
});

// =============================================================================
// Group 2: Bash Shell Guard (Lexer & Redirections)
// =============================================================================
console.log("\n--- Group 2: Bash Shell Guard ---");

test("Direct shell reading of .env", () => {
  assert.equal(checkBashCommand("cat .env").block, true);
  assert.equal(checkBashCommand("head -n 20 .env.local").block, true);
  assert.equal(checkBashCommand("more .env").block, true);
});

test("Shell input redirection (<)", () => {
  assert.equal(checkBashCommand("tail < .env").block, true);
  assert.equal(checkBashCommand("wc -l < .env.production").block, true);
});

test("Shell output redirection (> and >>)", () => {
  assert.equal(checkBashCommand("echo 'SECRET=123' > .env").block, true);
  assert.equal(checkBashCommand("cat extra >> .env").block, true);
});

test("Pipe to tee redirection (| tee)", () => {
  assert.equal(checkBashCommand("echo test | tee .env").block, true);
  assert.equal(checkBashCommand("echo test | tee -a .env").block, true);
});

test("Shell operations on SSH / AWS keys", () => {
  assert.equal(checkBashCommand("cp ~/.ssh/id_rsa /tmp/leak").block, true);
  assert.equal(checkBashCommand("tar -czf aws.tar ~/.aws").block, true);
});

test("Benign shell commands pass through", () => {
  assert.equal(checkBashCommand("git status").block, false);
  assert.equal(checkBashCommand("npm test").block, false);
  assert.equal(checkBashCommand("ls -la src/").block, false);
  assert.equal(checkBashCommand("node -v").block, false);
});

// =============================================================================
// Group 3: DLP Redaction & Relational Preservation (Hawking A == A)
// =============================================================================
console.log("\n--- Group 3: DLP Redaction & Relational Preservation ---");

test("AWS Access Key Redaction", () => {
  resetSessionState();
  const raw = "Found AWS key: AKIAIOSFODNN7EXAMPLE in log";
  const redacted = redactSecrets(raw);
  assert.match(redacted, /\[REDACTED_AWS_KEY_#1\]/);
  assert.ok(!redacted.includes("AKIAIOSFODNN7EXAMPLE"));
});

test("GitHub PAT Redaction", () => {
  resetSessionState();
  const raw = "Token is ghp_123456789012345678901234567890123456 for API";
  const redacted = redactSecrets(raw);
  assert.match(redacted, /\[REDACTED_GITHUB_TOKEN_#1\]/);
  assert.ok(!redacted.includes("ghp_123456789012345678901234567890123456"));
});

test("Private Key PEM Redaction", () => {
  resetSessionState();
  const raw = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0m8d7v8...fake...
-----END RSA PRIVATE KEY-----`;
  const redacted = redactSecrets(raw);
  assert.match(redacted, /\[REDACTED_PRIVATE_KEY_#1\]/);
  assert.ok(!redacted.includes("MIIEowIBAAKCAQEA0m8d7v8"));
});

test("Hawking Relational Preservation (A == A)", () => {
  resetSessionState();
  const keyA = "AKIAIOSFODNN7EXAMPLE";
  const keyB = "AKIA1111111111111111";

  const input = `Checking key 1: ${keyA}. Confirming key 1 again: ${keyA}. Compare with key 2: ${keyB}.`;
  const redacted = redactSecrets(input);

  // Key A should be mapped to #1 both times
  const matchesA = redacted.match(/\[REDACTED_AWS_KEY_#1\]/g);
  assert.equal(matchesA?.length, 2, "Same secret must map to the exact same relational token");

  // Key B should be mapped to #2
  const matchesB = redacted.match(/\[REDACTED_AWS_KEY_#2\]/g);
  assert.equal(matchesB?.length, 1, "Different secret must map to a distinct relational token");
});

test("Environment variable secret pattern", () => {
  resetSessionState();
  const raw = "export DATABASE_PASSWORD='ultra_secure_db_pass_999'";
  const redacted = redactSecrets(raw);
  assert.match(redacted, /\[REDACTED_ENV_SECRET_#1\]/);
  assert.ok(!redacted.includes("ultra_secure_db_pass_999"));
});

test("Negative branch: benign code is untouched", () => {
  resetSessionState();
  const cleanCode = "const port = 3000;\nconst name = 'pi-dlp-guard';\nfunction add(a, b) { return a + b; }";
  const result = redactSecrets(cleanCode);
  assert.equal(result, cleanCode);
});

// =============================================================================
// Group 4: Gitleaks Dual-Core & Fallback
// =============================================================================
console.log("\n--- Group 4: Gitleaks Dual-Core & Fallback ---");

test("Gitleaks pipe detection when binary exists", () => {
  const leaks = scanWithGitleaks("ghp_123456789012345678901234567890123456");
  assert.ok(Array.isArray(leaks));
  if (leaks.length > 0) {
    assert.ok(leaks[0].startsWith("ghp_"), "Gitleaks should find GitHub PAT");
  }
});

test("Graceful fallback when Gitleaks is disabled", () => {
  resetSessionState();
  const configNoGitleaks = { ...DEFAULT_CONFIG, enableGitleaks: false };
  const raw = "AKIAIOSFODNN7EXAMPLE";
  const redacted = redactSecrets(raw, configNoGitleaks);
  assert.match(redacted, /\[REDACTED_AWS_KEY_#1\]/);
});

// =============================================================================
// Summary
// =============================================================================
console.log(`\n🎉 Results: ${passed}/${total} tests passed successfully.`);
if (passed !== total) {
  process.exit(1);
}
