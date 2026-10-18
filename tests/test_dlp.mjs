/**
 * Regression suite for pi-dlp-guard. Run with `npm test`.
 * HOME points to a temp dir so the user's real config never influences results.
 */

import assert from "node:assert/strict";
import cp from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const origCwd = process.cwd();
const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "dlp-home-")));
const cwd = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "dlp-cwd-")));
process.env.HOME = home;
process.chdir(cwd);
const { default: register, isPathProtected, checkBashCommand, redactSecrets, scanWithGitleaks, resetSessionState, DEFAULT_CONFIG: C } =
  await import("../extensions/dlp-guard.ts");

let passed = 0;
let failed = 0;
const queue = [];
const test = (name, fn) => queue.push({ name, fn });
const section = (title) => queue.push({ title });
const prot = (p, op = "read", cfg = C) => isPathProtected(p, cfg, cwd, op).protected;
const blocked = (cmd) => checkBashCommand(cmd, C, cwd).block;
const hasGitleaks = cp.spawnSync("gitleaks", ["version"], { stdio: "ignore" }).status === 0;

const AWS = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
const GH = ["ghp_", "1234567890".repeat(3), "123456"].join("");
const NPM = ["npm_", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5"].join("");

section("path guard");
test(".env variants are protected, templates are not", () => {
  for (const p of [".env", ".env.local", "./.env", "../../.env", "a/b/../../.env"]) assert.ok(prot(p), p);
  for (const p of [".env.example", ".env.sample"]) assert.ok(!prot(p), p);
});
test("credentials, keys and shell rc files", () => {
  for (const p of ["~/.ssh/id_rsa", "$HOME/.aws/credentials", ".git/config", "certs/s.pem", "k/private.key", "~/.zshrc.local", "~/.pi/agent/auth.json"]) {
    assert.ok(prot(p), p);
  }
});
test("benign files are not protected", () => {
  for (const p of ["src/index.ts", "package.json", "README.md", "environment.ts", "my.git/notes.txt"]) assert.ok(!prot(p), p);
});
test("cwd-relative patterns only match under cwd", () => {
  const cfg = { ...C, protectedPaths: ["secrets/**"] };
  assert.ok(prot("secrets/a.txt", "read", cfg));
  assert.ok(!prot("other/secrets/a.txt", "read", cfg));
});
test("symlink to a built-in protected file", () => {
  fs.writeFileSync(path.join(cwd, ".env"), "X=1\n");
  fs.symlinkSync(path.join(cwd, ".env"), path.join(cwd, "innocent.txt"));
  assert.ok(prot("innocent.txt"));
});
test("symlink to a configured protected file", () => {
  const cfg = { ...C, protectedPaths: ["**/vault.txt"] };
  fs.writeFileSync(path.join(cwd, "vault.txt"), "x");
  fs.symlinkSync(path.join(cwd, "vault.txt"), path.join(cwd, "plain"));
  assert.ok(prot("plain", "read", cfg));
});
test("dangling symlink into an integrity path is blocked for write", () => {
  fs.symlinkSync(path.join(home, ".pi/agent/extensions/evil.ts"), path.join(cwd, "dangling"));
  assert.ok(prot("dangling", "write"));
  assert.ok(!prot("dangling", "read"));
});
test("integrity paths: read allowed, write blocked", () => {
  assert.ok(!prot("~/.pi/agent/settings.json", "read"));
  assert.ok(prot("~/.pi/agent/settings.json", "write"));
  assert.ok(prot("~/.pi/agent/dlp-guard.json", "write"));
});
test("the package's own directory is write-protected", () => {
  const own = path.resolve(import.meta.dirname, "..", "extensions", "dlp-guard.ts");
  assert.ok(prot(own, "write"));
  assert.ok(!prot(own, "read"));
});

section("bash guard");
test("redirects and tee to protected paths", () => {
  for (const c of ["echo x > .env", "echo x >> ~/.pi/agent/settings.json", "echo x>~/.pi/agent/s.json", "echo x | tee ~/.ssh/k"]) assert.ok(blocked(c), c);
});
test("mutating commands, including ones missing from the first version", () => {
  for (const c of ["rm -rf ~/.pi/agent", "cp evil.ts ~/.pi/agent/extensions/", "ln -s evil ~/.pi/agent/extensions/e.ts", "sed -i s/a/b/ ~/.pi/agent/settings.json", "mv x $HOME/.pi/agent/y"]) {
    assert.ok(blocked(c), c);
  }
});
test("chained and sequential commands", () => {
  for (const c of [
    "cd /tmp && rm -rf ~/.pi/agent",
    "ls; rm ~/.pi/agent/settings.json",
    "true || cp x ~/.pi/agent/y",
    "echo a & rm ~/.ssh/known_hosts",
    "echo a | cat\nrm ~/.pi/agent/settings.json",
  ]) {
    assert.ok(blocked(c), c);
  }
});
test("cd is tracked across a chain", () => {
  assert.ok(blocked("cd ~/.pi/agent && rm settings.json"));
  assert.ok(blocked("cd ~/.pi/agent && echo x > settings.json"));
  assert.ok(!blocked("cd ~/.pi/agent && cat settings.json"));
});
test("nested code: sh -c, eval, $(), backticks", () => {
  for (const c of [`sh -c "rm ~/.pi/agent/settings.json"`, `eval "rm ~/.pi/agent/settings.json"`, "echo $(rm ~/.pi/agent/settings.json)", "echo `rm ~/.pi/agent/settings.json`"]) {
    assert.ok(blocked(c), c);
  }
});
test("quote splitting does not hide the target", () => {
  assert.ok(blocked("rm ~/.pi/agent/sett''ings.json"));
  assert.ok(blocked('rm "$HOME/.pi/agent/settings.json"'));
});
test("reads, searches and ordinary commands pass", () => {
  for (const c of [
    "cat ~/.pi/agent/settings.json",
    "cat .env",
    'grep -rn "\\.env" src/',
    "git status",
    "npm test",
    "echo hi > /tmp/out.txt && cat .env",
    "ls 2>/dev/null",
    "echo err >&2",
    "cp a.txt b.txt",
    "cat > /tmp/x.txt << 'EOF'\nsee .env docs\nEOF",
  ]) {
    assert.ok(!blocked(c), c);
  }
});

section("redaction");
test("known token formats", () => {
  resetSessionState();
  const cases = {
    AWS_KEY: AWS,
    GITHUB_TOKEN: GH,
    API_KEY: ["sk-ant-api03-" + "Ab1_".repeat(20), "AIzaSy" + "A1b2C3d4E5".repeat(3) + "f6G", "sk-" + "a1B2c3D4e5".repeat(4) + "abcd"],
    SLACK_TOKEN: ["xoxb-", "1234567890-", "abcdefghij"].join(""),
    URL_CREDENTIAL: "postgres://admin:S3cretPw@db:5432/x",
    PRIVATE_KEY: ["-----", "BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0m8d\\n-----", "END RSA PRIVATE KEY-----"].join(""),
  };
  for (const [cat, vals] of Object.entries(cases)) {
    for (const v of [].concat(vals)) {
      const out = redactSecrets(`x ${v} y`);
      assert.match(out, new RegExp(`\\[REDACTED_${cat}_#\\d+\\]`), `${cat}: ${out}`);
      assert.ok(!out.includes(v.slice(8, 20)), `${cat} leaked`);
    }
  }
});
test("NAME=value forms, including bare PASSWORD/TOKEN/SECRET and JSON", () => {
  for (const s of ["export DATABASE_PASSWORD='ultra_secure_db_pass_999'", "PASSWORD=hunter2hunter2", "TOKEN=abcdef123456", "SECRET=abcdef123456", "DB_PASS=hunter2hunter2", '{"api_key": "abcdef0123456789"}']) {
    resetSessionState();
    assert.match(redactSecrets(s), /\[REDACTED_SECRET_#1\]/, s);
  }
});
test("the same secret keeps the same token, different secrets differ", () => {
  resetSessionState();
  const aws2 = ["AKIA", "1".repeat(16)].join("");
  const out = redactSecrets(`${AWS} ${AWS} ${aws2}`);
  assert.equal(out.match(/#1\]/g)?.length, 2);
  assert.equal(out.match(/#2\]/g)?.length, 1);
});
test("redaction is idempotent: placeholders are never re-redacted", () => {
  resetSessionState();
  const once = redactSecrets("API_KEY=hunter2hunter2 and " + AWS);
  assert.equal(redactSecrets(once), once);
});
test("no false positives", () => {
  resetSessionState();
  for (const s of ["MONKEY=banana12345", "AUTHOR=John Smith Jr", "KEY=short", "API_KEY=$OTHER_VARIABLE", "const port = 3000;", "commit 3f786850e387550fdab836ed7e6dc881de23001b"]) {
    assert.equal(redactSecrets(s), s, s);
  }
});

section("gitleaks");
test("safety net catches formats the regexes do not know (large buffers only)", () => {
  if (!hasGitleaks) return;
  assert.ok(scanWithGitleaks(`see ${NPM}\n`).length > 0);
  const big = `${"x".repeat(5000)}\nsee ${NPM}\n`;
  resetSessionState();
  assert.ok(!redactSecrets(big, C, true).includes(NPM), "tool_result path must redact");
  assert.ok(redactSecrets(big, C, false).includes(NPM), "context path is regex-only by design");
});
test("regexes keep working when gitleaks is disabled", () => {
  resetSessionState();
  assert.match(redactSecrets(AWS, { ...C, enableGitleaks: false }, true), /\[REDACTED_AWS_KEY_#1\]/);
});

section("extension hooks");
const handlers = {};
const commands = {};
register({ on: (e, h) => (handlers[e] = h), registerCommand: (n, o) => (commands[n] = o) });
const notes = [];
const ctx = { hasUI: true, ui: { notify: (m) => notes.push(m) } };
const call = (toolName, input) => handlers.tool_call({ toolName, input }, ctx);

test("tool_call blocks structured tools by path and operation", async () => {
  assert.equal((await call("read", { path: ".env" }))?.block, true);
  assert.equal((await call("read_symbol", { path: ".env", symbol: "x" }))?.block, true);
  assert.equal((await call("ast_grep_replace", { paths: ["~/.pi/agent/x.ts"] }))?.block, true);
  assert.equal(await call("read", { path: "~/.pi/agent/settings.json" }), undefined);
  assert.equal(await call("read", { path: "src/a.ts" }), undefined);
});
test("tool_call blocks chained bash and lets normal bash through", async () => {
  assert.equal((await call("bash", { command: "cd /tmp && rm -rf ~/.pi/agent" }))?.block, true);
  assert.equal(await call("bash", { command: "git status" }), undefined);
});
test("tool_result redacts text parts and leaves clean output untouched", async () => {
  resetSessionState();
  const dirty = await handlers.tool_result({ content: [{ type: "text", text: `key ${GH}` }] });
  assert.match(dirty.content[0].text, /\[REDACTED_GITHUB_TOKEN_#1\]/);
  assert.equal(await handlers.tool_result({ content: [{ type: "text", text: "hello" }] }), undefined);
});
test("context redacts string and array content, returns undefined when clean", async () => {
  resetSessionState();
  const messages = [
    { role: "user", content: `my key ${AWS}` },
    { role: "toolResult", content: [{ type: "text", text: GH }, { type: "image", data: "x" }] },
    { role: "assistant", content: [{ type: "text", text: "ok" }] },
  ];
  const res = await handlers.context({ messages });
  assert.match(res.messages[0].content, /REDACTED_AWS_KEY/);
  assert.match(res.messages[1].content[0].text, /REDACTED_GITHUB_TOKEN/);
  assert.deepEqual(res.messages[1].content[1], { type: "image", data: "x" });
  assert.ok(messages[0].content.includes(AWS), "input messages are not mutated");
  assert.equal(await handlers.context({ messages: [messages[2]] }), undefined);
});
test("/dlp off disables every hook, /dlp on restores them", async () => {
  await commands.dlp.handler("off", ctx);
  assert.equal(await call("read", { path: ".env" }), undefined);
  assert.equal(await handlers.tool_result({ content: [{ type: "text", text: GH }] }), undefined);
  await commands.dlp.handler("on", ctx);
  assert.equal((await call("read", { path: ".env" }))?.block, true);
});

for (const item of queue) {
  if (item.title) {
    console.log(item.title);
    continue;
  }
  try {
    await item.fn();
    passed++;
    console.log(`  ok   ${item.name}`);
  } catch (err) {
    failed++;
    console.error(`  FAIL ${item.name}\n${err.stack}`);
  }
}
process.chdir(origCwd);
fs.rmSync(home, { recursive: true, force: true });
fs.rmSync(cwd, { recursive: true, force: true });
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
