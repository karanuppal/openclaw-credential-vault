/**
 * ENV Injection Study v2
 * 
 * Tests 4 injection methods with EXACT shell behaviors.
 * Each method tested with:
 *   a) printenv VAR (direct)
 *   b) echo hello | printenv (piped — does second command see it?)
 *   c) bash -c 'printenv VAR' (child process)
 *   d) command --jq-style env access (simulated with: bash -c 'echo $VAR')
 * 
 * Run: npx ts-node tests/env-injection-study.ts
 */

import { execSync } from "child_process";

const SECRET = "SECRET_VALUE_12345";
const K = "TEST_CRED";

function safe(fn: () => string): string {
  try {
    return fn().trim() || "(empty)";
  } catch {
    return "(not found / error)";
  }
}

function visible(output: string): string {
  return output.includes(SECRET) ? "VISIBLE" : "NOT VISIBLE";
}

console.log("=== ENV INJECTION STUDY v2 ===\n");
console.log(`Secret: ${SECRET}`);
console.log(`Key: ${K}\n`);

// Method 1: params.env (spawn with env option)
console.log("--- 1. params.env (spawn env option) ---");
const env1 = { ...process.env, [K]: SECRET };
let out: string;

out = safe(() => execSync(`printenv ${K}`, { env: env1, encoding: "utf-8" }));
console.log(`  a) printenv ${K}:                  ${visible(out)} → ${out}`);

out = safe(() => execSync(`echo hello | printenv | grep ${K}`, { env: env1, encoding: "utf-8" }));
console.log(`  b) echo hello | printenv | grep:   ${visible(out)} → ${out}`);

out = safe(() => execSync(`bash -c 'printenv ${K}'`, { env: env1, encoding: "utf-8" }));
console.log(`  c) bash -c 'printenv':             ${visible(out)} → ${out}`);

out = safe(() => execSync(`bash -c 'echo $${K}'`, { env: env1, encoding: "utf-8" }));
console.log(`  d) bash -c 'echo $VAR':            ${visible(out)} → ${out}`);

// Method 2: process.env mutation
console.log("\n--- 2. process.env mutation ---");
process.env[K] = SECRET;

out = safe(() => execSync(`printenv ${K}`, { encoding: "utf-8" }));
console.log(`  a) printenv ${K}:                  ${visible(out)} → ${out}`);

out = safe(() => execSync(`echo hello | printenv | grep ${K}`, { encoding: "utf-8" }));
console.log(`  b) echo hello | printenv | grep:   ${visible(out)} → ${out}`);

out = safe(() => execSync(`bash -c 'printenv ${K}'`, { encoding: "utf-8" }));
console.log(`  c) bash -c 'printenv':             ${visible(out)} → ${out}`);

out = safe(() => execSync(`bash -c 'echo $${K}'`, { encoding: "utf-8" }));
console.log(`  d) bash -c 'echo $VAR':            ${visible(out)} → ${out}`);

delete process.env[K];

// Method 3: export && command
console.log("\n--- 3. export KEY=[VAULT:env-redacted] && command ---");
const esc = SECRET.replace(/'/g, "'\\''");

out = safe(() => execSync(`export ${K}='${esc}' && printenv ${K}`, { encoding: "utf-8", shell: "/bin/bash" }));
console.log(`  a) printenv ${K}:                  ${visible(out)} → ${out}`);

out = safe(() => execSync(`export ${K}='${esc}' && echo hello | printenv | grep ${K}`, { encoding: "utf-8", shell: "/bin/bash" }));
console.log(`  b) echo hello | printenv | grep:   ${visible(out)} → ${out}`);

out = safe(() => execSync(`export ${K}='${esc}' && bash -c 'printenv ${K}'`, { encoding: "utf-8", shell: "/bin/bash" }));
console.log(`  c) bash -c 'printenv':             ${visible(out)} → ${out}`);

out = safe(() => execSync(`export ${K}='${esc}' && bash -c 'echo $${K}'`, { encoding: "utf-8", shell: "/bin/bash" }));
console.log(`  d) bash -c 'echo $VAR':            ${visible(out)} → ${out}`);

// Method 4: VAR=value command (prefix, no export)
console.log("\n--- 4. VAR=value command (prefix) ---");

out = safe(() => execSync(`${K}='${esc}' printenv ${K}`, { encoding: "utf-8", shell: "/bin/bash" }));
console.log(`  a) printenv ${K}:                  ${visible(out)} → ${out}`);

out = safe(() => execSync(`${K}='${esc}' echo hello | printenv | grep ${K}`, { encoding: "utf-8", shell: "/bin/bash" }));
console.log(`  b) echo hello | printenv | grep:   ${visible(out)} → ${out}`);

out = safe(() => execSync(`${K}='${esc}' bash -c 'printenv ${K}'`, { encoding: "utf-8", shell: "/bin/bash" }));
console.log(`  c) bash -c 'printenv':             ${visible(out)} → ${out}`);

out = safe(() => execSync(`${K}='${esc}' bash -c 'echo $${K}'`, { encoding: "utf-8", shell: "/bin/bash" }));
console.log(`  d) bash -c 'echo $VAR':            ${visible(out)} → ${out}`);
