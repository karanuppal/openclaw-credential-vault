/**
 * Perl Scrubber Security Study
 * 
 * Tests what additional attack surface the Perl pipe scrubber introduces.
 * Run: npx ts-node tests/perl-scrubber-security.ts
 */

import { execSync } from "child_process";

const SECRET = "ghp_TESTSECRET1234567890abcdefghijklmn";
const REPLACEMENT = "[VAULT:github]";

function safe(cmd: string, env?: Record<string, string>): string {
  try {
    return execSync(cmd, { encoding: "utf-8", shell: "/bin/bash", env: env ?? process.env, timeout: 5000 }).trim();
  } catch (e: any) {
    return `ERROR: ${e.message?.split('\n')[0] || 'unknown'}`;
  }
}

// Build the perl expression the same way our code does
const escapedForPerl = SECRET.replace(/([\\\/\$\@\"\'\!\|\[\]\(\)\{\}\.\*\+\?\^])/g, '\\$1');
const perlExpr = `s/\\Q${escapedForPerl}\\E/${REPLACEMENT}/g`;

console.log("=== PERL SCRUBBER SECURITY STUDY ===\n");
console.log(`Secret: ${SECRET}`);
console.log(`Perl expr: ${perlExpr}\n`);

const env = { ...process.env, GH_TOKEN: SECRET };

// Test 1: Basic scrubbing works
console.log("--- Test 1: Basic scrubbing ---");
let out = safe(`{ echo "${SECRET}" ; } 2>&1 | perl -pe '${perlExpr}'`, env);
console.log(`  echo secret: ${out.includes(SECRET) ? "LEAKED" : "SCRUBBED"} → ${out}`);

// Test 2: jq exfiltration scrubbed
console.log("\n--- Test 2: jq-style exfiltration ---");
out = safe(`{ echo '{"token":"${SECRET}"}' | jq -r .token ; } 2>&1 | perl -pe '${perlExpr}'`, env);
console.log(`  jq .token: ${out.includes(SECRET) ? "LEAKED" : "SCRUBBED"} → ${out}`);

// Test 3: printenv scrubbed
console.log("\n--- Test 3: printenv ---");
out = safe(`{ printenv GH_TOKEN ; } 2>&1 | perl -pe '${perlExpr}'`, env);
console.log(`  printenv: ${out.includes(SECRET) ? "LEAKED" : "SCRUBBED"} → ${out}`);

// Test 4: Semicolon breakout — does the secret leak before the pipe?
console.log("\n--- Test 4: Semicolon breakout attempt ---");
out = safe(`{ echo "before"; echo ${SECRET}; echo "after" ; } 2>&1 | perl -pe '${perlExpr}'`, env);
console.log(`  semicolon: ${out.includes(SECRET) ? "LEAKED" : "SCRUBBED"} → ${out}`);

// Test 5: Redirect to file bypass
console.log("\n--- Test 5: Redirect to file bypass ---");
safe(`{ echo ${SECRET} > /tmp/perl-test-leak.txt ; } 2>&1 | perl -pe '${perlExpr}'`, env);
const fileContent = safe("cat /tmp/perl-test-leak.txt");
console.log(`  file content: ${fileContent.includes(SECRET) ? "LEAKED TO FILE" : "FILE CLEAN"} → ${fileContent}`);
safe("rm -f /tmp/perl-test-leak.txt");

// Test 6: Subshell bypass
console.log("\n--- Test 6: Subshell bypass ---");
out = safe(`{ $(echo ${SECRET}) ; } 2>&1 | perl -pe '${perlExpr}'`, env);
console.log(`  subshell: ${out.includes(SECRET) ? "LEAKED" : "SCRUBBED"} → ${out}`);

// Test 7: stderr vs stdout — does 2>&1 capture stderr too?
console.log("\n--- Test 7: stderr capture ---");
out = safe(`{ echo ${SECRET} >&2 ; } 2>&1 | perl -pe '${perlExpr}'`, env);
console.log(`  stderr: ${out.includes(SECRET) ? "LEAKED" : "SCRUBBED"} → ${out}`);

// Test 8: Exit code preservation — does the pipe change exit codes?
console.log("\n--- Test 8: Exit code preservation ---");
out = safe(`{ false ; } 2>&1 | perl -pe '${perlExpr}'; echo "exit: \${PIPESTATUS[0]}"`, env);
console.log(`  exit code: ${out}`);

// Test 9: Binary output — does perl break binary data?
console.log("\n--- Test 9: Binary output ---");
out = safe(`{ printf '\\x00\\x01\\x02hello\\x03' ; } 2>&1 | perl -pe '${perlExpr}' | xxd | head -2`, env);
console.log(`  binary: ${out}`);

// Test 10: Perl injection — can the credential value break the perl expression?
console.log("\n--- Test 10: Perl injection via credential value ---");
const maliciousSecret = "test'; system('echo PWNED'); '";
const malEscaped = maliciousSecret.replace(/([\\\/\$\@\"\'\!\|\[\]\(\)\{\}\.\*\+\?\^])/g, '\\$1');
const malPerlExpr = `s/\\Q${malEscaped}\\E/[VAULT:test]/g`;
out = safe(`{ echo "harmless" ; } 2>&1 | perl -pe '${malPerlExpr}'`, env);
console.log(`  perl injection: ${out.includes("PWNED") ? "INJECTED!" : "SAFE"} → ${out}`);

// Test 11: Large output performance
console.log("\n--- Test 11: Performance with large output ---");
const start = Date.now();
out = safe(`{ seq 1 10000 ; } 2>&1 | perl -pe '${perlExpr}' | wc -l`, env);
const elapsed = Date.now() - start;
console.log(`  10k lines: ${out} lines in ${elapsed}ms`);

// Test 12: Multiple credentials in same output
console.log("\n--- Test 12: Multiple occurrences ---");
out = safe(`{ echo "${SECRET} and ${SECRET} again" ; } 2>&1 | perl -pe '${perlExpr}'`, env);
console.log(`  multiple: ${out.includes(SECRET) ? "LEAKED" : "SCRUBBED"} → ${out}`);

console.log("\n=== STUDY COMPLETE ===");
