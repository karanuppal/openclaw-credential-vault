/**
 * Phase 5: Scrubbing Performance Benchmark Tests
 *
 * Validates spec section "Phase 5: Missing Tests" performance requirements:
 * - Regex + literal scrub benchmarks against 1KB, 10KB, 100KB, 1MB outputs
 * - Target: < 1ms for < 10KB, < 10ms for 1MB
 * - Test with 5, 10, 20 registered patterns simultaneously
 * - Include in CI (vitest benchmarks)
 *
 * Spec ref: "Scrubbing performance benchmarks"
 *
 * NOTE ON 1MB THRESHOLDS:
 * The spec target of <10ms for 1MB is aspirational. On current hardware
 * (cloud VM, single-threaded V8 regex engine), measured median times are:
 *   - 5 patterns:  ~13ms (1.3x over spec)
 *   - 10 patterns: ~15ms (1.5x over spec)
 *   - 20 patterns: ~21ms (2.1x over spec)
 *   - combined:    ~16ms (1.6x over spec)
 * Realistic thresholds for CI would be <25ms (5 patterns) to <70ms (20 patterns).
 * The scrubber iterates N regex patterns over the full string; for 1MB at 20 patterns
 * this is ~20MB of regex scanning. To hit <10ms would require a compiled multi-pattern
 * engine (e.g. Aho-Corasick or Hyperscan). Keeping spec thresholds as assertions
 * per task requirements — these will fail until the scrubber is optimized.
 */

import { describe, it, expect } from "vitest";
import {
  compileScrubRules,
  scrubText,
  scrubLiteralCredential,
  CompiledScrubRule,
} from "../src/scrubber.js";
import { ToolConfig } from "../src/types.js";

// --- Helpers ---

/**
 * Generate a random string of given length.
 */
function randomString(length: number): string {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

/**
 * Generate N tool configs with unique scrub patterns.
 */
function generateToolConfigs(count: number): Record<string, ToolConfig> {
  const tools: Record<string, ToolConfig> = {};
  const prefixes = [
    "sk_live_", "sk_test_", "rk_live_", "ghp_", "gum_",
    "github_pat_", "sk-", "sk-ant-", "xoxb-", "xoxp-",
    "AKIA", "shpat_", "sq0atp-", "EAA", "ya29.",
    "glpat-", "npm_", "pypi-", "nuget-", "docker_",
  ];

  for (let i = 0; i < count; i++) {
    const prefix = prefixes[i % prefixes.length];
    const name = `tool_${i}`;
    tools[name] = {
      name,
      addedAt: "2026-01-01",
      lastRotated: "2026-01-01",
      inject: [],
      scrub: {
        patterns: [`${prefix.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&")}[a-zA-Z0-9_-]{16,}`],
      },
    };
  }
  return tools;
}

/**
 * Measure execution time in milliseconds (high-resolution).
 */
function measureMs(fn: () => void): number {
  const start = performance.now();
  fn();
  return performance.now() - start;
}

/**
 * Run a function multiple times and return median execution time.
 */
function medianMs(fn: () => void, iterations: number = 10): number {
  const times: number[] = [];
  // Warm up
  fn();
  fn();
  for (let i = 0; i < iterations; i++) {
    times.push(measureMs(fn));
  }
  times.sort((a, b) => a - b);
  return times[Math.floor(times.length / 2)];
}

// --- Test data sizes ---
const SIZES = [
  { name: "1KB", bytes: 1024 },
  { name: "10KB", bytes: 10240 },
  { name: "100KB", bytes: 102400 },
  { name: "1MB", bytes: 1048576 },
];

// Pre-generate test data
const testData: Record<string, string> = {};
for (const size of SIZES) {
  testData[size.name] = randomString(size.bytes);
}

describe("Performance — regex scrubbing with 5 patterns", () => {
  const tools = generateToolConfigs(5);
  const rules = compileScrubRules(tools);

  for (const size of SIZES) {
    it(`should scrub ${size.name} output in acceptable time (5 patterns)`, () => {
      const input = testData[size.name];
      const time = medianMs(() => scrubText(input, rules));

      // Log for CI visibility
      console.log(`  Regex scrub (5 patterns, ${size.name}): ${time.toFixed(3)}ms`);

      // Spec thresholds: <1ms for <10KB, <10ms for 1MB
      // If these fail in CI, the actual measured time is logged above for analysis
      if (size.bytes <= 10240) {
        expect(time).toBeLessThan(1); // spec: <1ms for <10KB
      } else if (size.bytes >= 1048576) {
        expect(time).toBeLessThan(10); // spec: <10ms for 1MB
      }
    });
  }
});

describe("Performance — regex scrubbing with 10 patterns", () => {
  const tools = generateToolConfigs(10);
  const rules = compileScrubRules(tools);

  for (const size of SIZES) {
    it(`should scrub ${size.name} output in acceptable time (10 patterns)`, () => {
      const input = testData[size.name];
      const time = medianMs(() => scrubText(input, rules));

      console.log(`  Regex scrub (10 patterns, ${size.name}): ${time.toFixed(3)}ms`);

      // Spec thresholds: <1ms for <10KB, <10ms for 1MB
      // 10 patterns ≈ 2x overhead vs 5 patterns; spec thresholds still apply
      if (size.bytes <= 10240) {
        expect(time).toBeLessThan(1); // spec: <1ms for <10KB
      } else if (size.bytes >= 1048576) {
        expect(time).toBeLessThan(10); // spec: <10ms for 1MB
      }
    });
  }
});

describe("Performance — regex scrubbing with 20 patterns", () => {
  const tools = generateToolConfigs(20);
  const rules = compileScrubRules(tools);

  for (const size of SIZES) {
    it(`should scrub ${size.name} output in acceptable time (20 patterns)`, () => {
      const input = testData[size.name];
      const time = medianMs(() => scrubText(input, rules));

      console.log(`  Regex scrub (20 patterns, ${size.name}): ${time.toFixed(3)}ms`);

      // Spec thresholds: <1ms for <10KB, <10ms for 1MB
      // 20 patterns ≈ 4x overhead vs 5 patterns; spec thresholds still apply
      if (size.bytes <= 10240) {
        expect(time).toBeLessThan(1); // spec: <1ms for <10KB
      } else if (size.bytes >= 1048576) {
        expect(time).toBeLessThan(10); // spec: <10ms for 1MB
      }
    });
  }
});

describe("Performance — literal scrubbing", () => {
  const credentials = Array.from({ length: 10 }, (_, i) =>
    `credential_${i}_` + randomString(32)
  );

  for (const size of SIZES) {
    it(`should literal-scrub ${size.name} with 10 literals in acceptable time`, () => {
      const input = testData[size.name];
      const time = medianMs(() => {
        let result = input;
        for (const cred of credentials) {
          result = scrubLiteralCredential(result, cred, "tool");
        }
      });

      console.log(`  Literal scrub (10 literals, ${size.name}): ${time.toFixed(3)}ms`);

      // Spec thresholds: <1ms for <10KB, <10ms for 1MB
      if (size.bytes <= 10240) {
        expect(time).toBeLessThan(1); // spec: <1ms for <10KB
      } else if (size.bytes >= 1048576) {
        expect(time).toBeLessThan(10); // spec: <10ms for 1MB
      }
    });
  }
});

describe("Performance — combined regex + literal scrubbing", () => {
  const tools = generateToolConfigs(10);
  const rules = compileScrubRules(tools);
  const literals = Array.from({ length: 5 }, (_, i) =>
    `literal_cred_${i}_` + randomString(24)
  );

  for (const size of SIZES) {
    it(`should combined-scrub ${size.name} in acceptable time`, () => {
      const input = testData[size.name];
      const time = medianMs(() => {
        let result = scrubText(input, rules);
        for (const cred of literals) {
          result = scrubLiteralCredential(result, cred, "tool");
        }
      });

      console.log(`  Combined scrub (10 regex + 5 literal, ${size.name}): ${time.toFixed(3)}ms`);

      // Spec thresholds: <1ms for <10KB, <10ms for 1MB
      // Combined = regex + literal; spec thresholds apply to total pipeline
      if (size.bytes <= 10240) {
        expect(time).toBeLessThan(1); // spec: <1ms for <10KB
      } else if (size.bytes >= 1048576) {
        expect(time).toBeLessThan(10); // spec: <10ms for 1MB
      }
    });
  }
});

describe("Performance — scrubbing with actual credential matches", () => {
  const tools: Record<string, ToolConfig> = {
    stripe: {
      name: "stripe",
      addedAt: "2026-01-01",
      lastRotated: "2026-01-01",
      inject: [],
      scrub: { patterns: ["sk_live_[a-zA-Z0-9]{24,}"] },
    },
  };
  const rules = compileScrubRules(tools);

  it("should handle output with many matches efficiently", () => {
    // Embed 100 fake Stripe keys in 100KB of text
    const fakeKey = "sk_live_abcdefghijklmnopqrstuvwx";
    let input = "";
    for (let i = 0; i < 100; i++) {
      input += `Transaction ${i}: ${fakeKey}\n`;
      input += randomString(900); // ~1KB per block
    }

    const time = medianMs(() => scrubText(input, rules));

    console.log(`  Scrub with 100 matches in ~100KB: ${time.toFixed(3)}ms`);

    // Should still be fast even with many replacements
    expect(time).toBeLessThan(50);

    // Verify correctness
    const result = scrubText(input, rules);
    expect(result).not.toContain("sk_live_");
    expect(result).toContain("[VAULT:stripe]");
  });
});
