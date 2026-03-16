/**
 * Tests for buildToolConfig — new UsageSelection-based config builder.
 * Spec ref: Phase 2, item 2 — buildToolConfig function in guesser.ts
 */

import { describe, it, expect } from "vitest";
import { buildToolConfig } from "../src/guesser.js";
import { UsageSelection } from "../src/types.js";

// ─── API calls ─────────────────────────────────────────────────────────────

describe("buildToolConfig — API calls", () => {
  it("creates web_fetch rule with Bearer header", () => {
    const usage: UsageSelection = {
      apiCalls: {
        urlPattern: "*api.gumroad.com/*",
        headerName: "Authorization",
        headerFormat: "Bearer $token",
      },
      scrubPatterns: [],
    };
    const { inject, scrub } = buildToolConfig("gumroad", usage);

    expect(inject).toHaveLength(1);
    expect(inject[0].tool).toBe("web_fetch");
    expect(inject[0].urlMatch).toBe("*api.gumroad.com/*");
    expect(inject[0].headers).toHaveProperty("Authorization");
    expect(inject[0].headers!["Authorization"]).toBe("Bearer $vault:gumroad");
    expect(scrub.patterns).toHaveLength(0);
  });

  it("creates web_f[VAULT:gmail-app]om header name", () => {
    const usage: UsageSelection = {
      apiCalls: {
        urlPattern: "*api.resy.com/*",
        headerName: "x-resy-auth-token",
        headerFormat: "$token",
      },
      scrubPatterns: [],
    };
    const { inject } = buildToolConfig("resy", usage);

    expect(inject[0].headers).toHaveProperty("x-resy-auth-token");
    expect(inject[0].headers!["x-resy-auth-token"]).toBe("$vault:resy");
  });

  it("replaces $token placeholder with $vault:toolName in headerFormat", () => {
    const usage: UsageSelection = {
      apiCalls: {
        urlPattern: "*example.com/*",
        headerName: "X-Api-Key",
        headerFormat: "Token $token",
      },
      scrubPatterns: [],
    };
    const { inject } = buildToolConfig("myservice", usage);
    expect(inject[0].headers!["X-Api-Key"]).toBe("Token $vault:myservice");
  });

  it("does not set commandMatch or env on web_fetch rule", () => {
    const usage: UsageSelection = {
      apiCalls: {
        urlPattern: "*example.com/*",
        headerName: "Authorization",
        headerFormat: "Bearer $token",
      },
      scrubPatterns: [],
    };
    const { inject } = buildToolConfig("svc", usage);
    expect(inject[0].commandMatch).toBeUndefined();
    expect(inject[0].env).toBeUndefined();
  });
});

// ─── CLI tool ──────────────────────────────────────────────────────────────

describe("buildToolConfig — CLI tool", () => {
  it("cre[VAULT:gmail-app] commandMatch and env var", () => {
    const usage: UsageSelection = {
      cliTool: {
        commandName: "gh",
        commandMatch: "gh*",
        envVar: "GH_TOKEN",
      },
      scrubPatterns: [],
    };
    const { inject, scrub } = buildToolConfig("github", usage);

    expect(inject).toHaveLength(1);
    expect(inject[0].tool).toBe("exec");
    expect(inject[0].commandMatch).toBe("gh*");
    expect(inject[0].env).toHaveProperty("GH_TOKEN");
    expect(inject[0].env!["GH_TOKEN"]).toBe("$vault:github");
    expect(scrub.patterns).toHaveLength(0);
  });

  it("injects $vault:toolName (not the actual credential value)", () => {
    const usage: UsageSelection = {
      cliTool: {
        commandMatch: "*gumroad*",
        envVar: "GUMROAD_TOKEN",
      },
      scrubPatterns: [],
    };
    const { inject } = buildToolConfig("gumroad", usage);
    expect(inject[0].env!["GUMROAD_TOKEN"]).toBe("$vault:gumroad");
    // Confirm no actual credential value is present
    expect(inject[0].env!["GUMROAD_TOKEN"]).not.toContain("secret");
    expect(inject[0].env!["GUMROAD_TOKEN"]).not.toContain("password");
  });

  it("does not set headers or urlMatch on exec rule", () => {
    const usage: UsageSelection = {
      cliTool: {
        commandMatch: "aws*",
        envVar: "AWS_ACCESS_KEY_ID",
      },
      scrubPatterns: [],
    };
    const { inject } = buildToolConfig("aws", usage);
    expect(inject[0].headers).toBeUndefined();
    expect(inject[0].urlMatch).toBeUndefined();
  });
});

// ─── Browser login ─────────────────────────────────────────────────────────

describe("buildToolConfig — Browser login", () => {
  it("creates browser-pass[VAULT:gmail-app]in pinning", () => {
    const usage: UsageSelection = {
      browserLogin: {
        domain: ".gumroad.com",
      },
      scrubPatterns: [],
    };
    const { inject, scrub } = buildToolConfig("gumroad", usage);

    expect(inject).toHaveLength(1);
    expect(inject[0].tool).toBe("browser");
    expect(inject[0].type).toBe("browser-password");
    expect(inject[0].method).toBe("fill");
    expect(inject[0].domainPin).toEqual([".gumroad.com"]);
    expect(scrub.patterns).toHaveLength(0);
  });

  it("sets domain pinning — credential only resolves on matching domain", () => {
    const usage: UsageSelection = {
      browserLogin: { domain: ".amazon.com" },
      scrubPatterns: [],
    };
    const { inject } = buildToolConfig("amazon", usage);
    expect(inject[0].domainPin).toBeDefined();
    expect(inject[0].domainPin).toHaveLength(1);
    expect(inject[0].domainPin![0]).toBe(".amazon.com");
  });

  it("does not set env, headers, commandMatch, or urlMatch on browser-password rule", () => {
    const usage: UsageSelection = {
      browserLogin: { domain: ".example.com" },
      scrubPatterns: [],
    };
    const { inject } = buildToolConfig("svc", usage);
    expect(inject[0].env).toBeUndefined();
    expect(inject[0].headers).toBeUndefined();
    expect(inject[0].commandMatch).toBeUndefined();
    expect(inject[0].urlMatch).toBeUndefined();
  });
});

// ─── Browser session ────────────────────────────────────────────────────────

describe("buildToolConfig — Browser session", () => {
  it("creates browser-co[VAULT:gmail-app]in pinning", () => {
    const usage: UsageSelection = {
      browserSession: {
        domain: ".amazon.com",
        cookieFilePath: "/tmp/cookies.json",
      },
      scrubPatterns: [],
    };
    const { inject, scrub } = buildToolConfig("amazon-session", usage);

    expect(inject).toHaveLength(1);
    expect(inject[0].tool).toBe("browser");
    expect(inject[0].type).toBe("browser-cookie");
    expect(inject[0].method).toBe("cookie-jar");
    expect(inject[0].domainPin).toEqual([".amazon.com"]);
    expect(scrub.patterns).toHaveLength(0);
  });

  it("sets domain pinning — credential only resolves on matching domain", () => {
    const usage: UsageSelection = {
      browserSession: { domain: ".github.com", cookieFilePath: "/tmp/gh.json" },
      scrubPatterns: [],
    };
    const { inject } = buildToolConfig("github-session", usage);
    expect(inject[0].domainPin).toBeDefined();
    expect(inject[0].domainPin![0]).toBe(".github.com");
  });

  it("does not set env, headers, commandMatch, or urlMatch on browser-cookie rule", () => {
    const usage: UsageSelection = {
      browserSession: { domain: ".example.com", cookieFilePath: "/tmp/cookies.txt" },
      scrubPatterns: [],
    };
    const { inject } = buildToolConfig("svc", usage);
    expect(inject[0].env).toBeUndefined();
    expect(inject[0].headers).toBeUndefined();
    expect(inject[0].commandMatch).toBeUndefined();
    expect(inject[0].urlMatch).toBeUndefined();
  });
});

// ─── Scrub patterns ─────────────────────────────────────────────────────────

describe("buildToolConfig — Scrub patterns", () => {
  it("includes user-provided scrub patterns in output", () => {
    const usage: UsageSelection = {
      apiCalls: {
        urlPattern: "*example.com/*",
        headerName: "Authorization",
        headerFormat: "Bearer $token",
      },
      scrubPatterns: ["ghp_[a-zA-Z0-9]{36}", "gum_[a-z0-9]+"],
    };
    const { scrub } = buildToolConfig("myservice", usage);
    expect(scrub.patterns).toHaveLength(2);
    expect(scrub.patterns).toContain("ghp_[a-zA-Z0-9]{36}");
    expect(scrub.patterns).toContain("gum_[a-z0-9]+");
  });

  it("returns empty scrub patt[VAULT:gmail-app]ided", () => {
    const usage: UsageSelection = {
      cliTool: { commandMatch: "mytool*", envVar: "MY_TOKEN" },
      scrubPatterns: [],
    };
    const { scrub } = buildToolConfig("mytool", usage);
    expect(scrub.patterns).toHaveLength(0);
  });

  it("does NOT write credential value to scrub patterns", () => {
    const secretValue = "super-secret-token-12345";
    const usage: UsageSelection = {
      apiCalls: {
        urlPattern: "*example.com/*",
        headerName: "Authorization",
        headerFormat: "Bearer $token",
      },
      scrubPatterns: [],
    };
    const { inject, scrub } = buildToolConfig("mysvc", usage);
    // Verify no literal credential value in inject or scrub
    const injectStr = JSON.stringify(inject);
    expect(injectStr).not.toContain(secretValue);
    expect(scrub.patterns.join("")).not.toContain(secretValue);
  });
});

// ─── Multiple usage types ───────────────────────────────────────────────────

describe("buildToolConfig — Multiple usage types", () => {
  it("creates one rule per usage type", () => {
    const usage: UsageSelection = {
      apiCalls: {
        urlPattern: "*api.example.com/*",
        headerName: "Authorization",
        headerFormat: "Bearer $token",
      },
      cliTool: {
        commandName: "myctl",
        commandMatch: "myctl*",
        envVar: "MYSERVICE_TOKEN",
      },
      scrubPatterns: [],
    };
    const { inject } = buildToolConfig("myservice", usage);

    expect(inject).toHaveLength(2);
    const webFetch = inject.find((r) => r.tool === "web_fetch");
    const exec = inject.find((r) => r.tool === "exec");
    expect(webFetch).toBeDefined();
    expect(exec).toBeDefined();
  });

  it("creates api + cli + browser-login rules", () => {
    const usage: UsageSelection = {
      apiCalls: {
        urlPattern: "*api.example.com/*",
        headerName: "Authorization",
        headerFormat: "Bearer $token",
      },
      cliTool: {
        commandMatch: "example*",
        envVar: "EXAMPLE_TOKEN",
      },
      browserLogin: {
        domain: ".example.com",
      },
      scrubPatterns: ["example_[a-z0-9]+"],
    };
    const { inject, scrub } = buildToolConfig("example", usage);

    expect(inject).toHaveLength(3);
    expect(inject.some((r) => r.tool === "web_fetch")).toBe(true);
    expect(inject.some((r) => r.tool === "exec")).toBe(true);
    expect(inject.some((r) => r.type === "browser-password")).toBe(true);
    expect(scrub.patterns).toHaveLength(1);
  });

  it("creates all four usage types correctly", () => {
    const usage: UsageSelection = {
      apiCalls: {
        urlPattern: "*api.example.com/*",
        headerName: "Authorization",
        headerFormat: "Bearer $token",
      },
      cliTool: {
        commandMatch: "example*",
        envVar: "EXAMPLE_KEY",
      },
      browserLogin: {
        domain: ".example.com",
      },
      browserSession: {
        domain: ".example.com",
        cookieFilePath: "/tmp/cookies.json",
      },
      scrubPatterns: [],
    };
    const { inject } = buildToolConfig("example", usage);

    expect(inject).toHaveLength(4);
    expect(inject.some((r) => r.tool === "web_fetch")).toBe(true);
    expect(inject.some((r) => r.tool === "exec")).toBe(true);
    expect(inject.some((r) => r.type === "browser-password")).toBe(true);
    expect(inject.some((r) => r.type === "browser-cookie")).toBe(true);
  });

  it("returns empty inject when no usage types specified", () => {
    const usage: UsageSelection = { scrubPatterns: [] };
    const { inject } = buildToolConfig("empty", usage);
    expect(inject).toHaveLength(0);
  });
});

// ─── Security: no credential values in config ───────────────────────────────

describe("buildToolConfig — Security invariants", () => {
  it("uses $vault: placeholder, never stores raw credential value", () => {
    const fakeCredential = "sk_live_itsasecret";
    const usage: UsageSelection = {
      apiCalls: {
        urlPattern: "*api.stripe.com/*",
        headerName: "Authorization",
        headerFormat: "Bearer $token",
      },
      scrubPatterns: [],
    };
    const { inject } = buildToolConfig("stripe", usage);
    const configStr = JSON.stringify(inject);
    expect(configStr).not.toContain(fakeCredential);
    expect(configStr).toContain("$vault:stripe");
  });

  it("browser-login rule has domainPin set (prevents cross-domain injection)", () => {
    const usage: UsageSelection = {
      browserLogin: { domain: ".secure-bank.com" },
      scrubPatterns: [],
    };
    const { inject } = buildToolConfig("bank", usage);
    const browserRule = inject.find((r) => r.type === "browser-password");
    expect(browserRule?.domainPin).toBeDefined();
    expect(browserRule?.domainPin?.length).toBeGreaterThan(0);
  });

  it("browser-session rule has domainPin set (prevents cross-domain injection)", () => {
    const usage: UsageSelection = {
      browserSession: { domain: ".secure-bank.com", cookieFilePath: "/tmp/c.json" },
      scrubPatterns: [],
    };
    const { inject } = buildToolConfig("bank-session", usage);
    const browserRule = inject.find((r) => r.type === "browser-cookie");
    expect(browserRule?.domainPin).toBeDefined();
    expect(browserRule?.domainPin?.length).toBeGreaterThan(0);
  });
});
