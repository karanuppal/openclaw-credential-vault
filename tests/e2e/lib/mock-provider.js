#!/usr/bin/env node
/**
 * mock-provider.js — Fake LLM provider for E2E gateway integration tests
 *
 * Returns OpenAI-compatible chat completion responses with tool calls.
 * The gateway sends tool-use requests here; we return canned responses
 * that trigger credential injection and scrubbing.
 *
 * Usage:
 *   node mock-provider.js [port]
 *   MOCK_PORT=9876 node mock-provider.js
 *
 * Endpoints:
 *   POST /v1/chat/completions  — OpenAI-compatible completions
 *   GET  /health               — Health check
 *   POST /shutdown             — Graceful shutdown
 */

const http = require("http");

const PORT = parseInt(process.env.MOCK_PORT || process.argv[2] || "9876", 10);

// --- Canned tool call responses ---

// Maps user message content to tool-call responses
const TOOL_CALL_ROUTES = {
  // Phase 5 test 16: injection test — run gh api user
  "gh api user": {
    tool_calls: [
      {
        id: "call_gh_api_user",
        type: "function",
        function: {
          name: "shell",
          arguments: JSON.stringify({ command: "gh api user" }),
        },
      },
    ],
  },

  // Phase 5 test 17: scrubbing test — echo the token
  "echo github token": {
    tool_calls: [
      {
        id: "call_echo_gh",
        type: "function",
        function: {
          name: "shell",
          arguments: JSON.stringify({ command: "echo $GH_TOKEN" }),
        },
      },
    ],
  },

  // Phase 5 test 18: multi-credential — github + npm
  "use github and npm": {
    tool_calls: [
      {
        id: "call_multi_gh",
        type: "function",
        function: {
          name: "shell",
          arguments: JSON.stringify({ command: "echo GH=$GH_TOKEN NPM=$NPM_TOKEN" }),
        },
      },
    ],
  },

  // Phase 5 test 19: non-matching command — no credentials
  "list files": {
    tool_calls: [
      {
        id: "call_ls",
        type: "function",
        function: {
          name: "shell",
          arguments: JSON.stringify({ command: "ls -la" }),
        },
      },
    ],
  },

  // Phase 5 test 20: compound commands
  "compound github": {
    tool_calls: [
      {
        id: "call_compound",
        type: "function",
        function: {
          name: "shell",
          arguments: JSON.stringify({
            command: "gh api user && echo done",
          }),
        },
      },
    ],
  },

  // Phase 5 test 21: error command
  "github error": {
    tool_calls: [
      {
        id: "call_gh_error",
        type: "function",
        function: {
          name: "shell",
          arguments: JSON.stringify({ command: "gh api /nonexistent" }),
        },
      },
    ],
  },

  // Phase 5 test 22: hot-reload add — use newcred
  "use newcred": {
    tool_calls: [
      {
        id: "call_newcred",
        type: "function",
        function: {
          name: "shell",
          arguments: JSON.stringify({ command: "echo $NEWCRED_KEY" }),
        },
      },
    ],
  },

  // Phase 5 test 23: hot-reload remove — use removed cred
  "use removed newcred": {
    tool_calls: [
      {
        id: "call_removed",
        type: "function",
        function: {
          name: "shell",
          arguments: JSON.stringify({ command: "echo $NEWCRED_KEY" }),
        },
      },
    ],
  },
};

// Default text response for unmatched messages
const DEFAULT_RESPONSE = {
  content: "I don't have a canned response for that. This is the mock provider.",
};

function buildCompletionResponse(choice) {
  const id = "chatcmpl-mock-" + Date.now();
  const message = {};

  if (choice.tool_calls) {
    message.role = "assistant";
    message.content = null;
    message.tool_calls = choice.tool_calls;
  } else {
    message.role = "assistant";
    message.content = choice.content;
  }

  return {
    id,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: "mock-llm-v1",
    choices: [
      {
        index: 0,
        message,
        finish_reason: choice.tool_calls ? "tool_calls" : "stop",
      },
    ],
    usage: {
      prompt_tokens: 10,
      completion_tokens: 20,
      total_tokens: 30,
    },
  };
}

function extractUserMessage(body) {
  try {
    const parsed = JSON.parse(body);
    const messages = parsed.messages || [];
    // Find last user message
    for (let i = messages.length - 1; i >= 0; i--) {
      if (messages[i].role === "user") {
        return (messages[i].content || "").toLowerCase().trim();
      }
    }
  } catch {
    // ignore parse errors
  }
  return "";
}

const server = http.createServer((req, res) => {
  // Health check
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", provider: "mock-llm" }));
    return;
  }

  // Shutdown
  if (req.method === "POST" && req.url === "/shutdown") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "shutting_down" }));
    server.close(() => process.exit(0));
    return;
  }

  // Chat completions
  if (req.method === "POST" && req.url === "/v1/chat/completions") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      const userMsg = extractUserMessage(body);
      console.log(`[mock-provider] user message: "${userMsg}"`);

      // Find matching canned response
      let choice = DEFAULT_RESPONSE;
      for (const [key, value] of Object.entries(TOOL_CALL_ROUTES)) {
        if (userMsg.includes(key.toLowerCase())) {
          choice = value;
          break;
        }
      }

      const response = buildCompletionResponse(choice);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(response));
    });
    return;
  }

  // 404 for everything else
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "not found" }));
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[mock-provider] listening on http://0.0.0.0:${PORT}`);
  console.log(`[mock-provider] endpoints:`);
  console.log(`  POST /v1/chat/completions`);
  console.log(`  GET  /health`);
  console.log(`  POST /shutdown`);
});

// Handle graceful shutdown
process.on("SIGTERM", () => {
  console.log("[mock-provider] SIGTERM received, shutting down");
  server.close(() => process.exit(0));
});

process.on("SIGINT", () => {
  console.log("[mock-provider] SIGINT received, shutting down");
  server.close(() => process.exit(0));
});
