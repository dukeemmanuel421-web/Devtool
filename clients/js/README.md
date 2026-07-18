# @agentguard/client

JS/TS client for the [AgentGuard](../../README.md) prompt-injection firewall API. Screen untrusted
content and gate tool calls before your agent acts. Fetch-based — works in Node and edge runtimes,
and drops into LangChain.js / the Vercel AI SDK.

```bash
npm install @agentguard/client
```

```ts
import { AgentGuard } from "@agentguard/client";

const guard = new AgentGuard({ baseUrl: process.env.AGENTGUARD_URL!, apiKey: process.env.AGENTGUARD_KEY });

// 1. screen a scraped page before feeding it to the model
const result = await guard.scan(pageText, "WEB_PAGE");
if (result.blocked) throw new Error("blocked untrusted content");

// 2. gate a tool call before executing it
const decision = await guard.checkAction({
  tool_call: { name: "send_email", args: { to: "..." } },
  reasoning_trace: steps,
  trusted_context: trusted,
});
if (!decision.allowed) console.warn(decision.reason);
```
