/**
 * AgentGuard JS/TS client — screen untrusted content and gate tool calls
 * before your agent acts on them. Works in Node and edge runtimes (fetch-based).
 */

export type TrustLevel =
  | "USER_PROMPT" | "TRUSTED_TOOL" | "TOOL_OUTPUT"
  | "WEB_PAGE" | "DOCUMENT" | "MCP_OUTPUT" | "UNKNOWN";

export type Severity = "low" | "medium" | "high" | "critical";

export interface Finding {
  detector: string;
  severity: Severity;
  snippet: string;
  reason: string;
  pattern?: string;
}

export interface ScanResult {
  blocked: boolean;
  risk: number;
  findings: Finding[];
  sanitized_text?: string | null;
}

export interface ActionDecision {
  allowed: boolean;
  risk: number;
  reason: string;
  findings: Finding[];
}

export interface AgentGuardOptions {
  baseUrl: string;
  apiKey?: string;
  fetchImpl?: typeof fetch;
}

export class AgentGuard {
  private baseUrl: string;
  private apiKey?: string;
  private f: typeof fetch;

  constructor(opts: AgentGuardOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.apiKey = opts.apiKey;
    this.f = opts.fetchImpl ?? fetch;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiKey) h["Authorization"] = `Bearer ${this.apiKey}`;
    return h;
  }

  /** Screen inbound content before it enters the agent's context. */
  async scan(text: string, source: TrustLevel = "UNKNOWN"): Promise<ScanResult> {
    const res = await this.f(`${this.baseUrl}/scan`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({ text, source }),
    });
    if (!res.ok) throw new Error(`AgentGuard scan failed: ${res.status} ${await res.text()}`);
    return res.json() as Promise<ScanResult>;
  }

  /** Gate a tool call before it executes. */
  async checkAction(input: {
    tool_call: Record<string, unknown>;
    reasoning_trace?: unknown[];
    trusted_context?: unknown[];
  }): Promise<ActionDecision> {
    const res = await this.f(`${this.baseUrl}/check_action`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({
        tool_call: input.tool_call,
        reasoning_trace: input.reasoning_trace ?? [],
        trusted_context: input.trusted_context ?? [],
      }),
    });
    if (!res.ok) throw new Error(`AgentGuard checkAction failed: ${res.status} ${await res.text()}`);
    return res.json() as Promise<ActionDecision>;
  }

  async health(): Promise<{ status: string }> {
    const res = await this.f(`${this.baseUrl}/health`);
    return res.json() as Promise<{ status: string }>;
  }
}
