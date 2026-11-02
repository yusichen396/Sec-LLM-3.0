/** Agent API client for the Sec-LLM Agent platform. */

export interface AgentSession {
  id: string;
  status: string;
  task_type: string;
  target: string;
  created_at: string;
  findings_count: number;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export class AgentApiError extends Error {
  status: number;
  constructor(label: string, response: Response) {
    super(`${label}: ${response.status} ${response.statusText}`);
    this.name = "AgentApiError";
    this.status = response.status;
  }
}

function ensureOk(response: Response, label: string): Response {
  if (!response.ok) throw new AgentApiError(label, response);
  return response;
}

function authHeaders(): Record<string, string> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("token");
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

/** Submit a new agent task */
export async function runAgentTask(params: {
  target: string;
  task_type?: string;
  provider?: string;
}): Promise<{ session_id: string; status: string; message: string }> {
  const resp = await fetch(`${API_BASE}/api/agent/run`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({
      target: params.target,
      task_type: params.task_type || "web_scan",
      provider: params.provider || "local",
    }),
  });
  if (!resp.ok) throw new AgentApiError("Agent task failed", resp);
  return resp.json();
}

/** Get agent session status */
export async function getAgentStatus(sessionId: string): Promise<{
  session_id: string;
  status: string;
  phase: string;
  findings_count: number;
  steps_completed: number;
  steps_total: number;
  logs: string[];
  report: string | null;
}> {
  const resp = await fetch(`${API_BASE}/api/agent/${sessionId}/status`, {
    headers: authHeaders(),
  });
  if (!resp.ok) throw new AgentApiError("Status check failed", resp);
  return resp.json();
}

/** Get agent final report */
export async function getAgentReport(sessionId: string): Promise<{
  session_id: string;
  status: string;
  findings: Array<{ title: string; severity: string; description: string }>;
  report: string | null;
}> {
  const resp = await fetch(`${API_BASE}/api/agent/${sessionId}/report`, {
    headers: authHeaders(),
  });
  if (!resp.ok) throw new AgentApiError("Report fetch failed", resp);
  return resp.json();
}

/** List recent sessions */
export async function listAgentSessions(): Promise<{
  sessions: Array<{
    id: string;
    status: string;
    task_type: string;
    target: string;
    created_at: string;
    findings_count: number;
  }>;
}> {
  const resp = await fetch(`${API_BASE}/api/agent/sessions`, { headers: authHeaders() });
  if (!resp.ok) throw new AgentApiError("Session list failed", resp);
  return resp.json();
}

/** Create SSE connection for live agent logs (uses fetch + ReadableStream for auth header support) */
export function createAgentStream(
  sessionId: string,
  onLog: (msg: string) => void,
  onDone: (status: string, findingsCount: number) => void,
  onError: (err: string) => void,
): AbortController {
  const controller = new AbortController();
  const url = `${API_BASE}/api/agent/${sessionId}/stream`;

  fetch(url, { headers: authHeaders(), signal: controller.signal })
    .then(async (response) => {
      if (!response.ok) {
        onError(`Stream failed: ${response.status} ${response.statusText}`);
        return;
      }
      const reader = response.body?.getReader();
      if (!reader) { onError("No response body"); return; }
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) throw new Error("Stream ended before task completion");
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try {
              const data = JSON.parse(line.slice(6));
              if (data.type === "log") onLog(data.message);
              else if (data.type === "done") {
                onDone(data.status, data.findings_count || 0);
                controller.abort();
                return;
              }
            } catch { /* parse skip */ }
          }
        }
      }
    })
    .catch((err) => {
      if (err.name !== "AbortError") onError(err.message || "Stream connection lost");
    });

  return controller;
}
