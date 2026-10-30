"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Activity } from "lucide-react";
import AgentTaskPanel from "@/components/AgentTaskPanel";
import AgentLogStream from "@/components/AgentLogStream";
import { createAgentStream, getAgentReport, getAgentStatus, listAgentSessions } from "@/lib/agent-api";

export default function AgentPage() {
  const router = useRouter();
  const [isAuth, setIsAuth] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const [findingsCount, setFindingsCount] = useState(0);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [report, setReport] = useState<string | null>(null);
  const [sessions, setSessions] = useState<any[]>([]);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/login");
      return;
    }
    setIsAuth(true);
    listAgentSessions().then((data) => {
      const recent = data.sessions || [];
      setSessions(recent);
      const saved = sessionStorage.getItem("agent_session_id");
      const selected = recent.find((session) => session.id === saved) || recent.find((session) => session.status === "running");
      if (selected) setSessionId(selected.id);
    }).catch(() => {});
  }, [router]);

  useEffect(() => {
    if (!isAuth || !sessionId) return;
    sessionStorage.setItem("agent_session_id", sessionId);
    let active = true;
    let stream: AbortController | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let reconnects = 0;
    setLogs([]);
    setReport(null);
    const showReport = async () => {
      try {
        const result = await getAgentReport(sessionId);
        if (active) setReport(result.report);
      } catch { /* status and logs remain available if report loading fails */ }
    };
    const recover = (error: string) => {
      if (!active) return;
      stream?.abort();
      setStatus("reconnecting");
      setLogs((previous) => previous[previous.length - 1] === `[STREAM] ${error}`
        ? previous : [...previous, `[STREAM] ${error}`]);
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => { void syncStatus(); }, 3000);
    };
    const syncStatus = async () => {
      try {
        const data = await getAgentStatus(sessionId);
        if (!active) return;
        setStatus(data.status);
        setFindingsCount(data.findings_count);
        setLogs(data.logs || []);
        if (data.status !== "running") {
          void refreshSessions();
          await showReport();
          return;
        }
        if (reconnects >= 3) {
          timer = setTimeout(() => { void syncStatus(); }, 3000);
          return;
        }
        reconnects += 1;
        // The server replays logs from the start for every new stream.
        setLogs([]);
        stream = createAgentStream(
          sessionId,
          (message) => { if (active) setLogs((previous) => [...previous, message]); },
          async (finalStatus, count) => {
            if (!active) return;
            setStatus(finalStatus);
            setFindingsCount(count);
            refreshSessions();
            await showReport();
          },
          recover,
        );
      } catch (error: any) {
        recover(error.message || "Status connection lost");
      }
    };
    void syncStatus();
    return () => { active = false; stream?.abort(); if (timer) clearTimeout(timer); };
  }, [isAuth, sessionId]);

  const refreshSessions = async () => {
    try {
      const data = await listAgentSessions();
      setSessions(data.sessions || []);
    } catch {
      // ignore
    }
  };

  const handleTaskStart = (sid: string) => {
    setSessionId(sid);
    setLogs([]);
    setStatus("running");
    setFindingsCount(0);
    setReport(null);
    refreshSessions();
  };


  if (!isAuth) return null;

  return (
    <div className="flex h-screen bg-slate-950 overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 bg-slate-900 flex flex-col border-r border-slate-800 p-4">
        <div className="flex items-center gap-2 mb-6">
          <Shield className="w-6 h-6 text-cyan-400" />
          <span className="text-lg font-bold text-white">Sec-LLM Agent</span>
        </div>
        <button
          onClick={() => router.push("/")}
          className="text-sm text-gray-400 hover:text-white mb-4 text-left"
        >
          &larr; Dashboard
        </button>

        <AgentTaskPanel onTaskStart={handleTaskStart} running={status === "running" || status === "reconnecting"} />

        {/* Recent sessions */}
        {sessions.length > 0 && (
          <div className="mt-4">
            <h3 className="text-xs text-gray-500 mb-2">Recent Sessions</h3>
            <div className="space-y-1">
              {sessions.slice(0, 10).map((s: any) => (
                <button
                  key={s.id}
                  onClick={() => {
                    setSessionId(s.id);
                  }}
                  className={`w-full text-left text-xs px-2 py-1 rounded ${
                    sessionId === s.id
                      ? "bg-cyan-500/20 text-cyan-400"
                      : "text-gray-400 hover:text-white"
                  }`}
                >
                  <span className={s.status === "completed" ? "text-green-400" : "text-yellow-400"}>
                    {s.status === "completed" ? "O" : "~"}
                  </span>{" "}
                  {s.target?.slice(0, 25)}
                </button>
              ))}
            </div>
          </div>
        )}
      </aside>

      {/* Main content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        <header className="h-14 bg-slate-900/50 border-b border-white/5 flex items-center px-6">
          <h1 className="text-lg font-bold text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            Agent Console
            {sessionId && (
              <code className="text-xs text-gray-400 ml-2 bg-slate-800 px-2 py-0.5 rounded">
                {sessionId}
              </code>
            )}
          </h1>
        </header>

        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          <AgentLogStream logs={logs} status={status} findingsCount={findingsCount} />

          {report && (
            <div className="bg-slate-900/50 border border-white/5 rounded-lg p-6">
              <h2 className="text-lg font-semibold text-white mb-3">Report</h2>
              <div className="prose prose-invert max-w-none text-sm text-gray-300 whitespace-pre-wrap font-mono">
                {report}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
