import axios from 'axios';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers = config.headers || {};
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

export interface LoginRequest {
  username: string;
  password: string;
}

export interface RegisterRequest {
  username: string;
  password: string;
  email?: string;
  full_name?: string;
}

export interface UserInfo {
  id: number;
  username: string;
  email: string | null;
  full_name: string | null;
  role: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: UserInfo;
}

export interface RegisterResponse {
  status: string;
  message: string;
}

// 兼容旧版本的 LoginResponse
export interface LoginResponse {
  token: string;
  user: string;
}

export const login = async (credentials: LoginRequest): Promise<AuthResponse> => {
  const response = await api.post<AuthResponse>('/api/login', credentials);
  return response.data;
};

export const register = async (data: RegisterRequest): Promise<RegisterResponse> => {
  const response = await api.post<RegisterResponse>('/api/register', data);
  return response.data;
};

export const verifyEmail = async (token: string) => {
  const response = await api.get('/api/verify', {
    params: { token },
  });
  return response.data as { status: string; message: string };
};

export const resendVerification = async (email: string) => {
  const response = await api.post('/api/resend-verification', { email });
  return response.data as { status: string; message: string };
};

export type LLMProvider = 'local' | 'cloud';

export interface LLMProviderResponse {
  provider: LLMProvider;
  cloud_ready: boolean;
}

export const getLLMProvider = async (): Promise<LLMProviderResponse> => {
  const response = await api.get<LLMProviderResponse>('/api/llm/provider');
  return response.data;
};

export const setLLMProvider = async (provider: LLMProvider) => {
  const response = await api.put('/api/llm/provider', { provider });
  return response.data as { status: string; provider: LLMProvider };
};

export const getCurrentUser = async (token: string): Promise<UserInfo> => {
  const response = await api.get<UserInfo>('/api/me', {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });
  return response.data;
};

export interface ChatRequest {
  message: string;
}

/**
 * POST /api/chat returns a text/plain stream (not JSON). Callers that need
 * incremental rendering use fetch + ReadableStream; this helper buffers the whole
 * answer for one-shot use.
 */
export const chat = async (request: ChatRequest): Promise<string> => {
  const response = await api.post('/api/chat', request, {
    responseType: 'text',
    transformResponse: [(data) => data],
  });
  return typeof response.data === 'string' ? response.data : String(response.data ?? '');
};

export interface UploadResponse {
  status: string;
  message: string;
  chunks?: number;
}

export const uploadFile = async (file: File): Promise<UploadResponse> => {
  const formData = new FormData();
  formData.append('file', file);
  
  const response = await api.post<UploadResponse>('/api/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
};

export interface AnalysisResult {
  summary: string;
  threat_level: 'Low' | 'Medium' | 'High' | 'Critical';
  advice: string;
  details: Array<{
    type: string;
    payload: string;
    source_ip: string;
  }>;
}

export interface LogAnalysisResponse {
  filename: string;
  status: string;
  ai_analysis: AnalysisResult;
}

export interface LogRecord {
  id: number;
  filename: string;
  upload_time: string;
  threat_level: string;
  attack_type: string;
  source_ip: string;
  summary: string;
  status: 'unresolved' | 'resolved' | 'ignored';
}

export interface LogRecordsResponse {
  status: 'success' | 'error';
  records: LogRecord[];
}

export interface DashboardStatsResponse {
  total_events: number;
  active_threats: number;
  online_users: number;
  /** null 表示后端未接入负载采集（不是 0%） */
  system_load: number | null;
  ai_interactions: number;
  high_unresolved_count: number;
  chart_data: Array<{ time: string; value: number }>;
}

export interface ChatHistoryMessage {
  role: 'user' | 'ai';
  content: string;
}

export interface ChatHistory {
  id: number;
  title: string;
  messages: ChatHistoryMessage[];
  created_at: string;
  updated_at: string;
}

export interface ChatHistoriesResponse {
  status: 'success' | 'error';
  histories: ChatHistory[];
}

export interface KnowledgeFile {
  id: number;
  filename: string;
  upload_time: string;
  file_size: number | null;
  chunk_count: number | null;
  status: string;
}

export interface KnowledgeFilesResponse {
  files: KnowledgeFile[];
}

export interface PhishingAnalyzeResult {
  risk_score: number;
  verdict: string;
  dimensions: Record<string, number>;
  suspicious_urls: string[];
  suspicious_ips: string[];
  summary: string;
  recommendations: string[];
}

export interface PhishingAnalyzeResponse {
  status: 'success' | 'error';
  provider: 'local' | 'cloud';
  result: PhishingAnalyzeResult;
}

export interface CodeAuditFinding {
  title: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical' | string;
  line_hint: string;
  description: string;
  fix: string;
}

export interface CodeAuditResult {
  risk_level: 'Low' | 'Medium' | 'High' | 'Critical' | string;
  findings: CodeAuditFinding[];
  fixed_code: string;
  summary: string;
}

export interface CodeAuditResponse {
  status: 'success' | 'error';
  provider: 'local' | 'cloud';
  result: CodeAuditResult;
}

export interface ReportExplainResult {
  executive_summary: string;
  critical_findings: Array<{ item: string; risk: string; impact: string; action: string }>;
  exposed_ports: string[];
  priority_actions: string[];
  plain_language_brief: string;
}

export interface ReportExplainResponse {
  status: 'success' | 'error';
  provider: 'local' | 'cloud';
  result: ReportExplainResult;
}

export type ThreatIntelIocType = 'auto' | 'ip' | 'domain' | 'md5' | 'sha256';

export interface ThreatIntelSignal {
  source: string;
  status: string;
  score: number;
  confidence: number;
  tags: string[];
  summary: string;
  evidence: Record<string, unknown>;
}

export interface ThreatIntelEnrichment {
  signals: ThreatIntelSignal[];
  tags: string[];
  confidence: number;
  summary: string;
}

export interface ThreatIntelEnrichResponse {
  status: 'success' | 'error';
  ioc: string;
  normalized_ioc: string;
  detected_type: Exclude<ThreatIntelIocType, 'auto'>;
  source_hits: number;
  total_score: number;
  verdict: string;
  source_status: Record<string, { status: string; reason?: string }>;
  enrichment: ThreatIntelEnrichment;
}

export const uploadLogFile = async (file: File): Promise<LogAnalysisResponse> => {
  const formData = new FormData();
  formData.append('file', file);
  
  // 传递 mode=analysis 强制进行日志分析（而不是加入知识库）
  const response = await api.post<LogAnalysisResponse>('/api/upload?mode=analysis', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
};

export const getLogRecords = async (limit = 50, offset = 0): Promise<LogRecordsResponse> => {
  const response = await api.get<LogRecordsResponse>(`/api/log-records?limit=${limit}&offset=${offset}`);
  return response.data;
};

export const updateLogRecordStatus = async (
  recordId: number,
  status: 'unresolved' | 'resolved' | 'ignored'
) => {
  const response = await api.put(`/api/log-records/${recordId}/status?status=${status}`);
  return response.data as { status: string; updated?: number };
};

export const deleteLogRecord = async (recordId: number) => {
  const response = await api.delete(`/api/log-records/${recordId}`);
  return response.data as { status: string; deleted?: number };
};

export const getDashboardStats = async (): Promise<DashboardStatsResponse> => {
  const response = await api.get<DashboardStatsResponse>('/api/dashboard/stats');
  return response.data;
};

export const getChatHistories = async (
  token: string,
  limit = 50,
  offset = 0
): Promise<ChatHistoriesResponse> => {
  const response = await api.get<ChatHistoriesResponse>(
    `/api/chat-histories?limit=${limit}&offset=${offset}`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );
  return response.data;
};

export const createChatHistory = async (
  token: string,
  title: string,
  messages: ChatHistoryMessage[]
) => {
  const response = await api.post(
    '/api/chat-histories',
    { title, messages },
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );
  return response.data as { status: string; id?: number };
};

export const updateChatHistory = async (
  token: string,
  historyId: number,
  messages: ChatHistoryMessage[],
  title?: string
) => {
  const response = await api.put(
    `/api/chat-histories/${historyId}`,
    { title, messages },
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );
  return response.data as { status: string; updated?: number };
};

export const deleteChatHistory = async (token: string, historyId: number) => {
  const response = await api.delete(`/api/chat-histories/${historyId}`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return response.data as { status: string; deleted?: number };
};

export const getKnowledgeFiles = async (): Promise<KnowledgeFilesResponse> => {
  const response = await api.get<KnowledgeFilesResponse>('/api/knowledge/files');
  return response.data;
};

export const deleteKnowledgeFile = async (fileId: number) => {
  const response = await api.delete(`/api/knowledge/files/${fileId}`);
  return response.data as { status: string; message?: string };
};

export const analyzePhishingEmail = async (content: string): Promise<PhishingAnalyzeResponse> => {
  const response = await api.post<PhishingAnalyzeResponse>('/api/security-tools/phishing-analyzer', { content });
  return response.data;
};

export const analyzeCodeVulnerabilities = async (
  code: string,
  language: string
): Promise<CodeAuditResponse> => {
  const response = await api.post<CodeAuditResponse>('/api/security-tools/code-audit', { code, language });
  return response.data;
};

export const explainScanReport = async (content: string): Promise<ReportExplainResponse> => {
  const response = await api.post<ReportExplainResponse>('/api/security-tools/report-explainer', { content });
  return response.data;
};

export const enrichThreatIntel = async (
  ioc: string,
  iocType: ThreatIntelIocType = 'auto'
): Promise<ThreatIntelEnrichResponse> => {
  const response = await api.post<ThreatIntelEnrichResponse>('/api/security-tools/threat-intel/enrich', {
    ioc,
    ioc_type: iocType,
  });
  return response.data;
};

export default api;
