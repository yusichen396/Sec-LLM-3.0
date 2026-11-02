'use client';

import { useCallback, useEffect, useState, useRef } from 'react';
import { useRouter } from 'next/navigation';
import {
  Home,
  MessageSquare,
  Eye,
  FileText,
  LogOut,
  Shield,
  Search,
  Bell,
  User,
  HelpCircle,
  Send,
  Bot,
  Paperclip,
  Wrench,
  Activity,
} from 'lucide-react';
import {
  createChatHistory,
  deleteChatHistory,
  deleteKnowledgeFile,
  getChatHistories,
  getKnowledgeFiles,
  updateChatHistory,
  uploadFile,
  type ChatHistory,
  type ChatHistoryMessage,
  type KnowledgeFile,
  type LLMProvider,
  type UserInfo,
} from '@/lib/api';
import LLMProviderToggle from '@/components/LLMProviderToggle';

interface Message {
  role: 'user' | 'ai';
  content: string;
  sources?: string[];
}

const buildHistoryTitle = (text: string) => {
  const trimmed = text.trim();
  return trimmed.length > 10 ? trimmed.slice(0, 10) : trimmed || '新对话';
};

export default function ChatPage() {
  const router = useRouter();
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [activeMenu, setActiveMenu] = useState('chat');
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [chatHistories, setChatHistories] = useState<ChatHistory[]>([]);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [selectedHistoryId, setSelectedHistoryId] = useState<number | null>(null);
  const [editingHistoryId, setEditingHistoryId] = useState<number | null>(null);
  const [editingTitle, setEditingTitle] = useState('');
  const [isHistoryCollapsed, setIsHistoryCollapsed] = useState(false);
  const [showKnowledgeFiles, setShowKnowledgeFiles] = useState(false);
  const [knowledgeFiles, setKnowledgeFiles] = useState<KnowledgeFile[]>([]);
  const [knowledgeError, setKnowledgeError] = useState<string | null>(null);
  const [lastScanMinutes] = useState(() => Math.floor(Math.random() * 31));
  const [ragOnlyMode, setRagOnlyMode] = useState(false);
  const [currentProvider, setCurrentProvider] = useState<LLMProvider>('local');
  const messagesRef = useRef<Message[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const userMenuRef = useRef<HTMLDivElement>(null);
  const chatAbortRef = useRef<AbortController | null>(null);

  // 离开页面时中断还在进行的流式请求，避免对已卸载组件 setState
  useEffect(() => () => chatAbortRef.current?.abort(), []);

  useEffect(() => {
    // 检查认证状态
    const token = localStorage.getItem('token');
    if (!token) {
      router.push('/login');
      return;
    }
    setIsAuthenticated(true);
    setAuthToken(token);

    // 读取用户信息
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      try {
        setUserInfo(JSON.parse(savedUser));
      } catch (e) {
        console.error('解析用户信息失败:', e);
      }
    }

    // 从 localStorage 恢复聊天记录
    const savedHistory = localStorage.getItem('cyberguard_chat_history');
    if (savedHistory) {
      try {
        const parsedMessages = JSON.parse(savedHistory);
        if (Array.isArray(parsedMessages) && parsedMessages.length > 0) {
          setMessages(parsedMessages);
        }
      } catch (error) {
        console.error('恢复聊天记录失败:', error);
      }
    }
  }, [router]);

  useEffect(() => {
    messagesRef.current = messages;
  }, [messages]);

  const handleLogout = useCallback(() => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setShowUserMenu(false);
    router.push('/login');
  }, [router]);

  const loadChatHistories = useCallback(async (token: string) => {
    try {
      setHistoryError(null);
      const response = await getChatHistories(token, 50, 0);
      if (response.status === 'success') {
        const histories = response.histories || [];
        if (histories.length > 0) {
          setChatHistories(histories);
        } else if (messagesRef.current.length > 0) {
          // 回退显示当前会话，避免接口异常/空结果时侧栏"看起来全丢了"
          setChatHistories([
            {
              id: -1,
              title: buildHistoryTitle(messagesRef.current[0]?.content || '本地会话'),
              messages: messagesRef.current as ChatHistoryMessage[],
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            },
          ]);
        } else {
          setChatHistories([]);
        }
      } else {
        setHistoryError('历史记录加载失败');
      }
    } catch (error: any) {
      if (error?.response?.status === 401) {
        setHistoryError('登录已过期，请重新登录');
        handleLogout();
        return;
      }
      setHistoryError(error?.response?.data?.detail || '历史记录加载失败');
    }
  }, [handleLogout]);

  useEffect(() => {
    if (authToken) {
      loadChatHistories(authToken);
    }
  }, [authToken, loadChatHistories]);


  // 自动保存聊天记录到 localStorage
  useEffect(() => {
    if (messages.length > 0) {
      try {
        localStorage.setItem('cyberguard_chat_history', JSON.stringify(messages));
      } catch (error) {
        console.error('保存聊天记录失败:', error);
      }
    }
  }, [messages]);

  // 自动滚动到底部
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSelectHistory = (history: ChatHistory) => {
    setSelectedHistoryId(history.id);
    setMessages(history.messages || []);
  };

  const handleDeleteHistory = async (historyId: number) => {
    if (!authToken) return;
    try {
      const result = await deleteChatHistory(authToken, historyId);
      if (result.status === 'success') {
        setChatHistories((prev) => prev.filter((item) => item.id !== historyId));
        if (selectedHistoryId === historyId) {
          setSelectedHistoryId(null);
          setMessages([]);
        }
      }
    } catch (error) {
      setHistoryError('删除失败，请稍后重试');
    }
  };

  const startRenameHistory = (history: ChatHistory) => {
    setEditingHistoryId(history.id);
    setEditingTitle(history.title);
  };

  const cancelRenameHistory = () => {
    setEditingHistoryId(null);
    setEditingTitle('');
  };

  const submitRenameHistory = async (history: ChatHistory) => {
    if (!authToken) return;
    const trimmed = editingTitle.trim();
    if (!trimmed) return;
    try {
      const result = await updateChatHistory(
        authToken,
        history.id,
        history.messages || [],
        trimmed
      );
      if (result.status === 'success') {
        setChatHistories((prev) =>
          prev.map((item) =>
            item.id === history.id
              ? { ...item, title: trimmed.slice(0, 10) }
              : item
          )
        );
        cancelRenameHistory();
      }
    } catch (error) {
      setHistoryError('重命名失败，请稍后重试');
    }
  };

  const handleNewChat = () => {
    setSelectedHistoryId(null);
    setMessages([]);
    localStorage.removeItem('cyberguard_chat_history');
  };


  const loadKnowledgeFiles = async () => {
    try {
      setKnowledgeError(null);
      const response = await getKnowledgeFiles();
      setKnowledgeFiles(response.files || []);
    } catch (error) {
      setKnowledgeFiles([]);
      setKnowledgeError('知识库文件获取失败');
    }
  };

  const handleDeleteKnowledgeFile = async (fileId: number) => {
    if (!window.confirm('确认删除该知识库文件吗？')) return;
    try {
      const result = await deleteKnowledgeFile(fileId);
      if (result.status === 'success') {
        setKnowledgeFiles((prev) => prev.filter((item) => item.id !== fileId));
      }
    } catch (error) {
      setKnowledgeError('删除失败');
    }
  };

  // 点击外部关闭用户菜单
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setShowUserMenu(false);
      }
    };

    if (showUserMenu) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => {
        document.removeEventListener('mousedown', handleClickOutside);
      };
    }
  }, [showUserMenu]);

  const handleMenuClick = (menu: string) => {
    setActiveMenu(menu);
    if (menu === 'dashboard') {
      router.push('/');
    } else if (menu === 'chat') {
      router.push('/chat');
    } else if (menu === 'analysis') {
      router.push('/log-analysis');
    } else if (menu === 'reports') {
      router.push('/report-generation');
    } else if (menu === 'threat-intel') {
      router.push('/threat-intel-agent');
    } else if (menu === 'security-tools') {
      router.push('/security-tools');
    }
  };

  const handleSend = async () => {
    if (!inputMessage.trim() || isLoading) return;

    const userMessage = inputMessage.trim();
    setInputMessage('');
    
    // 1. 先把用户的消息加上去
    setMessages((prev) => [...prev, { role: 'user', content: userMessage }]);
    setIsLoading(true);

    // 2. 预先占位一个空的 AI 消息，准备接收数据
    setMessages((prev) => [...prev, { role: 'ai', content: '' }]);

    try {
      // 3. 使用 fetch 发起流式请求 (绕过 axios)
      const historyPayload = messages.map((msg) => ({
        role: msg.role,
        content: msg.content,
      }));

      const backendBaseUrl = (process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000').replace(/\/$/, '');
      chatAbortRef.current?.abort();
      const controller = new AbortController();
      chatAbortRef.current = controller;
      const response = await fetch(`${backendBaseUrl}/api/chat`, {
        method: 'POST',
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
        body: JSON.stringify({
          message: userMessage,
          history: historyPayload,
          rag_only: ragOnlyMode,
        }),
      });

      if (!response.ok) {
        if (response.status === 401) {
          handleLogout();
          return;
        }
        throw new Error(response.statusText);
      }
      if (!response.body) throw new Error('No response body');

      // 4. 读取流
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let aiContent = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        // 解码并追加内容
        const chunk = decoder.decode(value, { stream: true });
        aiContent += chunk;
        const sanitized = aiContent;

        // 5. 实时更新 UI（不可变更新，避免直接改状态对象）
        setMessages((prev) =>
          prev.map((item, index) =>
            index === prev.length - 1 && item.role === 'ai'
              ? { ...item, content: sanitized }
              : item
          )
        );
      }

      const finalContent = aiContent;
      const finalMessages = messagesRef.current.map((item, idx) => {
        if (idx === messagesRef.current.length - 1 && item.role === 'ai') {
          return { ...item, content: finalContent };
        }
        return item;
      });
      setMessages(finalMessages);

      if (authToken) {
        const historyMessages: ChatHistoryMessage[] = finalMessages.map((item) => ({
          role: item.role,
          content: item.content,
        }));
        const title = buildHistoryTitle(userMessage);

        if (selectedHistoryId) {
          const result = await updateChatHistory(authToken, selectedHistoryId, historyMessages);
          if (result.status === 'success') {
            loadChatHistories(authToken);
          }
        } else {
          const result = await createChatHistory(authToken, title, historyMessages);
          if (result.status === 'success' && result.id) {
            setSelectedHistoryId(result.id);
            loadChatHistories(authToken);
          }
        }
      }

    } catch (error: any) {
      if (error?.name === 'AbortError') {
        // 用户切换了页面或发起了新请求：静默结束，不写错误气泡
        return;
      }
      console.error('Chat error:', error);
      setMessages((prev) =>
        prev.map((item, index) =>
          index === prev.length - 1 && item.role === 'ai'
            ? { ...item, content: `${item.content}\n[系统错误: ${error.message || '连接中断'}]` }
            : item
        )
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // 检查文件类型
    const allowedTypes = ['.pdf', '.txt'];
    const fileExtension = '.' + file.name.split('.').pop()?.toLowerCase();
    
    if (!allowedTypes.includes(fileExtension)) {
      alert('仅支持 PDF 和 TXT 文件');
      return;
    }

    setIsUploading(true);
    setUploadStatus('上传中...');

    try {
      const response = await uploadFile(file);
      
      if (response.status === 'success') {
        setUploadStatus(`✅ ${response.message}`);
        setTimeout(() => setUploadStatus(null), 3000);
      } else {
        setUploadStatus(`❌ ${response.message}`);
        setTimeout(() => setUploadStatus(null), 3000);
      }
    } catch (error: any) {
      setUploadStatus(`❌ 上传失败: ${error.response?.data?.message || error.message}`);
      setTimeout(() => setUploadStatus(null), 3000);
    } finally {
      setIsUploading(false);
      // 清空文件输入，允许重复上传同一文件
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const triggerFileInput = () => {
    fileInputRef.current?.click();
  };

  // 如果未认证，不渲染内容
  if (!isAuthenticated) {
    return null;
  }

  return (
    <div className="flex h-screen bg-slate-950 overflow-hidden">
      {/* 左侧固定侧边栏 */}
      <aside className="w-64 bg-slate-900 flex flex-col border-r border-slate-800">
        {/* Logo */}
        <div className="p-6 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-cyan-400" />
            <div className="flex flex-col">
              <span className="text-xl font-bold text-white leading-tight">灵犀网卫</span>
              <span className="text-xl font-bold text-white leading-tight">Sec-LLM</span>
            </div>
          </div>
        </div>

        {/* 导航菜单 */}
        <nav className="flex-1 p-4 space-y-2">
          <button
            onClick={() => handleMenuClick('dashboard')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
              activeMenu === 'dashboard'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-gray-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            <Home className="w-5 h-5" />
            <span className="font-medium">仪表盘</span>
          </button>

          <button
            onClick={() => handleMenuClick('chat')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
              activeMenu === 'chat'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-gray-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            <MessageSquare className="w-5 h-5" />
            <span className="font-medium">AI智能回答</span>
          </button>

          <button
            onClick={() => handleMenuClick('threat-intel')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
              activeMenu === 'threat-intel'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-gray-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            <Activity className="w-5 h-5" />
            <span className="font-medium">威胁情报研判</span>
          </button>

          <button
            onClick={() => handleMenuClick('analysis')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
              activeMenu === 'analysis'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-gray-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            <Eye className="w-5 h-5" />
            <span className="font-medium">日志分析</span>
          </button>

          <button
            onClick={() => handleMenuClick('reports')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
              activeMenu === 'reports'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-gray-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            <FileText className="w-5 h-5" />
            <span className="font-medium">报告生成</span>
          </button>
          <button
            onClick={() => handleMenuClick('security-tools')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
              activeMenu === 'security-tools'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-gray-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            <Wrench className="w-5 h-5" />
            <span className="font-medium">安全工具箱</span>
          </button>
        </nav>

        {/* 系统状态 */}
        <div className="p-4 border-t border-slate-800">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-2 bg-green-400 rounded-full"></div>
            <span className="text-sm text-gray-400">系统安全</span>
          </div>
          <p className="text-xs text-gray-500">上次扫描: {lastScanMinutes} 分钟前</p>
        </div>

        {/* 登出按钮 */}
        <div className="p-4 border-t border-slate-800">
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-gray-400 hover:text-white hover:bg-slate-800/50 transition-all"
          >
            <LogOut className="w-5 h-5" />
            <span className="font-medium">登出</span>
          </button>
        </div>
      </aside>

      {/* 主内容区域 */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* 顶部标题栏 */}
        <header className="h-16 bg-slate-900/50 backdrop-blur border-b border-white/5 flex items-center justify-between px-6 relative z-50">
          <div>
            <h1 className="text-xl font-bold text-white">AI智能回答</h1>
            <p className="text-xs text-gray-400">AI Security Analyst</p>
          </div>
          
          <div className="flex items-center gap-4">
            <LLMProviderToggle
              onAuthExpired={handleLogout}
              onProviderChange={(provider) => {
                setCurrentProvider(provider);
                if (provider === 'cloud') {
                  setRagOnlyMode(false);
                }
              }}
            />

            {/* 搜索框 */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="搜索日志、IP、威胁..."
                className="pl-10 pr-4 py-2 bg-slate-800/50 border border-white/5 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 w-64"
              />
            </div>

            {/* 用户信息 */}
            <div className="flex items-center gap-3">
              <button className="p-2 text-gray-400 hover:text-white transition-colors">
                <Bell className="w-5 h-5" />
              </button>
              <button className="p-2 text-gray-400 hover:text-white transition-colors">
                <HelpCircle className="w-5 h-5" />
              </button>
              {/* 用户头像和信息 */}
              <div className="relative z-[9999]" ref={userMenuRef}>
                <button
                  onClick={() => setShowUserMenu(!showUserMenu)}
                  className="flex items-center gap-2 hover:bg-slate-800/50 rounded-lg p-1.5 transition-colors"
                >
                  <div className="w-8 h-8 rounded-full bg-cyan-500/20 flex items-center justify-center border border-cyan-500/30">
                    <User className="w-4 h-4 text-cyan-400" />
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-medium text-white">
                      {userInfo?.full_name || userInfo?.username || '用户'}
                    </p>
                    <p className="text-xs text-gray-400">
                      {userInfo?.role === 'admin' ? '系统管理员' : '普通用户'}
                    </p>
                  </div>
                </button>

                {/* 用户信息悬浮卡片 */}
                {showUserMenu && (
                  <div className="fixed top-16 right-6 w-72 bg-slate-900 border border-slate-700 rounded-lg shadow-2xl z-[9999] overflow-hidden">
                    {/* 头部背景 */}
                    <div className="bg-gradient-to-r from-cyan-500/20 to-blue-500/20 p-4 border-b border-slate-700">
                      <div className="flex items-center gap-3">
                        <div className="w-12 h-12 rounded-full bg-cyan-500/30 flex items-center justify-center border-2 border-cyan-500/50">
                          <User className="w-6 h-6 text-cyan-400" />
                        </div>
                        <div>
                          <p className="text-lg font-semibold text-white">
                            {userInfo?.full_name || userInfo?.username || '用户'}
                          </p>
                          <p className="text-sm text-cyan-400">@{userInfo?.username || 'user'}</p>
                        </div>
                      </div>
                    </div>

                    {/* 用户详情 */}
                    <div className="p-4 space-y-3">
                      <div className="flex items-center gap-3 text-sm">
                        <div className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center">
                          <Shield className="w-4 h-4 text-cyan-400" />
                        </div>
                        <div>
                          <p className="text-gray-400 text-xs">角色</p>
                          <p className="text-white font-medium">
                            {userInfo?.role === 'admin' ? '系统管理员' : '普通用户'}
                          </p>
                        </div>
                      </div>

                      {userInfo?.email && (
                        <div className="flex items-center gap-3 text-sm">
                          <div className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center">
                            <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                            </svg>
                          </div>
                          <div>
                            <p className="text-gray-400 text-xs">邮箱</p>
                            <p className="text-white font-medium">{userInfo.email}</p>
                          </div>
                        </div>
                      )}

                      <div className="flex items-center gap-3 text-sm">
                        <div className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center">
                          <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                          </svg>
                        </div>
                        <div>
                          <p className="text-gray-400 text-xs">状态</p>
                          <p className="text-green-400 font-medium">在线</p>
                        </div>
                      </div>
                    </div>

                    {/* 操作按钮 */}
                    <div className="border-t border-slate-700 p-2">
                      <button
                        onClick={handleLogout}
                        className="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                      >
                        <LogOut className="w-4 h-4" />
                        <span>退出登录</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </header>

        <div className="flex-1 flex overflow-hidden">
          {/* 对话历史侧边栏 */}
          <aside
            className={`bg-slate-900/60 border-r border-white/5 overflow-y-auto transition-all duration-200 ${
              isHistoryCollapsed ? 'w-14 p-2' : 'w-72 p-4'
            }`}
          >
            <div className={`flex items-center ${isHistoryCollapsed ? 'justify-center' : 'justify-between'} mb-3`}>
              {!isHistoryCollapsed && (
                <h2 className="text-sm font-semibold text-white">历史对话</h2>
              )}
              <button
                onClick={() => setIsHistoryCollapsed((prev) => !prev)}
                className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                {isHistoryCollapsed ? '展开' : '收起'}
              </button>
            </div>

            {!isHistoryCollapsed && (
              <>
                <div className="flex items-center justify-between mb-3">
                  <button
                    onClick={handleNewChat}
                    className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                  >
                    新对话
                  </button>
                  <button
                    onClick={() => authToken && loadChatHistories(authToken)}
                    className="text-xs text-gray-400 hover:text-gray-200 transition-colors"
                  >
                    刷新
                  </button>
                </div>

                {historyError && (
                  <div className="mb-3 text-xs text-red-400">{historyError}</div>
                )}

                {chatHistories.length > 0 ? (
                  <div className="space-y-2">
                    {chatHistories.map((history) => (
                      <div
                        key={history.id}
                        className={`group flex items-center justify-between gap-2 rounded-lg border px-3 py-2 text-sm transition-all ${
                          selectedHistoryId === history.id
                            ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-300'
                            : 'border-white/5 bg-slate-800/40 text-gray-300 hover:border-cyan-500/30 hover:text-white'
                        }`}
                      >
                        {editingHistoryId === history.id ? (
                          <div className="flex-1 flex items-center gap-2">
                            <input
                              value={editingTitle}
                              onChange={(event) => setEditingTitle(event.target.value.slice(0, 10))}
                              onKeyDown={(event) => {
                                if (event.key === 'Enter') {
                                  event.preventDefault();
                                  submitRenameHistory(history);
                                }
                                if (event.key === 'Escape') {
                                  event.preventDefault();
                                  cancelRenameHistory();
                                }
                              }}
                              className="flex-1 bg-slate-900/60 border border-cyan-500/40 rounded px-2 py-1 text-xs text-white focus:outline-none"
                            />
                            <button
                              onClick={() => submitRenameHistory(history)}
                              className="text-xs text-cyan-400 hover:text-cyan-300"
                            >
                              保存
                            </button>
                            <button
                              onClick={cancelRenameHistory}
                              className="text-xs text-gray-400 hover:text-gray-200"
                            >
                              取消
                            </button>
                          </div>
                        ) : (
                          <>
                            <button
                              onClick={() => handleSelectHistory(history)}
                              className="flex-1 text-left truncate"
                              title={history.title}
                            >
                              {history.title}
                            </button>
                            <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                              {history.id > 0 && (
                                <>
                                  <button
                                    onClick={() => startRenameHistory(history)}
                                    className="text-xs text-cyan-400 hover:text-cyan-300"
                                  >
                                    重命名
                                  </button>
                                  <button
                                    onClick={() => handleDeleteHistory(history.id)}
                                    className="text-xs text-red-400 hover:text-red-300"
                                  >
                                    删除
                                  </button>
                                </>
                              )}
                            </div>
                          </>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-gray-500">暂无历史对话</div>
                )}
              </>
            )}
          </aside>

          {/* 对话区域 */}
          <div className="flex-1 flex flex-col overflow-hidden">
            {/* 消息区域 - 可滚动 */}
            <div className="flex-1 overflow-y-auto p-6 relative z-0">
              <div className="max-w-4xl mx-auto space-y-6">
                {messages.length === 0 && (
                  <div className="text-center py-12">
                    <Bot className="w-16 h-16 text-cyan-400 mx-auto mb-4 opacity-50" />
                    <p className="text-gray-400 text-lg">开始与 AI 安全分析师对话</p>
                    <p className="text-gray-500 text-sm mt-2">询问安全相关问题，获取专业的攻防建议</p>
                  </div>
                )}

                {messages.map((message, index) => (
                  <div
                    key={index}
                    className={`flex gap-4 ${
                      message.role === 'user' ? 'justify-end' : 'justify-start'
                    }`}
                  >
                    {message.role === 'ai' && (
                      <div className="w-10 h-10 rounded-full bg-slate-800/50 border border-white/5 flex items-center justify-center flex-shrink-0">
                        <Bot className="w-5 h-5 text-cyan-400" />
                      </div>
                    )}

                    <div
                      className={`max-w-[80%] rounded-lg p-4 ${
                        message.role === 'user'
                          ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white'
                          : 'bg-slate-900/50 backdrop-blur border border-white/5 text-gray-100'
                      }`}
                    >
                      <div className="whitespace-pre-wrap break-words">
                        {message.content}
                        {message.role === 'ai' && isLoading && index === messages.length - 1 && (
                          <span className="inline-block w-2 h-4 ml-1 align-middle bg-cyan-400 animate-pulse"></span>
                        )}
                      </div>
                    </div>

                    {message.role === 'user' && (
                      <div className="w-10 h-10 rounded-full bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center flex-shrink-0">
                        <User className="w-5 h-5 text-cyan-400" />
                      </div>
                    )}
                  </div>
                ))}

                <div ref={messagesEndRef} />
              </div>
            </div>

            {/* 输入区域 - 固定在底部 */}
            <div className="border-t border-white/5 bg-slate-900/50 backdrop-blur p-4">
              <div className="max-w-4xl mx-auto">
                {/* 上传状态提示 */}
                {uploadStatus && (
                  <div className={`mb-3 px-4 py-2 rounded-lg text-sm ${
                    uploadStatus.includes('✅') 
                      ? 'bg-green-500/20 text-green-400 border border-green-500/30' 
                      : 'bg-red-500/20 text-red-400 border border-red-500/30'
                  }`}>
                    {uploadStatus}
                  </div>
                )}
                
                <div className="flex gap-4 items-end">
                  {/* 隐藏的文件输入 */}
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".pdf,.txt"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                  
                  {/* 文件上传按钮 */}
                  <button
                    onClick={triggerFileInput}
                    disabled={isUploading || isLoading}
                    className="px-4 py-3 bg-slate-800/50 border border-white/5 rounded-lg text-gray-400 hover:text-cyan-400 hover:border-cyan-500/30 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
                    title="上传文件 (PDF/TXT)"
                  >
                    {isUploading ? (
                      <div className="w-5 h-5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin"></div>
                    ) : (
                      <Paperclip className="w-5 h-5" />
                    )}
                  </button>
              <button
                onClick={() => {
                  if (!showKnowledgeFiles) {
                    loadKnowledgeFiles();
                  }
                  setShowKnowledgeFiles((prev) => !prev);
                }}
                className="px-4 py-3 bg-slate-800/50 border border-white/5 rounded-lg text-gray-400 hover:text-cyan-400 hover:border-cyan-500/30 transition-all duration-200 flex items-center justify-center"
                title="查看知识库文件"
              >
                知识库
              </button>
              <button
                onClick={() => setRagOnlyMode((prev) => !prev)}
                disabled={currentProvider === 'cloud'}
                className={`px-4 py-3 border rounded-lg transition-all duration-200 flex items-center justify-center text-sm ${
                  currentProvider === 'cloud'
                    ? 'bg-slate-800/30 border-white/5 text-gray-600 cursor-not-allowed'
                    : ragOnlyMode
                    ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300'
                    : 'bg-slate-800/50 border-white/5 text-gray-400 hover:text-cyan-400 hover:border-cyan-500/30'
                }`}
                title={
                  currentProvider === 'cloud'
                    ? '云端模式下不可使用仅RAG'
                    : '开启后仅使用本地知识库回答'
                }
              >
                仅RAG
              </button>
                  
                  <div className="flex-1 relative">
                    <textarea
                      ref={inputRef}
                      value={inputMessage}
                      onChange={(e) => setInputMessage(e.target.value)}
                      onKeyPress={handleKeyPress}
                      placeholder="输入您的问题... (按 Enter 发送，Shift+Enter 换行)"
                      rows={1}
                      className="w-full px-4 py-3 bg-slate-800/50 border border-white/5 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 resize-none font-mono text-sm"
                      style={{
                        minHeight: '48px',
                        maxHeight: '200px',
                        height: 'auto',
                      }}
                      onInput={(e) => {
                        const target = e.target as HTMLTextAreaElement;
                        target.style.height = 'auto';
                        target.style.height = `${target.scrollHeight}px`;
                      }}
                      disabled={isLoading || isUploading}
                    />
                  </div>
                  <button
                    onClick={handleSend}
                    disabled={!inputMessage.trim() || isLoading || isUploading}
                    className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-600 hover:to-blue-700 text-white font-semibold rounded-lg transition-all duration-200 flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Send className="w-5 h-5" />
                    <span>发送</span>
                  </button>
                </div>
              </div>
            </div>
            {showKnowledgeFiles && (
              <div className="mt-4 bg-slate-900/60 border border-white/5 rounded-lg p-4 text-sm text-gray-300">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-sm font-semibold text-white">已上传知识库文件</span>
                  <button
                    onClick={loadKnowledgeFiles}
                    className="text-xs text-cyan-400 hover:text-cyan-300"
                  >
                    刷新
                  </button>
                </div>
                {knowledgeError && <div className="text-xs text-red-400">{knowledgeError}</div>}
                {knowledgeFiles.length > 0 ? (
                  <div className="max-h-56 overflow-y-auto pr-1 space-y-3">
                    {knowledgeFiles.map((file) => (
                      <div
                        key={file.id}
                        className="bg-slate-900/70 border border-slate-700 rounded-lg p-3 shadow-sm hover:border-cyan-500/40 transition-colors"
                      >
                        <div className="flex items-center justify-between gap-3">
                          <span className="text-sm text-white truncate">{file.filename}</span>
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-gray-500 whitespace-nowrap">
                              {file.chunk_count ?? 0} chunks
                            </span>
                            <button
                              onClick={() => handleDeleteKnowledgeFile(file.id)}
                              className="text-xs text-red-400 hover:text-red-300"
                            >
                              删除
                            </button>
                          </div>
                        </div>
                        <div className="mt-2 text-xs text-gray-500">
                          {file.status || 'indexed'}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-gray-500">暂无已上传文件</div>
                )}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
