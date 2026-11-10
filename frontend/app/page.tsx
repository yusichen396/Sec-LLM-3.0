'use client';

import { useEffect, useState, useRef } from 'react';
import { useRouter } from 'next/navigation';
import {
  Home,
  MessageSquare,
  Eye,
  FileText,
  LogOut,
  Shield,
  Network,
  Server,
  Lock,
  Search,
  Bell,
  User,
  HelpCircle,
  AlertTriangle,
  UserX,
  Info,
  Ban,
  CheckCircle,
  Cpu,
  HardDrive,
  Wifi,
  TrendingUp,
  TrendingDown,
  Clock,
  Zap,
  ArrowRight,
  Wrench,
  Activity,
} from 'lucide-react';
import { getDashboardStats, getLogRecords, type AnalysisResult, type LogRecord, type SecurityScore, type UserInfo } from '@/lib/api';
import LLMProviderToggle from '@/components/LLMProviderToggle';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

interface DashboardStats {
  // number 是后端真实值；string 用于"未接入"占位（如 '—'）
  totalThreats: { value: number | string; trend: number | null };
  networkTraffic: { value: number | string; trend: number | null };
  activeEndpoints: { value: number | string; trend: number | null };
  securityScore: { value: number | string; trend: number | null };
}

interface RecentActivity {
  id: number;
  type: 'alert' | 'login' | 'info' | 'quarantine' | 'success';
  message: string;
  details: string;
  timestamp: string;
}

interface SystemStatus {
  cpu: { usage: number; cores: string };
  memory: { used: string; total: string; status: string };
  storage: { used: string; total: string; status: string };
  network: { speed: string; ping: string; jitter: string };
}

// 初始占位：全部显示"—"，等真实数据回来再替换；不再用随机数冒充安全指标
const UNAVAILABLE = '—';

const emptyDashboardStats = (): DashboardStats => ({
  totalThreats: { value: UNAVAILABLE, trend: null },
  networkTraffic: { value: UNAVAILABLE, trend: null },
  activeEndpoints: { value: UNAVAILABLE, trend: null },
  securityScore: { value: UNAVAILABLE, trend: null },
});

const formatMetric = (value: number | string) =>
  typeof value === 'number' ? value.toLocaleString() : value;

const formatPercent = (value: number | string) =>
  typeof value === 'number' ? `${value}%` : value;

const TrendBadge = ({ trend }: { trend: number | null }) => {
  if (trend === null) {
    return <span className="text-sm text-gray-500">—</span>;
  }
  return trend >= 0 ? (
    <div className="flex items-center gap-1 text-green-400 text-sm">
      <TrendingUp className="w-4 h-4" />
      <span>+{trend.toFixed(1)}%</span>
    </div>
  ) : (
    <div className="flex items-center gap-1 text-red-400 text-sm">
      <TrendingDown className="w-4 h-4" />
      <span>{trend.toFixed(1)}%</span>
    </div>
  );
};

// 系统资源指标后端未接入：明确显示"未接入"，不再伪造 CPU/内存/磁盘数值
const UNAVAILABLE_SYSTEM_STATUS: SystemStatus = {
  cpu: { usage: 0, cores: '未接入' },
  memory: { used: '—', total: '—', status: '未接入' },
  storage: { used: '—', total: '—', status: '未接入' },
  network: { speed: '未接入', ping: '—', jitter: '—' },
};

const buildSystemStatus = (cpuLoad: number | null): SystemStatus =>
  cpuLoad === null
    ? UNAVAILABLE_SYSTEM_STATUS
    : {
        ...UNAVAILABLE_SYSTEM_STATUS,
        cpu: { usage: cpuLoad, cores: '实时 CPU 负载' },
      };

// 图表数据全部来自后端统计，没有数据就是空图
const buildThreatTrafficData = (points: Array<{ time: string; value: number }>) =>
  (points || []).map((point) => ({ time: point.time, threats: point.value }));


const getActivityIcon = (type: RecentActivity['type']) => {
  switch (type) {
    case 'alert':
      return <AlertTriangle className="w-4 h-4 text-red-400" />;
    case 'login':
      return <UserX className="w-4 h-4 text-orange-400" />;
    case 'info':
      return <Info className="w-4 h-4 text-blue-400" />;
    case 'quarantine':
      return <Ban className="w-4 h-4 text-red-500" />;
    case 'success':
      return <CheckCircle className="w-4 h-4 text-green-400" />;
  }
};

const getThreatLevelTextColor = (level: string) => {
  switch (level) {
    case 'Critical':
    case 'High':
      return 'text-red-400';
    case 'Medium':
      return 'text-yellow-400';
    case 'Low':
      return 'text-green-400';
    default:
      return 'text-gray-400';
  }
};

interface LogAnalysisData {
  analysisResult: AnalysisResult;
  fileName: string;
  savedAt: string;
}

interface Message {
  role: 'user' | 'ai';
  content: string;
  sources?: string[];
}

interface SearchItem {
  id: string;
  title: string;
  description: string;
  keywords: string[];
  path: string;
  icon: React.ReactNode;
  category: 'page' | 'function' | 'data';
}

export default function Dashboard() {
  const router = useRouter();
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [activeMenu, setActiveMenu] = useState('dashboard');
  const [logAnalysis, setLogAnalysis] = useState<LogAnalysisData | null>(null);
  const [chatHistory, setChatHistory] = useState<Message[]>([]);
  const [currentTime, setCurrentTime] = useState(new Date());
  const [auditCount, setAuditCount] = useState(0);
  const [aiInteractionCount, setAiInteractionCount] = useState(0);
  const [dashboardStats, setDashboardStats] = useState<DashboardStats>(emptyDashboardStats());
  const [systemLoad, setSystemLoad] = useState<number | null>(null);
  const [securityScoreDetail, setSecurityScoreDetail] = useState<SecurityScore | null>(null);
  const [threatTrafficData, setThreatTrafficData] = useState(buildThreatTrafficData([]));
  const [logRecords, setLogRecords] = useState<LogRecord[]>([]);
  const [logRecordsError, setLogRecordsError] = useState<string | null>(null);
  const [hasHighUnresolved, setHasHighUnresolved] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<SearchItem[]>([]);
  const [showSearchResults, setShowSearchResults] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [animatedCpu, setAnimatedCpu] = useState(0);
  const [animatedMemory, setAnimatedMemory] = useState(0);
  const [animatedStorage, setAnimatedStorage] = useState(0);
  const searchContainerRef = useRef<HTMLDivElement>(null);
  const userMenuRef = useRef<HTMLDivElement>(null);

  const loadLogRecords = async () => {
    try {
      setLogRecordsError(null);
      const response = await getLogRecords(50, 0);
      if (response.status === 'success') {
        const records = response.records || [];
        setLogRecords(records);
        setAuditCount(records.length);
      } else {
        setLogRecords([]);
        setAuditCount(0);
        setLogRecordsError('日志记录获取失败');
      }
    } catch (error) {
      setLogRecords([]);
      setAuditCount(0);
      setLogRecordsError('日志记录获取失败');
    }
  };

  const loadDashboardStats = async () => {
    try {
      const stats = await getDashboardStats();
      const score = stats.security_score;
      setDashboardStats({
        totalThreats: { value: stats.active_threats ?? 0, trend: null },
        // 网络流量后端没有对应指标，保持"—"而不是编一个数
        networkTraffic: { value: UNAVAILABLE, trend: null },
        activeEndpoints: { value: stats.online_users ?? 0, trend: null },
        securityScore: {
          value: typeof score?.score === 'number' ? score.score : UNAVAILABLE,
          trend: null,
        },
      });
      setSecurityScoreDetail(score ?? null);
      setThreatTrafficData(buildThreatTrafficData(stats.chart_data || []));
      setSystemLoad(typeof stats.system_load === 'number' ? stats.system_load : null);
      if (typeof stats.total_events === 'number') {
        setAuditCount(stats.total_events);
      }
      if (typeof stats.ai_interactions === 'number') {
        setAiInteractionCount(stats.ai_interactions);
      }
      if (typeof stats.high_unresolved_count === 'number') {
        setHasHighUnresolved(stats.high_unresolved_count > 0);
      }
    } catch (error) {
      // 接口失败时回到占位态，而不是用随机数假装有数据
      setDashboardStats(emptyDashboardStats());
      setSecurityScoreDetail(null);
      setThreatTrafficData(buildThreatTrafficData([]));
      setSystemLoad(null);
    }
  };

  useEffect(() => {
    // 检查认证状态
    const token = localStorage.getItem('token');
    if (!token) {
      router.push('/login');
      return;
    }
    setIsAuthenticated(true);
    
    // 读取用户信息
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      try {
        const parsedUser = JSON.parse(savedUser);
        setUserInfo(parsedUser);
      } catch (e) {
        console.error('解析用户信息失败:', e);
      }
    }
    
    // 先显示占位，再拉真实数据（不再生成随机数）
    setDashboardStats(emptyDashboardStats());
    setThreatTrafficData(buildThreatTrafficData([]));

    // 从 localStorage 读取数据
    try {
      // 读取日志分析结果（兼容两个 key）
      const latestLogReport = localStorage.getItem('cyberguard_latest_log_report');
      const logAnalysisData = localStorage.getItem('cyberguard_log_analysis');
      
      const logData = latestLogReport || logAnalysisData;
      if (logData) {
        const parsedLog = JSON.parse(logData);
        if (parsedLog.analysisResult) {
          setLogAnalysis(parsedLog);
        }
      }

      // 读取聊天记录
      const savedChatHistory = localStorage.getItem('cyberguard_chat_history');
      if (savedChatHistory) {
        const parsedChat = JSON.parse(savedChatHistory);
        if (Array.isArray(parsedChat) && parsedChat.length > 0) {
          setChatHistory(parsedChat);
        }
      }

    } catch (error) {
      console.error('读取数据失败:', error);
    }

    loadLogRecords();
    loadDashboardStats();
  }, [router]);

  // 更新时间
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // 系统状态：只动画后端真实返回的 CPU 负载；其余指标未接入，保持"—"
  useEffect(() => {
    const newStatus = buildSystemStatus(systemLoad);
    setSystemStatus(newStatus);

    setAnimatedCpu(0);
    setAnimatedMemory(0);
    setAnimatedStorage(0);

    const animationDuration = 1500;
    const steps = 60;
    const stepDuration = animationDuration / steps;
    let currentStep = 0;

    const animationInterval = setInterval(() => {
      currentStep++;
      const progress = currentStep / steps;
      const easedProgress = 1 - (1 - progress) * (1 - progress);

      setAnimatedCpu(Math.round((newStatus.cpu.usage || 0) * easedProgress));

      if (currentStep >= steps) {
        clearInterval(animationInterval);
      }
    }, stepDuration);

    return () => clearInterval(animationInterval);
  }, [systemLoad]);

  // 上次扫描时间来自真实日志记录，没有记录就显示"—"
  const lastScanLabel = (() => {
    const newest = logRecords[0]?.upload_time;
    if (!newest) return '—';
    const minutes = Math.max(0, Math.round((Date.now() - new Date(newest).getTime()) / 60000));
    return `${minutes} 分钟前`;
  })();

  // 获取威胁等级
  const isUnderAttack = hasHighUnresolved;
  const threatLevelText = hasHighUnresolved ? 'High' : 'Low';

  // 计算统计数据
  const threatCount = logAnalysis?.analysisResult?.details?.length || 0;
  // auditCount 已在 useEffect 中设置

  const formatLogTime = (value?: string) => {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString();
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setShowUserMenu(false);
    router.push('/login');
  };

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

  // 搜索数据源
  const searchItems: SearchItem[] = [
    {
      id: 'dashboard',
      title: '仪表盘',
      description: '查看安全概览和系统统计',
      keywords: ['仪表盘', 'dashboard', '概览', '统计', '首页', '主页'],
      path: '/',
      icon: <Home className="w-4 h-4" />,
      category: 'page',
    },
    {
      id: 'chat',
      title: 'AI智能回答',
      description: 'AI 安全专家对话，支持 RAG 检索',
      keywords: ['对话', 'chat', '问答', 'ai', '智能', '攻防', '专家', '咨询'],
      path: '/chat',
      icon: <MessageSquare className="w-4 h-4" />,
      category: 'page',
    },
    {
      id: 'log-analysis',
      title: '日志分析',
      description: '上传日志文件进行 AI 威胁分析',
      keywords: ['日志', 'log', '分析', '分析', '审计', '威胁', '检测', '上传'],
      path: '/log-analysis',
      icon: <Eye className="w-4 h-4" />,
      category: 'page',
    },
    {
      id: 'report',
      title: '报告生成',
      description: '生成安全审计报告（PDF/Markdown）',
      keywords: ['报告', 'report', '生成', '导出', 'pdf', 'markdown', '审计报告'],
      path: '/report-generation',
      icon: <FileText className="w-4 h-4" />,
      category: 'page',
    },
    {
      id: 'security-tools',
      title: '安全工具箱',
      description: '钓鱼邮件鉴定与蓝队规则生成',
      keywords: ['安全工具箱', 'security tools', 'phishing', 'yara', 'snort', '规则生成'],
      path: '/security-tools',
      icon: <Wrench className="w-4 h-4" />,
      category: 'page',
    },
    {
      id: 'threat-intel',
      title: '威胁情报研判',
      description: 'IOC 自动识别、情报富化与 AI 研判',
      keywords: ['威胁情报', 'ioc', 'ip', 'domain', 'hash', 'enrichment', '研判'],
      path: '/threat-intel-agent',
      icon: <Activity className="w-4 h-4" />,
      category: 'page',
    },
    {
      id: 'threats',
      title: '威胁检测',
      description: '查看已检测到的威胁详情',
      keywords: ['威胁', 'threat', '攻击', '安全', '检测', '阻止'],
      path: '/',
      icon: <AlertTriangle className="w-4 h-4" />,
      category: 'function',
    },
    {
      id: 'network',
      title: '网络流量',
      description: '查看网络流量统计',
      keywords: ['网络', 'network', '流量', 'traffic', '带宽'],
      path: '/',
      icon: <Network className="w-4 h-4" />,
      category: 'function',
    },
    {
      id: 'endpoints',
      title: '活跃端点',
      description: '查看活跃端点统计',
      keywords: ['端点', 'endpoint', '服务器', 'server', '活跃'],
      path: '/',
      icon: <Server className="w-4 h-4" />,
      category: 'function',
    },
    {
      id: 'security-score',
      title: '安全评分',
      description: '查看系统安全评分',
      keywords: ['安全', 'security', '评分', 'score', '等级'],
      path: '/',
      icon: <Lock className="w-4 h-4" />,
      category: 'function',
    },
  ];

  // 模糊搜索函数
  const fuzzySearch = (query: string): SearchItem[] => {
    if (!query.trim()) {
      return [];
    }

    const lowerQuery = query.toLowerCase();
    const results: SearchItem[] = [];

    searchItems.forEach((item) => {
      let score = 0;
      
      // 标题完全匹配（最高优先级）
      if (item.title.toLowerCase().includes(lowerQuery)) {
        score += 100;
      }
      
      // 标题开头匹配
      if (item.title.toLowerCase().startsWith(lowerQuery)) {
        score += 50;
      }
      
      // 描述匹配
      if (item.description.toLowerCase().includes(lowerQuery)) {
        score += 30;
      }
      
      // 关键词匹配
      item.keywords.forEach((keyword) => {
        if (keyword.toLowerCase().includes(lowerQuery)) {
          score += 20;
        }
        if (keyword.toLowerCase() === lowerQuery) {
          score += 10;
        }
      });

      // 字符包含匹配（模糊搜索）
      const queryChars = lowerQuery.split('');
      const titleLower = item.title.toLowerCase();
      let charMatchCount = 0;
      let lastIndex = -1;
      
      queryChars.forEach((char) => {
        const index = titleLower.indexOf(char, lastIndex + 1);
        if (index !== -1) {
          charMatchCount++;
          lastIndex = index;
        }
      });
      
      if (charMatchCount === queryChars.length) {
        score += 10;
      }

      if (score > 0) {
        results.push({ ...item, id: `${item.id}-${score}` });
      }
    });

    // 按分数排序
    return results
      .sort((a, b) => {
        const scoreA = parseInt(a.id.split('-').pop() || '0');
        const scoreB = parseInt(b.id.split('-').pop() || '0');
        return scoreB - scoreA;
      })
      .slice(0, 6) // 最多显示 6 个结果
      .map((item) => ({
        ...item,
        id: item.id.split('-').slice(0, -1).join('-'),
      }));
  };

  // 处理搜索输入
  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const query = e.target.value;
    setSearchQuery(query);
    setSelectedIndex(-1);
    
    if (query.trim()) {
      const results = fuzzySearch(query);
      setSearchResults(results);
      setShowSearchResults(true);
    } else {
      setSearchResults([]);
      setShowSearchResults(false);
    }
  };

  // 处理键盘事件
  const handleSearchKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (!showSearchResults || searchResults.length === 0) return;

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelectedIndex((prev) => 
          prev < searchResults.length - 1 ? prev + 1 : prev
        );
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelectedIndex((prev) => (prev > 0 ? prev - 1 : -1));
        break;
      case 'Enter':
        e.preventDefault();
        if (selectedIndex >= 0 && selectedIndex < searchResults.length) {
          handleSearchResultClick(searchResults[selectedIndex]);
        } else if (searchResults.length > 0) {
          handleSearchResultClick(searchResults[0]);
        }
        break;
      case 'Escape':
        setShowSearchResults(false);
        setSearchQuery('');
        setSelectedIndex(-1);
        break;
    }
  };

  // 处理搜索结果点击
  const handleSearchResultClick = (item: SearchItem) => {
    setSearchQuery('');
    setShowSearchResults(false);
    setSearchResults([]);
    
    // 根据路径跳转
    if (item.path === '/') {
      handleMenuClick('dashboard');
    } else if (item.path === '/chat') {
      handleMenuClick('chat');
    } else if (item.path === '/log-analysis') {
      handleMenuClick('analysis');
    } else if (item.path === '/report-generation') {
      handleMenuClick('reports');
    } else if (item.path === '/threat-intel-agent') {
      handleMenuClick('threat-intel');
    }
    
    router.push(item.path);
  };

  // 点击外部关闭搜索结果
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (searchContainerRef.current && !searchContainerRef.current.contains(event.target as Node)) {
        setShowSearchResults(false);
      }
    };

    if (showSearchResults) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => {
        document.removeEventListener('mousedown', handleClickOutside);
      };
    }
  }, [showSearchResults]);

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
          <p className="text-xs text-gray-500">上次扫描: {lastScanLabel}</p>
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
        {/* 顶部导航栏 */}
        <header className="h-16 bg-slate-900/50 backdrop-blur border-b border-white/5 flex items-center justify-between px-6 relative z-50">
          <h1 className="text-xl font-bold text-white">仪表盘</h1>
          
          <div className="flex items-center gap-4">
            <LLMProviderToggle onAuthExpired={handleLogout} />
            {/* 搜索框 */}
            <div className="relative search-container" ref={searchContainerRef}>
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400 z-10" />
              <input
                type="text"
                value={searchQuery}
                onChange={handleSearchChange}
                onKeyDown={handleSearchKeyDown}
                onFocus={() => {
                  if (searchQuery.trim() && searchResults.length > 0) {
                    setShowSearchResults(true);
                  }
                }}
                placeholder="搜索日志、IP、威胁..."
                className="pl-10 pr-4 py-2 bg-slate-800/50 border border-white/5 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 w-64"
              />
              
              {/* 搜索结果下拉列表 */}
              {showSearchResults && searchResults.length > 0 && (
                <div className="absolute top-full left-0 mt-2 w-96 bg-slate-900 border border-slate-700 rounded-lg shadow-2xl z-50 max-h-96 overflow-y-auto">
                  <div className="p-2">
                    {searchResults.map((item, index) => (
                      <button
                        key={item.id}
                        onClick={() => handleSearchResultClick(item)}
                        onMouseEnter={() => setSelectedIndex(index)}
                        className={`w-full flex items-start gap-3 p-3 rounded-lg transition-colors text-left group ${
                          selectedIndex === index
                            ? 'bg-cyan-500/20 border border-cyan-500/30'
                            : 'hover:bg-slate-800/50'
                        }`}
                      >
                        <div className="mt-0.5 text-cyan-400 group-hover:text-cyan-300">
                          {item.icon}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-semibold text-white group-hover:text-cyan-400 transition-colors">
                              {item.title}
                            </span>
                            <span className="text-xs px-2 py-0.5 bg-slate-700 text-gray-400 rounded">
                              {item.category === 'page' ? '页面' : item.category === 'function' ? '功能' : '数据'}
                            </span>
                          </div>
                          <p className="text-xs text-gray-400 line-clamp-1">
                            {item.description}
                          </p>
                        </div>
                        <ArrowRight className="w-4 h-4 text-gray-500 group-hover:text-cyan-400 transition-colors flex-shrink-0 mt-1" />
                      </button>
                    ))}
                  </div>
                </div>
              )}
              
              {/* 无结果提示 */}
              {showSearchResults && searchQuery.trim() && searchResults.length === 0 && (
                <div className="absolute top-full left-0 mt-2 w-96 bg-slate-900 border border-slate-700 rounded-lg shadow-2xl z-50 p-4">
                  <p className="text-sm text-gray-400 text-center">未找到相关结果</p>
                </div>
              )}
            </div>

            {/* 用户信息 */}
            <div className="flex items-center gap-3">
              <div className="relative group">
                <button className="p-2 text-gray-400 hover:text-white transition-colors">
                  <Bell className="w-5 h-5" />
                </button>
                {/* Tooltip */}
                <div className="absolute right-0 top-full mt-2 px-3 py-1.5 bg-slate-800 text-white text-xs rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 whitespace-nowrap z-50 pointer-events-none">
                  没有通知
                  <div className="absolute -top-1 right-4 w-2 h-2 bg-slate-800 rotate-45"></div>
                </div>
              </div>
              <div className="relative group">
                <button className="p-2 text-gray-400 hover:text-white transition-colors">
                  <HelpCircle className="w-5 h-5" />
                </button>
                {/* Tooltip */}
                <div className="absolute right-0 top-full mt-2 px-3 py-1.5 bg-slate-800 text-white text-xs rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 whitespace-nowrap z-50 pointer-events-none">
                  帮助
                  <div className="absolute -top-1 right-4 w-2 h-2 bg-slate-800 rotate-45"></div>
                </div>
              </div>
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

                {/* 用户信息悬浮卡片 - 使用 fixed 定位确保在最顶层 */}
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

        {/* 可滚动内容 */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 relative z-0">
          {/* 安全概览 */}
          <div>
            <div className="mb-4">
              <h2 className="text-2xl font-bold text-white mb-1">安全概览</h2>
              <p className="text-sm text-gray-400">实时威胁监控和系统状态</p>
            </div>

            <div className="grid grid-cols-4 gap-4">
              {/* 统计卡片 */}
              <div className="bg-slate-900/50 backdrop-blur border border-white/5 rounded-lg p-6">
                <div className="flex items-center justify-between mb-4">
                  <Shield className="w-8 h-8 text-cyan-400" />
                  <TrendBadge trend={dashboardStats.totalThreats.trend} />
                </div>
                <p className="text-3xl font-bold text-white mb-1">
                  {formatMetric(dashboardStats.totalThreats.value)}
                </p>
                <p className="text-sm text-gray-400">已阻止威胁总数</p>
              </div>

              <div className="bg-slate-900/50 backdrop-blur border border-white/5 rounded-lg p-6">
                <div className="flex items-center justify-between mb-4">
                  <Network className="w-8 h-8 text-cyan-400" />
                  <TrendBadge trend={dashboardStats.networkTraffic.trend} />
                </div>
                <p className="text-3xl font-bold text-white mb-1">
                  {formatMetric(dashboardStats.networkTraffic.value)}
                </p>
                <p className="text-sm text-gray-400">网络流量</p>
              </div>

              <div className="bg-slate-900/50 backdrop-blur border border-white/5 rounded-lg p-6">
                <div className="flex items-center justify-between mb-4">
                  <Server className="w-8 h-8 text-cyan-400" />
                  <TrendBadge trend={dashboardStats.activeEndpoints.trend} />
                </div>
                <p className="text-3xl font-bold text-white mb-1">
                  {formatMetric(dashboardStats.activeEndpoints.value)}
                </p>
                <p className="text-sm text-gray-400">在线用户</p>
              </div>

              <div className="bg-slate-900/50 backdrop-blur border border-white/5 rounded-lg p-6">
                <div className="flex items-center justify-between mb-4">
                  <Lock className="w-8 h-8 text-cyan-400" />
                  <span className="text-xs text-gray-400">
                    {securityScoreDetail?.computed ? securityScoreDetail.grade : '—'}
                  </span>
                </div>
                <p className="text-3xl font-bold text-white mb-1">
                  {formatPercent(dashboardStats.securityScore.value)}
                </p>
                <p className="text-sm text-gray-400 mb-2">安全评分</p>
                {securityScoreDetail?.computed ? (
                  <details className="text-xs text-gray-400">
                    <summary className="cursor-pointer text-cyan-400 hover:text-cyan-300">计算依据</summary>
                    <ul className="mt-2 space-y-1">
                      {securityScoreDetail.penalties.length === 0 ? (
                        <li>当前没有扣分项（满分 100）</li>
                      ) : (
                        securityScoreDetail.penalties.map((item) => (
                          <li key={item.reason}>
                            {item.reason} ×{item.count} → −{item.points} 分
                          </li>
                        ))
                      )}
                      <li className="text-gray-500 pt-1 border-t border-white/5 mt-1">
                        {securityScoreDetail.formula}
                      </li>
                      <li className="text-gray-500">统计范围：{securityScoreDetail.window}</li>
                    </ul>
                  </details>
                ) : (
                  <p className="text-xs text-gray-500">{securityScoreDetail?.reason || '暂无数据'}</p>
                )}
              </div>
            </div>
          </div>

          {/* 中间行 */}
          <div className="grid grid-cols-3 gap-6">
            {/* 威胁流量分析图表 */}
            <div className="col-span-2 bg-slate-900/50 backdrop-blur border border-white/5 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">威胁流量分析</h3>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={threatTrafficData}>
                  <defs>
                    <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.8} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.1} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis
                    dataKey="time"
                    stroke="#94a3b8"
                    style={{ fontSize: '12px' }}
                  />
                  <YAxis stroke="#94a3b8" style={{ fontSize: '12px' }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1e293b',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px',
                      color: '#fff',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="threats"
                    stroke="#06b6d4"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorThreats)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            {/* 统计卡片 */}
            <div className="bg-slate-900/50 backdrop-blur border border-white/5 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">系统统计</h3>
              <div className="grid grid-cols-2 gap-4">
                {/* 威胁检测 */}
                <div className="bg-slate-800/50 border border-red-500/20 rounded-lg p-4 hover:border-red-500/40 transition-all">
                  <div className="flex items-center justify-between mb-2">
                    <AlertTriangle className="w-6 h-6 text-red-400" />
                    <div className="text-right">
                      <p className="text-2xl font-bold text-white">{threatCount}</p>
                      <p className="text-xs text-gray-400">威胁检测</p>
                    </div>
                  </div>
                  <p className="text-xs text-gray-500 mt-2">
                    {threatCount > 0 ? '最近一次检测到的威胁数量' : '暂无威胁检测'}
                  </p>
                </div>

                {/* AI 交互 */}
                <div className="bg-slate-800/50 border border-purple-500/20 rounded-lg p-4 hover:border-purple-500/40 transition-all">
                  <div className="flex items-center justify-between mb-2">
                    <MessageSquare className="w-6 h-6 text-purple-400" />
                    <div className="text-right">
                      <p className="text-2xl font-bold text-white">{aiInteractionCount}</p>
                      <p className="text-xs text-gray-400">AI 交互</p>
                    </div>
                  </div>
                  <p className="text-xs text-gray-500 mt-2">
                    {aiInteractionCount > 0 ? '已进行的对话次数' : '暂无对话记录'}
                  </p>
                </div>

                {/* 日志审计 */}
                <div className="bg-slate-800/50 border border-cyan-500/20 rounded-lg p-4 hover:border-cyan-500/40 transition-all">
                  <div className="flex items-center justify-between mb-2">
                    <Eye className="w-6 h-6 text-cyan-400" />
                    <div className="text-right">
                      <p className="text-2xl font-bold text-white">{auditCount}</p>
                      <p className="text-xs text-gray-400">日志审计</p>
                    </div>
                  </div>
                  <p className="text-xs text-gray-500 mt-2">
                    {auditCount > 0 ? '已进行审计的次数' : '暂无审计记录'}
                  </p>
                </div>

                {/* 防御等级 */}
                <div className="bg-slate-800/50 border border-green-500/20 rounded-lg p-4 hover:border-green-500/40 transition-all">
                  <div className="flex items-center justify-between mb-2">
                    <Shield className="w-6 h-6 text-green-400" />
                    <div className="text-right">
                      <p className="text-lg font-bold text-white">Level 4</p>
                      <p className="text-xs text-green-400">(Active)</p>
                    </div>
                  </div>
                  <p className="text-xs text-gray-500 mt-2">防御等级</p>
                </div>
              </div>
            </div>
          </div>

          {/* 底部行 */}
          <div className="grid grid-cols-2 gap-6">
            {/* 欢迎区域和状态指示器 */}
            <div className="bg-slate-900/50 backdrop-blur border border-white/5 rounded-lg p-6">
              {/* 欢迎区域 */}
              <div className="mb-6">
                <h2 className="text-2xl font-bold text-white mb-2">Welcome back, Commander.</h2>
                <div className="flex items-center gap-2 text-gray-400">
                  <Clock className="w-4 h-4" />
                  <span className="text-sm font-mono">
                    {currentTime.toLocaleString('zh-CN', {
                      year: 'numeric',
                      month: '2-digit',
                      day: '2-digit',
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                    })}
                  </span>
                </div>
              </div>

              {/* 核心状态指示器 */}
              <div className="flex items-center gap-6">
                {/* 状态球体 - 带呼吸灯动画 */}
                <div className="relative">
                  <div
                    className={`w-24 h-24 rounded-full flex items-center justify-center border-4 ${
                      isUnderAttack
                        ? 'bg-red-500/20 border-red-500 shadow-red-500/50'
                        : 'bg-green-500/20 border-green-500 shadow-green-500/50'
                    } shadow-lg`}
                    style={{
                      animation: isUnderAttack
                        ? 'pulse-red 2s ease-in-out infinite'
                        : 'pulse-green 2s ease-in-out infinite',
                    }}
                  >
                    <div
                      className={`w-16 h-16 rounded-full ${
                        isUnderAttack ? 'bg-red-500' : 'bg-green-500'
                      }`}
                      style={{
                        animation: isUnderAttack
                          ? 'pulse-red-inner 2s ease-in-out infinite'
                          : 'pulse-green-inner 2s ease-in-out infinite',
                      }}
                    ></div>
                  </div>
                  {/* 外圈光晕 */}
                  <div
                    className={`absolute inset-0 rounded-full ${
                      isUnderAttack ? 'bg-red-500/30' : 'bg-green-500/30'
                    }`}
                    style={{
                      animation: isUnderAttack
                        ? 'pulse-red-outer 2s ease-in-out infinite'
                        : 'pulse-green-outer 2s ease-in-out infinite',
                      transform: 'scale(1.2)',
                    }}
                  ></div>
                </div>

                {/* 状态文本 */}
                <div className="flex-1">
                  <div
                    className={`text-2xl font-bold mb-2 ${
                      isUnderAttack ? 'text-red-400' : 'text-green-400'
                    }`}
                  >
                    {isUnderAttack ? 'SYSTEM UNDER ATTACK' : 'SYSTEM SECURE'}
                  </div>
                  <p className="text-sm text-gray-400">
                    {isUnderAttack
                      ? `威胁等级: ${threatLevelText} | 建议立即采取行动`
                      : '所有系统运行正常 | 无威胁检测'}
                  </p>
                  {logAnalysis && (
                    <p className="text-xs text-gray-500 mt-1">
                      最新分析: {logAnalysis.fileName || '未知文件'}
                    </p>
                  )}
                </div>
              </div>

              {/* 快捷入口 */}
              <div className="mt-6 grid grid-cols-3 gap-3">
                <button
                  onClick={() => router.push('/log-analysis')}
                  className="group relative overflow-hidden bg-slate-800/50 hover:bg-slate-800 border border-white/5 rounded-lg p-4 transition-all hover:border-cyan-500/50 hover:shadow-lg hover:shadow-cyan-500/20"
                >
                  <div className="flex flex-col items-center gap-2">
                    <div className="w-10 h-10 rounded-lg bg-cyan-500/20 flex items-center justify-center group-hover:bg-cyan-500/30 transition-colors">
                      <Eye className="w-5 h-5 text-cyan-400" />
                    </div>
                    <span className="text-xs font-medium text-white">启动日志审计</span>
                  </div>
                </button>

                <button
                  onClick={() => router.push('/chat')}
                  className="group relative overflow-hidden bg-slate-800/50 hover:bg-slate-800 border border-white/5 rounded-lg p-4 transition-all hover:border-purple-500/50 hover:shadow-lg hover:shadow-purple-500/20"
                >
                  <div className="flex flex-col items-center gap-2">
                    <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center group-hover:bg-purple-500/30 transition-colors">
                      <MessageSquare className="w-5 h-5 text-purple-400" />
                    </div>
                    <span className="text-xs font-medium text-white">咨询 AI 专家</span>
                  </div>
                </button>

                <button
                  onClick={() => router.push('/report-generation')}
                  className="group relative overflow-hidden bg-slate-800/50 hover:bg-slate-800 border border-white/5 rounded-lg p-4 transition-all hover:border-pink-500/50 hover:shadow-lg hover:shadow-pink-500/20"
                >
                  <div className="flex flex-col items-center gap-2">
                    <div className="w-10 h-10 rounded-lg bg-pink-500/20 flex items-center justify-center group-hover:bg-pink-500/30 transition-colors">
                      <FileText className="w-5 h-5 text-pink-400" />
                    </div>
                    <span className="text-xs font-medium text-white">生成安全报告</span>
                  </div>
                </button>
              </div>
            </div>

            {/* 系统状态 */}
            <div className="bg-slate-900/50 backdrop-blur border border-white/5 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">系统状态</h3>
              <div className="space-y-6">
                {/* CPU */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <Cpu className="w-5 h-5 text-cyan-400" />
                      <span className="text-sm font-medium text-white">CPU 使用率</span>
                    </div>
                    <span className="text-sm font-bold text-white font-mono">
                      {animatedCpu}%
                    </span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                    <div
                      className="bg-gradient-to-r from-green-500 to-green-400 h-2 rounded-full transition-all duration-100 ease-out"
                      style={{ width: `${animatedCpu}%` }}
                    ></div>
                  </div>
                  <p className="text-xs text-gray-400 mt-1">
                    {systemStatus?.cpu.cores || '加载中...'}
                  </p>
                </div>

                {/* 内存 */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <HardDrive className="w-5 h-5 text-blue-400" />
                      <span className="text-sm font-medium text-white">内存</span>
                    </div>
                    <span className="text-sm font-bold text-white font-mono">
                      {systemStatus ? systemStatus.memory.used : '0GB'} / {systemStatus?.memory.total || '16GB'}
                    </span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                    <div
                      className="bg-gradient-to-r from-blue-500 to-blue-400 h-2 rounded-full transition-all duration-100 ease-out"
                      style={{ width: `${animatedMemory}%` }}
                    ></div>
                  </div>
                  <p className="text-xs text-gray-400 mt-1">
                    {systemStatus?.memory.status || '加载中...'}
                  </p>
                </div>

                {/* 存储 */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <HardDrive className="w-5 h-5 text-purple-400" />
                      <span className="text-sm font-medium text-white">存储</span>
                    </div>
                    <span className="text-sm font-bold text-white font-mono">
                      {systemStatus ? systemStatus.storage.used : '0TB'} / {systemStatus?.storage.total || '4TB'}
                    </span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                    <div
                      className="bg-gradient-to-r from-purple-500 to-purple-400 h-2 rounded-full transition-all duration-100 ease-out"
                      style={{ width: `${animatedStorage}%` }}
                    ></div>
                  </div>
                  <p className="text-xs text-gray-400 mt-1">
                    {systemStatus?.storage.status || '加载中...'}
                  </p>
                </div>

                {/* 网络状态 */}
                <div className="bg-slate-800/50 rounded-lg p-4 border border-white/5">
                  <div className="flex items-center gap-2 mb-2">
                    <Wifi className="w-5 h-5 text-cyan-400 animate-pulse" />
                    <span className="text-sm font-medium text-white">
                      {systemStatus?.network.speed || '连接中...'}
                    </span>
                  </div>
                  <div className="flex gap-4 text-xs text-gray-400 font-mono">
                    <span>延迟: {systemStatus?.network.ping || '--'}</span>
                    <span>抖动: {systemStatus?.network.jitter || '--'}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* 日志审计记录 */}
          <div className="bg-slate-900/50 backdrop-blur border border-white/5 rounded-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <Eye className="w-5 h-5 text-cyan-400" />
                日志审计记录
              </h3>
              <button
                onClick={loadLogRecords}
                className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                刷新
              </button>
            </div>

            {logRecordsError && (
              <div className="mb-3 text-sm text-red-400">{logRecordsError}</div>
            )}

            {logRecords.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-400 border-b border-slate-700">
                      <th className="py-2 pr-4">时间</th>
                      <th className="py-2 pr-4">文件</th>
                      <th className="py-2 pr-4">等级</th>
                      <th className="py-2 pr-4">类型</th>
                      <th className="py-2 pr-4">源 IP</th>
                      <th className="py-2 pr-4">摘要</th>
                      <th className="py-2">状态</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logRecords.map((record) => (
                      <tr key={record.id} className="border-b border-slate-800 text-gray-300">
                        <td className="py-2 pr-4 whitespace-nowrap">
                          {formatLogTime(record.upload_time)}
                        </td>
                        <td className="py-2 pr-4">{record.filename || '-'}</td>
                        <td className={`py-2 pr-4 ${getThreatLevelTextColor(record.threat_level)}`}>
                          {record.threat_level || 'Unknown'}
                        </td>
                        <td className="py-2 pr-4">{record.attack_type || '-'}</td>
                        <td className="py-2 pr-4 font-mono">{record.source_ip || '-'}</td>
                        <td className="py-2 pr-4 max-w-[360px] truncate">{record.summary || '-'}</td>
                        <td className="py-2">{record.status || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-gray-400 text-sm">暂无日志审计记录</div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
