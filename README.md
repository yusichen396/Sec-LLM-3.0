# Sec-LLM 4.0 — AI Agent 网络安全平台

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.128.0-009688.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/LangGraph-1.2-cyan.svg" alt="LangGraph">
  <img src="https://img.shields.io/badge/Next.js-14-black.svg" alt="Next.js">
  <img src="https://img.shields.io/badge/TypeScript-5.0-3178C6.svg" alt="TypeScript">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Tests-42+-green.svg" alt="Tests">
</p>

<p align="center">
  <b>第一作者：雨思晨</b> | 开发团队：灵犀网卫
</p>

> **关于本仓库**：这是团队项目 [Sec-LLM 3.0](https://github.com/yusichen396/Sec-LLM-3.0) 的个人工作副本，主仓库在团队负责人名下。我的提交集中在 [PR #13](https://github.com/yusichen396/Sec-LLM-3.0/pull/13)（待合并）。

**我负责的模块**

| 模块 | 具体工作 |
|---|---|
| Agent 编排 | 基于 LangGraph 的状态机（plan / execute / reflect / report），支持检查点恢复与结果纠错 |
| 多 Agent 协作 | 侦察 / 检测 / 报告三类专家的调度，共享黑板的归属校验与快照读写 |
| 检索链路 | BM25 + 向量 RRF 混合召回 + BGE 重排，评测集构建与 Top-k 命中率统计 |
| 安全边界 | 话题识别与授权判定的前置拦截，工具沙箱执行与单轮步数上限 |

<p align="center">
  <a href="#-核心能力">核心能力</a> •
  <a href="#-快速开始">快速开始</a> •
  <a href="#-项目架构">项目架构</a> •
  <a href="#-api-文档">API 文档</a> •
  <a href="#-cli--tui">CLI / TUI</a>
</p>

---

**Sec-LLM 4.0** 是一个面向网络安全的 **AI Agent 平台**——不是聊天机器人，而是能够**自主调用工具、编排多 Agent 协作、执行实际安全测试并生成可验证 PoC**的智能体系统。

基于 LangGraph 构建 Agent 状态图，集成 Playwright 浏览器自动化、Docker 沙箱命令执行、威胁情报富化、代码审计等 **10 个 Agent 工具**，支持 **local (Ollama) / cloud (DeepSeek) 双引擎实时切换**。

> 从 v3.1 聊天机器人/RAG 平台全面升级。新增 Agent 引擎、多 Agent 编排、工具注册表、CLI/TUI、Agent Web 控制台。

---

## ✨ 核心能力

### Agent 引擎
- **自主执行**：Agent 接收目标 → 规划 → 执行工具 → 反思 → 生成报告，无需人工干预
- **LangGraph 状态图**：5 节点图 `plan → execute → reflect → report`，最多 20 步
- **Multi-Agent 协作**：ReconAgent → ExploitAgent → ReportAgent，通过 Blackboard 共享发现
- **会话持久化**：Agent 会话自动写入 MySQL，支持异步非阻塞

### 10 个 Agent 工具

| 工具 | 类别 | 功能 |
|------|------|------|
| `browser_navigate` | 侦察 | Playwright 页面侦察，提取链接、表单、技术栈 |
| `browser_check_xss` | 漏洞利用 | XSS 漏洞检测，payload 注入 + dialog 捕获 |
| `browser_screenshot` | 侦察 | 网页截图 |
| `shell_exec` | 侦察 | Docker 沙箱执行 nmap、sqlmap、nuclei 等工具 |
| `phishing_analyzer` | 侦察 | 邮件钓鱼分析，风险评分，可疑 URL/IP 提取 |
| `code_auditor` | 漏洞利用 | SAST 代码审计，漏洞发现 + 修复建议 |
| `threat_intel_enrich` | 侦察 | IOC 富化（AbuseIPDB + AlienVault OTX） |
| `threat_intel_report` | 报告 | AI 威胁情报研判报告（流式 Markdown） |
| `rule_generator` | 报告 | YARA/Suricata 蓝队检测规则生成 |
| `report_explainer` | 报告 | Nmap/Nessus 扫描 → 管理层执行摘要 |

### 接口与界面

| 界面 | 说明 |
|------|------|
| **Web 控制台** | Next.js Agent 面板：任务提交 + 实时日志流 + 报告查看 |
| **CLI** | 6 条命令：`scan` `audit` `stream` `status` `report` `intel` |
| **TUI** | Textual 终端界面：实时 Agent 监控 + 状态面板 |
| **REST API** | 6 个 Agent 端点 + SSE 实时日志流 |
| **OpenClaw Skill** | Telegram / Discord / Slack 渠道集成 |

### 安全能力

- **CVSS 3.1 评分** + **OWASP Top 10 分类**
- **Auto-Fix PR**：自动创建分支 → 应用补丁 → 提交 → 推送 → 开 GitHub PR
- **双引擎**：local (Ollama) / cloud (DeepSeek) 运行时切换
- **沙箱隔离**：Docker 容器执行安全工具，内存/CPU/网络限制

---

## 项目架构

```
sec-llm-4.0/
├── backend/
│   ├── main.py              # FastAPI 入口 (~2,060 行, 从 v3.1 减少 18%)
│   ├── config.py            # Pydantic Settings (集中式配置)
│   ├── requirements.txt
│   ├── alembic.ini          # 数据库迁移配置
│   ├── migrations/          # Alembic 迁移
│   ├── api/
│   │   └── agent.py         # Agent API (6 端点 + SSE)
│   ├── core/
│   │   ├── llm/             # LLM 抽象层 (base, ollama, deepseek, router)
│   │   ├── auth/            # 认证 (jwt, password, dependencies)
│   │   └── rag/             # RAG 查询重写
│   ├── tools/               # Agent 工具注册表 (10 工具)
│   ├── agents/              # Agent 引擎
│   │   ├── orchestrator.py  # LangGraph 状态图
│   │   ├── supervisor.py    # Multi-Agent 编排器
│   │   ├── collaboration.py # Blackboard 共享状态
│   │   ├── reporting.py     # CVSS + OWASP
│   │   └── specialists/     # Recon, Exploit, Fix
│   ├── db/models.py         # SQLAlchemy ORM (6 张表)
│   └── tests/               # 42+ 项测试
├── frontend/                # Next.js 14
│   ├── app/agent/           # Agent Web 控制台
│   ├── components/          # AgentTaskPanel, AgentLogStream
│   └── lib/agent-api.ts     # Agent API 客户端
├── cli/                     # CLI + TUI
│   ├── main.py              # Typer CLI (6 命令)
│   └── tui.py               # Textual TUI
├── sandbox/
│   └── Dockerfile           # 隔离安全工具容器
└── openclaw-skill/          # OpenClaw 集成
```

---

## 快速开始

### 环境要求

- Python 3.10+
- Node.js 18+
- MySQL 8.x
- Ollama（本地模型：`llama3:8b` + `nomic-embed-text`）
- Docker（可选，用于沙箱工具执行）
- DeepSeek API Key（可选，启用云端引擎）

### 1. 克隆并安装

```bash
git clone https://github.com/Mengxun326/Sec-LLM-3.0.git
cd Sec-LLM-3.0
```

### 2. 后端

```bash
cd backend
python -m venv venv
source venv/bin/activate   # Linux/Mac
# .\venv\Scripts\activate  # Windows

pip install -r requirements.txt
pip install langgraph langgraph-checkpoint typer textual

# 配置 .env（参考下方配置说明）
cp .env.example .env

# 数据库迁移
alembic upgrade head

# 启动
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 3. 前端

```bash
cd frontend
npm install
npm run dev
```

### 4. Docker 沙箱（可选）

```bash
cd sandbox
docker build -t sec-llm-sandbox:latest .
```

### 5. 访问

| 界面 | 地址 |
|------|------|
| Web 仪表盘 | `http://localhost:3000` |
| Agent 控制台 | `http://localhost:3000/agent` |
| API 文档 | `http://localhost:8000/docs` |
| 初始管理员 | `admin` / 首次启动前配置的 `INITIAL_ADMIN_PASSWORD` |

---

## 配置说明（backend/.env）

```env
# LLM 引擎
INITIAL_ADMIN_PASSWORD=replace-with-a-unique-password-of-at-least-12-characters
LLM_PROVIDER=local          # local | cloud
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL_NAME=llama3:8b
DEEPSEEK_API_KEY=sk-...     # 可选
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL_NAME=deepseek-chat

# 威胁情报（可选）
ABUSEIPDB_API_KEY=...       # 可选
OTX_API_KEY=...              # 可选

AGENT_MAX_CONCURRENT=4
AGENT_TASK_TIMEOUT_SECONDS=1800

# 数据库
DATABASE_TYPE=mysql
MYSQL_USER=root
MYSQL_PASSWORD=your-password
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_DB=sec_llm_db

# Agent 配置
AGENT_MAX_STEPS=20
AGENT_STEP_TIMEOUT_SECONDS=300
AGENT_SANDBOX_IMAGE=sec-llm-sandbox:latest
AGENT_ALLOWED_TARGETS=example.com,192.0.2.10  # 生产环境扫描目标，精确匹配主机名/IP

# 邮件（可选，用于注册验证）
MAIL_USERNAME=...           # 可选
MAIL_PASSWORD=...           # 可选

# OpenClaw Skill API Key（可选）
SEC_LLM_SKILL_API_KEY=your-secure-key
```

---

## CLI / TUI

### CLI 命令

```bash
# 安装
cd cli && pip install typer httpx

# Web 扫描
python main.py scan https://example.com --mode quick

# 代码审计
python main.py audit ./src --language python

# 实时查看 Agent 日志
python main.py stream <session_id>

# 查看状态
python main.py status <session_id>

# 查看报告
python main.py report <session_id>

# 威胁情报查询
python main.py intel 8.8.8.8

# 自定义 API 地址
python main.py --base-url https://your-server:8000 scan example.com
```

### TUI 终端界面

```bash
pip install textual
python tui.py
```

---

## API 文档

启动后端后访问 `http://localhost:8000/docs`

### Agent API（v4.0 新增）

| 方法 | 端点 | 认证 | 说明 |
|------|------|------|------|
| POST | `/api/agent/run` | JWT / Skill Key | 提交 Agent 任务 |
| GET | `/api/agent/sessions` | JWT / Skill Key | 列出最近会话 |
| GET | `/api/agent/{id}/status` | JWT / Skill Key | 会话状态与进度 |
| GET | `/api/agent/{id}/stream` | JWT / Skill Key | SSE 实时日志流 |
| GET | `/api/agent/{id}/report` | JWT / Skill Key | 最终安全报告 |
| DELETE | `/api/agent/{id}` | JWT / Skill Key | 取消任务（跨 Worker 为协作取消） |

`task_type=web_scan` 使用侦察→检测→报告的多 Agent 图；`code_audit`、`threat_intel`、`comprehensive` 保留规划→执行图。两条路径共用同一会话、状态和报告接口。POST 创建会话后立即返回，任务在后台执行；进度查询中的 `steps_*` 分别表示多 Agent 阶段数或规划工具步数。

Agent 会话依赖 MySQL：创建任务和每个图节点完成后同步保存状态、日志与发现，`agent_sessions.findings` 是发现项的唯一运行时数据源。数据库不可用时任务不会以“已保存”继续执行。多个 Worker 通过 MySQL 条件更新原子认领排队任务；运行中每 30 秒刷新心跳，只有超过任务超时仍无心跳的中断任务才会标记失败，不重放安全工具。同 Worker 的 SSE 由状态事件唤醒，跨 Worker 的 SSE 每秒读取 MySQL；跨 Worker 取消最迟由下一次心跳发现并中止任务。现有数据库需先执行 `alembic upgrade head`，或由应用启动时的 `init_db` 补齐字段。

真实基础设施检查默认跳过；配置好本机 MySQL、Docker 和 Playwright 后运行：`RUN_AGENT_INTEGRATION=1 pytest backend/tests/test_agent_integration.py`。双进程用例验证跨 Worker 日志流、取消和唯一认领，并清理测试会话。

### 示例

```bash
# 提交 Agent 任务
curl -X POST http://localhost:8000/api/agent/run \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com","task_type":"web_scan","provider":"local"}'

# 查看状态
curl http://localhost:8000/api/agent/<session_id>/status \
  -H "Authorization: Bearer <token>"

# 流式日志（SSE）
curl -N http://localhost:8000/api/agent/<session_id>/stream \
  -H "Authorization: Bearer <token>"
```

### 现有 API 端点（v3.1 保留）

| 方法 | 端点 | 说明 |
|------|------|------|
| POST | `/api/register` | 用户注册 |
| POST | `/api/login` | 用户登录 |
| POST | `/api/chat` | 流式 AI 对话（含 RAG） |
| POST | `/api/upload` | 日志分析 / RAG 上传 |
| POST | `/api/security-tools/phishing-analyzer` | 钓鱼邮件鉴定 |
| POST | `/api/security-tools/code-audit` | 代码审计 |
| POST | `/api/security-tools/rule-generator` | 蓝队规则生成 |
| POST | `/api/security-tools/report-explainer` | 扫描报告解析 |
| POST | `/api/security-tools/threat-intel/enrich` | IOC 情报富化 |
| POST | `/api/security-tools/threat-intel/report` | 威胁情报 AI 研判 |
| GET | `/api/dashboard/stats` | 仪表盘统计 |
| GET | `/api/knowledge/files` | 知识库文件列表 |

---

## OpenClaw Skill 集成

将 Sec-LLM 能力暴露为 OpenClaw 技能，支持 Telegram / Discord / Slack 渠道。

```bash
# 1. 配置 backend/.env
SEC_LLM_SKILL_API_KEY=your-secure-key

# 2. 安装 Skill
cp -r openclaw-skill/sec-llm ~/.openclaw/workspace/skills/

# 3. 配置 OpenClaw 环境变量
export SEC_LLM_BASE_URL="http://localhost:8000"
export SEC_LLM_SKILL_API_KEY="your-secure-key"

# 4. 使用
# 在 Telegram/Discord 中:
#   "分析 IP 8.8.8.8 的威胁情报"
#   "扫描 https://example.com"
#   "审计这段 Python 代码"
```

---

## 技术栈

| 层 | 技术 |
|---|------|
| **Agent 引擎** | LangGraph 1.2, LangChain |
| **后端** | Python 3.10+, FastAPI, PyMySQL, SQLAlchemy |
| **LLM** | Ollama (llama3:8b), DeepSeek API, OpenAI SDK |
| **前端** | Next.js 14, React 18, TypeScript, Tailwind CSS |
| **向量数据库** | ChromaDB + OllamaEmbeddings (nomic-embed-text) |
| **数据库** | MySQL 8.x, Alembic 迁移 |
| **浏览器自动化** | Playwright (Chromium) |
| **沙箱** | Docker + docker-py |
| **CLI/TUI** | Typer, Textual, Rich |
| **测试** | pytest (42+ 项) |
| **CI/CD** | GitHub Actions |

---

## 测试

项目支持 RAG 检索评测和第一阶段的离线配置自优化（RSI 基础）。统一计算 Top-3 指标，按主题隔离开发、验证、测试样本，并记录配置版本、源码/模型指纹、完整检索延迟和安全回归。候选未达标时保留基线；CPU 冒烟运行不能启用在线配置。运行、晋级和回滚说明见 [RAG 评测与离线优化](docs/rag-optimization.md)。

Agent 也支持有限规划与报告策略的离线候选对比、晋级和回滚。评测回放固定工具结果，不执行安全扫描；标准答案回放不能启用策略。操作与指标边界见 [Agent 策略优化](docs/agent-optimization.md)。

代码级改进默认在禁网、只读、非 root 的 Docker 容器中验收候选，由宿主保管标签并独立计分。支持环境预检、封存数据防复用、多轮预算和停滞停止、改进谱系、达标应用与源码回滚；公开人工样本及本地回放没有晋级资格。Agent 策略启用还需要同版本模型与策略的任务级事实核对及人工复核。使用方式、证据限制和隔离边界见 [代码级 RSI](docs/code-rsi.md)。

```bash
cd backend
pip install pytest pytest-asyncio
python -m pytest tests/ -v
```

```
tests/test_tool_registry.py .........   9 passed
tests/test_agent_orchestrator.py .....  5 passed
tests/test_llm_router.py ......         6 passed
tests/test_auth.py ....                 4 passed
tests/test_tools.py ............       12 passed
tests/test_agent_supervisor.py ......  10 passed
====================================== 46 passed ==============================
```

---

## 从 v3.1 升级

| 指标 | v3.1 | v4.0 |
|------|------|------|
| 类型 | 聊天机器人 + RAG | AI Agent 平台 |
| 工具 | 0（内联端点） | 10（可插拔注册表） |
| Agent 引擎 | 无 | LangGraph 5 节点图 |
| Multi-Agent | 无 | Supervisor + 3 专业 Agent |
| CLI | 无 | 6 命令 + TUI |
| Web 控制台 | 仪表盘 | 仪表盘 + Agent 控制台 |
| 代码结构 | 1 个单体文件 (2,500 行) | 50+ 模块化文件 |
| 测试 | 0 | 46 项 |
| 数据库 | 原始 SQL | 原始 SQL + ORM + Alembic |

---

## 安全提示

- 首次启动必须配置 `INITIAL_ADMIN_PASSWORD`（至少 12 位）；已有管理员不会在启动时被重新激活
- 生产环境必须设置安全的 `JWT_SECRET_KEY`
- 不要将 API Key 提交到代码仓库
- 建议使用专用 MySQL 账号并限制权限
- Docker 沙箱对网络扫描工具使用 bridge 网络，对离线代码扫描工具禁用网络；均限制内存/CPU 并使用只读根文件系统
- 生产环境的 web_scan/comprehensive 任务要求配置 `AGENT_ALLOWED_TARGETS`；这是提交入口的范围控制，不是网络层隔离。实际部署仍须使用网络策略限制浏览器与 Docker 沙箱的出站地址，防止重定向、DNS 变化或 Agent 工具参数越界。

---

<p align="center">
  <b>Sec-LLM 4.0</b> — AI Agent 网络安全平台<br>
  第一作者：<b>雨思晨</b> | 开发团队：<b>灵犀网卫</b>
</p>
