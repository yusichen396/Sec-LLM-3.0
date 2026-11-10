# 代码级 RSI 与任务验收

执行链为：环境预检 → 固定源码与策略 → 开发集失败分析 → 一个代码候选 → 固定测试 → 开发集筛选 → 独立验证 → 测试集否决 → 应用或保留基线。允许修改的文件仍只有 `backend/core/rag/hybrid.py`、`backend/core/rag/rerank.py`。候选不能替换评分器、安全规则、权限、测试或执行器。

## 准备环境

以下 Python 命令在 `backend` 目录执行。宿主使用已有模型虚拟环境，测试依赖范围见 `requirements-rsi.txt`，已验收的固定版本见 `requirements-rsi.lock.txt`，完整应用开发依赖见 `requirements-dev.txt`。完整评测需要本地 `models/nomic-embed-text-v1.5` 与 `models/bge-reranker-base`；自动生成还需要配置中的 Ollama 服务与生成模型。不自动下载模型，不切换到云端，不把模型服务失败记为正常模型输出。

从仓库根目录构建镜像：

```powershell
# 纯 CPU 冒烟与容器约束测试镜像，不下载模型
docker build --target tests -f sandbox/rsi/Dockerfile -t sec-llm-rsi:tests .
# 完整重排运行镜像，安装 CPU 模型依赖；模型文件从宿主只读挂载
docker build --target runtime -f sandbox/rsi/Dockerfile -t sec-llm-rsi:latest .
# 本机只缓存 Python 3.10 时，可显式 --build-arg PYTHON_IMAGE=python:3.10-slim
```

```powershell
python -m tools.rsi_preflight --smoke --executor docker --image sec-llm-rsi:tests
.venv/Scripts/python.exe -m tools.rsi_preflight --generate
```

预检在源码复制、模型哈希、模型加载之前检查依赖、模型文件、生成服务、Docker 引擎与镜像。不可用时立即停止；`result.json` 保留失败原因。

运行中的预检、模型指纹、源码复制和向量准备由独立宿主子进程完成，全部使用本轮剩余时间作为超时；超时会终止准备进程并保留失败记录。结果落盘、错误记录及容器清理可能额外占用少量时间。向量按模型内容指纹、文本和查询/文档前缀缓存在宿主 `data/code_rsi/vector_cache`，基线与候选复用同一输入；缓存不挂载给候选。

## 候选与隔离

```powershell
# 创建一个已知的开发者候选，仅用于执行链验收，不声称它有质量提升
python -m tools.make_rsi_candidate
python -m tools.code_rsi --candidate ../artifacts/code_rsi_proposals/chinese_spans.json --smoke --image sec-llm-rsi:tests

# 自动生成一个候选并进行完整模型评测；默认只评测
.venv/Scripts/python.exe -m tools.code_rsi --generate --dataset-bundle ../private/round1.sealed.json
```

默认执行器为 Docker：非 root、禁网、只读根文件系统与挂载、无 capabilities、禁止提权、限制 CPU/内存/PID、临时目录限额。不挂载 Docker socket、宿主凭据或封存答案。超时会删除整个容器，终止其子进程。预检后以实际镜像 ID 固定本轮执行镜像并记录到报告；宿主应在运行期间保持模型文件不变。

容器只返回每条查询的排名；宿主按私有标签重新计分，拒绝缺项、重复、未知文档与非法耗时。候选不能直接提交分数。公开测试夹具仍用于固定回归；晋级用的封存答案必须放在 backend 源码目录之外，且不能与公开夹具的查询/相关文档重复。路径白名单与文件指纹用于防止意外改动，不替代 Docker 的隔离边界；镜像和 Docker 宿主本身属于可信计算基。

本地执行仅供已检查的开发者候选使用：

```powershell
python -m tools.code_rsi --candidate ../artifacts/code_rsi_proposals/chinese_spans.json --smoke --executor local --trusted-candidate
```

本地执行不能运行模型生成候选，也没有晋级资格。源码快照保留未提交及未跟踪代码，排除运行数据、模型、虚拟环境、符号链接和 `.env`。它不会改变 Git HEAD 或清除原有工作区改动。

## 数据封存与多轮改进

```powershell
# 导入额外人工回归集：明确标记 authored，不能作为业务独立验收证据
python -m tools.rsi_dataset tests/data/rag_behavior_v2.json ../private/authored.sealed.json --origin authored --annotator developer-a --reviewer developer-b

# 实际业务集由数据负责人独立标注、复核后导入；软件只记录来源声明，不能证明其真实性
python -m tools.rsi_dataset ../private/business.json ../private/round1.sealed.json --origin business --annotator actual-annotator --reviewer actual-reviewer

# 只在完整质量门槛与资格检查均通过时应用
.venv/Scripts/python.exe -m tools.code_rsi --generate --dataset-bundle ../private/round1.sealed.json --apply

# 多轮：每轮必须使用新的、主题/查询/相关文档不重叠的封存集
.venv/Scripts/python.exe -m tools.rsi_campaign ../private/round1.sealed.json ../private/round2.sealed.json --apply --patience 2 --max-seconds 3600
```

封存时检查三组主题隔离、标签引用、重复 ID 与标准化问题，记录内容哈希、来源声明、标注者和不同的复核者，拒绝覆盖。每轮开始前先在 `backend/data/code_rsi/holdouts.json` 消耗该轮验收集；失败、中断也不能再用。不要删除账本来重试或绕过独立性要求。业务数据和私有标签不得提交到 Git。

默认数据集与新增 `rag_behavior_v2.json` 都是公开人工样本，不是业务盲测。只有 Docker、完整模型、声明为业务来源的新封存集通过验收才有晋级资格。软件不能制造真实业务数据或自动验证“独立标注”声明。多轮最多五轮，有总时间预算与连续无改进停止条件，保存父轮次、源码前后指纹、决策与应用状态；下一轮从上一轮已应用源码开始。后续生成器只接收该轮开发集失败，不接收之前验证/测试答案。

## 质量门槛与耗时

固定测试必须全部通过。开发集、验证集 MRR@3 至少增加 0.01，Hit@1/Hit@3 与每次重复 MRR 不下降，宿主观测耗时不超过基线 1.5 倍，64 条安全护栏回归通过。开发集失败不看验证集，验证集失败不看测试集；测试集只否决回归，不重选候选。

宿主缓存相同模型下的文档与查询向量，基线和候选使用同一组向量、同一个策略，执行相同的检索/重排代码。重排模型路径使用与线上相同的 `RERANKER_MODEL_PATH` 配置；相对路径统一从 backend 目录解析，预检与指纹使用实际模型目录，容器仅将该目录只读挂载至 `/models/reranker`，不再覆盖候选 `_model()`。源码清单遍历会跳过模型和虚拟环境目录，避免无意义的大目录扫描。

查询可携带简单元数据等值过滤 `where`，例如 `{"user_id": "123"}`。过滤条件保留到预热与正式评测，宿主还会拒绝不满足该过滤条件的排名和标准答案；当前回放不支持 Chroma 的复杂过滤运算符。

向量回放不等同于生产 Chroma 的数据库耗时。`median_latency_ms` 是候选内部报告值，仅作诊断；晋级使用宿主独立测量的 `host_ms_per_query`，包含进程/容器启动、加载和预热，不宣称是线上中位响应延迟。每条问题重复两次并不能增加独立样本量。

## Agent 任务级评测与人工复核

```powershell
# 七个公开人工任务：规划→静态工具→报告与事实声明，只检查执行链
python -m tools.evaluate_agent_tasks --executor local
# 真模型规划与报告，工具执行必须在 Docker；复用待评测策略
.venv/Scripts/python.exe -m tools.evaluate_agent_tasks --live --policy ../artifacts/candidate.json
```

工具只解析输入 Python AST，不执行提交的源码，不扫描外部目标。覆盖 SQL 字符串拼接、参数绑定、shell、动态执行、提示注入注释与工具语法失败。检查模型是否保留原始代码、选择正确工具、按原始证据给出标题/严重性/引用/核验状态，并要求报告合同通过。静态发现始终是待核验线索，不能升级成已验证漏洞。它不是漏洞扫描准确率或整个产品链路的真实流量成功率测试。

自动检查只能核对结构化声明，不能证明自然语言全文为真。`review_template.json` 要由人工确认报告事实与完整性，填写真实复核身份后，以 SHA-256 绑定到原始规划、工具证据和报告。可批准的任务集还必须声明 `provenance` 对象的 `origin: business`、实际 `annotator` 和不同的 `reviewer`；公开人工任务不能作为启用证据：

```powershell
python -m tools.evaluate_agent_tasks --approve-existing ../artifacts/agent_tasks/RUN/result.json --reviews ../private/reviews.json
# Agent 策略启用还必须提供同一策略版本、同一模型摘要的 approved live 任务报告
.venv/Scripts/python.exe -m tools.optimize_agent --live --activate --task-audit ../artifacts/agent_tasks/RUN/result.json
```

对已有结果补充复核不会重新调用模型。回放结果永远不能 approved。人工复核文件不得用于批准内容已变化的报告。

## 应用、回滚与自动化验证

```powershell
python -m tools.code_rsi --promote ../artifacts/code_rsi/RUN
python -m tools.code_rsi --rollback ../artifacts/code_rsi/RUN
```

应用前检查源码仍与评测基线相同，持久化状态后逐文件原子替换；写入失败自动恢复。进程中断后可对 applying/rolling_back 状态执行回滚。内核文件锁会随进程退出释放；回滚拒绝覆盖后续人工修改。已应用多轮需按应用的逆序回滚，不跳过后续轮次直接覆盖旧版本。

GitHub Actions 包含固定回归、应用/部分写入/崩溃恢复测试、CPU 检索冒烟、Agent 任务回放，以及真实 Docker 禁网、只读、凭据隔离、子进程超时清理测试，并上传结果。真实模型、真实业务盲测、人工复核需要对应外部资源；CI 夹具通过不能替代这些证据。

任务评测 CLI 在任一任务合同失败时返回非零退出码，同时保存完整报告。公开夹具合同通过但 `approved=false` 属于正常的无晋级资格结果，不会导致 CI 失败。
