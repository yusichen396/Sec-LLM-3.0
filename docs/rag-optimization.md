# RAG 评测与离线配置优化

这是 RSI 的第一阶段基础：在固定预算内根据开发集失败问题生成有限的检索参数变体，用独立验证集比较，保留合格配置并支持回滚。当前没有自动修改源代码、提示词、模型权重、工具权限或评分规则，也不能据此宣称已实现递归自我改进或得到业务效果提升。

## 快速运行（Windows PowerShell）

在项目的 `backend` 目录运行。

```powershell
# 不加载模型的闭环冒烟测试；不会启用在线配置
python -m tools.optimize_rag --lexical-only --output-dir ../artifacts/rag_optimization

# 使用本机已有模型完成向量 + BM25 + 重排的完整评测
# 此项目的 .venv 包含模型依赖；其他 Python 环境需安装 requirements.txt
$env:HF_HUB_OFFLINE = '1'
$env:TRANSFORMERS_OFFLINE = '1'
$env:HF_HOME = Join-Path (Get-Location) 'models/.hf_cache'
$env:OMP_NUM_THREADS = '2'
$env:MKL_NUM_THREADS = '2'
$env:OPENBLAS_NUM_THREADS = '2'
.venv/Scripts/python.exe -m tools.optimize_rag --local-embedding-model models/nomic-embed-text-v1.5 --output-dir ../artifacts/rag_optimization

# 同一流程中请求晋级：完整评测全部达标才写入 active.json
.venv/Scripts/python.exe -m tools.optimize_rag --local-embedding-model models/nomic-embed-text-v1.5 --activate

# 恢复最近一次启用前的配置
python -m tools.optimize_rag --rollback
```

未指定 `--local-embedding-model` 时使用配置中的 Ollama 地址和 `nomic-embed-text`；重排使用现有的 `models/bge-reranker-base`。模型依赖或服务缺失时评测失败，写入 `error.json`，不会把降级结果记为模型输出。第一次使用模型可能需要准备依赖和完整模型文件；`HF_HUB_OFFLINE=1` 禁止联网下载。

只评测不带 `--activate` 时，结果仅保存在每轮独立目录中。运行不会发起安全扫描或调用云端 LLM。

## 数据和指标

固定数据：`backend/tests/data/rag_optimization_v1.json`，共 26 篇文档、56 条问题。

| 集合 | 问题数 | 用途 |
|---|---:|---|
| dev | 30 | 识别失败问题、比较有限候选并选择第一名 |
| validation | 13 | 与基线对比，决定是否有晋级资格 |
| test | 13 | 第一名的最后一次回归检查；不重新选第二名 |

同一主题、同一相关文档的问题及其口语改写只能出现在一个集合。加载时检查 ID、标准化文本、标签引用和主题隔离。文档库是三组共享的检索语料；不把查询和答案标签交给检索策略。该数据由项目已有的人工样本组成，规模小、先前已被开发者查看，不是外部盲测集。正式效果结论仍需新增真实、独立标注的业务样本。

- `Hit@1`：第一个文档相关的问题比例。
- `Hit@3`：前三个文档中至少有一个相关的问题比例。
- `MRR@3`：首个相关文档在前三位的倒数排名平均值，排在第四位不计分。
- 延迟：一次完整召回和可选重排的耗时；不包含文档建库、模型冷加载。策略先预热，再轮换执行顺序。默认每条问题运行 3 次，可用 `--repeats` 设置 2–10 次。

BM25 的建索引成本和模型冷启动未计入在线请求延迟；短查询上的毫秒差异可能含测量噪声。重复测量不增加独立样本量。

原有 `tests.evaluate_rag_rerank`、`tests.evaluate_hybrid_recall` 共用同一 Top-3 评分函数。混合加重排的延迟包含混合召回阶段。旧 `rag_eval_result.json` 是历史结果，不是本次修正后的重跑证据。

## 候选、预算和晋级

每轮以当前已启用配置为基线；没有启用配置时以应用的 `HYBRID_RECALL_ENABLED` 为准。开发集有首位未命中的问题才生成候选，最多 7 个，每个候选只修改允许的参数：BM25 的 k1/b、向量融合权重、RRF 常数或候选数量。策略种类和是否重排不在自动搜索范围内。

开发集先选一个候选；如果 MRR@3 增益小于 0.01，则直接保留基线。晋级还要求：

1. 验证集 MRR@3 至少增加 0.01，Hit@1、Hit@3 均不下降，每轮 MRR 不低于基线。
2. 验证集完整检索中位延迟不超过基线的 1.5 倍。
3. 测试集 Hit@1、Hit@3、MRR@3 均不下降；不根据测试结果重选候选。
4. 现有 64 条安全护栏规则测试全部通过。这里将 `clarify` 和 `refuse` 都算作未直接放行，不能解释为都已拒绝。

`--lexical-only` 使用 BM25 基线，仅验证执行链和词法参数搜索。无论分数多高，均没有在线启用资格。不能用它证明混合检索变好了。

默认输出在 `backend/data/rag_optimization/runs`，每轮包含：

- `SUMMARY.md`：可直接阅读的分数、延迟和决策摘要。
- `result.json`：逐问题、逐重复结果，基线/候选配置、版本哈希、数据哈希、源码哈希、Python/依赖版本、本地模型文件哈希、安全回归和决策。
- `candidate.json`：本轮选中配置；未晋级时可能就是基线。
- `error.json`：执行失败信息（失败轮次不产生有效晋级结果）。

本流程不调用生成式 LLM，记录 LLM 调用次数和云端 LLM 费用为零。向量和重排的本地计算成本通过耗时体现，没有将本机硬件耗用虚构为货币费用。

## 在线启用与回滚

默认启用文件是 `backend/data/rag_optimization/active.json`。可以在后端配置 `RAG_POLICY_PATH` 指向其他文件。在线 `/api/chat` 的普通 RAG 路径与离线评测共用检索函数，每次请求加载有效配置，并继续传递用户隔离过滤条件。`rag_only` 严格模式保留已有距离阈值和上下文检查，不受这次优化影响。

仅在 `--activate` 且完整运行通过时写入配置。写入前检查基线未变化，保存 `active.previous.json`，再原子替换 `active.json`。无效配置会记录错误并回退到配置中的默认策略。`--rollback` 恢复最近一次晋级前的配置。

评测集、安全规则和评分逻辑由代码固定。不要依据测试集反馈反复调参；需要继续迭代时，应冻结一份新的外部测试集。生产启用前还应在实际用户语料、真实流量和隔离环境中复核质量、权限和资源开销。

## 测试

```powershell
python -m pytest tests/test_rag_optimization.py tests/test_rerank.py tests/test_agent_orchestrator.py tests/test_agent_supervisor.py tests/test_tool_registry.py -q -k 'not run_recon_no_tools and not run_exploit_empty_blackboard and not run_supervisor_basic'
```

上面排除的 3 个既有用例会实际调用模型或浏览器，不属于纯离线单元测试；基础设施测试仍按项目原有方式单独运行。Agent 的 `completed` 现在要求报告有效，并且通用执行计划没有超时、跳过或报错；这仍只表示执行完成，不能代替证据核验或任务质量评测。

GitHub Actions 中的 `rag-regression` 作业会运行检索单元测试和 CPU 冒烟评测，并上传结果；该作业不下载模型，也不会改动在线配置。
