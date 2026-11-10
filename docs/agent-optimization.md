# Agent 规划与报告策略优化

通用 Agent 的模型规划与通用 Agent、Web Supervisor 的报告共用有限策略。Web 扫描仍执行固定专家流程。策略文件只允许选择规划、报告提示变体；工具权限、证据验证和评分规则不参与搜索。每次任务固定一份策略快照。

## 运行

在 `backend` 目录运行：

```powershell
# 标准答案回放：验证闭环，不调用模型、不执行安全工具、不能启用策略
python -m tools.optimize_agent --output-dir ../artifacts/agent_optimization

# 使用配置中的本地 Ollama 模型评测；不调用云端模型
python -m tools.optimize_agent --live --output-dir ../artifacts/agent_optimization

# 只有真实模型评测通过全部门槛后才启用
python -m tools.optimize_agent --live --activate --task-audit ../artifacts/agent_tasks/RUN/result.json

# 恢复最近一次启用之前的策略
python -m tools.optimize_agent --rollback
```

Ollama 必须已运行并安装 `OLLAMA_MODEL_NAME` 指定的模型。连接失败会保存 `error.json`，不启用策略。`--dataset` 可指定其他任务集，报告记录实际文件的 SHA-256。默认启用文件为 `backend/data/agent_optimization/active.json`，可用 `AGENT_POLICY_PATH` 覆盖。启用前检查基线未变化，保存 `active.previous.json`，再原子替换启用文件。

合同分数通过还不足以启用。`--task-audit` 必须指向同一候选策略版本、同一模型摘要的 approved live 任务报告；任务级评测要求结构化事实核对及绑定到原始输出与证据的人工复核，业务来源也必须明确声明。公开人工任务和 fixture 回放不能 approved。操作见 [代码级 RSI 的 Agent 任务验收](code-rsi.md)。

## 任务、门槛与输出

固定任务集 `backend/tests/data/agent_optimization_v1.json` 共 18 个案例，开发、验证、测试各 6 个，每组同时包含规划与报告，主题组不能跨集合。规划只向模型提供任务及工具签名；报告使用固定工具结果，不实际调用扫描工具。默认重复 2 次，可设为 3 次；最多生成 5 个候选，真实模型最多调用 200 次，总预算 900 秒，单次超时最多 45 秒。

候选由开发集选择。开发集与验证集合同得分至少增加 0.02，规划、报告和成功比例均不能下降，各次重复也不能下降。验证集中位延迟不超过基线 1.5 倍。测试集只否决回归，不用于重新选择候选。64 条安全护栏回归必须通过，模型调用错误会阻止晋级。

每轮输出 `SUMMARY.md`、含逐项模型输出与版本指纹的 `result.json`、`candidate.json`；失败轮次输出 `error.json`。回放模式即使得满分也没有启用资格。分数只衡量工具及参数选择、报告章节与证据引用位置，不能证明漏洞检测准确率、全文事实正确率或实际任务成功率。当前数据规模小且已用于开发，正式效果结论仍需独立业务样本。

## 离线回归

```powershell
python -m pytest tests/test_agent_optimization.py tests/test_agent_orchestrator.py tests/test_agent_supervisor.py tests/test_tool_registry.py -q -k 'not run_recon_no_tools and not run_exploit_empty_blackboard and not run_supervisor_basic'
```

排除的三个既有用例会调用真实模型或浏览器，需在对应服务可用的隔离环境单独运行。
