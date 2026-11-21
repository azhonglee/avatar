# personal-agent

飞书个人 superagent：在远程开发机上静默运行，识别和追踪任务、整理知识库、早晚提醒，并通过 [acpx](https://github.com/openclaw/acpx)（ACP）把工作派给 Claude Code / Codex / Gemini / DeepSeek Harness / Doubao 等不同 harness，执行后由另一个 harness 交叉审查。

完整方案见 [docs/方案.md](docs/方案.md)，可靠性设计（账本、对账、验收关卡）见 [docs/可靠性设计.md](docs/可靠性设计.md)。

## 快速开始

```bash
# 1. 依赖（Node ≥ 22.13）
npm i -g @larksuite/cli acpx
npx skills add larksuite/cli -y -g     # 可选：给各 harness 装飞书官方 skills

# 2. 飞书应用与登录（按提示在浏览器完成）
lark-cli config init --new
#   开发者后台：开启“刷新 user_access_token”；“事件与回调 → 长连接”开启
#   im.message.receive_v1、task.task.update_user_access_v2、drive.notice.comment_add_v1、
#   minutes.minute.generated_v1，然后发布版本
lark-cli auth login --recommend

# 3. 本项目
npm install
cp config.example.yaml config.yaml     # 按需修改 harness、仓库别名、时间表
bin/pa doctor                          # 检查依赖、登录、初始化
bin/pa init                            # 建「Agent 看板」任务清单和「个人知识库」空间
bin/pa publish-doc docs/方案.md --parent 项目   # 把方案发布成飞书文档

# 4. 常驻运行
bin/pa run                             # 前台试跑；常驻见 deploy/
```

## 日常使用

| 你做什么 | 发生什么 |
|---|---|
| 什么都不做 | 每 15 分钟识别 @我/私聊/评论/妙记里的任务 → 看板“待确认”；工作日 8:30、18:30 私信概览；周五整理知识库 |
| 把卡片拖进“派给Agent” | 5 分钟内被领取。标题前缀 `[codex]` 选执行者，描述写 `repo: 别名` 在独立 worktree 执行；完成后跑校验命令（可选）并由另一个 harness 审查。**通过验收**才移到“待验收”；审查未通过、无法验证或执行出错移到“需人工介入”。每一步写在卡片评论里 |
| 把进行中的卡片拖走 / 标记完成 | 取消这次派单，改动保留在 worktree |
| 进程崩溃或重启 | 没做完的派单、事件、飞书写入从断点继续；派单回到本轮检查点重跑 |
| 私聊机器人 | `/brief` `/capture` `/dispatch` `/status` `/do [harness] 描述`；其他文字交给 superagent 处理 |

## 命令

```
pa doctor | init | run | brief [morning|evening] [--print] | capture | dispatch | status
pa job <名称> | ask <文字> | publish-doc <file.md> [--title] [--parent 节点名]
pa guard-check <none|readonly|agent> -- <lark-cli 参数…>
```

## 代码结构

```
src/
  cli.ts            命令入口
  app.ts            组装组件、初始化、常驻进程（事件 → inbox，定时 → 对账/入队，引擎执行）
  ledger.ts         账本：work（event/effect/dispatch/job）+ steps，租约、fencing、幂等入队
  engine.ts         工作引擎：领取、心跳续约、退避重试、耗尽落终态、取消与优雅退出
  effects.ts        outbox 发布器：评论 / 移卡片 / 私信，幂等投递
  config.ts         配置加载与校验（config.example.yaml）
  lark.ts           lark-cli 封装（身份、JSON 信封、错误、私信主人）
  guard.ts          agent 调 lark-cli 的放行策略；guard-cli.ts 是 bin/guard/lark-cli 的实现
  harness.ts        通过 acpx 调用任一 harness（权限、超时、守卫环境、日志）
  events.ts         lark-cli event consume 子进程守护（事件写入 inbox、退避重启、优雅退出）
  board.ts          看板（任务清单/分组）与知识库（空间/节点/文档）
  store.ts          SQLite：kv（游标、ID、幂等操作结果）、信号队列
  workflows/
    triage.ts       分诊（无工具，只输出 JSON）
    capture.ts      任务识别：消息/评论/妙记 → 信号 → 分诊 → 建任务
    dispatch.ts     派单状态机：对账 → worktree → 检查点 → 执行 → 校验/审查 → 验收关卡
    brief.ts        早晚报（不调模型）
    agent.ts        superagent 作业（至多一次）与私聊指令
prompts/            各角色提示词（可直接改）
deploy/             systemd 单元 / 无 systemd 时的守护脚本
test/               单元测试 + 基于有状态桩（test/stubs）的端到端测试
```

## 可靠性

- **能重启就能续跑**：所有工作（派单、事件、作业、对飞书的写操作）都记在本地账本里，用租约表示归属。进程崩溃后，工作会被接管并从最后的检查点继续，不需要手动处理。
- **事件不会丢**：飞书事件先落库再处理，处理失败会退避重试；重试耗尽会私信告诉你。看板靠定时对账兜底，不依赖事件。
- **完成 = 达标**：派单是否进“待验收”由验收关卡决定。没配置 reviewer 或 verify 时默认进“需人工介入”，可以用 `acceptance.on_unverified` 调整。
- `pa status` 查看最近的工作，以及重试中或失败的事件和飞书写入。详见 [docs/可靠性设计.md](docs/可靠性设计.md)。

## 安全边界

- 分诊和 worker 完全不能调用 lark-cli；superagent 作业只能读、建/改自己的任务和文档、给你本人发消息。删除、移动、改权限、指派他人、给他人发消息一律被守卫拒绝，记录在 `<data_dir>/logs/guard.log`。策略在 `src/guard.ts`。
- 机器人只处理你本人私聊发来的消息。
- worker 在独立 worktree 分支 `pa/<任务ID>` 上工作，不 push，合并由你决定。
- 守卫是防误操作和提示注入的护栏，不是操作系统级沙箱：`--approve-all` 的 worker 仍可在开发机上执行命令，请只在你信任的仓库上派单。

## 开发

```bash
npm test          # 单元 / 账本引擎 / 端到端测试（桩程序，不访问飞书和模型；含 kill -9 崩溃恢复、故障注入）
npm run typecheck
```

## 联调注意

框架用桩程序验证过编排逻辑，飞书接口的真实返回结构需要在开发机上确认。如果某一步报“创建…失败”或解析不到字段，看 `runs/` 下的日志和 `lark-cli <命令> --dry-run` 的输出，调整 `src/board.ts` / `src/workflows/capture.ts` 中的字段名即可。
