# personal-agent (Avatar)

飞书个人 superagent，替你维护一份始终最新的**工作上下文**：从飞书消息、Meego、妙记、日历、飞书任务和文档评论里识别你的项目、事项、知识、动态和人，每天告诉你先做什么、谁在等你、你答应过什么、哪里说法不一致，并帮你推进——起草回复 / 跟进 / Meego 评论 / 周报，**你确认后才以你本人身份发出**。需要动手的事可以一键交给 Claude Code / Codex / Gemini 等 harness 执行（经 [acpx](https://github.com/openclaw/acpx)），执行后经确定性校验与交叉审查，打通到 PR / MR / 本地合并。

入口是**飞书交互卡片**（晨间卡、收尾卡、实时提醒、草稿）和**本机 Web 控制台**（今天 · 项目 · 事项 · 知识 · 动态 · 人 · 草稿；派单、健康、花费、设置在「更多」里）。

设计文档：[工作上下文](docs/工作上下文.md) · [总体方案](docs/方案.md) · [可靠性设计](docs/可靠性设计.md) · [产品化架构](docs/产品化架构.md)。

## 快速开始

```bash
# 1. 依赖（Node ≥ 22.13，飞书交互卡片需 lark-cli ≥ 1.0.100）
npm i -g @larksuite/cli acpx
npx skills add larksuite/cli -y -g     # 可选：给各 harness 装飞书官方 skills

# 2. 飞书应用与登录（按提示在浏览器完成）
lark-cli config init --new
#   开发者后台：开启“刷新 user_access_token”；“事件与回调 → 长连接”开启
#   im.message.receive_v1、task.task.update_user_access_v2、drive.notice.comment_add_v1、
#   minutes.minute.generated_v1、card.action.trigger，然后发布版本
lark-cli auth login --recommend

# 3. 本项目
npm install
npm run build:web                      # 构建本机 Web 控制台
cp config.example.yaml config.yaml     # 按需修改 harness、仓库别名、交付平台、时间表
bin/pa doctor                          # 逐项体检（缺项附修复指引）
bin/pa init                            # 建「Agent 看板」任务清单和「个人知识库」空间
bin/pa publish-doc docs/方案.md --parent 项目   # 把方案发布成飞书文档

# 4. 先试一轮工作上下文（会把消息内容发给 context.harness 对应的模型，见 docs/工作上下文.md）
bin/pa context run && bin/pa context today

# 5. 常驻运行 & 打开控制台
bin/pa run                             # 前台试跑；常驻见 deploy/
bin/pa console                         # 打印带令牌的控制台登录链接（默认 http://<局域网IP>:7878）
```

控制台默认监听 `0.0.0.0:7878`，同局域网浏览器可直接打开打印的 `http://<局域网IP>:7878/login?token=...`；如需仅限本机访问，可将 `server.host` 设为 `127.0.0.1` 并经 SSH / VS Code 端口转发访问（`ssh -L 7878:127.0.0.1:7878 <开发机>`）。

## 日常使用

| 你做什么 | 发生什么 |
|---|---|
| 什么都不做 | 每 10 分钟采集 Meego / 消息 / 妙记 / 日历 / 飞书任务 / 文档评论并理解（每条结论都带原文证据）；工作日 8:30 发**晨间卡**（先做这几件、需要你判断的冲突、今天的会、24 小时变化），18:30 发**收尾卡**；新出现的紧急请求或风险**实时提醒**；周五起草周报 |
| 在卡片或控制台上处理事项 | 「完成 / 稍后 / 不对 / 不重要」；「不对」会作为校准样例让之后的识别更准。冲突选一个说法为准，会沉淀为项目的决策知识 |
| 让我帮你推进 | 「起草」回复 / 跟进 / Meego 评论 / 周报 → 草稿卡片里可直接修改 → 「以我的身份发送」。不确认就什么都不会发出 |
| 交给 Agent | 事项详情里「交给 Agent」新建派单，描述附上上下文和原文链接 |
| 派单（拖卡片 / 私聊 `/do` / 控制台） | 私聊 `/do` 弹出派单表单卡片（不用记格式），也可拖卡片进「派给Agent」或从控制台新建。同一任务在飞书只有一张**派单卡片**，随阶段原地更新；完成后先跑仓库 `verify` 命令再由另一 harness 交叉审查。**通过验收**进「待验收」，否则进「需人工介入」 |
| 验收交付（卡片或控制台） | 一键「创建 PR」（GitHub / GitLab / 公司 Codebase）、「合并到本地分支」（仅快进）、「带意见返工」、「换执行者重试」或「放弃」（保留期内可恢复） |
| 把进行中的卡片拖走 / 点取消 | 按任务 ID 核实后取消这次派单并结束 harness 进程组，改动保留在 worktree |
| 进程崩溃或重启 | 没做完的派单、事件、交付、飞书写入从断点继续；派单回到本轮 git 检查点重跑 |
| 看过程与调设置 | 打开 Web 控制台查看实时日志、diff、审查全文、花费预算、健康队列（一键重试失败项）和可视化设置（保存即热生效，保留 YAML 注释） |

## 命令

```
pa doctor | init | run | brief [morning|evening] [--print] | capture | dispatch | status
pa context run | today | digest [morning|evening] [--print]   工作上下文：采集理解一轮 / 看今天 / 发晨间卡
pa context web-status [--verify]       查询独立飞书个人 Web 网关状态（网关部署见下）
pa context web-unbind                  解除当前工作区与个人 Web 账号的绑定并重置本地网关游标（切换网关账号时使用）
feishu-gateway login | run | status [--verify] | logout | tokens   独立飞书个人 Web 常驻网关（单独进程/OS 用户/容器部署）
pa console [--rotate]                  打印控制台登录链接（--rotate 作废旧令牌）
pa command <名称> [JSON 参数]          通过统一命令层执行操作（与卡片/控制台按钮一致）
pa job <名称> | ask <文字> | publish-doc <file.md> [--title] [--parent 节点名]
pa guard-check <none|readonly|agent> -- <lark-cli 参数…>
```

## 代码结构

```
src/
  cli.ts            命令入口
  app.ts            组装组件、初始化、常驻进程（事件 → inbox，定时 → 对账/入队，引擎 + 控制台服务）
  bus.ts            进程内事件总线（刷新 SSE、驱动卡片更新）
  ledger.ts         账本：work（event/effect/dispatch/job/delivery）+ steps（含用量）+ audit，租约与 fencing
  engine.ts         工作引擎：领取、心跳续约、退避重试、耗尽落终态、取消与优雅退出
  effects.ts        outbox 发布器：评论 / 移卡片 / 完成 / 私信 / 交互卡片原地更新（含通知偏好门控）
  commands.ts       统一命令层（校验、前置条件、审计）+ core-commands.ts
  modules.ts        可选模块注册表 + ext.ts 扩展点定义
  api/              types.ts（前后端共用契约）、queries.ts（只读视图、diff、分段日志）
  server/           本机 HTTP API + SSE + 静态 SPA 托管（令牌鉴权 + 同源防 CSRF）
  cards/            飞书交互卡片（schema 2.0 模板、card.action.trigger 解析与去抖服务）
  delivery/         交付闭环（GitHub / GitLab / Codebase PR、本地快进合并、放弃保留与恢复）
  settings.ts       设置读写（保留 YAML 注释、脱敏、热加载）
  doctor.ts         结构化体检与修复指引
  notify-prefs.ts   通知偏好（免打扰时段、按类型开关、失败告警不拦截）
  usage.ts          acpx 用量解析、按天/执行者/任务统计、每日与单任务预算守卫
  candidates.ts     候选任务反馈、准确率统计、分诊校准闭环
  gateway/          独立部署边界的飞书个人 Web 常驻网关（0 处依赖 Avatar 业务模块）：
                    config / store（独立 SQLite 游标缓存 + 幂等发送账本 + 读写双令牌）/ service / server（Unix Socket 或回环 HTTP + SSE）/
                    client / cli（bin/feishu-gateway）/ feishu-web（基于 ws/qrcode/tough-cookie 的协议层）
  context/          工作上下文：connectors（采集）· personal-web（纯网关客户端桥接层）· understand（带证据的理解）·
                    store（ctx_* 图谱）· views（排序与视图）· drafts（起草）· cards（晨间卡 / 收尾卡 / 提醒 / 草稿）· index（周期、命令、自主等级）
  config.ts / lark.ts / guard.ts / harness.ts / events.ts / board.ts / store.ts
  workflows/        triage.ts / capture.ts / dispatch.ts / brief.ts / agent.ts
web/                React + Vite + TypeScript 本机控制台 SPA + scripts/demo-server.ts
prompts/            各角色提示词（可直接改）
deploy/             systemd 单元 / 无 systemd 时的守护脚本
test/               后端单元/引擎/集成/端到端测试（桩程序，不访问飞书和模型）
```

## 可靠性与安全边界

- **能重启就能续跑**：所有工作和飞书写操作都记在本地 SQLite 账本里，租约过期或持有者进程已死即被接管，从 git 检查点继续。详见 [docs/可靠性设计.md](docs/可靠性设计.md)。
- **完成 = 达标**：派单是否进「待验收」由验收关卡决定（确定性校验 + 结构化审查），未通过/无校验/审查器故障进「需人工介入」。
- **对外动作只在你确认后发生**：工作上下文的理解与起草都没有工具、没有写权限，消息内容按不可信数据处理；回复 / 评论 / 建文档只在你确认草稿后经 outbox 以你本人身份执行。开启理解会把消息内容发给所选模型服务（`context.understand: false` 可关闭）。
- **飞书权限守卫**：分诊和 worker 不能调用 `lark-cli`；superagent 作业只放行读和白名单写操作，审计记入 `<data_dir>/logs/guard.log`。机器人和卡片按钮只响应主人本人。
- **控制台鉴权与边界**：默认监听 `0.0.0.0`（可设为 `127.0.0.1` 仅限本机），访问需令牌（HttpOnly + SameSite=Strict Cookie），写请求校验同源与 JSON，禁止经 API 修改 `data_dir` / `bins`，日志读取限定在 `data_dir` 内。
- 守卫不是操作系统级沙箱：`--approve-all` 的 worker 仍可在开发机上执行命令，请只在你信任的仓库上派单。
- **个人 Web 独立常驻网关边界（可选功能，默认关闭）**：个人 Web 协议、AES-256-GCM 静态加密会话 Cookie（`FEISHU_GW_KEY` / `PA_FEISHU_WEB_KEY` / systemd `LoadCredential`）与长连接已完整拆出到独立进程 `bin/feishu-gateway`（见 [gateway.example.yaml](gateway.example.yaml)、[deploy/feishu-gateway.service](deploy/feishu-gateway.service)、[deploy/Dockerfile.gateway](deploy/Dockerfile.gateway)）。推荐以独立 OS 用户或独立容器部署，通过 `0660` Unix Domain Socket + 读写分离双令牌（`read_token` 只读流与游标补拉，`reply_token` 且网关侧默认 `allow_reply: false` 才允许受控回复）与 Avatar 主进程隔离开，Avatar 及其 `--approve-all` worker 不再接触飞书 Cookie 与加密密钥。边界与运维注意：
  - 与 Avatar 同一 OS 用户的 worker 仍能从 `/proc/<pid>/environ` 或 `$CREDENTIALS_DIRECTORY` 读到网关令牌（`read_token` 可读任意会话历史，`reply_token` 在 `allow_reply: true` 时可发消息；开启 `send_replies` 时 `pa doctor` 会显式告警），需要真正隔离时请让 worker 以独立 OS 用户或容器运行。
  - **私聊排除**：飞书个人 Web 会话元信息接口对单聊（P2P DM）不返回对方姓名，因此在网关边界 `gateway.yaml` 的 `deny_chats` 中排除私聊必须使用原生数字 `chat_id` 或 `pw_chat:<id>`；按联系人姓名排除/静音私聊在 Avatar 侧跨通道学到对方姓名后生效。
  - **切换账号**：在网关侧执行 `feishu-gateway login --force-switch-account` 会原子清空旧账号的事件日志/缓存/投递账本并轮换 `db_epoch`，随后在 Avatar 侧执行 `pa context web-unbind` 解绑旧账号即可重新同步。
  - **systemd 令牌**：`deploy/feishu-gateway.service` 通过 `LoadCredential` 从 `/etc/feishu-gateway/secrets/{read-token,reply-token}` 加载令牌；此模式下直接查看凭据文件即可，在无 `CREDENTIALS_DIRECTORY` 的 shell 中运行 `feishu-gateway tokens` 会拒绝静默生成冲突的 `tokens.json`。
  - 仍存在上游私有协议变更风险，请按需开启并遵守组织合规要求。
- **从进程内个人 Web 升级**：旧版 `pa context web-login` 把加密会话保存在 `<data_dir>/feishu-web.json`。改用网关后请运行 `pa context web-logout` 删除它，从 Avatar 的运行环境中移除 `PA_FEISHU_WEB_KEY`，并在飞书 App 的登录设备管理里移除旧的网页登录；`pa doctor` 会提示残留。

## 开发与本地演示

```bash
npm test                               # 后端测试（126 个：单元/账本/对账/卡片/交付/平台/用量/集成/端到端）
npm run typecheck                      # 后端类型检查
npm run build:web                      # 构建前端控制台到 web/dist/
npm run test:web                       # 前端 Vitest 组件测试（24 个）
npm run typecheck:web                  # 前端类型检查
npm run dev:web                        # Vite 开发服务器（代理 /api 到 127.0.0.1:7878）

# 无需飞书账号，在本地用桩数据预览完整控制台：
node --experimental-strip-types --disable-warning=ExperimentalWarning web/scripts/demo-server.ts
```

## 联调注意

框架用桩程序验证过全部编排与前后端链路；接真实飞书 / 代码平台时请核对 [docs/产品化架构.md](docs/产品化架构.md) 第 4 节的联调清单（`card.action.trigger` 回调、`im messages patch`、`task comments list`、`task sections tasks` 分页、以及 `bytedcli codebase mr create` 返回字段）。
