import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";
import { z } from "zod";
import { expandHome } from "./util.ts";

/** 项目根目录（prompts/、bin/guard/ 都相对它）。 */
export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const Harness = z.object({
  /** acpx 内置或在 ~/.acpx/config.json 自定义的 agent 名，例如 claude / codex / gemini / deepseek-harness / trae */
  agent: z.string().optional(),
  /** 原始 ACP 启动命令（走 acpx --agent），与 agent 二选一 */
  agentCommand: z.string().optional(),
  model: z.string().optional(),
  env: z.record(z.string(), z.string()).default({}),
  extraArgs: z.array(z.string()).default([]),
});
export type Harness = z.infer<typeof Harness>;

const Schema = z.object({
  owner: z
    .object({
      /** 你的 open_id（ou_xxx）；留空则 pa init 时从 lark-cli auth status 推断并保存 */
      open_id: z.string().default(""),
      timezone: z.string().default("Asia/Shanghai"),
    })
    .prefault({}),
  data_dir: z.string().default("~/.personal-agent"),
  bins: z
    .object({
      lark: z.string().default("lark-cli"),
      acpx: z.string().default("acpx"),
      /** 交付到公司 Codebase 时用的 bytedcli */
      bytedcli: z.string().default("bytedcli"),
    })
    .prefault({}),
  applink_host: z.string().default("applink.feishu.cn"),
  /** 飞书网页域名，用于拼文档/妙记链接；企业租户一般是 https://<租户>.feishu.cn */
  lark_web: z.string().default("https://feishu.cn"),
  board: z
    .object({
      name: z.string().default("Agent 看板"),
      /** 看板列（任务清单分组）。“已完成”用任务的完成状态表示，不单独建列。 */
      sections: z
        .object({
          inbox: z.string().default("Inbox"),
          pending: z.string().default("待确认"),
          dispatch: z.string().default("派给Agent"),
          running: z.string().default("Agent进行中"),
          review: z.string().default("待验收"),
          /** 审查未通过 / 无法验证 / 执行出错：需要你介入 */
          attention: z.string().default("需人工介入"),
          waiting: z.string().default("等待他人"),
        })
        .prefault({}),
    })
    .prefault({}),
  kb: z
    .object({
      space_name: z.string().default("个人知识库"),
      nodes: z.array(z.string()).default(["00 Inbox", "会议纪要", "项目", "主题", "变更日志"]),
      /** 妙记生成后，让 brain 把它整理成知识库里的会议纪要（agent 作业，见 prompts/kb-minutes.md） */
      minutes_notes: z.boolean().default(true),
    })
    .prefault({}),
  harnesses: z.record(z.string(), Harness),
  roles: z.object({
    /** 分诊、机器人对话、知识库整理等“大脑”工作用哪个 harness */
    brain: z.string(),
    /** 派单结果交叉审查用哪个 harness；留空则不审查 */
    reviewer: z.string().default(""),
  }),
  dispatch: z
    .object({
      default_harness: z.string().default(""),
      max_parallel: z.number().int().min(1).default(2),
      timeout_sec: z.number().int().min(60).default(3600),
      fix_rounds: z.number().int().min(0).default(1),
      /** 同一阶段最多尝试几次（含进程崩溃中断）；超过后落到“需人工介入” */
      max_attempts: z.number().int().min(1).default(2),
      /**
       * 仓库别名 → 本地路径，或 { path, verify }；任务描述里写 `repo: 别名` 即在该仓库的 git worktree 中执行。
       * verify 是确定性校验命令（如 npm test），在 worktree 里运行，失败即打回返工。
       */
      repos: z
        .record(
          z.string(),
          z.union([
            z.string(),
            z.object({
              path: z.string(),
              verify: z.string().optional(),
              /** 交付：用 delivery.providers 里的哪个平台创建 PR/MR（缺省用 delivery.default_provider） */
              provider: z.string().optional(),
              /** 交付：PR/MR 的目标分支（缺省用仓库当前默认分支） */
              target_branch: z.string().optional(),
            }),
          ]),
        )
        .default({}),
    })
    .prefault({}),
  /** 验收关卡：派单“完成”由它定义，而不是由执行者退出码定义 */
  acceptance: z
    .object({
      /** 没有任何校验（无 reviewer、无 verify 命令）时：needs_human 进“需人工介入”；review 标为未验证后进“待验收” */
      on_unverified: z.enum(["needs_human", "review"]).default("needs_human"),
      /** reviewer 故障（超时、无输出、结论无法解析）时重试几次；仍失败则需人工介入，不算打回 */
      review_retries: z.number().int().min(0).default(1),
      review_timeout_sec: z.number().int().min(60).default(1200),
      verify_timeout_sec: z.number().int().min(10).default(1800),
    })
    .prefault({}),
  /** Web 控制台与 API（默认监听 0.0.0.0，同局域网可直接访问，令牌鉴权；仅限本机可改为 127.0.0.1） */
  server: z
    .object({
      enabled: z.boolean().default(true),
      host: z.string().default("0.0.0.0"),
      /** 0 表示随机端口（测试用） */
      port: z.number().int().min(0).max(65535).default(7878),
    })
    .prefault({}),
  /** 飞书交互卡片（候选任务、派单进度、验收结果、失败告警、早晚报） */
  cards: z.object({ enabled: z.boolean().default(true) }).prefault({}),
  /** 交付：把派单结果变成 PR/MR、合并到本地分支或放弃 */
  delivery: z
    .object({
      default_provider: z.string().default(""),
      providers: z
        .record(
          z.string(),
          z.object({
            type: z.enum(["github", "gitlab", "codebase"]),
            /** GitLab/自建实例的地址，如 https://gitlab.example.com；GitHub 缺省 https://api.github.com */
            base_url: z.string().optional(),
            /** 存放访问令牌的环境变量名（codebase 走 bytedcli 登录态，不需要） */
            token_env: z.string().optional(),
            /** 推送用的 git remote 名 */
            remote: z.string().default("origin"),
          }),
        )
        .default({}),
      /** 放弃后保留 worktree 与分支的天数，期间可以恢复 */
      discard_retention_days: z.number().int().min(0).default(7),
    })
    .prefault({}),
  /** 用量与预算：0 表示不限制 */
  budget: z
    .object({
      daily_usd: z.number().min(0).default(0),
      per_task_usd: z.number().min(0).default(0),
      /** 每百万 token 单价（美元），按 harness 名；没配的只记耗时不计费 */
      pricing: z.record(z.string(), z.object({ input: z.number().min(0), output: z.number().min(0) })).default({}),
    })
    .prefault({}),
  /** 通知偏好 */
  notify: z
    .object({
      /** 免打扰时段（按 owner.timezone，如 "22:00"–"08:00"）；期间的非紧急私信延后到结束时发送 */
      quiet_start: z.string().default(""),
      quiet_end: z.string().default(""),
      types: z
        .object({
          candidate: z.boolean().default(true),
          progress: z.boolean().default(true),
          result: z.boolean().default(true),
          failure: z.boolean().default(true),
          brief: z.boolean().default(true),
        })
        .prefault({}),
    })
    .prefault({}),
  /** 工作引擎（一般不用改） */
  engine: z
    .object({
      lease_sec: z.number().min(1).default(60),
      tick_ms: z.number().int().min(50).default(5000),
      retry_base_ms: z.number().int().min(10).default(5000),
      retry_max_ms: z.number().int().min(10).default(600_000),
      /** 事件处理、飞书写入各自最多尝试几次 */
      event_attempts: z.number().int().min(1).default(6),
      effect_attempts: z.number().int().min(1).default(10),
    })
    .prefault({}),
  capture: z
    .object({
      /** 置信度不低于该值的候选任务进“待确认”，更低的只记录 */
      min_confidence: z.number().min(0).max(1).default(0.6),
      /** 置信度不低于该值的直接进 Inbox */
      auto_inbox_confidence: z.number().min(0).max(1).default(0.9),
      /** 首次运行时回看多少小时的消息 */
      lookback_hours: z.number().int().min(1).default(24),
    })
    .prefault({}),
  schedules: z
    .object({
      capture: z.string().default("*/15 * * * *"),
      dispatch: z.string().default("*/5 * * * *"),
      brief_morning: z.string().default("30 8 * * 1-5"),
      brief_evening: z.string().default("30 18 * * 1-5"),
    })
    .prefault({}),
  /** 开启哪些事件长连接（需在飞书开发者后台“事件订阅-长连接”里开启对应事件并发布版本） */
  events: z
    .object({
      bot_messages: z.boolean().default(true),
      task_updates: z.boolean().default(true),
      doc_comments: z.boolean().default(true),
      minutes: z.boolean().default(true),
      /** card.action.trigger：飞书卡片上的按钮 / 表单 */
      card_actions: z.boolean().default(true),
    })
    .prefault({}),
  /** 定时的 agent 作业：用 brain（或指定 harness）带受限的 lark-cli 执行一段提示词 */
  jobs: z
    .record(
      z.string(),
      z.object({
        cron: z.string(),
        prompt: z.string(),
        harness: z.string().optional(),
        notify: z.boolean().default(true),
      }),
    )
    .default({}),
});

export type Config = z.infer<typeof Schema> & { dataDir: string; file: string };

/** 解析 `repo:` 引用：配置里的别名（字符串或 {path, verify}），否则当作路径。 */
export interface RepoSpec {
  path: string;
  verify?: string;
  provider?: string;
  target_branch?: string;
}

export function repoSpec(cfg: Config, ref: string): RepoSpec {
  const v = cfg.dispatch.repos[ref];
  if (v === undefined) return { path: path.resolve(expandHome(ref)) };
  if (typeof v === "string") return { path: path.resolve(expandHome(v)) };
  return { path: path.resolve(expandHome(v.path)), verify: v.verify, provider: v.provider, target_branch: v.target_branch };
}

/** 配置的 zod schema（设置服务用它校验写入）。 */
export const ConfigSchema = Schema;

export function loadConfig(file = process.env.PA_CONFIG ?? path.join(ROOT, "config.yaml")): Config {
  if (!fs.existsSync(file)) {
    throw new Error(`找不到配置文件 ${file}。先执行：cp config.example.yaml config.yaml 并按需修改`);
  }
  const parsed = Schema.safeParse(YAML.parse(fs.readFileSync(file, "utf8")) ?? {});
  if (!parsed.success) throw new Error(`配置文件 ${file} 有误：\n${z.prettifyError(parsed.error)}`);
  const cfg = parsed.data;
  for (const name of [cfg.roles.brain, cfg.roles.reviewer, cfg.dispatch.default_harness].filter(Boolean)) {
    if (!cfg.harnesses[name]) throw new Error(`配置引用了未定义的 harness：${name}`);
  }
  for (const h of Object.values(cfg.harnesses)) {
    if (!h.agent === !h.agentCommand) throw new Error("每个 harness 必须且只能设置 agent 或 agentCommand 之一");
  }
  const dataDir = path.resolve(expandHome(cfg.data_dir));
  for (const sub of ["logs", "runs", "workspace", "worktrees"]) fs.mkdirSync(path.join(dataDir, sub), { recursive: true });
  return { ...cfg, dataDir, file };
}
