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
    .object({ lark: z.string().default("lark-cli"), acpx: z.string().default("acpx") })
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
      /** 仓库别名 → 本地路径；任务描述里写 `repo: 别名` 即在该仓库的 git worktree 中执行 */
      repos: z.record(z.string(), z.string()).default({}),
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
