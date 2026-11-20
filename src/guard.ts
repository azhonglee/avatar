/**
 * lark-cli 守卫策略。agent（任何 harness）调用 lark-cli 时，PATH 里排在最前面的是 bin/guard/lark-cli，
 * 它按这里的策略放行或拒绝，再转交真正的 lark-cli。这样不依赖各家 harness 的权限系统，换 harness 不用改。
 *
 * profile：
 *   none     —— 一律拒绝（worker、分诊不该碰飞书）
 *   readonly —— 只放行读操作
 *   agent    —— 读操作 + 白名单内的写操作（只写自己的任务/文档，只给主人发消息）
 */
export type Profile = "none" | "readonly" | "agent";

export interface Decision {
  allow: boolean;
  reason: string;
}

const ALWAYS_DENY_DOMAINS = new Set(["auth", "config", "event", "profile", "update"]);
const DANGEROUS = /(delete|remove|revert|member|permission|secure-label|move|sync|push|upload|edit|transfer|share|assign|follower|speaker-replace|word-replace)/;
const READ_VERB =
  /^\+?(get|list|search|fetch|detail|inspect|query|batch-query|mget|agenda|tasks|node-get|node-list|space-list|tasklist-search|chat-list|chat-search|chat-messages-list|threads-messages-list|messages-search|messages-mget|messages-read-status|list-|history-list|preview|export|download|media-download|media-preview|resource-download|version-history|read|free-busy|freebusy)(\b|$)/;

/** agent 允许的写操作（domain + 命令）。 */
const WRITE_ALLOW = new Set([
  "docs +create",
  "docs +update",
  "docs +media-insert",
  "wiki +node-create",
  "task +create",
  "task +update",
  "task +comment",
  "task +complete",
  "task +reopen",
  "task +reminder",
  "task +tasklist-task-add",
  "im +messages-send",
]);

export function getFlag(argv: string[], name: string): string | undefined {
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === name) return argv[i + 1];
    if (argv[i].startsWith(name + "=")) return argv[i].slice(name.length + 1);
  }
  return undefined;
}

export function decide(argv: string[], profile: Profile, ownerOpenId: string): Decision {
  const positional: string[] = [];
  for (const a of argv) {
    if (a.startsWith("-")) break;
    positional.push(a);
  }
  const [domain = "", cmd = "", method = ""] = positional;

  if (argv.includes("--help") || argv.includes("-h") || domain === "help" || positional.length === 0)
    return { allow: true, reason: "help" };
  if (domain === "schema" || (domain === "skills" && cmd === "read") || domain === "--version")
    return { allow: true, reason: "文档/schema 查询" };
  if (profile === "none") return { allow: false, reason: "当前角色不允许访问飞书" };
  if (argv.includes("--dry-run")) return { allow: true, reason: "dry-run 不产生副作用" };
  if (ALWAYS_DENY_DOMAINS.has(domain)) return { allow: false, reason: `禁止 agent 使用 ${domain} 命令` };

  // 原生 API 形如 `task sections list`，快捷命令形如 `task +create`
  const verb = cmd.startsWith("+") ? cmd : method || cmd;
  if (DANGEROUS.test(verb)) return { allow: false, reason: `高风险操作 ${domain} ${cmd} ${method}`.trim() };
  if (READ_VERB.test(verb)) return { allow: true, reason: "读操作" };
  if (profile === "readonly") return { allow: false, reason: "当前角色只允许读操作" };

  const key = `${domain} ${cmd}`;
  if (!WRITE_ALLOW.has(key)) return { allow: false, reason: `写操作 ${key} 不在白名单（见 src/guard.ts）` };
  if (key === "im +messages-send") {
    if (getFlag(argv, "--as") !== "bot" || getFlag(argv, "--user-id") !== ownerOpenId || !ownerOpenId)
      return { allow: false, reason: "agent 只能以机器人身份（--as bot）给主人本人发消息（--user-id 主人 open_id）" };
  }
  const assignee = getFlag(argv, "--assignee");
  if (assignee && assignee !== ownerOpenId) return { allow: false, reason: "不允许把任务指派给别人" };
  return { allow: true, reason: "白名单写操作" };
}
