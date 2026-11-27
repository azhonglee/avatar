import fs from "node:fs";
import path from "node:path";
import { Cron } from "croner";
import YAML, { isMap, type Document } from "yaml";
import { z } from "zod";
import type { App } from "./app.ts";
import type { SettingsUpdateResult, SettingsView } from "./api/types.ts";
import { ConfigSchema, markConfigMutated } from "./config.ts";
import { parseHHMM } from "./notify-prefs.ts";
import { errMsg, log } from "./util.ts";

/**
 * 设置服务：控制台“设置”页读写 config.yaml。
 *
 *   - 读：文件内容 + 默认值（即保存后的配置），harness.env 里的明文值打码（${VAR} 引用原样显示）
 *   - 写：把局部补丁深合并进 YAML（保留注释和顺序），用与 loadConfig 相同的 schema 和交叉检查校验；
 *     失败返回带点分路径的中文错误，文件不动；成功原子写入（临时文件 + rename，保留 .bak），
 *     可热加载的部分立即同步到内存里的 app.cfg（原地修改，所有组件都能看到），其余标记为需要重启
 *   - 补丁语义：对象逐键合并；数组整体替换；值为 null 表示删除该键（如删除一个仓库别名）；
 *     harness.env 的值等于打码占位符时保持原值不变（前端回传整份配置也不会把密钥覆盖成占位符）
 *   - data_dir / bins 不允许经 API 修改（改错会让守护进程读写别处的数据或执行别的程序）
 */

export const MASK = "******";

const HOT = new Set(["notify", "budget", "acceptance", "capture", "dispatch", "delivery", "cards", "lark_web", "applink_host", "context"]);
/** 热加载分组里仍需重启的字段（引擎并发上限、定时任务、模块开关、常驻长连接开关在启动时确定） */
const COLD_PATHS = new Set([
  "dispatch.max_parallel",
  "context.enabled",
  "context.schedule",
  "context.morning",
  "context.evening",
  "context.weekly",
  "context.personal_web.enabled",
]);
const FORBIDDEN = ["data_dir", "bins"];

type Obj = Record<string, unknown>;
type Issue = { path: string; message: string };

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

/** 某个配置路径是否保存即生效 */
export function isHotPath(p: string[]): boolean {
  if (!HOT.has(p[0])) return false;
  for (let i = 1; i <= p.length; i++) if (COLD_PATHS.has(p.slice(0, i).join("."))) return false;
  return true;
}

/** 两份配置之间有差异的叶子路径（对象逐键比较，其他值整体比较）。 */
export function diffPaths(a: unknown, b: unknown, prefix: string[] = []): string[][] {
  if (isObj(a) && isObj(b)) {
    const out: string[][] = [];
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) out.push(...diffPaths(a[k], b[k], [...prefix, k]));
    return out;
  }
  return JSON.stringify(a) === JSON.stringify(b) ? [] : [prefix];
}

/** 把 target 原地同步成 source（按完整点分路径递归跳过冷配置项），保留 target 对象本身的引用。 */
function syncInPlace(target: Obj, source: Obj, prefix: string[]): void {
  for (const k of Object.keys(target)) {
    if (!(k in source) && isHotPath([...prefix, k])) delete target[k];
  }
  for (const [k, v] of Object.entries(source)) {
    const p = [...prefix, k];
    if (!isHotPath(p)) continue;
    if (isObj(v)) {
      if (!isObj(target[k])) target[k] = {};
      syncInPlace(target[k] as Obj, v, p);
    } else {
      target[k] = structuredClone(v);
    }
  }
}

const ENV_REF = /^\$\{\w+\}$/;

/** harness.env 的明文值打码；${VAR} 引用原样显示 */
function redact(cfg: Obj): Obj {
  const out = structuredClone(cfg);
  const hs = out.harnesses;
  if (isObj(hs)) {
    for (const h of Object.values(hs)) {
      if (!isObj(h) || !isObj(h.env)) continue;
      for (const [k, v] of Object.entries(h.env)) if (typeof v === "string" && !ENV_REF.test(v)) h.env[k] = MASK;
    }
  }
  return out;
}

const fmtPath = (p: readonly PropertyKey[]) => p.map(String).join(".");

/** 与 loadConfig 一致的交叉检查，外加控制台需要的格式检查（时间、时区、cron、引用）。 */
export function crossCheck(cfg: z.infer<typeof ConfigSchema>): Issue[] {
  const issues: Issue[] = [];
  const hasHarness = (n: string) => Object.hasOwn(cfg.harnesses, n);
  const refs: [string, string][] = [
    ["roles.brain", cfg.roles.brain],
    ["roles.reviewer", cfg.roles.reviewer],
    ["dispatch.default_harness", cfg.dispatch.default_harness],
    ["context.harness", cfg.context.harness],
    ...Object.entries(cfg.jobs).map(([n, j]) => [`jobs.${n}.harness`, j.harness ?? ""] as [string, string]),
  ];
  for (const [p, name] of refs) if (name && !hasHarness(name)) issues.push({ path: p, message: `引用了未定义的 harness：${name}` });
  for (const [n, h] of Object.entries(cfg.harnesses)) {
    if (h.type === "acpx" && !h.agent === !h.agentCommand) issues.push({ path: `harnesses.${n}`, message: "acpx 类型必须且只能设置 agent 或 agentCommand 之一" });
  }
  const hasProvider = (n: string) => Object.hasOwn(cfg.delivery.providers, n);
  if (cfg.delivery.default_provider && !hasProvider(cfg.delivery.default_provider))
    issues.push({ path: "delivery.default_provider", message: `引用了未定义的交付平台：${cfg.delivery.default_provider}` });
  for (const [alias, r] of Object.entries(cfg.dispatch.repos)) {
    if (typeof r !== "string" && r.provider && !hasProvider(r.provider))
      issues.push({ path: `dispatch.repos.${alias}.provider`, message: `引用了未定义的交付平台：${r.provider}` });
  }
  const qs = cfg.notify.quiet_start.trim();
  const qe = cfg.notify.quiet_end.trim();
  if (qs && parseHHMM(qs) === undefined) issues.push({ path: "notify.quiet_start", message: "时间格式应为 HH:MM，如 22:00" });
  if (qe && parseHHMM(qe) === undefined) issues.push({ path: "notify.quiet_end", message: "时间格式应为 HH:MM，如 08:00" });
  if (!qs !== !qe) issues.push({ path: qs ? "notify.quiet_end" : "notify.quiet_start", message: "免打扰的开始和结束时间需要同时填写（都留空表示关闭）" });
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: cfg.owner.timezone });
  } catch {
    issues.push({ path: "owner.timezone", message: `无效的时区：${cfg.owner.timezone}（例如 Asia/Shanghai）` });
  }
  const crons: [string, string][] = [
    ...Object.entries(cfg.schedules).map(([k, v]) => [`schedules.${k}`, v] as [string, string]),
    ...Object.entries(cfg.jobs).map(([n, j]) => [`jobs.${n}.cron`, j.cron] as [string, string]),
    ...(["schedule", "morning", "evening", "weekly"] as const).map((k) => [`context.${k}`, cfg.context[k]] as [string, string]),
  ];
  for (const [p, expr] of crons) {
    try {
      new Cron(expr, { paused: true }).stop();
    } catch (e) {
      issues.push({ path: p, message: `无效的 cron 表达式「${expr}」：${errMsg(e)}` });
    }
  }
  cfg.context.bot_allow.forEach((p, i) => {
    try {
      new RegExp(p);
    } catch {
      issues.push({ path: `context.bot_allow.${i}`, message: `无效的正则：${p}` });
    }
  });
  if (cfg.capture.auto_inbox_confidence < cfg.capture.min_confidence)
    issues.push({ path: "capture.auto_inbox_confidence", message: "直接进 Inbox 的置信度不能低于进“待确认”的置信度" });
  return issues;
}

/** 校验一份完整配置（未带默认值的原始对象）。 */
export function validateConfig(raw: unknown): { ok: true; data: z.infer<typeof ConfigSchema> } | { ok: false; errors: Issue[] } {
  const parsed = ConfigSchema.safeParse(raw ?? {}, { error: z.locales.zhCN().localeError });
  if (!parsed.success) return { ok: false, errors: parsed.error.issues.map((i) => ({ path: fmtPath(i.path), message: i.message })) };
  const errors = crossCheck(parsed.data);
  return errors.length ? { ok: false, errors } : { ok: true, data: parsed.data };
}

/** 补丁的叶子路径（null 表示删除；对象继续展开；空对象也算叶子） */
function leaves(patch: Obj, prefix: string[] = []): { path: string[]; value: unknown }[] {
  const out: { path: string[]; value: unknown }[] = [];
  for (const [k, v] of Object.entries(patch)) {
    if (isObj(v) && Object.keys(v).length) out.push(...leaves(v, [...prefix, k]));
    else out.push({ path: [...prefix, k], value: v });
  }
  return out;
}

function getIn(o: unknown, p: string[]): unknown {
  let cur = o;
  for (const k of p) {
    if (!isObj(cur) || !Object.hasOwn(cur, k)) return undefined;
    cur = cur[k];
  }
  return cur;
}

/**
 * 把补丁合并进 YAML 文档：已有映射逐键合并（保留注释），其余位置整体写入。
 * 与当前生效值（current，带默认值）相同的叶子跳过，前端回传整份配置时文件里只落真正的改动。
 */
function applyPatch(doc: Document, patch: Obj, current: unknown, prefix: string[] = []): void {
  for (const [k, v] of Object.entries(patch)) {
    const p = [...prefix, k];
    const node = doc.getIn(p, true);
    if (v === null) {
      doc.deleteIn(p);
    } else if (isObj(v) && (isMap(node) || node === undefined)) {
      applyPatch(doc, v, current, p);
    } else if (JSON.stringify(getIn(current, p)) === JSON.stringify(v)) {
      continue; // 与当前生效值相同
    } else {
      // 标量直接给值：yaml 会原地改已有标量节点，保留它的行尾注释
      doc.setIn(p, typeof v === "object" ? doc.createNode(v) : v);
    }
  }
}

/** 去掉补丁里 harness.env 的打码占位符（保持原值） */
function dropMasked(patch: Obj): void {
  const hs = patch.harnesses;
  if (!isObj(hs)) return;
  for (const h of Object.values(hs)) {
    if (!isObj(h) || !isObj(h.env)) continue;
    for (const [k, v] of Object.entries(h.env)) if (v === MASK) delete h.env[k];
  }
}

export class SettingsService {
  app: App;
  /** 启动时文件里的配置（带默认值）：据此判断是否有需要重启才生效的改动 */
  private startup: Obj | undefined;
  private restartFlag = false;
  private chain: Promise<unknown> = Promise.resolve();

  constructor(app: App) {
    this.app = app;
    const r = this.readFile();
    if (r.ok) this.startup = r.data as Obj;
  }

  get file(): string {
    return this.app.cfg.file;
  }

  private readFile(): { ok: true; doc: Document; data: z.infer<typeof ConfigSchema> } | { ok: false; errors: Issue[] } {
    if (!this.file || !fs.existsSync(this.file)) return { ok: false, errors: [{ path: "", message: `找不到配置文件 ${this.file || "（未指定）"}` }] };
    const doc = YAML.parseDocument(fs.readFileSync(this.file, "utf8"));
    if (doc.errors.length) return { ok: false, errors: doc.errors.map((e) => ({ path: "", message: `配置文件语法错误：${e.message}` })) };
    const v = validateConfig(doc.toJS());
    return v.ok ? { ok: true, doc, data: v.data } : v;
  }

  /** 文件里的配置与启动时相比，是否有需要重启才生效的差异（current 缺省时读文件） */
  private restartRequired(current?: Obj): boolean {
    if (this.restartFlag) return true;
    if (!current) {
      const r = this.readFile();
      if (!r.ok) return false;
      current = r.data as Obj;
    }
    if (!this.startup) return false;
    return diffPaths(this.startup, current).some((p) => !isHotPath(p));
  }

  get(): SettingsView {
    const r = this.readFile();
    let config: Obj;
    if (r.ok) config = r.data as Obj;
    else {
      // 文件当前不可用（被手工改坏等）：显示内存中生效的配置
      const { dataDir: _d, file: _f, ...mem } = this.app.cfg;
      config = mem as Obj;
    }
    const hot_reload: Record<string, boolean> = {};
    for (const k of Object.keys(ConfigSchema.shape)) hot_reload[k] = HOT.has(k);
    for (const p of COLD_PATHS) hot_reload[p] = false;
    return { config: redact(config), hot_reload, file: this.file, restart_required: this.restartRequired(r.ok ? (r.data as Obj) : undefined) };
  }

  put(patch: Record<string, unknown>): Promise<SettingsUpdateResult> {
    const run = this.chain.then(() => this.doPut(patch));
    this.chain = run.catch(() => undefined);
    return run;
  }

  private doPut(input: Record<string, unknown>): SettingsUpdateResult {
    const fail = (errors: Issue[]): SettingsUpdateResult => {
      this.audit(input, false, `保存失败：${errors.map((e) => `${e.path || "配置"}：${e.message}`).join("；")}`.slice(0, 1000));
      return { ok: false, errors, restart_required: this.restartRequired() };
    };
    if (!isObj(input)) return fail([{ path: "", message: "请求体必须是对象" }]);
    const patch = structuredClone(input);
    dropMasked(patch);

    const cur = this.readFile();
    if (!cur.ok) return fail(cur.errors);
    const doc = cur.doc;
    // data_dir / bins：回传原值（前端提交整份配置）可以，改动一律拒绝
    const trial = doc.clone();
    const before = (doc.toJS() ?? {}) as Obj;
    applyPatch(trial, patch, cur.data);
    const after = (trial.toJS() ?? {}) as Obj;
    const forbidden = FORBIDDEN.filter((k) => {
      if (!Object.hasOwn(patch, k)) return false;
      const sch = ConfigSchema.shape[k as "data_dir" | "bins"];
      const a = sch.safeParse(before[k]);
      const b = sch.safeParse(after[k]);
      return !b.success || JSON.stringify(a.data) !== JSON.stringify(b.data);
    });
    if (forbidden.length) return fail(forbidden.map((k) => ({ path: k, message: `出于安全考虑，${k} 不能在控制台修改，请直接编辑 ${this.file}` })));
    for (const k of FORBIDDEN) delete patch[k]; // 没有改动：不写进文件
    applyPatch(doc, patch, cur.data);
    const v = validateConfig(doc.toJS());
    if (!v.ok) return fail(v.errors);
    const unknown = leaves(patch)
      .filter((l) => l.value !== null && getIn(v.data, l.path) === undefined)
      .map((l) => ({ path: l.path.join("."), message: "未知的配置项" }));
    if (unknown.length) return fail(unknown);

    const changed = diffPaths(cur.data, v.data);
    if (!changed.length) {
      this.audit(input, true, "配置没有变化");
      return { ok: true, errors: [], restart_required: this.restartRequired(v.data as Obj) };
    }
    try {
      this.writeAtomic(doc.toString());
    } catch (e) {
      return fail([{ path: "", message: `写入配置文件失败：${errMsg(e)}` }]);
    }
    this.applyHot(v.data as Obj);
    const cold = changed.filter((p) => !isHotPath(p)).map((p) => p.join("."));
    if (cold.length && !this.startup) this.restartFlag = true;
    const restart = this.restartRequired(v.data as Obj);
    this.audit(
      input,
      true,
      `已保存 ${changed.length} 项：${changed.map((p) => p.join(".")).join("、")}`.slice(0, 600) + (cold.length ? `；需要重启常驻进程生效：${cold.join("、")}`.slice(0, 400) : ""),
    );
    log("info", "设置已保存", { changed: changed.length, restart_required: restart });
    return { ok: true, errors: [], restart_required: restart };
  }

  /** 临时文件 + rename；原文件先复制为 .bak；保持原文件权限 */
  private writeAtomic(text: string): void {
    const file = this.file;
    const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.tmp`);
    const mode = fs.statSync(file).mode & 0o777;
    const fd = fs.openSync(tmp, "w", mode);
    try {
      fs.writeFileSync(fd, text);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    try {
      fs.copyFileSync(file, `${file}.bak`);
      fs.renameSync(tmp, file);
    } catch (e) {
      fs.rmSync(tmp, { force: true });
      throw e;
    }
  }

  /** 可热加载的分组原地同步到 app.cfg（深层嵌套冷字段保持启动时的原值，直到重启） */
  private applyHot(data: Obj): void {
    const cfg = this.app.cfg as unknown as Obj;
    for (const k of HOT) {
      const src = data[k];
      if (isObj(src) && isObj(cfg[k])) syncInPlace(cfg[k] as Obj, src, [k]);
      else if (src !== undefined && isHotPath([k])) cfg[k] = structuredClone(src);
    }
    markConfigMutated(this.app.cfg);
  }

  private audit(args: Record<string, unknown>, ok: boolean, message: string): void {
    try {
      const safe = isObj(args) ? redact(args) : args;
      this.app.ledger.audit({ source: "web", actor: "owner", command: "settings.update", target: "config", args: safe, ok, message });
    } catch (e) {
      log("warn", "写设置审计失败", { err: errMsg(e) });
    }
  }
}

export function registerSettings(app: App): void {
  const svc = new SettingsService(app);
  app.ext.settings = { get: () => svc.get(), put: (patch) => svc.put(patch) };
}
