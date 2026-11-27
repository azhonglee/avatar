import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { ROOT, type Config } from "./config.ts";
import type { Profile } from "./guard.ts";
import { isPlainTable, parseToml, parseTomlKeyPath, parseTomlValue, type TomlTable, type TomlValue } from "./toml.ts";
import { runProcess } from "./util.ts";

const FEISHU_WEB_KEY_CRED = "feishu-web-key";
/** Linux kernel tmpfs magic number (`linux/magic.h`: `TMPFS_MAGIC`). */
const LINUX_TMPFS_MAGIC = 0x01021994;

export type MountMaskBackend =
  | { kind: "bwrap"; bin: string }
  | { kind: "unshare"; bin: string; setprivBin: string; pivotRootBin?: string }
  | { kind: "none" };
let cachedMountMaskBackend: MountMaskBackend | undefined;

export interface IsolationOptions {
  /** 强制指定隔离后端（仅用于测试 bwrap / unshare / none 分支） */
  forceBackend?: MountMaskBackend;
  /** 常驻进程数据目录：以空 tmpfs 遮蔽整个 dataDir（隐藏 state.db、feishu-web.json、logs、runs 等私有状态） */
  dataDir?: string;
  /** 即使当前交互式 shell 未携带密钥环境变量，也按工作区身份强制启用内核隔离 */
  requireIsolation?: boolean;
  /** 隔离后的工作目录（作为子进程 chdir 目标） */
  cwd?: string;
  /** 仅对这些路径开放可写挂载（如当前派单 worktree 或独立 scratch 目录） */
  writablePaths?: string[];
  /** 需要额外显式只读暴露的路径（例如位于 /tmp 下的只读输入、CODEX_HOME 或仓库 .git） */
  readOnlyPaths?: string[];
  /** 需要以 /dev/null 遮罩的独立敏感文件 */
  maskFiles?: string[];
}

function safeRealpath(p: string): string {
  const abs = path.resolve(p);
  try {
    return fs.realpathSync(abs);
  } catch {
    return abs;
  }
}

function isPathInsideOrEqual(child: string, parent: string): boolean {
  const rel = path.relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function resolvePivotRootBin(): string | undefined {
  for (const cand of ["/sbin/pivot_root", "/usr/sbin/pivot_root"]) {
    try {
      fs.accessSync(cand, fs.constants.X_OK);
      return cand;
    } catch {
      // try next
    }
  }
  try {
    return resolveBin("pivot_root");
  } catch {
    return undefined;
  }
}

function resolveExpectedGitCommonDir(repoRoot: string): string {
  const realRoot = safeRealpath(repoRoot);
  const dotGit = path.join(realRoot, ".git");
  try {
    const st = fs.lstatSync(dotGit);
    if (st.isDirectory()) return safeRealpath(dotGit);
    if (st.isFile()) {
      const m = fs.readFileSync(dotGit, "utf8").match(/^gitdir:\s*(.+)$/m);
      if (m) {
        const gd = safeRealpath(path.isAbsolute(m[1].trim()) ? m[1].trim() : path.resolve(realRoot, m[1].trim()));
        const cf = path.join(gd, "commondir");
        if (fs.existsSync(cf) && fs.lstatSync(cf).isFile()) {
          const rawC = fs.readFileSync(cf, "utf8").trim();
          if (rawC) return safeRealpath(path.isAbsolute(rawC) ? rawC : path.resolve(gd, rawC));
        }
        return gd;
      }
    }
  } catch {
    // 裸仓库直接以 repoRoot 为 commonDir
  }
  return realRoot;
}

function isGenuineGitCommonDir(dir: string): boolean {
  try {
    return (
      fs.statSync(dir).isDirectory() &&
      fs.lstatSync(path.join(dir, "HEAD")).isFile() &&
      fs.statSync(path.join(dir, "objects")).isDirectory() &&
      fs.statSync(path.join(dir, "refs")).isDirectory()
    );
  } catch {
    return false;
  }
}

function parseGitConfigWorktree(gitDir: string): string | undefined {
  const cfgPath = path.join(gitDir, "config");
  try {
    if (!fs.lstatSync(cfgPath).isFile()) return undefined;
    const text = fs.readFileSync(cfgPath, "utf8");
    let inCore = false;
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#") || line.startsWith(";")) continue;
      const sec = line.match(/^\[([^\]]+)\]$/);
      if (sec) {
        inCore = sec[1].trim().toLowerCase() === "core";
        continue;
      }
      if (!inCore) continue;
      const m = line.match(/^worktree\s*=\s*(.+)$/i);
      if (m) {
        let val = m[1].trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.slice(1, -1);
        }
        if (val) return safeRealpath(path.isAbsolute(val) ? val : path.resolve(gitDir, val));
      }
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/**
 * 探测并严格校验 worktree / `--separate-git-dir` / submodule 对应的 .git 管理目录与主仓 commondir：
 *   - 绝不盲信可写工作区内的 `.git` / `commondir` 指向任意宿主机路径；
 *   - 拒绝符号链接 `.git` / `commondir` / `gitdir`；
 *   - 链接 worktree（存在 commondir）：要求 `<gitDir>/gitdir` 反向指向当前 `<dir>/.git`、
 *     `gitDir` 严格位于 `<commonDir>/worktrees/` 下且 `commonDir` 为合法 Git 仓库目录且不在 `dataDir` 内；
 *   - `--separate-git-dir` 或 submodule（无 commondir）：要求 `gitDir` 自身为合法 Git 仓库目录且 `core.worktree` 指回当前 `dir`，
 *     提供 `trustedRepoRoot` 时要求 `gitDir` 归属受信任仓库（等于其 `.git` 或位于其 `.git/modules/` 下）；
 *   - 不满足以上任一约束时直接抛错拒绝挂载。
 */
export function detectGitWorktreeDirs(
  dir: string,
  opts?: { trustedRepoRoot?: string; dataDir?: string },
): { gitDir?: string; commonDir?: string } {
  const realDir = safeRealpath(dir);
  const dotGit = path.join(realDir, ".git");
  let st: fs.Stats;
  try {
    st = fs.lstatSync(dotGit);
  } catch {
    return {};
  }
  if (st.isSymbolicLink()) {
    throw new Error(`检测到符号链接 .git，已按安全策略拒绝挂载：${realDir}`);
  }
  if (!st.isFile()) return {};

  const reject = (reason: string): never => {
    throw new Error(`worktree .git 元数据校验失败（${reason}），已按安全策略拒绝挂载：${realDir}`);
  };

  let content: string;
  try {
    content = fs.readFileSync(dotGit, "utf8");
  } catch {
    return reject("无法读取 .git 文件");
  }
  const m = content.match(/^gitdir:\s*(.+)$/m);
  if (!m) return reject(".git 文件缺少 gitdir 声明");
  const rawGitDir = m[1].trim();
  const absGitDir = path.isAbsolute(rawGitDir) ? rawGitDir : path.resolve(realDir, rawGitDir);
  let gitDir: string;
  try {
    if (!fs.statSync(absGitDir).isDirectory()) return reject("gitdir 目标不是目录");
    gitDir = fs.realpathSync(absGitDir);
  } catch {
    return reject("gitdir 目标不存在或不可访问");
  }

  const resolvedDataDir = opts?.dataDir ? safeRealpath(opts.dataDir) : undefined;
  const commonFile = path.join(gitDir, "commondir");
  const hasCommonFile = fs.existsSync(commonFile);

  if (!hasCommonFile) {
    // 区分合法的 `--separate-git-dir` 仓库与 submodule 检出（两者均无 commondir，gitDir 自身是完整 Git 目录）：
    //   - submodule 的 <gitDir>/config 含 core.worktree 且必须反向指向 realDir；
    //   - `git init --separate-git-dir` 不写 core.worktree，若指定了 trustedRepoRoot 必须严格匹配该受信任仓库的 expectedCommon。
    if (!isGenuineGitCommonDir(gitDir)) {
      return reject("gitdir 缺少 commondir 且自身不是合法 Git 仓库目录");
    }
    if (resolvedDataDir && isPathInsideOrEqual(gitDir, resolvedDataDir)) {
      return reject("Git 元数据目录不得落入 dataDir 私有目录内");
    }
    const configuredWt = parseGitConfigWorktree(gitDir);
    if (configuredWt && configuredWt !== realDir) {
      return reject("gitdir/config 中的 core.worktree 与当前检出目录不一致");
    }
    if (opts?.trustedRepoRoot) {
      const trustedRoot = safeRealpath(opts.trustedRepoRoot);
      const expectedCommon = resolveExpectedGitCommonDir(trustedRoot);
      const modulesRoot = path.join(expectedCommon, "modules");
      const isTrustedSeparate = realDir === trustedRoot && gitDir === expectedCommon;
      const isTrustedSubmodule =
        isPathInsideOrEqual(gitDir, modulesRoot) &&
        gitDir !== modulesRoot &&
        configuredWt === realDir;
      if (!isTrustedSeparate && !isTrustedSubmodule) {
        return reject(`gitdir (${gitDir}) 不属于受信任仓库 (${expectedCommon})`);
      }
    }
    return { gitDir, commonDir: gitDir };
  }

  const backFile = path.join(gitDir, "gitdir");
  let commonDir: string;
  try {
    if (!fs.lstatSync(commonFile).isFile()) return reject("缺少合法 commondir 文件");
    const rawCommon = fs.readFileSync(commonFile, "utf8").trim();
    if (!rawCommon) return reject("commondir 为空");
    const absCommon = path.isAbsolute(rawCommon) ? rawCommon : path.resolve(gitDir, rawCommon);
    if (!fs.statSync(absCommon).isDirectory()) return reject("commondir 目标不是目录");
    commonDir = fs.realpathSync(absCommon);
  } catch (err) {
    if (err instanceof Error && err.message.includes("worktree .git 元数据校验失败")) throw err;
    return reject("无法读取或解析 commondir");
  }

  // 双向绑定校核：<gitDir>/gitdir 必须反向指回本 checkout 的 .git
  try {
    if (!fs.lstatSync(backFile).isFile()) return reject("缺少合法反向 gitdir 指针");
    const rawBack = fs.readFileSync(backFile, "utf8").trim();
    if (!rawBack) return reject("反向 gitdir 指针为空");
    const absBack = path.isAbsolute(rawBack) ? rawBack : path.resolve(gitDir, rawBack);
    const backTarget = path.join(safeRealpath(path.dirname(absBack)), path.basename(absBack));
    if (backTarget !== dotGit) return reject("反向 gitdir 指针与当前 worktree 不一致");
  } catch (err) {
    if (err instanceof Error && err.message.includes("worktree .git 元数据校验失败")) throw err;
    return reject("无法校验反向 gitdir 指针");
  }

  const worktreesRoot = path.join(commonDir, "worktrees");
  if (!isPathInsideOrEqual(gitDir, worktreesRoot) || gitDir === worktreesRoot) {
    return reject("gitDir 不在 commondir/worktrees 目录下");
  }
  if (!isGenuineGitCommonDir(commonDir)) {
    return reject("commondir 不是合法的 Git 仓库目录");
  }
  if (resolvedDataDir) {
    if (isPathInsideOrEqual(gitDir, resolvedDataDir) || isPathInsideOrEqual(commonDir, resolvedDataDir)) {
      return reject("Git 元数据目录不得落入 dataDir 私有目录内");
    }
  }
  if (opts?.trustedRepoRoot) {
    const expectedCommon = resolveExpectedGitCommonDir(opts.trustedRepoRoot);
    if (commonDir !== expectedCommon) {
      return reject(`commondir (${commonDir}) 不属于受信任仓库 (${expectedCommon})`);
    }
  }
  return { gitDir, commonDir };
}

function hasStateDbSensitiveState(dataDir: string, includeContextObs = false): boolean {
  const dbPath = path.join(dataDir, "state.db");
  if (!fs.existsSync(dbPath)) return false;
  let db: DatabaseSync | undefined;
  try {
    db = new DatabaseSync(dbPath, { readOnly: true });
    const hasKvTbl = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'kv' LIMIT 1").get();
    if (hasKvTbl) {
      const hasPwKv = db
        .prepare(
          "SELECT 1 FROM kv WHERE (k LIKE 'ctx.personal_web.%' AND v != '') OR (k = 'daemon.holds_web_key' AND v = '1') LIMIT 1",
        )
        .get();
      if (hasPwKv) return true;
    }
    if (includeContextObs) {
      const hasObsTbl = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ctx_obs' LIMIT 1").get();
      if (hasObsTbl) {
        const hasObs = db.prepare("SELECT 1 FROM ctx_obs LIMIT 1").get();
        if (hasObs) return true;
      }
    }
    return false;
  } catch (err) {
    // 仅在数据库文件并发消失时返回 false；锁冲突、权限不足或损坏等意外检查失败一律按 fail-closed 要求隔离
    if ((err as NodeJS.ErrnoException)?.code === "ENOENT" || !fs.existsSync(dbPath)) return false;
    return true;
  } finally {
    try {
      db?.close();
    } catch {
      // ignore
    }
  }
}

/**
 * 按工作区配置、本地敏感状态与当前进程凭据综合判断是否必须启用内核级 PID + 挂载命名空间隔离：
 *   - 不再仅依赖当前 shell 的环境变量：即便交互式 shell（如 `pa dispatch`）未持有服务密钥，
 *     只要工作区启用了个人 Web、存在加密凭据文件，或 `state.db` 含个人 Web 绑定/常驻持钥标记（以及对仓库能力进程检查私有上下文观测），均强制隔离；
 *   - 若 `state.db` 存在但检查发生锁冲突/权限/损坏等异常，按 fail-closed 要求隔离。
 */
export function workspaceRequiresIsolation(
  cfgOrDataDir: Pick<Config, "dataDir" | "context"> | string | undefined,
  rawEnv: NodeJS.ProcessEnv = process.env,
  opts?: { includeContextObs?: boolean },
): boolean {
  const credDir = rawEnv.CREDENTIALS_DIRECTORY?.trim();
  if (credDir && fs.existsSync(path.join(credDir, FEISHU_WEB_KEY_CRED))) return true;
  if (rawEnv.PA_FEISHU_WEB_KEY?.trim()) return true;
  if (rawEnv.PA_FEISHU_WEB_CRED_FILE?.trim()) return true;
  if (!cfgOrDataDir) return false;
  const dataDir = typeof cfgOrDataDir === "string" ? cfgOrDataDir : cfgOrDataDir.dataDir;
  if (typeof cfgOrDataDir === "object" && cfgOrDataDir.context?.personal_web?.enabled) return true;
  if (!dataDir) return false;
  if (fs.existsSync(path.join(dataDir, "feishu-web.json")) || fs.existsSync(path.join(dataDir, "feishu-web.json.staged"))) {
    return true;
  }
  return hasStateDbSensitiveState(dataDir, opts?.includeContextObs);
}

export type WorkspaceIsolationMode =
  | "llm-none"
  | "verify"
  | "worker-write"
  | "worker-ro"
  | "codex-exec"
  | "git-rw"
  | "git-ro";

/** 根据工作区配置与子进程角色生成最小权限文件系统挂载视图（始终排除 dataDir 私有状态，不开放宿主机共享代理配置目录写权限） */
export function buildWorkspaceIsolation(
  cfg: Pick<Config, "dataDir" | "context"> | undefined,
  opts: {
    mode: WorkspaceIsolationMode;
    cwd?: string;
    cmdPath?: string;
    /** 受信任的派单仓库根目录：存在时严格校核 worktree `.git` / `commondir` 归属该仓库 */
    trustedRepoRoot?: string;
    /** 显式禁止挂载任何外部 worktree `.git` 目录（用于非 Git 派单的空工作区） */
    disableGitWorktreeMounts?: boolean;
    allowGuardLog?: boolean;
    extraWritablePaths?: string[];
    extraReadOnlyPaths?: string[];
  },
  rawEnv: NodeJS.ProcessEnv = process.env,
): IsolationOptions {
  const dataDir = cfg?.dataDir;
  // 纯无工具推理（llm-none）在未启用个人 Web 时不因轮询 ctx_obs 强制要求 Linux 命名空间，保持 macOS/受限主机兼容；
  // 所有具备仓库访问能力的进程（verify / worker / codex-exec 审查 / git-rw / git-ro）均对 ctx_obs 启用隔离。
  const includeContextObs = opts.mode !== "llm-none";
  const requireIsolation = workspaceRequiresIsolation(cfg, rawEnv, { includeContextObs });
  const writablePaths: string[] = [];
  const readOnlyPaths: string[] = [];
  const resolvedCwd = opts.cwd ? safeRealpath(opts.cwd) : undefined;
  // 仅在实际需要启用沙箱隔离时才规划并校验 Git 外部挂载目录，避免未启用隔离的工作区在 submodule / --separate-git-dir 上误报
  const shouldInspectGit =
    requireIsolation && opts.mode !== "llm-none" && !opts.disableGitWorktreeMounts && !!resolvedCwd;
  const wt = shouldInspectGit
    ? detectGitWorktreeDirs(resolvedCwd!, { trustedRepoRoot: opts.trustedRepoRoot, dataDir })
    : {};

  if (opts.mode === "llm-none") {
    if (resolvedCwd) readOnlyPaths.push(resolvedCwd);
  } else if (opts.mode === "verify" || opts.mode === "worker-write") {
    if (resolvedCwd) {
      writablePaths.push(resolvedCwd);
      // 若工作目录自身直接含 .git 目录（非 linked worktree），同样将其覆挂为只读，防止不可信 worker/verify 改写仓库 hooks 或配置
      const localDotGit = path.join(resolvedCwd, ".git");
      try {
        if (fs.lstatSync(localDotGit).isDirectory()) readOnlyPaths.push(safeRealpath(localDotGit));
      } catch {
        // ignore
      }
    }
    // 共享 Git 元数据（主仓 commondir 及 worktree admin gitDir）对不可信 worker 与 verify 一律只读，
    // 防止改写共享 refs / config / hooks 或 commondir；实际 Git 提交由受信任的 Dispatcher/Delivery (git-rw) 完成。
    if (wt.commonDir) readOnlyPaths.push(wt.commonDir);
    if (wt.gitDir && wt.gitDir !== wt.commonDir) readOnlyPaths.push(wt.gitDir);
  } else if (opts.mode === "worker-ro" || opts.mode === "codex-exec") {
    if (resolvedCwd) readOnlyPaths.push(resolvedCwd);
    if (wt.commonDir) readOnlyPaths.push(wt.commonDir);
    if (wt.gitDir && wt.gitDir !== wt.commonDir) readOnlyPaths.push(wt.gitDir);
  } else if (opts.mode === "git-rw") {
    if (resolvedCwd) writablePaths.push(resolvedCwd);
    if (wt.commonDir) writablePaths.push(wt.commonDir);
    else if (wt.gitDir) writablePaths.push(wt.gitDir);
  } else if (opts.mode === "git-ro") {
    if (resolvedCwd) readOnlyPaths.push(resolvedCwd);
    if (wt.commonDir) readOnlyPaths.push(wt.commonDir);
    if (wt.gitDir && wt.gitDir !== wt.commonDir) readOnlyPaths.push(wt.gitDir);
  }

  // 当需要 lark 守卫审计日志时，仅单独挂载 guard.log 单文件（绝不暴露 dataDir 或 state.db）
  if (opts.allowGuardLog && dataDir) {
    const guardLog = path.join(dataDir, "logs", "guard.log");
    try {
      fs.mkdirSync(path.dirname(guardLog), { recursive: true });
      if (!fs.existsSync(guardLog)) fs.writeFileSync(guardLog, "", { mode: 0o600 });
      writablePaths.push(safeRealpath(guardLog));
    } catch {
      // 审计日志创建失败不影响隔离
    }
  }

  if (opts.cmdPath) {
    try {
      const resolvedCmd = path.isAbsolute(opts.cmdPath) ? safeRealpath(opts.cmdPath) : safeRealpath(resolveBin(opts.cmdPath));
      if (isPathInsideOrEqual(resolvedCmd, "/tmp") || isPathInsideOrEqual(resolvedCmd, "/dev/shm")) {
        readOnlyPaths.push(resolvedCmd);
      }
    } catch {
      // ignore unresolved cmd
    }
  }

  for (const p of opts.extraWritablePaths ?? []) {
    if (p && fs.existsSync(p)) writablePaths.push(safeRealpath(p));
  }
  for (const p of opts.extraReadOnlyPaths ?? []) {
    if (p && fs.existsSync(p)) readOnlyPaths.push(safeRealpath(p));
  }

  return {
    dataDir,
    requireIsolation,
    cwd: resolvedCwd,
    writablePaths,
    readOnlyPaths,
  };
}

function probeMountMaskBackend(): MountMaskBackend {
  if (cachedMountMaskBackend) return cachedMountMaskBackend;
  try {
    const bwrapBin = resolveBin("bwrap");
    const r = spawnSync(
      bwrapBin,
      ["--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--tmpfs", "/tmp", "--", "true"],
      { timeout: 3_000, stdio: "ignore" },
    );
    if (r.status === 0) {
      cachedMountMaskBackend = { kind: "bwrap", bin: bwrapBin };
      return cachedMountMaskBackend;
    }
  } catch {
    // 尝试 unshare + pivot_root + setpriv 降权回退
  }
  try {
    const unshareBin = resolveBin("unshare");
    const setprivBin = resolveBin("setpriv");
    const pivotRootBin = resolvePivotRootBin();
    if (pivotRootBin) {
      const probeScript = [
        "set -e",
        'PIVOT="$1"; SP="$2"',
        "mount -n --make-rprivate /",
        "S=",
        "for d in /mnt /media /srv /var/tmp; do [ -d \"$d\" ] && S=\"$d\" && break; done",
        'if [ -z "$S" ]; then exit 1; fi',
        'mount -n -t tmpfs tmpfs "$S"',
        'mkdir -p "$S/newroot"',
        'mount -n --rbind / "$S/newroot"',
        'mount -n -t tmpfs tmpfs "$S/newroot/tmp"',
        'mkdir -p "$S/newroot/tmp/.oldroot"',
        'cd "$S/newroot"',
        '"$PIVOT" . tmp/.oldroot',
        "umount -n -l /tmp/.oldroot",
        "rmdir /tmp/.oldroot",
        'exec "$SP" --bounding-set -all --inh-caps -all --ambient-caps -all --no-new-privs true',
      ].join("\n");
      const r = spawnSync(
        unshareBin,
        ["--user", "--map-root-user", "--mount", "--pid", "--fork", "--mount-proc", "--", "sh", "-c", probeScript, "_", pivotRootBin, setprivBin],
        { timeout: 3_000, stdio: "ignore" },
      );
      if (r.status === 0) {
        cachedMountMaskBackend = { kind: "unshare", bin: unshareBin, setprivBin, pivotRootBin };
        return cachedMountMaskBackend;
      }
    }
  } catch {
    // 均不可用
  }
  cachedMountMaskBackend = { kind: "none" };
  return cachedMountMaskBackend;
}

/** 探测当前宿主机是否具备零特权 PID + 最小权限只读根挂载命名空间隔离能力（bwrap 或 unshare+pivot_root+setpriv） */
export function hasCredentialMountIsolation(): boolean {
  return probeMountMaskBackend().kind !== "none";
}

const MOUNTINFO_UNESCAPE_AWK = [
  "function unescape(s, out, i, c, oct) {",
  '  out = ""',
  "  for (i = 1; i <= length(s); i++) {",
  "    c = substr(s, i, 1)",
  '    if (c == "\\\\" && i + 3 <= length(s)) {',
  "      oct = substr(s, i + 1, 3)",
  '      if (oct == "040") { out = out " "; i += 3; continue }',
  '      if (oct == "011") { out = out "\\t"; i += 3; continue }',
  '      if (oct == "134") { out = out "\\\\"; i += 3; continue }',
  '      if (oct == "012") { exit 42 }',
  "    }",
  "    out = out c",
  "  }",
  "  return out",
  "}",
  "function is_virt(subp) {",
  '  return (subp == "/proc" || subp == "/dev" || subp == "/sys" || index(subp, "/proc/") == 1 || index(subp, "/dev/") == 1 || index(subp, "/sys/") == 1)',
  "}",
].join("\n");

const UNSHARE_ISOLATION_SCRIPT = [
  "set -e",
  'PIVOT_ROOT="$1"; SETPRIV="$2"; DD="$3"; CWD="$4"; TM_COUNT="$5"; PRE_COUNT="$6"; POST_COUNT="$7"; M_COUNT="$8"',
  "shift 8",
  "mount -n --make-rprivate /",
  "S=",
  'TMP_STAGE=""',
  "for cand in /mnt /media /srv /var/tmp; do",
  '  [ -d "$cand" ] || continue',
  "  conflict=0",
  '  if [ -n "$DD" ]; then case "$DD" in "$cand"|"$cand"/*) conflict=1;; esac; fi',
  '  if [ -n "$CWD" ]; then case "$CWD" in "$cand"|"$cand"/*) conflict=1;; esac; fi',
  '  if [ "$conflict" -eq 0 ]; then',
  '    for arg in "$@"; do',
  '      case "$arg" in "$cand"|"$cand"/*) conflict=1; break;; esac',
  "    done",
  "  fi",
  '  if [ "$conflict" -eq 0 ]; then S="$cand"; break; fi',
  "done",
  'if [ -z "$S" ]; then S=$(mktemp -d /tmp/.pa-ns-XXXXXX); TMP_STAGE="$S"; fi',
  'mount -n -t tmpfs tmpfs "$S"',
  'mkdir -p "$S/newroot" "$S/save"',
  'mount -n --rbind / "$S/newroot"',
  "i=0",
  'while [ "$i" -lt "$TM_COUNT" ]; do',
  '  p="$1"; shift',
  '  printf "%sx" "$p" > "$S/save/tm$i.path"',
  "  i=$((i + 1))",
  "done",
  "i=0",
  'while [ "$i" -lt "$PRE_COUNT" ]; do',
  '  mode="$1"; p="$2"; shift 2',
  '  printf "%sx" "$mode" > "$S/save/pre$i.mode"',
  '  printf "%sx" "$p" > "$S/save/pre$i.path"',
  '  if [ -d "$p" ]; then mkdir -p "$S/save/pre$i"; else : > "$S/save/pre$i"; fi',
  '  mount -n --bind "$p" "$S/save/pre$i"',
  "  i=$((i + 1))",
  "done",
  "i=0",
  'while [ "$i" -lt "$POST_COUNT" ]; do',
  '  mode="$1"; p="$2"; shift 2',
  '  printf "%sx" "$mode" > "$S/save/post$i.mode"',
  '  printf "%sx" "$p" > "$S/save/post$i.path"',
  '  if [ -d "$p" ]; then mkdir -p "$S/save/post$i"; else : > "$S/save/post$i"; fi',
  '  mount -n --bind "$p" "$S/save/post$i"',
  "  i=$((i + 1))",
  "done",
  "i=0",
  'while [ "$i" -lt "$M_COUNT" ]; do',
  '  p="$1"; shift',
  '  printf "%sx" "$p" > "$S/save/m$i.path"',
  "  i=$((i + 1))",
  "done",
  // 解码 /proc/self/mountinfo 八进制转义（空格 \040 / 制表符 \011 / 反斜杠 \134），将全部非虚拟挂载强制重新挂载为只读；
  // 任一 remount 失败或复查发现仍存在可写非虚拟挂载点时，立即以非零退出中止子进程启动（fail-closed）。
  `awk -v prefix="$S/newroot" '${MOUNTINFO_UNESCAPE_AWK}\n{ mp = unescape($5); if (mp == prefix || index(mp, prefix "/") == 1) { subp = substr(mp, length(prefix) + 1); if (is_virt(subp)) next; opts = "," $6 ","; if (index(opts, ",ro,") > 0) next; print mp } }' /proc/self/mountinfo > "$S/save/ro-mounts"`,
  'while IFS= read -r mp; do',
  '  [ -n "$mp" ] || continue',
  '  mount -n -o remount,ro,bind "$mp"',
  'done < "$S/save/ro-mounts"',
  `awk -v prefix="$S/newroot" '${MOUNTINFO_UNESCAPE_AWK}\n{ mp = unescape($5); if (mp == prefix || index(mp, prefix "/") == 1) { subp = substr(mp, length(prefix) + 1); if (is_virt(subp)) next; opts = "," $6 ","; if (index(opts, ",ro,") == 0) { print "unshare read-only verification failed: " mp > "/dev/stderr"; exit 1 } } }' /proc/self/mountinfo`,
  'mount -n -t tmpfs tmpfs "$S/newroot/tmp"',
  'if [ -d "$S/newroot/dev/shm" ]; then mount -n -t tmpfs tmpfs "$S/newroot/dev/shm"; fi',
  // 遮蔽宿主机用户运行时目录（如 /run/user、$XDG_RUNTIME_DIR），隔离 systemd --user 与 D-Bus 套接字
  "i=0",
  'while [ "$i" -lt "$TM_COUNT" ]; do',
  '  p=$(cat "$S/save/tm$i.path"); p=${p%x}',
  '  if [ -d "$S/newroot$p" ]; then mount -n -t tmpfs tmpfs "$S/newroot$p"; fi',
  "  i=$((i + 1))",
  "done",
  // 第一阶段：挂载位于 dataDir 之外（含可能包含 dataDir 的祖先目录）的允许路径
  "i=0",
  'while [ "$i" -lt "$PRE_COUNT" ]; do',
  '  mode=$(cat "$S/save/pre$i.mode"); mode=${mode%x}',
  '  p=$(cat "$S/save/pre$i.path"); p=${p%x}',
  '  if [ -d "$S/save/pre$i" ]; then [ -d "$S/newroot$p" ] || mkdir -p "$S/newroot$p"; else [ -e "$S/newroot$p" ] || { mkdir -p "$(dirname "$S/newroot$p")"; : > "$S/newroot$p"; }; fi',
  '  mount -n --move "$S/save/pre$i" "$S/newroot$p"',
  '  if [ "$mode" = "ro" ]; then mount -n -o remount,ro,bind "$S/newroot$p"; else mount -n -o remount,rw,bind "$S/newroot$p"; fi',
  "  i=$((i + 1))",
  "done",
  // 第二阶段：在所有祖先挂载之后覆盖空 tmpfs 遮蔽整个 dataDir，确保 state.db / feishu-web.json / logs / runs 绝不重现
  'if [ -n "$DD" ]; then',
  '  [ -d "$S/newroot$DD" ] || mkdir -p "$S/newroot$DD"',
  '  mount -n -t tmpfs tmpfs "$S/newroot$DD"',
  "fi",
  // 第三阶段：在空 dataDir tmpfs 之上仅恢复显式允许的子路径（如当前派单 worktree 或 guard.log）
  "i=0",
  'while [ "$i" -lt "$POST_COUNT" ]; do',
  '  mode=$(cat "$S/save/post$i.mode"); mode=${mode%x}',
  '  p=$(cat "$S/save/post$i.path"); p=${p%x}',
  '  if [ -d "$S/save/post$i" ]; then [ -d "$S/newroot$p" ] || mkdir -p "$S/newroot$p"; else [ -e "$S/newroot$p" ] || { mkdir -p "$(dirname "$S/newroot$p")"; : > "$S/newroot$p"; }; fi',
  '  mount -n --move "$S/save/post$i" "$S/newroot$p"',
  '  if [ "$mode" = "ro" ]; then mount -n -o remount,ro,bind "$S/newroot$p"; else mount -n -o remount,rw,bind "$S/newroot$p"; fi',
  "  i=$((i + 1))",
  "done",
  'if [ -n "$DD" ]; then',
  '  mount -n -o remount,ro,bind "$S/newroot$DD"',
  "fi",
  "i=0",
  'while [ "$i" -lt "$M_COUNT" ]; do',
  '  p=$(cat "$S/save/m$i.path"); p=${p%x}',
  '  if [ -e "$S/newroot$p" ]; then mount -n --bind /dev/null "$S/newroot$p"; fi',
  "  i=$((i + 1))",
  "done",
  'mkdir -p "$S/newroot/tmp/.oldroot"',
  'cd "$S/newroot"',
  '"$PIVOT_ROOT" . tmp/.oldroot',
  'if [ -n "$TMP_STAGE" ]; then umount -n -l "/tmp/.oldroot$TMP_STAGE" 2>/dev/null || true; rmdir "/tmp/.oldroot$TMP_STAGE" 2>/dev/null || true; fi',
  "umount -n -l /tmp/.oldroot",
  "rmdir /tmp/.oldroot",
  'if [ -n "$CWD" ]; then cd "$CWD"; fi',
  'exec "$SETPRIV" --bounding-set -all --inh-caps -all --ambient-caps -all --no-new-privs "$@"',
].join("\n");

/**
 * 为模型执行器、仓库校验命令、git 子进程等同 UID 不可信子进程提供内核级进程与最小权限文件系统隔离：
 *   - 只要当前进程持有密钥，或工作区启用了个人 Web / 存有私有状态（即使交互式 shell 本身未持有密钥），均强制激活隔离；
 *   - 优先用 `bwrap --ro-bind / / --dev /dev --unshare-pid --proc /proc --tmpfs /tmp` 构建只读根视图，
 *     先挂载 dataDir 之外的路径（含任何祖先路径），再用空 `--tmpfs <dataDir>` 重新彻底遮蔽 `dataDir`
 *     （隐藏 `state.db`、outbox、`feishu-web.json`、`runs/`、`logs/`），随后仅在其上恢复显式允许的 worktree / `guard.log`，
 *     并用 `/dev/null` 遮罩外部密钥与凭据文件；
 *   - 回退用 `unshare --user --map-root-user --mount --pid --fork --mount-proc` + `pivot_root` 构建完全等价边界，
 *     解码 `/proc/self/mountinfo` 并在任一只读重挂无法验证时 fail-closed 中止，再以 `setpriv` 永久剥离全部 capabilities；
 *   - 宿主机不支持时按 fail-closed 拒绝启动子进程。
 */
export function wrapCredentialIsolatedCommand(
  cmd: string,
  args: string[],
  rawEnv: NodeJS.ProcessEnv = process.env,
  opts?: IsolationOptions,
): { cmd: string; args: string[]; isolated: boolean } {
  const credDir = rawEnv.CREDENTIALS_DIRECTORY?.trim();
  const keyFile = credDir ? path.join(credDir, FEISHU_WEB_KEY_CRED) : "";
  const hasCredKeyFile = !!keyFile && fs.existsSync(keyFile);
  const hasEnvKey = !!(rawEnv.PA_FEISHU_WEB_KEY?.trim());
  const extCredFile = rawEnv.PA_FEISHU_WEB_CRED_FILE?.trim() ? path.resolve(rawEnv.PA_FEISHU_WEB_CRED_FILE.trim()) : "";
  const needByWorkspace =
    !!opts?.requireIsolation ||
    (!!opts?.dataDir && workspaceRequiresIsolation(opts.dataDir, rawEnv));
  if (!hasCredKeyFile && !hasEnvKey && !extCredFile && !needByWorkspace) {
    return { cmd, args, isolated: false };
  }

  const resolvedDataDir = opts?.dataDir && fs.existsSync(opts.dataDir) ? safeRealpath(opts.dataDir) : "";
  const resolvedCwd = opts?.cwd && fs.existsSync(opts.cwd) ? safeRealpath(opts.cwd) : "";

  // 绝不允许把 dataDir 根目录或其核心敏感文件/运行日志目录放进 writable/readOnly 列表
  const isForbiddenDaemonTarget = (p: string): boolean => {
    if (!resolvedDataDir) return false;
    if (p === resolvedDataDir) return true;
    for (const sensitive of [
      "state.db",
      "state.db-wal",
      "state.db-shm",
      "feishu-web.json",
      "feishu-web.json.staged",
      "feishu-web.json.lock.db",
      "runs",
    ]) {
      const target = path.join(resolvedDataDir, sensitive);
      if (p === target || (sensitive === "runs" && isPathInsideOrEqual(p, target))) return true;
    }
    return false;
  };

  const dedupeSorted = (list: string[]): string[] => {
    const set = new Set<string>();
    for (const raw of list) {
      if (!raw) continue;
      const real = safeRealpath(raw);
      if (!fs.existsSync(real) || isForbiddenDaemonTarget(real)) continue;
      set.add(real);
    }
    return [...set].sort((a, b) => a.length - b.length || a.localeCompare(b));
  };

  // 遮蔽宿主机用户运行时目录（含 systemd --user 控制套接字、D-Bus 会话总线、GPG/SSH 代理套接字等）：
  // 只读挂载不能阻止同 UID 进程 connect(2) 到 Unix 域套接字，必须用空 tmpfs 彻底隐藏后再按需恢复显式允许路径。
  const runtimeMaskDirs: string[] = [];
  const addRuntimeMaskDir = (dir: string | undefined) => {
    if (!dir) return;
    const real = safeRealpath(dir);
    if (real === "/" || !fs.existsSync(real)) return;
    try {
      if (!fs.statSync(real).isDirectory()) return;
    } catch {
      return;
    }
    if (isPathInsideOrEqual(real, "/tmp") || isPathInsideOrEqual(real, "/dev/shm")) return;
    if (runtimeMaskDirs.some((existing) => isPathInsideOrEqual(real, existing))) return;
    runtimeMaskDirs.push(real);
  };
  addRuntimeMaskDir("/run/user");
  const rawXdgRuntime = rawEnv.XDG_RUNTIME_DIR?.trim();
  if (rawXdgRuntime) addRuntimeMaskDir(rawXdgRuntime);
  runtimeMaskDirs.sort((a, b) => a.length - b.length || a.localeCompare(b));

  const isHiddenByEphemeralTmpfs = (p: string): boolean =>
    isPathInsideOrEqual(p, "/tmp") ||
    isPathInsideOrEqual(p, "/dev/shm") ||
    runtimeMaskDirs.some((d) => isPathInsideOrEqual(p, d));

  const writablePaths = dedupeSorted(opts?.writablePaths ?? []);
  const writableSet = new Set(writablePaths);
  const rawReadOnly = [...(opts?.readOnlyPaths ?? [])];
  if (hasCredKeyFile && credDir && fs.existsSync(credDir)) {
    const resolvedCredDir = safeRealpath(credDir);
    if (isHiddenByEphemeralTmpfs(resolvedCredDir)) {
      rawReadOnly.push(resolvedCredDir);
    }
  }
  const readOnlyPaths = dedupeSorted(rawReadOnly).filter((p) => !writableSet.has(p));

  type MountEntry = { mode: "ro" | "rw"; path: string };
  const allMounts: MountEntry[] = [
    ...readOnlyPaths.map((p): MountEntry => ({ mode: "ro", path: p })),
    ...writablePaths.map((p): MountEntry => ({ mode: "rw", path: p })),
  ];
  // 按是否位于 dataDir 内部拆分为两阶段挂载（每阶段按路径长度升序，确保更深层子路径覆盖父路径）：
  //   1) preMounts：dataDir 之外的路径（含可能包含 dataDir 的仓库祖先目录），先挂载；
  //   2) tmpfs(dataDir)：在 preMounts 之后覆盖空 tmpfs，确保 dataDir 始终被遮蔽；
  //   3) postMounts：严格位于 dataDir 内部且显式放行的子路径（如当前派单 worktree 或 guard.log），最后恢复。
  const isStrictlyInsideDataDir = (p: string): boolean =>
    !!resolvedDataDir && p !== resolvedDataDir && isPathInsideOrEqual(p, resolvedDataDir);
  const sortEntries = (list: MountEntry[]): MountEntry[] =>
    list.sort((a, b) => a.path.length - b.path.length || a.path.localeCompare(b.path));
  const preMounts = sortEntries(allMounts.filter((m) => !isStrictlyInsideDataDir(m.path)));
  const postMounts = sortEntries(allMounts.filter((m) => isStrictlyInsideDataDir(m.path)));

  const rawMasks: string[] = [...(opts?.maskFiles ?? [])];
  if (hasCredKeyFile) {
    rawMasks.push(path.resolve(keyFile), safeRealpath(keyFile));
  }
  if (extCredFile) {
    for (const f of [extCredFile, `${extCredFile}.staged`, `${extCredFile}.lock.db`]) {
      if (fs.existsSync(f)) rawMasks.push(path.resolve(f), safeRealpath(f));
    }
    // 同时遮罩按工作区隔离的外部暂存文件（<extCredFile>.<wsTag>.staged）与在途临时文件
    const extDir = path.dirname(extCredFile);
    const extBase = path.basename(extCredFile);
    try {
      for (const entry of fs.readdirSync(extDir)) {
        if (
          (entry.startsWith(`${extBase}.`) && entry.endsWith(".staged")) ||
          (entry.startsWith(`.${extBase}.`) && entry.endsWith(".tmp"))
        ) {
          const full = path.join(extDir, entry);
          rawMasks.push(path.resolve(full), safeRealpath(full));
        }
      }
    } catch {
      // 外部凭据父目录不可列举时跳过通配补扫
    }
  }
  // 遮罩宿主机全局服务控制套接字（保留 /run/systemd/resolve 以免破坏 DNS 解析）
  for (const hostSock of [
    "/run/systemd/private",
    "/run/systemd/notify",
    "/run/dbus/system_bus_socket",
    "/var/run/dbus/system_bus_socket",
    "/run/docker.sock",
    "/var/run/docker.sock",
  ]) {
    if (fs.existsSync(hostSock)) rawMasks.push(safeRealpath(hostSock));
  }
  const dbusAddr = rawEnv.DBUS_SESSION_BUS_ADDRESS?.trim();
  if (dbusAddr) {
    const dm = dbusAddr.match(/unix:path=([^,;]+)/);
    if (dm?.[1] && fs.existsSync(dm[1])) rawMasks.push(safeRealpath(dm[1]));
  }
  const isReExposedBy = (p: string, mounts: MountEntry[]): boolean =>
    mounts.some((m) => isPathInsideOrEqual(p, m.path));
  const maskFiles = [...new Set(rawMasks.map((m) => safeRealpath(m)).filter((m) => fs.existsSync(m)))].filter((m) => {
    // 位于 dataDir 内的文件已被空 tmpfs 遮蔽，仅当被 postMounts 重新暴露时才需额外 /dev/null 遮罩
    if (resolvedDataDir && isPathInsideOrEqual(m, resolvedDataDir)) {
      return isReExposedBy(m, postMounts);
    }
    // 位于 /tmp、/dev/shm 或已遮蔽用户运行时目录内的文件已被空 tmpfs 隐藏，仅当被 preMounts 重新暴露时才需额外 /dev/null 遮罩
    if (isHiddenByEphemeralTmpfs(m)) {
      return isReExposedBy(m, preMounts);
    }
    return true;
  });

  const backend = opts?.forceBackend ?? probeMountMaskBackend();
  if (backend.kind === "bwrap") {
    const bwrapArgs: string[] = [
      "--die-with-parent",
      "--ro-bind",
      "/",
      "/",
      "--dev",
      "/dev",
      "--unshare-pid",
      "--proc",
      "/proc",
      "--tmpfs",
      "/tmp",
    ];
    for (const d of runtimeMaskDirs) {
      bwrapArgs.push("--tmpfs", d);
    }
    for (const m of preMounts) {
      bwrapArgs.push(m.mode === "ro" ? "--ro-bind" : "--bind", m.path, m.path);
    }
    if (resolvedDataDir) {
      bwrapArgs.push("--tmpfs", resolvedDataDir);
    }
    for (const m of postMounts) {
      bwrapArgs.push(m.mode === "ro" ? "--ro-bind" : "--bind", m.path, m.path);
    }
    for (const mf of maskFiles) {
      bwrapArgs.push("--bind", "/dev/null", mf);
    }
    if (resolvedCwd) {
      bwrapArgs.push("--chdir", resolvedCwd);
    }
    return { cmd: backend.bin, args: [...bwrapArgs, "--", cmd, ...args], isolated: true };
  }
  if (backend.kind === "unshare") {
    if (!backend.setprivBin || !backend.pivotRootBin) {
      throw new Error("unshare 回退缺少 setpriv 或 pivot_root，无法构建只读根挂载视图并永久剥离权限，已按安全策略拒绝执行");
    }
    const flatten = (list: MountEntry[]): string[] => list.flatMap((m) => [m.mode, m.path]);
    const unshareArgs = [
      "--user",
      "--map-root-user",
      "--mount",
      "--pid",
      "--fork",
      "--mount-proc",
      "--",
      "sh",
      "-c",
      UNSHARE_ISOLATION_SCRIPT,
      "_",
      backend.pivotRootBin,
      backend.setprivBin,
      resolvedDataDir,
      resolvedCwd,
      String(runtimeMaskDirs.length),
      String(preMounts.length),
      String(postMounts.length),
      String(maskFiles.length),
      ...runtimeMaskDirs,
      ...flatten(preMounts),
      ...flatten(postMounts),
      ...maskFiles,
      cmd,
      ...args,
    ];
    return { cmd: backend.bin, args: unshareArgs, isolated: true };
  }
  throw new Error(
    "检测到当前环境持有个人 Web 加密密钥或工作区存在个人 Web/私有上下文状态，" +
      "但宿主机不支持 bwrap 或带 pivot_root+setpriv 降权的 unshare PID+只读挂载命名空间隔离；" +
      "为防止同 UID 子进程读写 dataDir/state.db、读取密钥文件或通过 /proc/<daemon-pid> 检查常驻进程，已拒绝执行。请安装 bubblewrap 或将不可信 worker 运行在独立 OS 用户身份下。",
  );
}

/** 检测目录是否位于易失性内存文件系统（tmpfs），绝不把无关 systemd 凭据复制到磁盘介质的 /tmp */
function findVolatileTmpfsBase(env: NodeJS.ProcessEnv, overrideCandidates?: string[]): string | undefined {
  const candidates = (overrideCandidates ?? [env.XDG_RUNTIME_DIR?.trim(), "/dev/shm"]).filter((d): d is string => !!d);
  for (const dir of candidates) {
    try {
      const st = fs.statfsSync(dir);
      if (st.type === LINUX_TMPFS_MAGIC) {
        fs.accessSync(dir, fs.constants.W_OK | fs.constants.X_OK);
        return dir;
      }
    } catch {
      // 跳过不可访问或非 tmpfs 目录
    }
  }
  return undefined;
}

/**
 * 构造传给子模型或仓库校验进程的基础环境：
 *   - 始终剥离所有 `PA_FEISHU_WEB_*` 环境变量（凭据路径与静态加密密钥）；
 *   - 若 `CREDENTIALS_DIRECTORY` 不包含 `feishu-web-key`，原样保留（不破坏无关的 systemd 凭据）；
 *   - 若 `CREDENTIALS_DIRECTORY` 仅包含 `feishu-web-key`，直接移除 `CREDENTIALS_DIRECTORY`；
 *   - 若 `CREDENTIALS_DIRECTORY` 同时包含 `feishu-web-key` 与无关凭据：
 *     仅在检测到内核级内存 tmpfs（`$XDG_RUNTIME_DIR` 或 `/dev/shm`）时，将无关凭据以 0400 投影到 0700 易失目录并在结束及进程退出时清理；
 *     绝不将任何无关凭据落盘写入磁盘 `os.tmpdir()`（无可用 tmpfs 时按安全策略移除 `CREDENTIALS_DIRECTORY`）。
 */
const STRIPPED_HOST_SOCKET_ENVS = new Set([
  "DBUS_SESSION_BUS_ADDRESS",
  "NOTIFY_SOCKET",
  "GPG_AGENT_INFO",
]);

export function prepareHarnessEnv(
  env: NodeJS.ProcessEnv = process.env,
  opts?: { tmpfsCandidates?: string[]; preserveSshAgent?: boolean },
): { env: NodeJS.ProcessEnv; cleanup: () => void } {
  const clean: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(env)) {
    if (k.startsWith("PA_FEISHU_WEB_")) continue;
    if (STRIPPED_HOST_SOCKET_ENVS.has(k)) continue;
    if (!opts?.preserveSshAgent && (k === "SSH_AUTH_SOCK" || k === "SSH_AGENT_PID")) continue;
    clean[k] = v;
  }
  const credDir = env.CREDENTIALS_DIRECTORY?.trim();
  if (!credDir) return { env: clean, cleanup: () => undefined };

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(credDir, { withFileTypes: true });
  } catch {
    if (fs.existsSync(path.join(credDir, FEISHU_WEB_KEY_CRED))) {
      delete clean.CREDENTIALS_DIRECTORY;
    }
    return { env: clean, cleanup: () => undefined };
  }

  if (!entries.some((e) => e.name === FEISHU_WEB_KEY_CRED)) {
    return { env: clean, cleanup: () => undefined };
  }

  const others = entries.filter((e) => e.name !== FEISHU_WEB_KEY_CRED);
  if (others.length === 0) {
    delete clean.CREDENTIALS_DIRECTORY;
    return { env: clean, cleanup: () => undefined };
  }

  const volatileBase = findVolatileTmpfsBase(env, opts?.tmpfsCandidates);
  if (!volatileBase) {
    // 无内核级易失 tmpfs 时绝不向磁盘 TMPDIR 复制无关密钥，按 fail-closed 移除 CREDENTIALS_DIRECTORY
    delete clean.CREDENTIALS_DIRECTORY;
    return { env: clean, cleanup: () => undefined };
  }

  const filteredDir = fs.mkdtempSync(path.join(volatileBase, "pa-creds-"));
  fs.chmodSync(filteredDir, 0o700);
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    process.off("exit", cleanup);
    try {
      fs.rmSync(filteredDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  };
  process.once("exit", cleanup);
  try {
    for (const entry of others) {
      const src = path.join(credDir, entry.name);
      const dst = path.join(filteredDir, entry.name);
      try {
        const st = fs.statSync(src);
        if (st.isFile()) {
          fs.writeFileSync(dst, fs.readFileSync(src), { mode: 0o400 });
        }
      } catch {
        // 跳过不可读或特殊节点
      }
    }
  } catch (err) {
    cleanup();
    throw err;
  }
  clean.CREDENTIALS_DIRECTORY = filteredDir;
  return { env: clean, cleanup };
}

/**
 * 合并 harness.env：仅从过滤后的基础环境展开 `${VAR}`，且禁止通过覆写还原被过滤的 `PA_FEISHU_WEB_*` 或含 `feishu-web-key` 的 `CREDENTIALS_DIRECTORY`。
 */
export function mergeHarnessEnv(
  sanitizedBase: NodeJS.ProcessEnv,
  overrides: Record<string, string>,
  originalCredDir = process.env.CREDENTIALS_DIRECTORY?.trim(),
): NodeJS.ProcessEnv {
  const expanded: NodeJS.ProcessEnv = {};
  const credWasFiltered = !!originalCredDir && sanitizedBase.CREDENTIALS_DIRECTORY !== originalCredDir;
  for (const [k, rawVal] of Object.entries(overrides)) {
    if (k.startsWith("PA_FEISHU_WEB_")) continue;
    const val = rawVal.replace(/\$\{(\w+)\}/g, (_, n: string) => sanitizedBase[n] ?? "");
    if (k === "CREDENTIALS_DIRECTORY") {
      const candidate = val.trim();
      if (!candidate) continue;
      if (credWasFiltered) {
        if (path.resolve(candidate) === path.resolve(originalCredDir)) continue;
        try {
          if (fs.realpathSync(candidate) === fs.realpathSync(originalCredDir)) continue;
        } catch {
          // 路径不存在或不可解析时继续用后续检查兜底
        }
      }
      if (fs.existsSync(path.join(candidate, FEISHU_WEB_KEY_CRED))) continue;
    }
    expanded[k] = val;
  }
  return { ...sanitizedBase, ...expanded };
}

function formatTomlKeySegment(seg: string): string {
  return /^[A-Za-z0-9_-]+$/.test(seg) ? seg : JSON.stringify(seg);
}

function serializeTomlScalar(v: TomlValue): string {
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("不支持的非有限数值 TOML 配置");
    return String(v);
  }
  throw new Error("不支持的非标量 TOML 配置值");
}

function serializeTomlInlineValue(v: TomlValue): string {
  if (isPlainTable(v)) {
    const entries = Object.entries(v).map(([k, val]) => `${formatTomlKeySegment(k)}=${serializeTomlInlineValue(val)}`);
    return `{${entries.join(",")}}`;
  }
  if (Array.isArray(v)) {
    return `[${v.map((el) => serializeTomlInlineValue(el)).join(",")}]`;
  }
  return serializeTomlScalar(v);
}

// 对齐 Codex CLI 0.169+ 内置供应商、凭据存储与账号限制白名单（无需 [model_providers.*]；oss 不是 provider ID）
const BUILTIN_CODEX_PROVIDERS = new Set(["openai", "ollama", "lmstudio", "amazon-bedrock", "gcp"]);
const ALLOWED_CODEX_CREDENTIAL_STORES = new Set(["file", "keyring", "auto", "ephemeral"]);
const ALLOWED_CODEX_LOGIN_METHODS = new Set(["chatgpt", "api"]);
const SAFE_CODEX_TOP_SCALARS = new Set([
  "model",
  "model_provider",
  "model_reasoning_effort",
  "service_tier",
  "openai_base_url",
  "chatgpt_base_url",
  "oss_provider",
  "cli_auth_credentials_store",
  "forced_login_method",
  "forced_chatgpt_workspace_id",
]);
const SAFE_CODEX_EXTRA_SCALARS = [
  "model_reasoning_effort",
  "service_tier",
  "openai_base_url",
  "chatgpt_base_url",
  "oss_provider",
  "cli_auth_credentials_store",
  "forced_login_method",
  "forced_chatgpt_workspace_id",
] as const;
const SAFE_CODEX_PROVIDER_SCALARS = new Set([
  "name",
  "base_url",
  "env_key",
  "env_key_instructions",
  "wire_api",
  "requires_openai_auth",
  "request_max_retries",
  "stream_max_retries",
  "stream_idle_timeout_ms",
]);
const SECRET_QUERY_PARAM_RE = /(?:key|token|secret|auth|sig|pass|cred)/i;

function validateSafeCodexUrl(rawUrl: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`Codex ${label} 不是合法 URL；已中止 tools=none 执行`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error(`Codex ${label} 仅支持 http/https 协议；已中止 tools=none 执行`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(
      `Codex ${label} 包含内嵌账号/口令（userinfo）；为避免凭据暴露在命令行参数与运行日志中，tools=none 模式拒绝透传，请改用 env_key 或 env_http_headers`,
    );
  }
  for (const [k] of parsed.searchParams) {
    if (SECRET_QUERY_PARAM_RE.test(k)) {
      throw new Error(
        `Codex ${label} 的查询参数 "${k}" 疑似包含凭据；为避免密钥暴露在命令行参数与运行日志中，tools=none 模式拒绝透传，请改用 env_key 或 env_http_headers`,
      );
    }
  }
  if (parsed.hash && SECRET_QUERY_PARAM_RE.test(parsed.hash)) {
    throw new Error(`Codex ${label} 的 URL 片段疑似包含凭据；已中止 tools=none 执行`);
  }
  return rawUrl;
}

function validateSafeScalarValue(key: string, val: TomlValue): TomlValue {
  if (key === "openai_base_url" || key === "chatgpt_base_url") {
    if (typeof val !== "string" || !val.trim()) throw new Error(`Codex ${key} 必须为非空 URL 字符串`);
    return validateSafeCodexUrl(val.trim(), key);
  }
  if (key === "cli_auth_credentials_store") {
    if (typeof val !== "string" || !ALLOWED_CODEX_CREDENTIAL_STORES.has(val)) {
      throw new Error(`Codex cli_auth_credentials_store 仅支持 file / keyring / auto / ephemeral`);
    }
    return val;
  }
  if (key === "forced_login_method") {
    if (typeof val !== "string" || !ALLOWED_CODEX_LOGIN_METHODS.has(val)) {
      throw new Error(`Codex forced_login_method 仅支持 chatgpt / api；为避免破坏账号登录限制，已中止 tools=none 执行`);
    }
    return val;
  }
  if (key === "forced_chatgpt_workspace_id") {
    if (typeof val === "string") {
      if (!val.trim()) {
        throw new Error(`Codex forced_chatgpt_workspace_id 不能为空字符串；为避免绕过工作区限制，已中止 tools=none 执行`);
      }
      return val;
    }
    if (Array.isArray(val) && val.every((item) => typeof item === "string" && item.trim().length > 0)) {
      return val;
    }
    throw new Error(
      `Codex forced_chatgpt_workspace_id 必须为非空字符串或非空字符串列表；为避免破坏工作区限制，已中止 tools=none 执行`,
    );
  }
  if (Array.isArray(val) || isPlainTable(val)) {
    throw new Error(`Codex ${key} 必须为标量配置值`);
  }
  return val;
}

function parseCliConfigAssignment(expr: string): { key: string; value: string } | undefined {
  const eq = expr.indexOf("=");
  if (eq <= 0) return undefined;
  return { key: expr.slice(0, eq).trim(), value: expr.slice(eq + 1).trim() };
}

function parseCliTomlOrLiteral(keyLabel: string, raw: string): TomlValue {
  try {
    return parseTomlValue(raw);
  } catch {
    if (/^[A-Za-z0-9._:/+-]+$/.test(raw)) return raw;
    // 绝不回显原始配置值，防止未加引号的密钥泄漏到日志或错误信息
    throw new Error(`无法解析 Codex -c 键 "${keyLabel}" 的配置值（请检查 TOML 语法或引号）`);
  }
}

function redactCodexLogArgs(args: string[]): string[] {
  return args.map((a) => {
    if (/^(?:--config=)?model_providers\.[^=]+\.(?:http_headers|experimental_bearer_token|query_params)(?:\.[^=]+)?=/.test(a)) {
      return a.replace(/=.*$/, "=<redacted>");
    }
    if (/^(?:--config=)?(?:openai_base_url|chatgpt_base_url|model_providers\.[^=]+\.base_url)=/.test(a) && /[@?]/.test(a)) {
      return a.replace(/=.*$/, "=<redacted-url>");
    }
    return a;
  });
}

export interface SafeCodexProviderConfig {
  /** 从用户 config.toml 提取的安全 `-c` 参数（不含任何静态凭据明文；含点号供应商名以 TOML 内联表编码避免 `-c` 按点切分） */
  args: string[];
  /** 仅通过子进程环境变量传递的静态请求头（由 `env_http_headers` 引用，永不出现在 argv 或运行日志中） */
  extraEnv: Record<string, string>;
  /** 经过白名单校验与凭据环境变量化后的 `extraArgs` */
  sanitizedExtraArgs: string[];
  /** 生效的 cli_auth_credentials_store（优先取 extraArgs 覆盖值，其次取 config.toml） */
  credentialStore?: string;
}

/** 轻量读取某组 env + extraArgs 下 Codex 生效的 cli_auth_credentials_store（供隔离沙箱预检与 doctor 共用） */
export function resolveEffectiveCodexCredentialStore(
  env: NodeJS.ProcessEnv,
  extraArgs: string[],
): { store?: string; codexHome: string; hasConfig: boolean } {
  const effectiveHome = env.HOME?.trim() || os.homedir();
  const codexHome = env.CODEX_HOME?.trim() || path.join(effectiveHome, ".codex");
  const configPath = path.join(codexHome, "config.toml");

  let extraStore: string | undefined;
  const scanExpr = (expr: string) => {
    const parsed = parseCliConfigAssignment(expr);
    if (!parsed || parsed.key !== "cli_auth_credentials_store") return;
    try {
      const val = parseCliTomlOrLiteral(parsed.key, parsed.value);
      if (typeof val === "string") extraStore = val.trim();
    } catch {
      // 由严格提取阶段统一报错
    }
  };
  for (let i = 0; i < extraArgs.length; i++) {
    const a = extraArgs[i];
    if ((a === "-c" || a === "--config") && extraArgs[i + 1]) {
      scanExpr(extraArgs[++i]);
    } else if (a.startsWith("--config=")) {
      scanExpr(a.slice("--config=".length));
    }
  }

  const hasConfig = fs.existsSync(configPath);
  if (extraStore) return { store: extraStore, codexHome, hasConfig };
  if (!hasConfig) return { store: undefined, codexHome, hasConfig: false };
  try {
    const doc = parseToml(fs.readFileSync(configPath, "utf8"));
    const v = doc.cli_auth_credentials_store;
    return { store: typeof v === "string" ? v.trim() : undefined, codexHome, hasConfig: true };
  } catch {
    return { store: undefined, codexHome, hasConfig: true };
  }
}

export interface CodexKeyringConflict {
  severity: "error" | "warn";
  message: string;
  fix: string;
}

/**
 * 检测 Linux 隔离沙箱与 Codex `cli_auth_credentials_store = "keyring"`（或缺少文件凭据的 `"auto"`）的冲突：
 * 隔离沙箱会屏蔽宿主机 D-Bus 会话总线与 XDG_RUNTIME_DIR，导致容器内无法访问 Secret Service keyring。
 */
export function detectIsolatedCodexKeyringConflict(
  cfg: Pick<Config, "dataDir" | "context" | "harnesses">,
  rawEnv: NodeJS.ProcessEnv = process.env,
  harnessName?: string,
  opts?: { home?: string; includeContextObs?: boolean },
): CodexKeyringConflict | undefined {
  if (process.platform !== "linux") return undefined;
  if (!harnessName) return undefined;
  const h = cfg.harnesses[harnessName];
  if (!h || h.type !== "codex-exec") return undefined;
  const isoActive = workspaceRequiresIsolation(cfg, rawEnv, { includeContextObs: opts?.includeContextObs ?? false });
  if (!isoActive) return undefined;

  const baseEnv: NodeJS.ProcessEnv = opts?.home ? { ...rawEnv, HOME: opts.home } : { ...rawEnv };
  const merged = mergeHarnessEnv(baseEnv, h.env);
  const { store, codexHome } = resolveEffectiveCodexCredentialStore(merged, h.extraArgs);
  const fix =
    '在 ~/.codex/config.toml 中设置 `cli_auth_credentials_store = "file"` 并重新运行 `codex login`，或在常驻进程环境中通过 `OPENAI_API_KEY` / 自定义供应商 `env_key` 提供 API 密钥';
  if (store === "keyring") {
    return {
      severity: "error",
      message: `执行者 ${harnessName} 配置了 cli_auth_credentials_store="keyring"，但当前 Linux 隔离沙箱已屏蔽宿主机 D-Bus 会话总线与 XDG_RUNTIME_DIR，无法访问 Secret Service；请改用文件凭据或 API 密钥`,
      fix,
    };
  }
  if (store === "auto" && !fs.existsSync(path.join(codexHome, "auth.json")) && !merged.OPENAI_API_KEY?.trim()) {
    return {
      severity: "warn",
      message: `执行者 ${harnessName} 使用 cli_auth_credentials_store="auto" 且 ${codexHome}/auth.json 与 OPENAI_API_KEY 均不存在；Linux 隔离沙箱内无法访问宿主机 keyring，若 Codex 登录态仅存于 keyring 将导致鉴权失败`,
      fix,
    };
  }
  return undefined;
}

/**
 * 为 `codex-exec` 的 `tools: "none"` 模式构造工具隔离参数：
 *   1. 按子进程实际 `CODEX_HOME` / `HOME` 定位 `config.toml`，并用严格 TOML 1.0 解析器解析（拒绝重复键与多行字符串误判）；
 *   2. 保留 `cli_auth_credentials_store`、`model`、`model_provider`、`model_reasoning_effort`、`service_tier`、安全 base_url 等配置；
 *   3. 严格校验 `extraArgs`，拒绝 `--profile`、`--enable`、`-c mcp_servers.*` / `plugins.*` / `hooks.*` / `sandbox_permissions` 及含凭据 URL；
 *   4. 静态 `http_headers`（无论点分表还是内联表 `{ ... }`）与 `experimental_bearer_token` 一律转为子进程环境变量 + `env_http_headers`；
 *   5. 通过 `-c model_providers={<provider>={...}}` 内联表形式下发供应商配置，兼容带点号的供应商名（如 `corp.test`）。
 */
export function extractSafeCodexProviderConfig(
  env: NodeJS.ProcessEnv,
  extraArgs: string[],
  hasExplicitModel: boolean,
): SafeCodexProviderConfig {
  const effectiveHome = env.HOME?.trim() || os.homedir();
  const codexHome = env.CODEX_HOME?.trim() || path.join(effectiveHome, ".codex");
  const configPath = path.join(codexHome, "config.toml");

  const extraEnv: Record<string, string> = {};
  let secretHdrIdx = 0;
  const allocEnvHeaderVar = (headerValue: string): string => {
    const varName = `__PA_CODEX_HDR_${secretHdrIdx++}`;
    extraEnv[varName] = headerValue;
    return varName;
  };

  const sanitizeProviderTable = (providerName: string, obj: TomlTable): TomlTable => {
    const sanitized: TomlTable = Object.create(null) as TomlTable;
    const envHeaders: TomlTable = Object.create(null) as TomlTable;
    const explicitEnvLower = new Set<string>();

    const rawEnvHeaders = obj.env_http_headers;
    if (rawEnvHeaders !== undefined) {
      if (!isPlainTable(rawEnvHeaders)) {
        throw new Error(`Codex [model_providers.${providerName}.env_http_headers] 格式非法，已中止 tools=none 执行`);
      }
      for (const [hk, hv] of Object.entries(rawEnvHeaders)) {
        if (typeof hv !== "string") {
          throw new Error(`Codex env_http_headers.${hk} 必须为环境变量名字符串`);
        }
        explicitEnvLower.add(hk.toLowerCase());
        envHeaders[hk] = hv;
      }
    }

    const rawHttpHeaders = obj.http_headers;
    if (rawHttpHeaders !== undefined) {
      if (!isPlainTable(rawHttpHeaders)) {
        throw new Error(`Codex [model_providers.${providerName}.http_headers] 格式非法，已中止 tools=none 执行`);
      }
      for (const [hk, hv] of Object.entries(rawHttpHeaders)) {
        if (typeof hv !== "string") {
          throw new Error(`Codex http_headers.${hk} 必须为字符串`);
        }
        if (!explicitEnvLower.has(hk.toLowerCase())) {
          envHeaders[hk] = allocEnvHeaderVar(hv);
        }
      }
    }

    const rawBearer = obj.experimental_bearer_token;
    if (rawBearer !== undefined) {
      if (typeof rawBearer !== "string" || !rawBearer) {
        throw new Error(`Codex [model_providers.${providerName}].experimental_bearer_token 格式非法`);
      }
      const hasAuthHdr =
        explicitEnvLower.has("authorization") ||
        (isPlainTable(rawHttpHeaders) && Object.keys(rawHttpHeaders).some((k) => k.toLowerCase() === "authorization"));
      if (!hasAuthHdr) {
        envHeaders.Authorization = allocEnvHeaderVar(`Bearer ${rawBearer}`);
      }
    }

    if (Object.keys(envHeaders).length > 0) {
      sanitized.env_http_headers = envHeaders;
    }

    const rawQuery = obj.query_params;
    if (rawQuery !== undefined) {
      if (!isPlainTable(rawQuery)) {
        throw new Error(`Codex [model_providers.${providerName}.query_params] 格式非法`);
      }
      const qMap: TomlTable = Object.create(null) as TomlTable;
      for (const [qk, qv] of Object.entries(rawQuery)) {
        if (typeof qv !== "string") throw new Error(`Codex query_params.${qk} 必须为字符串`);
        if (SECRET_QUERY_PARAM_RE.test(qk)) {
          throw new Error(
            `Codex [model_providers.${providerName}.query_params] 包含疑似密钥参数 "${qk}"；为避免密钥暴露在命令行参数中，tools=none 模式拒绝透传，请改用 env_key 或 env_http_headers`,
          );
        }
        qMap[qk] = qv;
      }
      if (Object.keys(qMap).length > 0) {
        sanitized.query_params = qMap;
      }
    }

    const rawAws = obj.aws;
    if (rawAws !== undefined) {
      if (!isPlainTable(rawAws)) {
        throw new Error(`Codex [model_providers.${providerName}.aws] 格式非法`);
      }
      const awsMap: TomlTable = Object.create(null) as TomlTable;
      for (const [ak, av] of Object.entries(rawAws)) {
        if (ak !== "profile" && ak !== "region") {
          throw new Error(
            `Codex [model_providers.${providerName}.aws] 包含不受支持的字段 "${ak}"；为防止改变认证方式或引入非白名单凭据设置，tools=none 模式仅保留 aws.profile 与 aws.region`,
          );
        }
        if (typeof av !== "string" || !av.trim()) {
          throw new Error(`Codex [model_providers.${providerName}.aws].${ak} 必须为非空字符串`);
        }
        awsMap[ak] = av;
      }
      if (Object.keys(awsMap).length > 0) {
        sanitized.aws = awsMap;
      }
    }

    for (const [k, v] of Object.entries(obj)) {
      if (k === "http_headers" || k === "env_http_headers" || k === "query_params" || k === "experimental_bearer_token" || k === "aws") continue;
      if (!SAFE_CODEX_PROVIDER_SCALARS.has(k)) {
        if (k === "gcp" || k === "auth" || k === "credentials" || k.includes("token") || k.includes("secret") || k.includes("key")) {
          throw new Error(
            `Codex [model_providers.${providerName}] 包含不受支持的认证/路由字段 "${k}"；为避免静默切换目标账号或认证方式，已中止 tools=none 执行`,
          );
        }
        continue;
      }
      if (k === "base_url") {
        if (typeof v !== "string" || !v.trim()) throw new Error(`Codex [model_providers.${providerName}].base_url 必须为非空 URL 字符串`);
        sanitized.base_url = validateSafeCodexUrl(v.trim(), `model_providers.${providerName}.base_url`);
      } else {
        sanitized[k] = v;
      }
    }
    return sanitized;
  };

  // 1) 严格校验并净化 extraArgs：tools="none" 仅允许模型/供应商/特性禁用参数
  let extraHasModelProvider = false;
  let extraProvider: string | undefined;
  let extraCredentialStore: string | undefined;
  let configCredentialStore: string | undefined;
  const extraProviderTables = new Map<string, TomlTable>();
  let extraHasModel = hasExplicitModel;
  const sanitizedExtraArgs: string[] = [];

  const ensureExtraProvider = (pName: string): TomlTable => {
    let t = extraProviderTables.get(pName);
    if (!t) {
      t = Object.create(null) as TomlTable;
      extraProviderTables.set(pName, t);
    }
    return t;
  };

  const mergeProviderSubtable = (target: TomlTable, subKey: string, entries: TomlTable) => {
    const existing = target[subKey];
    const sub: TomlTable = isPlainTable(existing) ? existing : (Object.create(null) as TomlTable);
    for (const [k, v] of Object.entries(entries)) sub[k] = v;
    target[subKey] = sub;
  };

  const handleExtraConfigExpr = (expr: string) => {
    const parsed = parseCliConfigAssignment(expr);
    if (!parsed) {
      throw new Error('codex-exec tools="none" 模式拒绝无法解析的 -c 参数（缺少 key=value）');
    }
    const segs = parseTomlKeyPath(parsed.key);
    const val = parseCliTomlOrLiteral(parsed.key, parsed.value);
    if (segs.length === 1 && SAFE_CODEX_TOP_SCALARS.has(segs[0])) {
      const checkedVal = validateSafeScalarValue(segs[0], val);
      if (segs[0] === "model") {
        extraHasModel = true;
      } else if (segs[0] === "model_provider") {
        if (typeof checkedVal !== "string" || !checkedVal) {
          throw new Error("codex-exec extraArgs 中的 model_provider 必须为非空字符串");
        }
        extraHasModelProvider = true;
        extraProvider = checkedVal;
      } else if (segs[0] === "cli_auth_credentials_store" && typeof checkedVal === "string") {
        extraCredentialStore = checkedVal;
      }
      sanitizedExtraArgs.push("-c", `${formatTomlKeySegment(segs[0])}=${serializeTomlInlineValue(checkedVal)}`);
      return;
    }
    if (segs.length === 1 && segs[0] === "model_providers") {
      if (!isPlainTable(val)) throw new Error("extraArgs 中的 model_providers 必须为 TOML 内联表");
      for (const [pName, pDef] of Object.entries(val)) {
        if (!isPlainTable(pDef)) throw new Error(`extraArgs model_providers.${pName} 必须为表`);
        const sanitizedP = sanitizeProviderTable(pName, pDef);
        const dst = ensureExtraProvider(pName);
        for (const [fk, fv] of Object.entries(sanitizedP)) {
          if (isPlainTable(fv)) mergeProviderSubtable(dst, fk, fv);
          else dst[fk] = fv;
        }
      }
      return;
    }
    if (segs[0] === "model_providers" && segs.length >= 3) {
      const pName = segs[1];
      const field = segs[2];
      const dst = ensureExtraProvider(pName);
      if (segs.length === 3 && SAFE_CODEX_PROVIDER_SCALARS.has(field)) {
        if (field === "base_url") {
          if (typeof val !== "string" || !val.trim()) throw new Error(`extraArgs model_providers.${pName}.base_url 必须为非空 URL`);
          dst.base_url = validateSafeCodexUrl(val.trim(), `extraArgs model_providers.${pName}.base_url`);
        } else {
          dst[field] = val;
        }
        return;
      }
      if (segs.length === 3 && field === "experimental_bearer_token") {
        if (typeof val !== "string" || !val) throw new Error("experimental_bearer_token 必须为非空字符串");
        mergeProviderSubtable(dst, "env_http_headers", { Authorization: allocEnvHeaderVar(`Bearer ${val}`) });
        return;
      }
      if (field === "http_headers") {
        if (segs.length === 3 && isPlainTable(val)) {
          const mapped: TomlTable = Object.create(null) as TomlTable;
          for (const [hk, hv] of Object.entries(val)) {
            if (typeof hv !== "string") throw new Error(`extraArgs http_headers.${hk} 必须为字符串`);
            mapped[hk] = allocEnvHeaderVar(hv);
          }
          mergeProviderSubtable(dst, "env_http_headers", mapped);
          return;
        }
        if (segs.length === 4 && typeof val === "string") {
          mergeProviderSubtable(dst, "env_http_headers", { [segs[3]]: allocEnvHeaderVar(val) });
          return;
        }
        throw new Error(`extraArgs 中的 model_providers.${pName}.http_headers 格式非法`);
      }
      if (field === "env_http_headers") {
        if (segs.length === 3 && isPlainTable(val)) {
          for (const [hk, hv] of Object.entries(val)) {
            if (typeof hv !== "string") throw new Error(`extraArgs env_http_headers.${hk} 必须为字符串`);
          }
          mergeProviderSubtable(dst, "env_http_headers", val);
          return;
        }
        if (segs.length === 4 && typeof val === "string") {
          mergeProviderSubtable(dst, "env_http_headers", { [segs[3]]: val });
          return;
        }
        throw new Error(`extraArgs 中的 model_providers.${pName}.env_http_headers 格式非法`);
      }
      if (field === "aws") {
        if (segs.length === 3 && isPlainTable(val)) {
          const awsMap: TomlTable = Object.create(null) as TomlTable;
          for (const [ak, av] of Object.entries(val)) {
            if (ak !== "profile" && ak !== "region") {
              throw new Error(`extraArgs model_providers.${pName}.aws 不支持字段 "${ak}"，仅允许 profile 与 region`);
            }
            if (typeof av !== "string" || !av.trim()) {
              throw new Error(`extraArgs model_providers.${pName}.aws.${ak} 必须为非空字符串`);
            }
            awsMap[ak] = av;
          }
          mergeProviderSubtable(dst, "aws", awsMap);
          return;
        }
        if (segs.length === 4 && (segs[3] === "profile" || segs[3] === "region") && typeof val === "string" && val.trim()) {
          mergeProviderSubtable(dst, "aws", { [segs[3]]: val });
          return;
        }
        throw new Error(`extraArgs 中的 model_providers.${pName}.aws 格式或字段不受支持（仅允许 profile 与 region）`);
      }
      if (field === "query_params") {
        if (segs.length === 3 && isPlainTable(val)) {
          for (const [qk, qv] of Object.entries(val)) {
            if (typeof qv !== "string") throw new Error(`extraArgs query_params.${qk} 必须为字符串`);
            if (SECRET_QUERY_PARAM_RE.test(qk)) {
              throw new Error(`extraArgs query_params 包含疑似密钥参数 "${qk}"，tools=none 模式拒绝透传`);
            }
          }
          mergeProviderSubtable(dst, "query_params", val);
          return;
        }
        if (segs.length === 4 && typeof val === "string") {
          if (SECRET_QUERY_PARAM_RE.test(segs[3])) {
            throw new Error(`extraArgs query_params 包含疑似密钥参数 "${segs[3]}"，tools=none 模式拒绝透传`);
          }
          mergeProviderSubtable(dst, "query_params", { [segs[3]]: val });
          return;
        }
        throw new Error(`extraArgs 中的 model_providers.${pName}.query_params 格式非法`);
      }
    }
    throw new Error(
      `codex-exec tools="none" 模式禁止在 extraArgs 中通过 -c 注入非模型/供应商配置（${parsed.key}）；请改用独立无工具 harness 配置`,
    );
  };

  for (let i = 0; i < extraArgs.length; i++) {
    const a = extraArgs[i];
    if (a === "-m" || a === "--model") {
      const next = extraArgs[++i];
      if (!next) throw new Error(`codex-exec extraArgs 中的 ${a} 缺少值`);
      extraHasModel = true;
      sanitizedExtraArgs.push(a, next);
      continue;
    }
    if (a.startsWith("--model=")) {
      extraHasModel = true;
      sanitizedExtraArgs.push(a);
      continue;
    }
    if (a === "--disable") {
      const next = extraArgs[++i];
      if (!next) throw new Error("codex-exec extraArgs 中的 --disable 缺少值");
      sanitizedExtraArgs.push("--disable", next);
      continue;
    }
    if (a.startsWith("--disable=")) {
      sanitizedExtraArgs.push(a);
      continue;
    }
    if (a === "-c" || a === "--config") {
      const next = extraArgs[++i];
      if (!next) throw new Error(`codex-exec extraArgs 中的 ${a} 缺少配置表达式`);
      handleExtraConfigExpr(next);
      continue;
    }
    if (a.startsWith("--config=")) {
      handleExtraConfigExpr(a.slice("--config=".length));
      continue;
    }
    if (a === "-p" || a === "--profile" || a.startsWith("--profile=")) {
      const prof = a.startsWith("--profile=") ? a.slice("--profile=".length) : extraArgs[i + 1] ?? "";
      throw new Error(
        `codex-exec tools="none" 模式已禁用用户配置文件以避免加载 MCP/工具，暂不支持通过 --profile ${prof} 叠加外部配置；请在 config.yaml 的 harnesses.<name> 中直接配置 model 与 -c model_provider=...`,
      );
    }
    throw new Error(
      `codex-exec tools="none" 模式拒绝不支持或不安全的 extraArgs 选项 "${a}"；此模式仅允许模型、供应商及 --disable 参数`,
    );
  }

  // 2) 解析子进程主目录对应的 $CODEX_HOME/config.toml
  const out: string[] = [];
  const mergedProviders: TomlTable = Object.create(null) as TomlTable;

  if (fs.existsSync(configPath)) {
    const rawContent = fs.readFileSync(configPath, "utf8");
    let doc: TomlTable;
    try {
      doc = parseToml(rawContent);
    } catch (err) {
      throw new Error(
        `无法安全解析 Codex 配置文件 (${configPath})：${err instanceof Error ? err.message : "TOML 语法错误"}；为避免将私聊发往默认供应商，已中止 tools=none 执行`,
      );
    }

    const profileRaw = doc.profile;
    if (profileRaw !== undefined) {
      const legacyName = typeof profileRaw === "string" && profileRaw.trim() ? profileRaw.trim() : "<name>";
      throw new Error(
        `Codex 0.169 已废弃 config.toml 中的顶层 profile = "${legacyName}"（请改用 --profile ${legacyName} 与 ${legacyName}.config.toml，或在 config.yaml 中直接配置 model / model_provider）；为避免激活失效配置，已中止 tools=none 执行`,
      );
    }

    const effectiveVal = (key: string): TomlValue | undefined => doc[key];

    const selectedProviderVal = effectiveVal("model_provider");
    if (selectedProviderVal !== undefined && (typeof selectedProviderVal !== "string" || !selectedProviderVal.trim())) {
      throw new Error("Codex config.toml 中的 model_provider 配置非法；为避免将私聊发往默认供应商，已中止执行");
    }
    const selectedProvider = typeof selectedProviderVal === "string" ? selectedProviderVal.trim() : undefined;
    const effectiveProvider = extraProvider ?? selectedProvider ?? "openai";

    const modelVal = effectiveVal("model");
    if (!extraHasModel && modelVal !== undefined) {
      if (typeof modelVal !== "string") throw new Error("Codex config.toml 中的 model 必须为字符串");
      out.push("-c", `model=${JSON.stringify(modelVal)}`);
    }
    for (const scalarKey of SAFE_CODEX_EXTRA_SCALARS) {
      const v = effectiveVal(scalarKey);
      if (v !== undefined) {
        const checked = validateSafeScalarValue(scalarKey, v);
        if (scalarKey === "cli_auth_credentials_store" && typeof checked === "string") {
          configCredentialStore = checked;
        }
        out.push("-c", `${scalarKey}=${serializeTomlInlineValue(checked)}`);
      }
    }

    if (selectedProvider && !extraHasModelProvider) {
      out.push("-c", `model_provider=${JSON.stringify(selectedProvider)}`);
    }

    const providersRoot = doc.model_providers;
    if (providersRoot !== undefined && !isPlainTable(providersRoot)) {
      throw new Error("Codex config.toml 中的 model_providers 必须为表；已中止 tools=none 执行");
    }
    const providerObj = isPlainTable(providersRoot) ? providersRoot[effectiveProvider] : undefined;
    if (providerObj !== undefined && !isPlainTable(providerObj)) {
      throw new Error(`Codex config.toml 中的 [model_providers.${effectiveProvider}] 格式非法；已中止执行`);
    }
    if (!providerObj && !BUILTIN_CODEX_PROVIDERS.has(effectiveProvider) && !extraProviderTables.has(effectiveProvider)) {
      throw new Error(
        `Codex config.toml 指定了自定义供应商 "${effectiveProvider}"，但未能解析对应的 [model_providers.${effectiveProvider}] 配置；为避免私聊误发往默认供应商，已中止执行`,
      );
    }
    if (providerObj) {
      mergedProviders[effectiveProvider] = sanitizeProviderTable(effectiveProvider, providerObj);
    }
  }

  // 将 extraArgs 中覆盖的 model_providers 合并进同一个 TOML 内联表（extraArgs 优先），
  // 通过 `-c model_providers={...}` 传给 Codex，彻底兼容带点号的供应商名（如 corp.test）
  for (const [pName, pOverride] of extraProviderTables) {
    const existing = mergedProviders[pName];
    if (isPlainTable(existing)) {
      const combined: TomlTable = Object.create(null) as TomlTable;
      for (const [k, v] of Object.entries(existing)) combined[k] = v;
      for (const [k, v] of Object.entries(pOverride)) {
        if (isPlainTable(v)) mergeProviderSubtable(combined, k, v);
        else combined[k] = v;
      }
      mergedProviders[pName] = combined;
    } else {
      mergedProviders[pName] = pOverride;
    }
  }

  if (Object.keys(mergedProviders).length > 0) {
    out.push("-c", `model_providers=${serializeTomlInlineValue(mergedProviders)}`);
  }

  const credentialStore = extraCredentialStore ?? configCredentialStore;
  return { args: out, extraEnv, sanitizedExtraArgs, ...(credentialStore ? { credentialStore } : {}) };
}

/** 兼容辅助：仅返回提取后的 `-c` 参数（用于既有单元测试） */
export function extractSafeCodexProviderArgs(
  env: NodeJS.ProcessEnv,
  extraArgs: string[],
  hasExplicitModel: boolean,
): string[] {
  return extractSafeCodexProviderConfig(env, extraArgs, hasExplicitModel).args;
}

export interface HarnessRun {
  harness: string;
  prompt: string;
  cwd: string;
  /**
   * 工具权限（交给 acpx）：
   *   none  —— 拒绝所有工具调用，只要文本输出（分诊）
   *   read  —— 只自动批准读/搜索
   *   write —— 全部批准（worker 在自己的 worktree 里改代码、跑命令）
   */
  tools: "none" | "read" | "write";
  /** agent 调 lark-cli 时的守卫策略，见 guard.ts */
  lark: Profile;
  timeoutSec: number;
  logFile: string;
  /** 中止（取消 / 优雅退出）：结束整个 harness 进程组 */
  signal?: AbortSignal;
  /** harness 进程组启动后回调 pgid，调用方持久化它，崩溃恢复时据此清理遗留进程 */
  onSpawn?: (pgid: number) => void;
  /** 对应的步骤 id（用量记录用） */
  stepId?: number;
  /** 受信任的派单仓库根目录（用于校核 worktree .git / commondir 归属，防 worker 篡改元数据） */
  trustedRepoRoot?: string;
  /** 非 Git 派单的空工作区：禁止探测或挂载外部 worktree .git 目录 */
  disableGitWorktreeMounts?: boolean;
}

/**
 * 用量记录器：每次 harness 结束后调用（由用量模块设置），从输出里解析 token 数并写入步骤。
 * 解析失败不影响主流程。
 */
export type UsageRecorder = (run: HarnessRun, out: { stdout: string; stderr: string; code: number }) => void;
let usageRecorder: UsageRecorder | undefined;
export function setUsageRecorder(fn: UsageRecorder | undefined): void {
  usageRecorder = fn;
}

export interface HarnessResult {
  ok: boolean;
  exitCode: number;
  text: string;
  timedOut: boolean;
  aborted: boolean;
}

/** 通过 acpx（ACP）以无头方式调用任一 harness 跑一次性任务，返回最终回复文本。 */
export async function runHarness(cfg: Config, run: HarnessRun): Promise<HarnessResult> {
  const h = cfg.harnesses[run.harness];
  if (!h) throw new Error(`未定义的 harness：${run.harness}`);
  if (h.type === "codex-exec") return runCodexExec(cfg, run, h);
  if (h.type === "doubao-cli") return runDoubaoCli(cfg, run, h);
  const args = ["--cwd", run.cwd, "--format", "quiet", "--timeout", String(run.timeoutSec)];
  args.push(run.tools === "write" ? "--approve-all" : run.tools === "read" ? "--approve-reads" : "--deny-all");
  args.push("--non-interactive-permissions", "deny");
  if (run.tools === "none") args.push("--no-terminal");
  if (h.model) args.push("--model", h.model);
  args.push(...h.extraArgs);
  if (h.agentCommand) args.push("--agent", h.agentCommand, "exec", "--file", "-");
  else args.push(h.agent!, "exec", "--file", "-");

  fs.mkdirSync(run.cwd, { recursive: true });
  // 先解析可执行路径再准备临时凭据环境，确保 resolveBin 异常不会泄漏易失目录
  const realLark = resolveBin(cfg.bins.lark);
  const baseEnv = prepareHarnessEnv();
  const started = new Date().toISOString();
  let r: Awaited<ReturnType<typeof runProcess>>;
  try {
    const mode: WorkspaceIsolationMode =
      run.tools === "write" ? "worker-write" : run.tools === "read" ? "worker-ro" : "llm-none";
    const wrapped = wrapCredentialIsolatedCommand(
      cfg.bins.acpx,
      args,
      process.env,
      buildWorkspaceIsolation(cfg, {
        mode,
        cwd: run.cwd,
        cmdPath: cfg.bins.acpx,
        trustedRepoRoot: run.trustedRepoRoot,
        disableGitWorktreeMounts: run.disableGitWorktreeMounts,
        allowGuardLog: run.lark !== "none",
        extraReadOnlyPaths: baseEnv.env.CREDENTIALS_DIRECTORY ? [baseEnv.env.CREDENTIALS_DIRECTORY] : [],
      }),
    );
    const env: NodeJS.ProcessEnv = {
      ...mergeHarnessEnv(baseEnv.env, h.env),
      PATH: `${path.join(ROOT, "bin", "guard")}${path.delimiter}${process.env.PATH ?? ""}`,
      PA_GUARD_PROFILE: run.lark,
      PA_OWNER_OPEN_ID: cfg.owner.open_id,
      PA_LARK_REAL: realLark,
      PA_GUARD_LOG: path.join(cfg.dataDir, "logs", "guard.log"),
      ...(wrapped.isolated
        ? {
            TMPDIR: "/tmp",
            XDG_CACHE_HOME: "/tmp/.pa-cache",
            XDG_STATE_HOME: "/tmp/.pa-state",
            XDG_RUNTIME_DIR: "/tmp/.pa-run",
          }
        : {}),
    };
    r = await runProcess(wrapped.cmd, wrapped.args, {
      cwd: run.cwd,
      env,
      input: run.prompt,
      // acpx 自己有 --timeout；这里多留 2 分钟兜底，防止进程卡死
      timeoutMs: (run.timeoutSec + 120) * 1000,
      group: true,
      signal: run.signal,
      onSpawn: run.onSpawn,
    });
  } finally {
    baseEnv.cleanup();
  }
  fs.writeFileSync(
    run.logFile,
    [
      `# ${started} harness=${run.harness} tools=${run.tools} lark=${run.lark} cwd=${run.cwd}`,
      `# acpx ${args.join(" ")}`,
      `# exit=${r.code} timedOut=${r.timedOut} aborted=${!!run.signal?.aborted}`,
      "## prompt",
      run.prompt,
      "## stdout",
      r.stdout,
      "## stderr",
      r.stderr,
    ].join("\n"),
  );
  try {
    usageRecorder?.(run, { stdout: r.stdout, stderr: r.stderr, code: r.code });
  } catch {
    // 用量解析失败不影响主流程
  }
  const aborted = !!run.signal?.aborted;
  return { ok: r.code === 0 && !r.timedOut && !aborted, exitCode: r.code, text: r.stdout.trim(), timedOut: r.timedOut, aborted };
}

/** 守卫需要真实 lark-cli 的绝对路径，否则会递归调用自己。 */
export function resolveBin(bin: string): string {
  if (path.isAbsolute(bin)) return bin;
  const guardDir = path.join(ROOT, "bin", "guard");
  for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
    if (!dir || path.resolve(dir) === guardDir) continue;
    const p = path.join(dir, bin);
    try {
      fs.accessSync(p, fs.constants.X_OK);
      return p;
    } catch {
      // 继续找
    }
  }
  throw new Error(`在 PATH 中找不到 ${bin}`);
}

export function loadPrompt(name: string): string {
  const p = path.isAbsolute(name) ? name : path.join(ROOT, name.includes("/") ? name : `prompts/${name}`);
  return fs.readFileSync(p, "utf8");
}

/**
 * codex-exec：直接调用本机已登录的 codex CLI（只读沙箱、不保存会话），提示词从标准输入传入，
 * 最终回复写到临时文件读回。只用于不需要写权限的任务（理解、起草、审查）；派单执行需要 acpx。
 */
async function runCodexExec(cfg: Config, run: HarnessRun, h: Config["harnesses"][string]): Promise<HarnessResult> {
  if (run.tools === "write") throw new Error(`harness ${run.harness} 是 codex-exec（只读），不能执行需要写权限的任务；请改用 acpx 类型的 harness`);
  const cmd = h.cmd || "codex";
  // tools === "none"（处理不可信聊天文本的理解/起草）：在 dataDir 之外的空临时目录运行并彻底关闭 shell/执行工具与磁盘全读权限，
  // 避免模型经文件系统越界读取 dataDir 下的会话凭据或状态库。
  const isolatedTmp = run.tools === "none" ? fs.mkdtempSync(path.join(os.tmpdir(), "pa-codex-none-")) : undefined;
  // tools === "read"（仓库审查）：把最终回复临时文件放进独立 scratch 目录，避免给只读审查进程开放仓库目录写权限。
  const readOutDir = run.tools === "read" ? safeRealpath(fs.mkdtempSync(path.join(os.tmpdir(), "pa-codex-out-"))) : undefined;
  const execCwd = isolatedTmp ?? run.cwd;
  if (!isolatedTmp) fs.mkdirSync(execCwd, { recursive: true });
  const outFile = readOutDir
    ? path.join(readOutDir, "last.txt")
    : path.join(execCwd, `.codex-last-${process.pid}-${Date.now()}.txt`);
  const outArg = readOutDir ? outFile : path.basename(outFile);
  const baseEnv = prepareHarnessEnv();
  const started = new Date().toISOString();
  let r: Awaited<ReturnType<typeof runProcess>>;
  let text = "";
  let args: string[] = [];
  try {
    let finalEnv = mergeHarnessEnv(baseEnv.env, h.env);
    args = ["exec", "--skip-git-repo-check", "--sandbox", "read-only", "--ephemeral", "--color", "never", "-o", outArg];
    let extraToPass = h.extraArgs;
    let effectiveCredStore: string | undefined;
    if (run.tools === "none") {
      // 彻底隔离用户配置（包括 ~/.codex/config.toml 中配置的任意 MCP Server / 插件 / 钩子）与执行规则，
      // 仅保留认证与提取后的安全供应商/模型参数；静态 http_headers 改走环境变量引用，并严格过滤 extraArgs。
      const safeCfg = extractSafeCodexProviderConfig(finalEnv, h.extraArgs, !!h.model);
      effectiveCredStore = safeCfg.credentialStore;
      finalEnv = { ...finalEnv, ...safeCfg.extraEnv };
      extraToPass = safeCfg.sanitizedExtraArgs;
      args.push(
        "--ignore-user-config",
        "--ignore-rules",
        ...safeCfg.args,
        "--disable", "shell_tool",
        "--disable", "unified_exec",
        "--disable", "apps",
        "--disable", "browser_use",
        "--disable", "computer_use",
        "--disable", "view_image",
        "--disable", "image_generation",
        "--disable", "plugins",
        "--disable", "remote_plugin",
        "--disable", "sleep_tool",
        "--disable", "hooks",
        "--disable", "multi_agent",
        "--disable", "code_mode",
        "--disable", "code_mode_host",
        "-c", "sandbox_permissions=[]",
        "-c", 'web_search="disabled"',
      );
    }
    if (h.model) args.push("-m", h.model);
    args.push(...extraToPass, "-");
    const codexHome = finalEnv.CODEX_HOME?.trim();
    const extraRo = [
      ...(codexHome && fs.existsSync(codexHome) ? [codexHome] : []),
      ...(baseEnv.env.CREDENTIALS_DIRECTORY ? [baseEnv.env.CREDENTIALS_DIRECTORY] : []),
    ];
    const extraRw = [
      ...(isolatedTmp ? [isolatedTmp] : []),
      ...(readOutDir ? [readOutDir] : []),
    ];
    const wrapped = wrapCredentialIsolatedCommand(
      cmd,
      args,
      process.env,
      buildWorkspaceIsolation(cfg, {
        mode: run.tools === "none" ? "llm-none" : "codex-exec",
        cwd: execCwd,
        cmdPath: cmd,
        trustedRepoRoot: run.trustedRepoRoot,
        disableGitWorktreeMounts: run.disableGitWorktreeMounts,
        extraWritablePaths: extraRw,
        extraReadOnlyPaths: extraRo,
      }),
    );
    if (wrapped.isolated) {
      const credStore = effectiveCredStore ?? resolveEffectiveCodexCredentialStore(finalEnv, extraToPass).store;
      if (process.platform === "linux" && credStore === "keyring") {
        throw new Error(
          `执行者 ${run.harness} 配置了 cli_auth_credentials_store="keyring"，但当前 Linux 隔离沙箱已屏蔽宿主机 D-Bus 会话总线与 XDG_RUNTIME_DIR，无法访问 Secret Service；请在 ~/.codex/config.toml 中改用 cli_auth_credentials_store="file" 并重新运行 codex login，或通过 OPENAI_API_KEY / 供应商 env_key 提供 API 密钥`,
        );
      }
      finalEnv = {
        ...finalEnv,
        TMPDIR: "/tmp",
        XDG_CACHE_HOME: "/tmp/.pa-cache",
        XDG_STATE_HOME: "/tmp/.pa-state",
        XDG_RUNTIME_DIR: "/tmp/.pa-run",
      };
    }
    r = await runProcess(wrapped.cmd, wrapped.args, {
      cwd: execCwd,
      env: finalEnv,
      input: run.prompt,
      timeoutMs: (run.timeoutSec + 60) * 1000,
      group: true,
      signal: run.signal,
      onSpawn: run.onSpawn,
    });
    try {
      text = fs.readFileSync(outFile, "utf8").trim();
      fs.rmSync(outFile, { force: true });
    } catch {
      text = r.stdout.trim();
    }
  } finally {
    baseEnv.cleanup();
    if (isolatedTmp) fs.rmSync(isolatedTmp, { recursive: true, force: true });
    if (readOutDir) fs.rmSync(readOutDir, { recursive: true, force: true });
  }
  fs.writeFileSync(
    run.logFile,
    [`# ${started} harness=${run.harness} type=codex-exec tools=${run.tools} cwd=${execCwd}`, `# ${cmd} ${redactCodexLogArgs(args).join(" ")}`, `# exit=${r.code} timedOut=${r.timedOut}`, "## prompt", run.prompt, "## reply", text, "## stderr", r.stderr.slice(-4000)].join("\n"),
  );
  try {
    usageRecorder?.(run, { stdout: r.stdout, stderr: r.stderr, code: r.code });
  } catch {
    // 忽略
  }
  const aborted = !!run.signal?.aborted;
  return { ok: r.code === 0 && !r.timedOut && !aborted, exitCode: r.code, text, timedOut: r.timedOut, aborted };
}

/**
 * doubao-cli：直接调用本机已登录的豆包 CLI（`doubao -p -`，提示词走标准输入），
 * 接通飞书守卫 PATH 与权限档位（write → always_allow，read → ask_risky，none → ask_always）。
 */
async function runDoubaoCli(cfg: Config, run: HarnessRun, h: Config["harnesses"][string]): Promise<HarnessResult> {
  const cmd = h.cmd || "doubao";
  fs.mkdirSync(run.cwd, { recursive: true });
  const perm = run.tools === "write" ? "always_allow" : run.tools === "read" ? "ask_risky" : "ask_always";
  const hasPermOverride = h.extraArgs.some((a) => a === "--permission-mode" || a.startsWith("--permission-mode=") || a === "--dangerously-bypass-approvals-and-sandbox");
  const args = ["-C", run.cwd];
  if (!hasPermOverride) args.push("--permission-mode", perm);
  if (h.model) args.push("--model", h.model);
  args.push(...h.extraArgs, "-p", "-");

  let realLark = cfg.bins.lark;
  try {
    realLark = resolveBin(cfg.bins.lark);
  } catch {
    // run.lark === "none" 时不会执行真实 lark-cli
  }
  const started = new Date().toISOString();
  // Node.js spawn 的 stdio:"pipe" 在 Linux 上是 Unix socketpair（S_IFSOCK），doubao 会报
  // "stdin must be a terminal, pipe or regular file"；写到 0600 临时普通文件以 FD 传入，用完立即删除。
  const promptDir = path.join(cfg.dataDir, "runs");
  fs.mkdirSync(promptDir, { recursive: true });
  const promptFile = path.join(promptDir, `.doubao-in-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.txt`);
  fs.writeFileSync(promptFile, run.prompt, { mode: 0o600 });
  const fd = fs.openSync(promptFile, "r");
  const baseEnv = prepareHarnessEnv();
  let r: Awaited<ReturnType<typeof runProcess>>;
  try {
    const mode: WorkspaceIsolationMode =
      run.tools === "write" ? "worker-write" : run.tools === "read" ? "worker-ro" : "llm-none";
    const wrapped = wrapCredentialIsolatedCommand(
      cmd,
      args,
      process.env,
      buildWorkspaceIsolation(cfg, {
        mode,
        cwd: run.cwd,
        cmdPath: cmd,
        trustedRepoRoot: run.trustedRepoRoot,
        disableGitWorktreeMounts: run.disableGitWorktreeMounts,
        allowGuardLog: run.lark !== "none",
        extraReadOnlyPaths: baseEnv.env.CREDENTIALS_DIRECTORY ? [baseEnv.env.CREDENTIALS_DIRECTORY] : [],
      }),
    );
    const env: NodeJS.ProcessEnv = {
      ...mergeHarnessEnv(baseEnv.env, h.env),
      DOUBAO_CLI_NO_UPDATE_CHECK: "1",
      PATH: `${path.join(ROOT, "bin", "guard")}${path.delimiter}${process.env.PATH ?? ""}`,
      PA_GUARD_PROFILE: run.lark,
      PA_OWNER_OPEN_ID: cfg.owner.open_id,
      PA_LARK_REAL: realLark,
      PA_GUARD_LOG: path.join(cfg.dataDir, "logs", "guard.log"),
      ...(wrapped.isolated
        ? {
            TMPDIR: "/tmp",
            XDG_CACHE_HOME: "/tmp/.pa-cache",
            XDG_STATE_HOME: "/tmp/.pa-state",
            XDG_RUNTIME_DIR: "/tmp/.pa-run",
          }
        : {}),
    };
    r = await runProcess(wrapped.cmd, wrapped.args, {
      cwd: run.cwd,
      env,
      stdinFd: fd,
      timeoutMs: (run.timeoutSec + 60) * 1000,
      group: true,
      signal: run.signal,
      onSpawn: run.onSpawn,
    });
  } finally {
    baseEnv.cleanup();
    try {
      fs.closeSync(fd);
    } catch {
      // ignore
    }
    fs.rmSync(promptFile, { force: true });
  }
  const text = r.stdout.trim();
  fs.writeFileSync(
    run.logFile,
    [
      `# ${started} harness=${run.harness} type=doubao-cli tools=${run.tools} lark=${run.lark} cwd=${run.cwd}`,
      `# ${cmd} ${args.join(" ")}`,
      `# exit=${r.code} timedOut=${r.timedOut} aborted=${!!run.signal?.aborted}`,
      "## prompt",
      run.prompt,
      "## stdout",
      r.stdout,
      "## stderr",
      r.stderr.slice(-4000),
    ].join("\n"),
  );
  try {
    usageRecorder?.(run, { stdout: r.stdout, stderr: r.stderr, code: r.code });
  } catch {
    // 忽略
  }
  const aborted = !!run.signal?.aborted;
  return { ok: r.code === 0 && !r.timedOut && !aborted, exitCode: r.code, text, timedOut: r.timedOut, aborted };
}
