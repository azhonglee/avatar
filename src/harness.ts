import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { ROOT, type Config } from "./config.ts";
import type { Profile } from "./guard.ts";
import { isPlainTable, parseToml, parseTomlKeyPath, parseTomlValue, type TomlTable, type TomlValue } from "./toml.ts";
import { errMsg, log, runProcess } from "./util.ts";

const FEISHU_WEB_KEY_CRED = "feishu-web-key";
/** Linux kernel tmpfs magic number (`linux/magic.h`: `TMPFS_MAGIC`). */
const LINUX_TMPFS_MAGIC = 0x01021994;

export type MountMaskBackend =
  | { kind: "bwrap"; bin: string }
  | { kind: "unshare"; bin: string; setprivBin: string; pivotRootBin?: string; shBin?: string; killChild?: boolean }
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
  /** 需要保留/解析并只读放行的可执行文件路径（如外部脚本或自定义工具链命令） */
  cmdPath?: string;
  /** 除主命令外需要只读放行及其 npm 运行时依赖的辅助可执行文件（如 acpx 调用的底层 agent CLI 或 lark-cli） */
  extraCmdPaths?: string[];
  /** 需要保留逻辑路径的只读文件符号链接（如 dotfiles 仓库中的 ~/.gitconfig -> ~/dotfiles/gitconfig，绝不暴露 dotfiles 其余文件） */
  extraSymlinks?: { dest: string; target: string }[];
  /** 将宿主机独立投影源路径按只读或可写方式绑定挂载到沙箱内指定目标路径（例如脱敏 ~/.npmrc、私有 ~/.acpx 或独立暂存的 Doubao 数据目录） */
  extraBindMounts?: { src: string; dest: string; mode: "ro" | "rw" }[];
}

const BROAD_UNSAFE_AUTO_MOUNT_ROOTS = new Set([
  "/",
  "/tmp",
  "/var",
  "/var/tmp",
  "/dev",
  "/dev/shm",
  "/run",
  "/proc",
  "/sys",
  "/root",
  "/mnt",
  "/media",
  "/srv",
  "/opt",
  "/boot",
  "/home",
]);

// 仅包含纯解释器/运行时版本管理根目录；严禁加入 .cargo（含 credentials.toml）、go（含 src/）等含凭据或私有源码的目录
const USER_TOOLCHAIN_SUBDIRS = [
  ".nvm",
  ".fnm",
  ".volta",
  ".asdf",
  ".mise",
  ".rustup",
  ".pyenv",
  ".rbenv",
  ".local/bin",
  ".local/share/fnm",
  ".local/share/mise",
  ".local/share/pnpm",
  ".local/share/nvm",
  ".local/share/uv",
  ".local/pipx",
  ".rye",
  ".uv",
];

function resolveBinInPath(bin: string, pathEnv?: string): string | undefined {
  if (!bin) return undefined;
  if (path.isAbsolute(bin)) return fs.existsSync(bin) ? bin : undefined;
  const guardDir = path.join(ROOT, "bin", "guard");
  const rawPath = pathEnv ?? process.env.PATH ?? "";
  for (const dir of rawPath.split(path.delimiter)) {
    if (!dir || path.resolve(dir) === guardDir) continue;
    const candidate = path.join(dir, bin);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {
      // try next
    }
  }
  return undefined;
}

function collectDirectorySymlinksAlongPaths(logicalPaths: (string | undefined)[]): Map<string, string> {
  const symlinks = new Map<string, string>();
  for (const raw of logicalPaths) {
    if (!raw || !path.isAbsolute(raw)) continue;
    const normalized = path.resolve(raw);
    const parts = normalized.split(path.sep).filter(Boolean);
    let cur = "";
    for (const part of parts) {
      cur += path.sep + part;
      if (symlinks.has(cur)) break;
      try {
        const lst = fs.lstatSync(cur);
        if (lst.isSymbolicLink()) {
          const st = fs.statSync(cur);
          if (st.isDirectory()) {
            symlinks.set(cur, fs.readlinkSync(cur));
          }
          break;
        }
      } catch {
        break;
      }
    }
  }
  return symlinks;
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

const TRUSTED_BOOTSTRAP_PATH = "/usr/sbin:/usr/bin:/sbin:/bin";
const TRUSTED_SYSTEM_BIN_DIRS = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] as const;
const TRUSTED_BOOTSTRAP_ENV: NodeJS.ProcessEnv = {
  PATH: TRUSTED_BOOTSTRAP_PATH,
  LC_ALL: "C",
};

function isSafeBootstrapDir(dirPath: string, allowCurrentUid: boolean): boolean {
  try {
    const st = fs.statSync(dirPath);
    if (!st.isDirectory()) return false;
    if ((st.mode & 0o022) !== 0) return false;
    if (typeof process.getuid === "function") {
      const uid = process.getuid();
      if (allowCurrentUid) {
        if (st.uid !== 0 && st.uid !== uid) return false;
      } else if (st.uid !== 0) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

function isSafeBootstrapBinary(binPath: string, opts: { allowCurrentUid?: boolean } = {}): boolean {
  if (!binPath || !path.isAbsolute(binPath)) return false;
  const allowCurrentUid = opts.allowCurrentUid === true;
  try {
    if (!isSafeBootstrapDir(path.dirname(binPath), allowCurrentUid)) return false;
    const real = fs.realpathSync(binPath);
    if (!isSafeBootstrapDir(path.dirname(real), allowCurrentUid)) return false;
    const st = fs.statSync(real);
    if (!st.isFile()) return false;
    if ((st.mode & 0o022) !== 0) return false;
    if (typeof process.getuid === "function") {
      const uid = process.getuid();
      if (allowCurrentUid) {
        if (st.uid !== 0 && st.uid !== uid) return false;
      } else if (st.uid !== 0) {
        return false;
      }
    }
    if (allowCurrentUid) {
      // 用户级固定安装路径（如 ~/.local/bin/bwrap）绝不得落入当前工作目录或项目仓库根下，防止检出仓库劫持引导程序
      const realRoot = safeRealpath(ROOT);
      const realCwd = safeRealpath(process.cwd());
      if (isPathInsideOrEqual(real, realRoot) || isPathInsideOrEqual(real, realCwd)) return false;
    }
    fs.accessSync(real, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** 严格仅从 root 拥有的可信系统目录解析沙箱引导程序（sh / unshare / setpriv / pivot_root），绝不搜索进程继承的 PATH */
export function resolveTrustedSystemBin(name: string): string | undefined {
  if (!name || name.includes("/") || name.includes("\\")) return undefined;
  for (const dir of TRUSTED_SYSTEM_BIN_DIRS) {
    const cand = path.join(dir, name);
    if (isSafeBootstrapBinary(cand, { allowCurrentUid: false })) return cand;
  }
  return undefined;
}

/**
 * 解析可信的 bubblewrap（bwrap）引导程序路径：
 *   1. 优先查 root 拥有的系统目录（/usr/bin、/bin、/usr/local/bin）；
 *   2. 其次仅检查固定受控安装位置（/home/linuxbrew/.linuxbrew/bin/bwrap 与 ~/.local/bin/bwrap），
 *      严格校验目录与文件归属 root 或当前 UID、非组/全局可写且不在当前工作目录或仓库根下；
 *   3. 绝不搜索进程继承的 PATH，避免 npm/项目脚本在 PATH 头部注入恶意 bwrap 并在隔离建立前执行。
 */
export function resolveTrustedBwrapBin(): string | undefined {
  for (const cand of ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"]) {
    if (isSafeBootstrapBinary(cand, { allowCurrentUid: false })) return cand;
  }
  const userHome = os.homedir();
  const userFixed = [
    "/home/linuxbrew/.linuxbrew/bin/bwrap",
    ...(userHome ? [path.join(userHome, ".local", "bin", "bwrap")] : []),
  ];
  for (const cand of userFixed) {
    if (isSafeBootstrapBinary(cand, { allowCurrentUid: true })) return cand;
  }
  return undefined;
}

function resolvePivotRootBin(): string | undefined {
  return resolveTrustedSystemBin("pivot_root");
}

/** 仅返回 bin/guard/lark-cli 运行所需的 4 个精确只读文件，绝不挂载整个 ROOT（防暴露 ROOT/config.yaml 与 ROOT/.worktrees） */
export function collectLarkGuardReadOnlyFiles(): string[] {
  const candidates = [
    path.join(ROOT, "bin", "guard", "lark-cli"),
    path.join(ROOT, "src", "guard-cli.ts"),
    path.join(ROOT, "src", "guard.ts"),
    path.join(ROOT, "package.json"),
  ];
  return candidates.filter((p) => fs.existsSync(p)).map((p) => safeRealpath(p));
}

function resolveMountDestRealpath(destPath: string): string {
  const abs = path.resolve(destPath);
  const tail: string[] = [];
  let cur = abs;
  while (cur && cur !== path.dirname(cur)) {
    if (fs.existsSync(cur)) {
      return tail.length ? path.join(safeRealpath(cur), ...tail) : safeRealpath(cur);
    }
    tail.unshift(path.basename(cur));
    cur = path.dirname(cur);
  }
  return abs;
}

/**
 * 解析豆包 CLI 在隔离沙箱中运行所需的只读配置、二进制与登录态目录：
 *   - `~/.doubao` 与 `${XDG_CONFIG_HOME:-~/.config}/doubao`
 *   - Linux 上 `@bytedance/doubao-cli` 运行目录 `app/current` 以及登录态 `doubao-cli-pc-login`、`keys`（绝不暴露 logs/agent_mode/sandbox_envs_dir）
 */
export function selectDoubaoRuntimePaths(hostEnv: NodeJS.ProcessEnv = process.env): string[] {
  const hostHome = hostEnv.HOME?.trim() || os.homedir();
  const xdgConfig = hostEnv.XDG_CONFIG_HOME?.trim() || (hostHome ? path.join(hostHome, ".config") : "");
  const xdgData = hostEnv.XDG_DATA_HOME?.trim() || (hostHome ? path.join(hostHome, ".local", "share") : "");
  const out: string[] = [];
  if (hostHome) out.push(path.join(hostHome, ".doubao"));
  if (xdgConfig) out.push(path.join(xdgConfig, "doubao"));
  if (xdgData) {
    out.push(path.join(xdgData, "doubao_cli", "app", "current"));
    out.push(path.join(xdgData, "doubao_cli", "doubao-cli-pc-login"));
    out.push(path.join(xdgData, "doubao_cli", "keys"));
  }
  return [...new Set(out)];
}

/**
 * 解析受守卫保护的 `lark-cli` 所需的配置与 Linux 文件存储登录态目录：
 *   - `~/.lark-cli`、`${XDG_CONFIG_HOME:-~/.config}/lark-cli`
 *   - Linux 文件存储加密凭据与主密钥目录 `${XDG_DATA_HOME:-~/.local/share}/lark-cli`
 */
export function selectLarkCliAuthPaths(hostEnv: NodeJS.ProcessEnv = process.env): string[] {
  const hostHome = hostEnv.HOME?.trim() || os.homedir();
  const xdgConfig = hostEnv.XDG_CONFIG_HOME?.trim() || (hostHome ? path.join(hostHome, ".config") : "");
  const xdgData = hostEnv.XDG_DATA_HOME?.trim() || (hostHome ? path.join(hostHome, ".local", "share") : "");
  const out: string[] = [];
  if (hostHome) out.push(path.join(hostHome, ".lark-cli"));
  if (xdgConfig) out.push(path.join(xdgConfig, "lark-cli"));
  if (xdgData) out.push(path.join(xdgData, "lark-cli"));
  return [...new Set(out)];
}

function copyTreeBounded(
  srcDir: string,
  destDir: string,
  allowedRoot: string,
  resolvedDataDir: string,
  opts?: { skipNames?: Set<string>; depth?: number; budget?: { files: number; bytes: number } },
): void {
  const depth = opts?.depth ?? 0;
  const budget = opts?.budget ?? { files: 0, bytes: 0 };
  if (depth > 8 || budget.files > 512 || budget.bytes > 16 * 1024 * 1024) return;
  let realSrc: string;
  try {
    const st = fs.statSync(srcDir);
    if (!st.isDirectory()) return;
    realSrc = fs.realpathSync(srcDir);
  } catch {
    return;
  }
  if (!isPathInsideOrEqual(realSrc, allowedRoot)) return;
  if (resolvedDataDir && (isPathInsideOrEqual(realSrc, resolvedDataDir) || isPathInsideOrEqual(resolvedDataDir, realSrc))) return;
  fs.mkdirSync(destDir, { recursive: true, mode: 0o700 });
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(realSrc, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    if (opts?.skipNames?.has(ent.name)) continue;
    const srcPath = path.join(realSrc, ent.name);
    const dstPath = path.join(destDir, ent.name);
    try {
      const lst = fs.lstatSync(srcPath);
      if (lst.isSymbolicLink()) continue;
      if (lst.isDirectory()) {
        copyTreeBounded(srcPath, dstPath, allowedRoot, resolvedDataDir, {
          skipNames: opts?.skipNames,
          depth: depth + 1,
          budget,
        });
      } else if (lst.isFile()) {
        if (lst.size > 4 * 1024 * 1024) continue;
        budget.files++;
        budget.bytes += lst.size;
        if (budget.files > 512 || budget.bytes > 16 * 1024 * 1024) return;
        const buf = fs.readFileSync(srcPath);
        fs.writeFileSync(dstPath, buf, { mode: (lst.mode & 0o111) ? 0o700 : 0o600 });
      }
    } catch {
      // ignore unreadable entry
    }
  }
}

export interface StagedDoubaoDataDir {
  hostDataDir: string;
  bindMounts: { src: string; dest: string; mode: "ro" | "rw" }[];
  cleanup: () => void;
}

/**
 * 为 Linux `@bytedance/doubao-cli` 构建隔离且独立的私有可写 `doubao_cli` 运行目录：
 *   - 仅复制 `doubao-cli-pc-login` 与 `keys`（跳过实例锁），在私有 `0700` 临时目录中为本次调用提供独立的 `doubao-cli-instance.lock` 与日志空间；
 *   - 将宿主机 `app/current` 二进制目录以只读方式叠加挂载到 `<doubao_cli>/app/current`，既无需复制大体积二进制又防止子进程篡改；
 *   - 绝不暴露宿主机 `logs`、`agent_mode`、`crash-monitor`、`sandbox_envs_dir` 等历史数据。
 */
export function stageIsolatedDoubaoDataDir(
  hostEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
): StagedDoubaoDataDir | undefined {
  const hostHome = hostEnv.HOME?.trim() || os.homedir();
  const xdgData = hostEnv.XDG_DATA_HOME?.trim() || (hostHome ? path.join(hostHome, ".local", "share") : "");
  if (!xdgData) return undefined;
  const hostDoubaoDir = path.join(xdgData, "doubao_cli");
  if (!fs.existsSync(hostDoubaoDir)) return undefined;
  const realHostDoubao = safeRealpath(hostDoubaoDir);
  const resolvedDataDir = dataDir && fs.existsSync(dataDir) ? safeRealpath(dataDir) : "";
  if (
    resolvedDataDir &&
    (isPathInsideOrEqual(realHostDoubao, resolvedDataDir) || isPathInsideOrEqual(resolvedDataDir, realHostDoubao))
  ) {
    return undefined;
  }
  const appCurrentSrc = path.join(realHostDoubao, "app", "current");
  const loginSrc = path.join(realHostDoubao, "doubao-cli-pc-login");
  const keysSrc = path.join(realHostDoubao, "keys");
  const hasAppCurrent = fs.existsSync(appCurrentSrc);
  const hasLogin = fs.existsSync(loginSrc);
  const hasKeys = fs.existsSync(keysSrc);
  if (!hasAppCurrent && !hasLogin && !hasKeys) return undefined;

  const scoped = createScopedSecretDir("pa-doubao-data-", hostEnv);
  try {
    const stageDir = path.join(scoped.dir, "doubao_cli");
    fs.mkdirSync(stageDir, { recursive: true, mode: 0o700 });
    if (hasLogin) {
      copyTreeBounded(loginSrc, path.join(stageDir, "doubao-cli-pc-login"), realHostDoubao, resolvedDataDir, {
        skipNames: new Set(["lock"]),
      });
    }
    if (hasKeys) {
      copyTreeBounded(keysSrc, path.join(stageDir, "keys"), realHostDoubao, resolvedDataDir, {
        skipNames: new Set(["lock"]),
      });
    }
    const bindMounts: { src: string; dest: string; mode: "ro" | "rw" }[] = [
      { src: stageDir, dest: realHostDoubao, mode: "rw" },
    ];
    if (hasAppCurrent) {
      const realAppCurrent = safeRealpath(appCurrentSrc);
      fs.mkdirSync(path.join(stageDir, "app", "current"), { recursive: true, mode: 0o700 });
      bindMounts.push({ src: realAppCurrent, dest: path.join(realHostDoubao, "app", "current"), mode: "ro" });
    }
    return { hostDataDir: realHostDoubao, bindMounts, cleanup: scoped.cleanup };
  } catch (err) {
    scoped.cleanup();
    throw err;
  }
}

const SAFE_NPMRC_SCALAR_KEYS = new Set([
  "registry",
  "proxy",
  "https-proxy",
  "http-proxy",
  "noproxy",
  "no-proxy",
  "strict-ssl",
  "fetch-retries",
  "fetch-retry-mintimeout",
  "fetch-retry-maxtimeout",
  "fetch-timeout",
  "fetch-retry-factor",
  "maxsockets",
  "prefer-offline",
  "prefer-online",
  "offline",
  "loglevel",
  "progress",
  "fund",
  "audit",
  "save-exact",
  "engine-strict",
  "legacy-peer-deps",
  "disturl",
  "sass_binary_site",
  "electron_mirror",
  "puppeteer_download_host",
  "sharp_binary_host",
  "sharp_libvips_binary_host",
]);

/** 仅保留 `.npmrc` 中非敏感的镜像/代理/网络行为配置，彻底剥离注册表令牌、密码、Basic Auth、URL 内嵌凭据与环境变量展开。 */
export function sanitizeNpmrcContent(raw: string): string {
  const out: string[] = [];
  for (const rawLine of raw.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    const val = trimmed.slice(eq + 1).trim();
    if (!key || !val) continue;
    if (key.startsWith("//")) continue;
    const lowerKey = key.toLowerCase();
    const isScopedRegistry = /^@[a-z0-9_.-]+:registry$/i.test(key);
    if (!isScopedRegistry && !SAFE_NPMRC_SCALAR_KEYS.has(lowerKey)) continue;
    if (val.includes("${") || /[\r\n\0]/.test(val)) continue;
    const unquoted =
      (val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))
        ? val.slice(1, -1).trim()
        : val;
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(unquoted)) {
      try {
        const parsed = new URL(unquoted);
        if (parsed.username || parsed.password) continue;
      } catch {
        continue;
      }
    } else if (/:\/\/[^/\s@]+@/.test(unquoted)) {
      continue;
    }
    out.push(`${key}=${val}`);
  }
  return out.length ? `${out.join("\n")}\n` : "";
}

export interface StagedSanitizedNpmrc {
  dir: string;
  file: string;
  homeMountDest: string;
  cleanup: () => void;
}

/** 读取宿主机用户 `.npmrc`（或 `NPM_CONFIG_USERCONFIG`），仅将非敏感配置写入独立 `0600` 临时文件供隔离任务只读使用。 */
export function stageSanitizedNpmrc(
  rawEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
): StagedSanitizedNpmrc | undefined {
  const rawHome = rawEnv.HOME?.trim() || os.homedir();
  if (!rawHome) return undefined;
  const resolvedHome = safeRealpath(rawHome);
  const resolvedData = dataDir && fs.existsSync(dataDir) ? safeRealpath(dataDir) : "";
  const explicit = rawEnv.NPM_CONFIG_USERCONFIG?.trim() || rawEnv.npm_config_userconfig?.trim();
  const sourcePath = explicit ? path.resolve(explicit) : path.join(resolvedHome, ".npmrc");
  try {
    const st = fs.statSync(sourcePath);
    if (!st.isFile() || st.size > 256 * 1024) return undefined;
    const realSource = fs.realpathSync(sourcePath);
    if (resolvedData && (isPathInsideOrEqual(realSource, resolvedData) || isPathInsideOrEqual(resolvedData, realSource))) {
      return undefined;
    }
    const sanitized = sanitizeNpmrcContent(fs.readFileSync(realSource, "utf8"));
    if (!sanitized) return undefined;
    const scoped = createScopedSecretDir("pa-npmrc-", rawEnv);
    try {
      const file = path.join(scoped.dir, "npmrc");
      fs.writeFileSync(file, sanitized, { mode: 0o600 });
      return {
        dir: scoped.dir,
        file,
        homeMountDest: path.join(resolvedHome, ".npmrc"),
        cleanup: scoped.cleanup,
      };
    } catch (err) {
      scoped.cleanup();
      throw err;
    }
  } catch {
    return undefined;
  }
}

export function applySanitizedNpmrcEnv(
  env: NodeJS.ProcessEnv,
  staged: StagedSanitizedNpmrc | undefined,
  isolated: boolean,
): void {
  if (!isolated) return;
  delete env.npm_config_userconfig;
  if (staged) {
    env.NPM_CONFIG_USERCONFIG = staged.file;
  } else {
    delete env.NPM_CONFIG_USERCONFIG;
  }
}

function isSafeGitConfigIncludeTarget(realPath: string, resolvedData: string): boolean {
  if (!realPath) return false;
  if (resolvedData && (isPathInsideOrEqual(realPath, resolvedData) || isPathInsideOrEqual(resolvedData, realPath))) {
    return false;
  }
  const base = path.basename(realPath).toLowerCase();
  if (base === ".git-credentials") return false;
  if (realPath.toLowerCase().endsWith(`${path.sep}git${path.sep}credentials`)) return false;
  return true;
}

function expandGitIncludePath(rawPath: string, baseDir: string, resolvedHome: string): string | undefined {
  let s = rawPath.trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    s = s.slice(1, -1).trim();
  }
  if (!s) return undefined;
  if (s === "~") return resolvedHome || undefined;
  if (s.startsWith("~/")) return resolvedHome ? path.join(resolvedHome, s.slice(2)) : undefined;
  return path.isAbsolute(s) ? s : path.resolve(baseDir, s);
}

function matchesGitDirIncludeIf(condition: string, cwd: string | undefined, resolvedHome: string): boolean {
  if (!cwd) return false;
  const ci = condition.toLowerCase().startsWith("gitdir/i:");
  const prefixLen = ci ? "gitdir/i:".length : condition.toLowerCase().startsWith("gitdir:") ? "gitdir:".length : 0;
  if (!prefixLen) return false;
  let pat = condition.slice(prefixLen).trim();
  if (!pat) return false;
  if (pat.startsWith("~/")) pat = path.join(resolvedHome, pat.slice(2));
  else if (pat.startsWith("./")) pat = path.resolve(resolvedHome, pat);
  const normCwd = safeRealpath(cwd).replace(/\/?$/, "/");
  const normPat = pat.startsWith("/") ? path.resolve(pat) + (pat.endsWith("/") ? "/" : "") : pat;
  const target = ci ? normCwd.toLowerCase() : normCwd;
  const cmpPat = ci ? normPat.toLowerCase() : normPat;
  if (!/[*?[\]]/.test(cmpPat)) {
    return cmpPat.startsWith("/") ? target.startsWith(cmpPat) : target.includes(`/${cmpPat}`);
  }
  const esc = cmpPat
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "__GLOBSTAR__")
    .replace(/\*/g, "[^/]*")
    .replace(/\?/g, "[^/]")
    .replace(/__GLOBSTAR__/g, ".*");
  const re = new RegExp(cmpPat.startsWith("/") ? `^${esc}` : `(?:^|/)${esc}`);
  return re.test(target);
}

/**
 * 仅收集安全的 Git 只读配置文件（含适用当前工作目录的全局 `[include]` / `[includeIf]` 文件，绝不挂载整个 `~/.config/git` 目录、
 * `~/.config/git/credentials`、`~/.git-credentials` 或原始 `~/.npmrc`），
 * 并为符号链接 dotfiles（如 `~/.gitconfig -> ~/dotfiles/gitconfig`）保留逻辑路径符号链接，避免 Git 丢失配置且不暴露 dotfiles 其余文件。
 */
export function collectSafeGitConfigMounts(
  rawEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
  opts?: { cwd?: string },
): { readOnlyPaths: string[]; symlinks: { dest: string; target: string }[] } {
  const readOnlyPaths: string[] = [];
  const symlinks: { dest: string; target: string }[] = [];
  const addedFiles = new Set<string>();
  const addedSymlinks = new Set<string>();
  const rawHome = rawEnv.HOME?.trim() || os.homedir();
  if (!rawHome) return { readOnlyPaths, symlinks };
  const resolvedHome = safeRealpath(rawHome);
  const resolvedData = dataDir && fs.existsSync(dataDir) ? safeRealpath(dataDir) : "";
  const rawXdgConfig = rawEnv.XDG_CONFIG_HOME?.trim();
  const xdgConfigBase = rawXdgConfig ? safeRealpath(rawXdgConfig) : path.join(resolvedHome, ".config");

  const addLogicalFile = (logicalPath: string): string | undefined => {
    try {
      const lst = fs.lstatSync(logicalPath);
      const st = fs.statSync(logicalPath);
      if (!st.isFile() || st.size > 512 * 1024) return undefined;
      const real = fs.realpathSync(logicalPath);
      if (!isSafeGitConfigIncludeTarget(real, resolvedData)) return undefined;
      if (!addedFiles.has(real)) {
        addedFiles.add(real);
        readOnlyPaths.push(real);
      }
      if (lst.isSymbolicLink()) {
        const logicalDest = path.join(safeRealpath(path.dirname(logicalPath)), path.basename(logicalPath));
        if (logicalDest !== real && !addedSymlinks.has(logicalDest)) {
          addedSymlinks.add(logicalDest);
          symlinks.push({ dest: logicalDest, target: real });
        }
      }
      return real;
    } catch {
      return undefined;
    }
  };

  const visitedStatic = new Set<string>();
  const parseStaticIncludes = (logicalCfgPath: string, depth: number) => {
    if (depth > 4) return;
    const real = addLogicalFile(logicalCfgPath);
    if (!real || visitedStatic.has(real)) return;
    visitedStatic.add(real);
    let text: string;
    try {
      text = fs.readFileSync(real, "utf8");
    } catch {
      return;
    }
    const logicalDir = path.dirname(logicalCfgPath);
    const realDir = path.dirname(real);
    let activeInclude = false;
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#") || line.startsWith(";")) continue;
      const sec = line.match(/^\[([^\]]+)\]$/);
      if (sec) {
        const header = sec[1].trim();
        if (/^include$/i.test(header)) {
          activeInclude = true;
        } else {
          const condMatch = header.match(/^includeIf\s+"([^"]+)"$/i);
          activeInclude = !!condMatch && matchesGitDirIncludeIf(condMatch[1], opts?.cwd, resolvedHome);
        }
        continue;
      }
      if (!activeInclude) continue;
      const pm = line.match(/^path\s*=\s*(.+)$/i);
      if (!pm) continue;
      const candidateLogical = expandGitIncludePath(pm[1], logicalDir, resolvedHome);
      if (candidateLogical && fs.existsSync(candidateLogical)) {
        parseStaticIncludes(candidateLogical, depth + 1);
      } else {
        const candidateReal = expandGitIncludePath(pm[1], realDir, resolvedHome);
        if (candidateReal && fs.existsSync(candidateReal)) {
          parseStaticIncludes(candidateReal, depth + 1);
        }
      }
    }
  };

  const globalGitConfig = path.join(resolvedHome, ".gitconfig");
  const xdgGitConfig = path.join(xdgConfigBase, "git", "config");
  parseStaticIncludes(globalGitConfig, 0);
  parseStaticIncludes(xdgGitConfig, 0);
  addLogicalFile(path.join(xdgConfigBase, "git", "ignore"));
  addLogicalFile(path.join(xdgConfigBase, "git", "attributes"));

  // 当指定 cwd 且存在受信任 git 可执行文件时，借助 Git 自身只读解析 global scope 的全部 include / includeIf（含 gitdir / onbranch / hasconfig），
  // 严格过滤 scope === "global"（忽略仓库 local .git/config 注入的任意 include），并排除凭据文件与 dataDir。
  if (opts?.cwd && fs.existsSync(opts.cwd)) {
    const gitBin = resolveTrustedSystemBin("git");
    if (gitBin) {
      try {
        const gitEnv: NodeJS.ProcessEnv = {
          PATH: TRUSTED_BOOTSTRAP_PATH,
          LC_ALL: "C",
          HOME: rawHome,
          GIT_TERMINAL_PROMPT: "0",
          ...(rawXdgConfig ? { XDG_CONFIG_HOME: rawXdgConfig } : {}),
        };
        const r = spawnSync(
          gitBin,
          [
            "-C",
            opts.cwd,
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "config",
            "--includes",
            "--show-scope",
            "--show-origin",
            "--null",
            "--list",
          ],
          { env: gitEnv, timeout: 3_000, encoding: "utf8" },
        );
        if (r.status === 0 && r.stdout) {
          const tokens = r.stdout.split("\0");
          for (let i = 0; i + 2 < tokens.length; i += 3) {
            const scope = tokens[i];
            const origin = tokens[i + 1];
            if (scope !== "global" || !origin.startsWith("file:")) continue;
            const originPath = origin.slice("file:".length);
            if (!originPath) continue;
            const absOrigin = path.isAbsolute(originPath) ? originPath : path.resolve(opts.cwd, originPath);
            addLogicalFile(absOrigin);
          }
        }
      } catch {
        // 静态解析已兜底
      }
    }
  }

  return { readOnlyPaths, symlinks };
}

const KNOWN_ACPX_PROVIDERS = ["claude", "codex", "gemini", "doubao", "opencode"] as const;

function resolveSelectedAcpxAgentId(h: Pick<Config["harnesses"][string], "agent" | "agentCommand">): string {
  const agentRaw = (h.agent?.trim() || "").toLowerCase();
  const cmdFirst = h.agentCommand?.trim().split(/\s+/)[0] || "";
  const cmdBase = cmdFirst ? path.basename(cmdFirst).toLowerCase() : "";
  return agentRaw || cmdBase;
}

export interface StagedAcpxState {
  dir: string;
  mountDest: string;
  extraCmdPaths: string[];
  cleanup: () => void;
}

/**
 * 为一次性 `acpx exec` 调用分配私有 `0700` 状态目录并绑定挂载到 `~/.acpx`：
 *   - 绝不暴露宿主机 `~/.acpx/sessions` 或 `~/.acpx/queues` 中的跨仓库历史会话；
 *   - 仅投影经过过滤的 `config.json`（保留全局选项与选定 agent/适配器条目）以及位于 `~/.acpx` 内且被选定 agent 显式引用的本地适配器文件。
 */
export function stageIsolatedAcpxState(
  h: Pick<Config["harnesses"][string], "agent" | "agentCommand">,
  hostHome: string,
  rawEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
): StagedAcpxState | undefined {
  if (!hostHome) return undefined;
  const resolvedHome = safeRealpath(hostHome);
  const resolvedData = dataDir && fs.existsSync(dataDir) ? safeRealpath(dataDir) : "";
  const hostAcpxDir = path.join(resolvedHome, ".acpx");
  const realHostAcpxDir = fs.existsSync(hostAcpxDir) ? safeRealpath(hostAcpxDir) : hostAcpxDir;
  const selectedId = resolveSelectedAcpxAgentId(h);
  const scoped = createScopedSecretDir("pa-acpx-state-", rawEnv);
  const extraCmdPaths: string[] = [];

  try {
    const stateDir = path.join(scoped.dir, "acpx");
    fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    const hostCfgPath = path.join(hostAcpxDir, "config.json");
    if (
      fs.existsSync(hostCfgPath) &&
      !(resolvedData && isPathInsideOrEqual(safeRealpath(hostCfgPath), resolvedData))
    ) {
      try {
        const st = fs.statSync(hostCfgPath);
        if (st.isFile() && st.size <= 256 * 1024) {
          const parsed = JSON.parse(fs.readFileSync(hostCfgPath, "utf8")) as Record<string, unknown>;
          if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
            const outCfg: Record<string, unknown> = {};
            for (const key of [
              "defaultAgent",
              "defaultPermissions",
              "nonInteractivePermissions",
              "authPolicy",
              "ttl",
              "timeout",
              "queueMaxDepth",
              "format",
              "disableExec",
              "mcpServers",
            ]) {
              if (Object.prototype.hasOwnProperty.call(parsed, key)) {
                outCfg[key] = parsed[key];
              }
            }
            const adapterCommands: string[] = [];
            if (parsed.agents && typeof parsed.agents === "object" && !Array.isArray(parsed.agents)) {
              const filteredAgents: Record<string, unknown> = {};
              const agentEntries = Object.entries(parsed.agents as Record<string, unknown>);
              for (const [name, def] of agentEntries) {
                const lowerName = name.toLowerCase();
                if (selectedId && !h.agentCommand?.trim() && lowerName !== selectedId) continue;
                filteredAgents[name] = def;
                if (def && typeof def === "object" && !Array.isArray(def)) {
                  const rec = def as Record<string, unknown>;
                  if (typeof rec.command === "string" && rec.command.trim()) {
                    adapterCommands.push(rec.command.trim().split(/\s+/)[0]);
                  } else if (Array.isArray(rec.argv) && typeof rec.argv[0] === "string" && rec.argv[0].trim()) {
                    adapterCommands.push(rec.argv[0].trim());
                  }
                }
              }
              if (Object.keys(filteredAgents).length > 0) {
                outCfg.agents = filteredAgents;
              }
            }
            if (parsed.auth && typeof parsed.auth === "object" && !Array.isArray(parsed.auth)) {
              const filteredAuth: Record<string, unknown> = {};
              for (const [k, v] of Object.entries(parsed.auth as Record<string, unknown>)) {
                const lk = k.toLowerCase();
                const otherProvider = KNOWN_ACPX_PROVIDERS.find(
                  (prov) =>
                    lk.includes(prov) &&
                    (!selectedId || (!selectedId.startsWith(prov) && selectedId !== `${prov}-code`)),
                );
                if (otherProvider) continue;
                filteredAuth[k] = v;
              }
              if (Object.keys(filteredAuth).length > 0) {
                outCfg.auth = filteredAuth;
              }
            }
            fs.writeFileSync(path.join(stateDir, "config.json"), `${JSON.stringify(outCfg, null, 2)}\n`, {
              mode: 0o600,
            });

            // 仅复制被选定 agent 显式引用的 `~/.acpx` 内适配器文件（绝不触及 sessions/queues/logs/cache/history）
            const forbiddenTopDirs = new Set(["sessions", "queues", "logs", "cache", "history"]);
            for (const rawCmd of adapterCommands) {
              const expanded = rawCmd.startsWith("~/") ? path.join(resolvedHome, rawCmd.slice(2)) : rawCmd;
              if (!path.isAbsolute(expanded)) {
                extraCmdPaths.push(rawCmd);
                continue;
              }
              const realCmd = fs.existsSync(expanded) ? safeRealpath(expanded) : "";
              if (!realCmd) continue;
              if (fs.existsSync(hostAcpxDir) && isPathInsideOrEqual(realCmd, realHostAcpxDir)) {
                const rel = path.relative(realHostAcpxDir, realCmd);
                const top = rel.split(path.sep)[0];
                if (!rel || rel.startsWith("..") || forbiddenTopDirs.has(top)) continue;
                try {
                  const cst = fs.statSync(realCmd);
                  if (cst.isFile() && cst.size <= 4 * 1024 * 1024) {
                    const dst = path.join(stateDir, rel);
                    fs.mkdirSync(path.dirname(dst), { recursive: true, mode: 0o700 });
                    fs.writeFileSync(dst, fs.readFileSync(realCmd), { mode: cst.mode & 0o700 ? 0o700 : 0o600 });
                  }
                } catch {
                  // ignore unreadable adapter file
                }
              } else {
                extraCmdPaths.push(realCmd);
              }
            }
          }
        }
      } catch {
        // 忽略损坏的 config.json，保持空白私有状态目录
      }
    }
    return {
      dir: stateDir,
      mountDest: hostAcpxDir,
      extraCmdPaths: [...new Set(extraCmdPaths)],
      cleanup: scoped.cleanup,
    };
  } catch (err) {
    scoped.cleanup();
    throw err;
  }
}

/**
 * 按 acpx 实际选中的 agent 仅暴露该单一提供方的配置目录（从合并展开后的子进程环境解析，
 * 绝不挂载整个 `~/.acpx` 或向 Claude 工人暴露 `~/.codex` 等其他提供方凭据）。
 */
export function selectAcpxAgentConfigPaths(
  h: Pick<Config["harnesses"][string], "agent" | "agentCommand" | "env">,
  hostHome: string,
  hostEnv: NodeJS.ProcessEnv = process.env,
): string[] {
  const effectiveEnv = mergeHarnessEnv(hostEnv, h.env);
  const resolvedHome = effectiveEnv.HOME?.trim() || hostHome || os.homedir();
  const xdgConfig = effectiveEnv.XDG_CONFIG_HOME?.trim() || (resolvedHome ? path.join(resolvedHome, ".config") : "");
  const xdgData = effectiveEnv.XDG_DATA_HOME?.trim() || (resolvedHome ? path.join(resolvedHome, ".local", "share") : "");
  const out: string[] = [];
  const addSub = (sub: string) => {
    if (resolvedHome && sub) out.push(path.join(resolvedHome, sub));
  };
  const addAbs = (p: string | undefined) => {
    const t = p?.trim();
    if (t) out.push(path.isAbsolute(t) ? t : path.join(resolvedHome, t));
  };

  const id = resolveSelectedAcpxAgentId(h);

  if (id === "claude" || id === "claude-code" || id.startsWith("claude-")) {
    const claudeDir = effectiveEnv.CLAUDE_CONFIG_DIR?.trim();
    if (claudeDir) addAbs(claudeDir);
    else addSub(".claude");
    addSub(".claude.json");
  } else if (id === "codex" || id.startsWith("codex-")) {
    const codexHome = effectiveEnv.CODEX_HOME?.trim();
    if (codexHome) addAbs(codexHome);
    else addSub(".codex");
  } else if (id === "gemini" || id.startsWith("gemini-")) {
    const geminiHome = effectiveEnv.GEMINI_CLI_HOME?.trim();
    if (geminiHome) addAbs(geminiHome);
    else addSub(".gemini");
  } else if (id === "doubao" || id.startsWith("doubao-")) {
    out.push(...selectDoubaoRuntimePaths({ ...effectiveEnv, HOME: resolvedHome }));
  } else if (id === "opencode" || id.startsWith("opencode-")) {
    if (xdgConfig) out.push(path.join(xdgConfig, "opencode"));
    if (xdgData) out.push(path.join(xdgData, "opencode"));
  }
  return [...new Set(out)];
}

/** 提取 acpx 选定 agent 对应的底层可执行名/路径，供沙箱挂载其全局 npm 包与运行时依赖 */
function resolveAcpxAgentExecutable(h: Pick<Config["harnesses"][string], "agent" | "agentCommand">): string | undefined {
  if (h.agentCommand?.trim()) {
    return h.agentCommand.trim().split(/\s+/)[0];
  }
  const a = (h.agent?.trim() || "").toLowerCase();
  if (a === "claude" || a === "claude-code") return "claude";
  if (a === "codex") return "codex";
  if (a === "gemini") return "gemini";
  if (a === "doubao") return "doubao";
  if (a === "opencode") return "opencode";
  return a || undefined;
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
    extraCmdPaths?: string[];
    /** 受信任的派单仓库根目录：存在时严格校核 worktree `.git` / `commondir` 归属该仓库 */
    trustedRepoRoot?: string;
    /** 显式禁止挂载任何外部 worktree `.git` 目录（用于非 Git 派单的空工作区） */
    disableGitWorktreeMounts?: boolean;
    allowGuardLog?: boolean;
    extraWritablePaths?: string[];
    extraReadOnlyPaths?: string[];
    extraBindMounts?: { src: string; dest: string; mode: "ro" | "rw" }[];
  },
  rawEnv: NodeJS.ProcessEnv = process.env,
): IsolationOptions {
  const dataDir = cfg?.dataDir;
  // 纯无工具推理（llm-none）在未启用个人 Web 时不因轮询 ctx_obs 强制要求 Linux 命名空间，保持非个人 Web 环境下的 keyring 兼容；
  // 所有具备仓库访问能力的进程（verify / worker / codex-exec 审查 / git-rw / git-ro）在 Linux 上一律默认启用隔离，
  // 不依赖启动工作区当前是否已写入密钥或 ctx_obs（避免新工作区或消息到达前启动的工人直接访问同 OS 用户其他工作区的 state.db）。
  const includeContextObs = opts.mode !== "llm-none";
  const requireIsolation =
    opts.mode !== "llm-none"
      ? process.platform === "linux" || workspaceRequiresIsolation(cfg, rawEnv, { includeContextObs: true })
      : workspaceRequiresIsolation(cfg, rawEnv, { includeContextObs: false });
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
      const resolvedCmd = resolveBinInPath(opts.cmdPath, rawEnv.PATH || process.env.PATH);
      if (resolvedCmd) {
        const realCmd = safeRealpath(resolvedCmd);
        if (fs.existsSync(realCmd)) readOnlyPaths.push(realCmd);
      }
    } catch {
      // ignore unresolved cmd
    }
  }

  // 最小化允许的个人工具配置（严格只读、仅挂载单个安全 Git 配置文件及适用当前仓库的全局 include，绝不挂载 ~/.config/git 整目录或原始 ~/.npmrc，并保留 dotfiles 符号链接逻辑路径）
  const extraSymlinks: { dest: string; target: string }[] = [];
  if (opts.mode !== "llm-none") {
    const gitCfgMounts = collectSafeGitConfigMounts(rawEnv, dataDir, { cwd: resolvedCwd });
    readOnlyPaths.push(...gitCfgMounts.readOnlyPaths);
    extraSymlinks.push(...gitCfgMounts.symlinks);
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
    cmdPath: opts.cmdPath,
    extraCmdPaths: opts.extraCmdPaths,
    ...(extraSymlinks.length ? { extraSymlinks } : {}),
    ...(opts.extraBindMounts?.length ? { extraBindMounts: opts.extraBindMounts } : {}),
  };
}

/** 收集最小只读系统根（/usr、/etc、/nix、/home/linuxbrew 等）与顶层 usrmerge 符号链接，绝不暴露 /、/home、$HOME 或 /opt -> /data00 */
function collectMinimalSystemRoot(excludedAncestors: string[]): {
  systemRoDirs: string[];
  systemRoFiles: string[];
  systemSymlinks: { target: string; dest: string }[];
} {
  const systemRoDirs: string[] = [];
  const systemRoFiles: string[] = [];
  const systemSymlinks: { target: string; dest: string }[] = [];

  const collidesWithExcluded = (realDir: string): boolean =>
    excludedAncestors.some(
      (ex) => !!ex && (isPathInsideOrEqual(ex, realDir) || isPathInsideOrEqual(realDir, ex)),
    );

  const tryAddDir = (dir: string) => {
    try {
      const lst = fs.lstatSync(dir);
      if (lst.isSymbolicLink() || !lst.isDirectory()) return;
      const real = safeRealpath(dir);
      if (collidesWithExcluded(real)) return;
      if (!systemRoDirs.includes(real)) systemRoDirs.push(real);
    } catch {
      // absent on this host
    }
  };

  for (const base of ["/usr", "/etc", "/nix", "/home/linuxbrew"]) {
    tryAddDir(base);
  }

  for (const top of ["/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32"]) {
    try {
      const lst = fs.lstatSync(top);
      if (lst.isSymbolicLink()) {
        const target = fs.readlinkSync(top);
        const absTarget = path.resolve("/", target);
        if (systemRoDirs.some((d) => isPathInsideOrEqual(absTarget, d))) {
          systemSymlinks.push({ target, dest: top });
        }
      } else if (lst.isDirectory()) {
        tryAddDir(top);
      }
    } catch {
      // absent on this host
    }
  }

  // 若 /etc/resolv.conf 为指向 /run/systemd/resolve 等只读 DNS 配置的符号链接，仅挂载该单个目标文件
  try {
    const rlst = fs.lstatSync("/etc/resolv.conf");
    if (rlst.isSymbolicLink()) {
      const realResolv = safeRealpath("/etc/resolv.conf");
      if (
        fs.existsSync(realResolv) &&
        !systemRoDirs.some((d) => isPathInsideOrEqual(realResolv, d)) &&
        ["/run/systemd/resolve", "/run/resolvconf", "/run/NetworkManager"].some((prefix) =>
          isPathInsideOrEqual(realResolv, prefix),
        )
      ) {
        systemRoFiles.push(realResolv);
      }
    }
  } catch {
    // ignore
  }

  systemRoDirs.sort((a, b) => a.length - b.length || a.localeCompare(b));
  return { systemRoDirs, systemRoFiles, systemSymlinks };
}

function probeMountMaskBackend(): MountMaskBackend {
  if (cachedMountMaskBackend) return cachedMountMaskBackend;
  const { systemRoDirs, systemRoFiles, systemSymlinks } = collectMinimalSystemRoot([]);
  try {
    const bwrapBin = resolveTrustedBwrapBin();
    if (bwrapBin) {
      const trueBin = resolveTrustedSystemBin("true") ?? "/bin/true";
      const bwrapProbeArgs: string[] = ["--die-with-parent"];
      for (const d of systemRoDirs) bwrapProbeArgs.push("--ro-bind", d, d);
      for (const f of systemRoFiles) bwrapProbeArgs.push("--ro-bind", f, f);
      for (const s of systemSymlinks) bwrapProbeArgs.push("--symlink", s.target, s.dest);
      bwrapProbeArgs.push("--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--tmpfs", "/tmp", "--remount-ro", "/", "--", trueBin);
      const r = spawnSync(bwrapBin, bwrapProbeArgs, {
        env: TRUSTED_BOOTSTRAP_ENV,
        timeout: 3_000,
        stdio: "ignore",
      });
      if (r.status === 0) {
        cachedMountMaskBackend = { kind: "bwrap", bin: bwrapBin };
        return cachedMountMaskBackend;
      }
    }
  } catch {
    // 尝试 unshare + pivot_root + setpriv 降权回退
  }
  try {
    const unshareBin = resolveTrustedSystemBin("unshare");
    const setprivBin = resolveTrustedSystemBin("setpriv");
    const pivotRootBin = resolvePivotRootBin();
    const shBin = resolveTrustedSystemBin("sh");
    if (unshareBin && setprivBin && pivotRootBin && shBin) {
      const probeScript = [
        "set -e",
        `export PATH="${TRUSTED_BOOTSTRAP_PATH}"`,
        'PIVOT="$1"; SP="$2"',
        "mount -n --make-rprivate /",
        "S=",
        "for d in /mnt /media /srv /var/tmp; do [ -d \"$d\" ] && S=\"$d\" && break; done",
        'if [ -z "$S" ]; then exit 1; fi',
        'mount -n -t tmpfs tmpfs "$S"',
        'mkdir -p "$S/newroot"',
        'mount -n -t tmpfs tmpfs "$S/newroot"',
        'mkdir -p "$S/newroot/proc" "$S/newroot/dev" "$S/newroot/tmp" "$S/newroot/usr" "$S/newroot/etc"',
        'mount -n --rbind /proc "$S/newroot/proc"',
        'mount -n -t tmpfs -o mode=755,nosuid tmpfs "$S/newroot/dev"',
        ': > "$S/newroot/dev/null"; mount -n --bind /dev/null "$S/newroot/dev/null"',
        'mount -n -t tmpfs -o mode=1777,nosuid,nodev tmpfs "$S/newroot/tmp"',
        'mount -n --rbind /usr "$S/newroot/usr"; mount -n -o remount,ro,bind "$S/newroot/usr"',
        'mount -n --rbind /etc "$S/newroot/etc"; mount -n -o remount,ro,bind "$S/newroot/etc"',
        'for top in bin sbin lib lib64 lib32 libx32; do',
        '  if [ -L "/$top" ]; then ln -s "$(readlink "/$top")" "$S/newroot/$top"; elif [ -d "/$top" ]; then mkdir -p "$S/newroot/$top"; mount -n --rbind "/$top" "$S/newroot/$top"; mount -n -o remount,ro,bind "$S/newroot/$top"; fi',
        "done",
        'mount -n -o remount,ro,bind "$S/newroot"',
        'mkdir -p "$S/newroot/tmp/.oldroot"',
        'cd "$S/newroot"',
        '"$PIVOT" . tmp/.oldroot',
        "umount -n -l /tmp/.oldroot",
        "rmdir /tmp/.oldroot",
        'exec "$SP" --bounding-set -all --inh-caps -all --ambient-caps -all --no-new-privs true',
      ].join("\n");
      const probeArgsWithKill = [
        "--user",
        "--map-root-user",
        "--mount",
        "--pid",
        "--fork",
        "--mount-proc",
        "--kill-child",
        "--",
        shBin,
        "-c",
        probeScript,
        "_",
        pivotRootBin,
        setprivBin,
      ];
      const rKill = spawnSync(unshareBin, probeArgsWithKill, {
        env: TRUSTED_BOOTSTRAP_ENV,
        timeout: 3_000,
        stdio: "ignore",
      });
      if (rKill.status === 0) {
        cachedMountMaskBackend = { kind: "unshare", bin: unshareBin, setprivBin, pivotRootBin, shBin, killChild: true };
        return cachedMountMaskBackend;
      }
      const r = spawnSync(
        unshareBin,
        ["--user", "--map-root-user", "--mount", "--pid", "--fork", "--mount-proc", "--", shBin, "-c", probeScript, "_", pivotRootBin, setprivBin],
        { env: TRUSTED_BOOTSTRAP_ENV, timeout: 3_000, stdio: "ignore" },
      );
      if (r.status === 0) {
        cachedMountMaskBackend = { kind: "unshare", bin: unshareBin, setprivBin, pivotRootBin, shBin, killChild: false };
        return cachedMountMaskBackend;
      }
    }
  } catch {
    // 均不可用
  }
  cachedMountMaskBackend = { kind: "none" };
  return cachedMountMaskBackend;
}

/** 探测当前宿主机是否具备零特权 PID + 最小白名单只读根挂载命名空间隔离能力（bwrap 或 unshare+pivot_root+setpriv） */
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
  '  return (subp == "" || subp == "/proc" || subp == "/dev" || subp == "/tmp" || subp == "/sys" || index(subp, "/proc/") == 1 || index(subp, "/dev/") == 1 || index(subp, "/tmp/") == 1 || index(subp, "/sys/") == 1)',
  "}",
].join("\n");

const UNSHARE_ISOLATION_SCRIPT = [
  "set -e",
  'ORIG_PATH="${PATH-}"',
  'HAS_ORIG_PATH="${PATH+1}"',
  `export PATH="${TRUSTED_BOOTSTRAP_PATH}"`,
  'PIVOT_ROOT="$1"; SETPRIV="$2"; DD="$3"; CWD="$4"; SYS_COUNT="$5"; SYM_COUNT="$6"; TM_COUNT="$7"; PRE_COUNT="$8"; POST_COUNT="$9"; EXTRA_COUNT="${10}"; M_COUNT="${11}"',
  "shift 11",
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
  // 以空白 tmpfs 作为最小根文件系统（绝不 --rbind /，防止同 OS 用户其他工作区 state.db / feishu-web.json 暴露）
  'mount -n -t tmpfs tmpfs "$S/newroot"',
  'mkdir -p "$S/newroot/proc" "$S/newroot/dev" "$S/newroot/tmp"',
  'mount -n --rbind /proc "$S/newroot/proc"',
  'mount -n -t tmpfs -o mode=755,nosuid tmpfs "$S/newroot/dev"',
  'mkdir -p "$S/newroot/dev/pts" "$S/newroot/dev/shm"',
  'mount -n -t tmpfs -o mode=1777,nosuid,nodev tmpfs "$S/newroot/dev/shm"',
  "for devn in null zero full random urandom tty; do",
  '  if [ -e "/dev/$devn" ]; then : > "$S/newroot/dev/$devn"; mount -n --bind "/dev/$devn" "$S/newroot/dev/$devn"; fi',
  "done",
  'mount -n -t devpts -o newinstance,ptmxmode=0666,mode=0620 devpts "$S/newroot/dev/pts" 2>/dev/null || true',
  'ln -s /proc/self/fd "$S/newroot/dev/fd"',
  'ln -s /proc/self/fd/0 "$S/newroot/dev/stdin"',
  'ln -s /proc/self/fd/1 "$S/newroot/dev/stdout"',
  'ln -s /proc/self/fd/2 "$S/newroot/dev/stderr"',
  'if [ -e "$S/newroot/dev/pts/ptmx" ]; then ln -s pts/ptmx "$S/newroot/dev/ptmx"; elif [ -e /dev/ptmx ]; then : > "$S/newroot/dev/ptmx"; mount -n --bind /dev/ptmx "$S/newroot/dev/ptmx"; fi',
  'mount -n -t tmpfs -o mode=1777,nosuid,nodev tmpfs "$S/newroot/tmp"',
  // 0a) 只读系统根白名单（/usr、/etc、/nix、/home/linuxbrew 等），随后强制验证其及全部子挂载均为 ro
  "i=0",
  'while [ "$i" -lt "$SYS_COUNT" ]; do',
  '  p="$1"; shift',
  '  if [ -d "$p" ]; then mkdir -p "$S/newroot$p"; mount -n --rbind "$p" "$S/newroot$p"; else mkdir -p "$(dirname "$S/newroot$p")"; : > "$S/newroot$p"; mount -n --bind "$p" "$S/newroot$p"; fi',
  "  i=$((i + 1))",
  "done",
  `awk -v prefix="$S/newroot" '${MOUNTINFO_UNESCAPE_AWK}\n{ mp = unescape($5); if (index(mp, prefix "/") == 1) { subp = substr(mp, length(prefix) + 1); if (is_virt(subp)) next; opts = "," $6 ","; if (index(opts, ",ro,") > 0) next; print mp } }' /proc/self/mountinfo > "$S/save/ro-mounts"`,
  'while IFS= read -r mp; do',
  '  [ -n "$mp" ] || continue',
  '  mount -n -o remount,ro,bind "$mp"',
  'done < "$S/save/ro-mounts"',
  `awk -v prefix="$S/newroot" '${MOUNTINFO_UNESCAPE_AWK}\n{ mp = unescape($5); if (index(mp, prefix "/") == 1) { subp = substr(mp, length(prefix) + 1); if (is_virt(subp)) next; opts = "," $6 ","; if (index(opts, ",ro,") == 0) { print "unshare read-only verification failed: " mp > "/dev/stderr"; exit 1 } } }' /proc/self/mountinfo`,
  // 0b) 重建必要的只读目录符号链接（如 /bin -> usr/bin、/home/<user> -> /data00/home/<user>），自身不暴露未挂载路径
  "i=0",
  'while [ "$i" -lt "$SYM_COUNT" ]; do',
  '  target="$1"; dest="$2"; shift 2',
  '  mkdir -p "$(dirname "$S/newroot$dest")"',
  '  [ -e "$S/newroot$dest" ] || [ -L "$S/newroot$dest" ] || ln -s "$target" "$S/newroot$dest"',
  "  i=$((i + 1))",
  "done",
  // 0c) 遮蔽宿主机用户运行时目录（如 /run/user、$XDG_RUNTIME_DIR）
  "i=0",
  'while [ "$i" -lt "$TM_COUNT" ]; do',
  '  p="$1"; shift',
  '  mkdir -p "$S/newroot$p"',
  '  mount -n -t tmpfs tmpfs "$S/newroot$p"',
  "  i=$((i + 1))",
  "done",
  // 第一阶段：挂载位于 dataDir 之外（含显式允许的工具链与当前仓库路径）的白名单路径
  "i=0",
  'while [ "$i" -lt "$PRE_COUNT" ]; do',
  '  mode="$1"; p="$2"; shift 2',
  '  if [ -d "$p" ]; then [ -d "$S/newroot$p" ] || mkdir -p "$S/newroot$p"; else [ -e "$S/newroot$p" ] || { mkdir -p "$(dirname "$S/newroot$p")"; : > "$S/newroot$p"; }; fi',
  '  mount -n --bind "$p" "$S/newroot$p"',
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
  '  mode="$1"; p="$2"; shift 2',
  '  if [ -d "$p" ]; then [ -d "$S/newroot$p" ] || mkdir -p "$S/newroot$p"; else [ -e "$S/newroot$p" ] || { mkdir -p "$(dirname "$S/newroot$p")"; : > "$S/newroot$p"; }; fi',
  '  mount -n --bind "$p" "$S/newroot$p"',
  '  if [ "$mode" = "ro" ]; then mount -n -o remount,ro,bind "$S/newroot$p"; else mount -n -o remount,rw,bind "$S/newroot$p"; fi',
  "  i=$((i + 1))",
  "done",
  // 第四阶段：异路径投影绑定（如私有 ~/.acpx、脱敏 ~/.npmrc、暂存 Doubao 数据目录）
  "i=0",
  'while [ "$i" -lt "$EXTRA_COUNT" ]; do',
  '  mode="$1"; src="$2"; dest="$3"; shift 3',
  '  if [ -d "$src" ]; then [ -d "$S/newroot$dest" ] || mkdir -p "$S/newroot$dest"; else [ -e "$S/newroot$dest" ] || { mkdir -p "$(dirname "$S/newroot$dest")"; : > "$S/newroot$dest"; }; fi',
  '  mount -n --bind "$src" "$S/newroot$dest"',
  '  if [ "$mode" = "ro" ]; then mount -n -o remount,ro,bind "$S/newroot$dest"; else mount -n -o remount,rw,bind "$S/newroot$dest"; fi',
  "  i=$((i + 1))",
  "done",
  'if [ -n "$DD" ]; then',
  '  mount -n -o remount,ro,bind "$S/newroot$DD"',
  "fi",
  "i=0",
  'while [ "$i" -lt "$M_COUNT" ]; do',
  '  p="$1"; shift',
  '  if [ -e "$S/newroot$p" ]; then mount -n --bind /dev/null "$S/newroot$p"; fi',
  "  i=$((i + 1))",
  "done",
  // 锁定新根自身为只读（不递归影响 /tmp 与显式 rw 挂载）
  'mount -n -o remount,ro,bind "$S/newroot"',
  `awk -v prefix="$S/newroot" '${MOUNTINFO_UNESCAPE_AWK}\n{ mp = unescape($5); if (mp == prefix) { opts = "," $6 ","; if (index(opts, ",ro,") == 0) { print "unshare root read-only verification failed" > "/dev/stderr"; exit 1 } } }' /proc/self/mountinfo`,
  'mkdir -p "$S/newroot/tmp/.oldroot"',
  'cd "$S/newroot"',
  '"$PIVOT_ROOT" . tmp/.oldroot',
  'if [ -n "$TMP_STAGE" ]; then umount -n -l "/tmp/.oldroot$TMP_STAGE" 2>/dev/null || true; rmdir "/tmp/.oldroot$TMP_STAGE" 2>/dev/null || true; fi',
  "umount -n -l /tmp/.oldroot",
  "rmdir /tmp/.oldroot",
  'if [ -n "$CWD" ]; then cd "$CWD"; fi',
  'if [ -n "$HAS_ORIG_PATH" ]; then export PATH="$ORIG_PATH"; else unset PATH; fi',
  'exec "$SETPRIV" --bounding-set -all --inh-caps -all --ambient-caps -all --no-new-privs "$@"',
].join("\n");

/**
 * 为模型执行器、仓库校验命令、git 子进程等同 UID 不可信子进程提供内核级进程与最小白名单空根挂载隔离：
 *   - 只要当前进程持有密钥，或工作区启用了个人 Web / 存有私有状态（即使交互式 shell 本身未持有密钥），均强制激活隔离；
 *   - 无论是 `bwrap` 还是 `unshare + pivot_root + setpriv` 均从空白 tmpfs 根起步（绝不挂载整棵 `/`、`/home`、`$HOME` 或 `/data00`），
 *     仅按白名单只读暴露核心 OS 目录（`/usr`、`/etc`、usrmerge 符号链接、允许的工具链）及当前任务显式需要的仓库/目录，
 *     使同 OS 用户下其他工作区的 `state.db`、`feishu-web.json` 与个人文件彻底不可见；
 *   - 随后以空 `tmpfs` 遮蔽当前 `dataDir` 并仅恢复显式允许的子路径（如当前派单 worktree / `guard.log`），
 *     对任何被暴露的密钥/外部凭据/宿主套接字叠加 `/dev/null` 遮罩，并将根 `/` 锁定为只读；
 *   - 宿主机不支持时按 fail-closed 拒绝启动子进程。
 */
export function isolatedSandboxTempEnv(): Record<string, string> {
  return {
    TMPDIR: "/tmp",
    XDG_CACHE_HOME: "/tmp/.pa-cache",
    XDG_STATE_HOME: "/tmp/.pa-state",
    XDG_RUNTIME_DIR: "/tmp/.pa-run",
    npm_config_cache: "/tmp/.pa-npm-cache",
    NPM_CONFIG_CACHE: "/tmp/.pa-npm-cache",
    npm_config_logs_dir: "/tmp/.pa-npm-cache/_logs",
    npm_config_update_notifier: "false",
  };
}

export function willIsolateCommand(rawEnv: NodeJS.ProcessEnv, opts?: IsolationOptions): boolean {
  const credDir = rawEnv.CREDENTIALS_DIRECTORY?.trim();
  const keyFile = credDir ? path.join(credDir, FEISHU_WEB_KEY_CRED) : "";
  const hasCredKeyFile = !!keyFile && fs.existsSync(keyFile);
  const hasEnvKey = !!(rawEnv.PA_FEISHU_WEB_KEY?.trim());
  const extCredFile = rawEnv.PA_FEISHU_WEB_CRED_FILE?.trim() ? path.resolve(rawEnv.PA_FEISHU_WEB_CRED_FILE.trim()) : "";
  const needByWorkspace =
    !!opts?.requireIsolation ||
    (!!opts?.dataDir && workspaceRequiresIsolation(opts.dataDir, rawEnv));
  return hasCredKeyFile || hasEnvKey || !!extCredFile || needByWorkspace;
}

export function wrapCredentialIsolatedCommand(
  cmd: string,
  args: string[],
  rawEnv: NodeJS.ProcessEnv = process.env,
  opts?: IsolationOptions,
): { cmd: string; args: string[]; isolated: boolean } {
  const credDir = rawEnv.CREDENTIALS_DIRECTORY?.trim();
  const keyFile = credDir ? path.join(credDir, FEISHU_WEB_KEY_CRED) : "";
  const hasCredKeyFile = !!keyFile && fs.existsSync(keyFile);
  const extCredFile = rawEnv.PA_FEISHU_WEB_CRED_FILE?.trim() ? path.resolve(rawEnv.PA_FEISHU_WEB_CRED_FILE.trim()) : "";
  if (!willIsolateCommand(rawEnv, opts)) {
    return { cmd, args, isolated: false };
  }

  const resolvedDataDir = opts?.dataDir && fs.existsSync(opts.dataDir) ? safeRealpath(opts.dataDir) : "";
  const resolvedCwd = opts?.cwd && fs.existsSync(opts.cwd) ? safeRealpath(opts.cwd) : "";
  const rawHome = rawEnv.HOME?.trim() || os.homedir();
  const resolvedHome = rawHome ? safeRealpath(rawHome) : "";

  const { systemRoDirs, systemRoFiles, systemSymlinks } = collectMinimalSystemRoot([resolvedDataDir, resolvedHome]);
  const isCoveredBySystemRo = (real: string): boolean =>
    systemRoDirs.some((d) => isPathInsideOrEqual(real, d)) || systemRoFiles.includes(real);

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

  // 自动发现工具链路径时严禁误挂宽泛根目录、$HOME 及其祖先（如 /data00/home/<user>）、dataDir 或含其他工作区状态库的目录
  const isBroadOrUnsafeAutoMount = (real: string): boolean => {
    if (BROAD_UNSAFE_AUTO_MOUNT_ROOTS.has(real)) return true;
    if (resolvedDataDir && (isPathInsideOrEqual(real, resolvedDataDir) || isPathInsideOrEqual(resolvedDataDir, real))) {
      return true;
    }
    if (resolvedHome && isPathInsideOrEqual(resolvedHome, real)) return true;
    if (fs.existsSync(path.join(real, "state.db")) || fs.existsSync(path.join(real, "feishu-web.json"))) {
      return true;
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
  // 即使被显式路径触及，也以空 tmpfs 彻底隐藏宿主机运行时目录后再按需恢复显式允许路径。
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

  // 宿主机 systemd 凭据目录（含 feishu-web-key）：只读暴露整个目录以便无关凭据可读，随后用 maskFiles 把 feishu-web-key 遮为 /dev/null
  if (hasCredKeyFile && credDir && fs.existsSync(credDir)) {
    rawReadOnly.push(safeRealpath(credDir));
  }

  // 自动放行当前运行所需的只读可执行文件及其 npm/独立包运行时依赖（绝不暴露 $HOME、ROOT 或其他工作区）
  const resolvedRoot = safeRealpath(ROOT);
  const candidateFileSymlinks: { dest: string; target: string; parentReal: string }[] = [];
  const collectExecutableRuntimeDeps = (logicalBin: string | undefined, realBin: string | undefined) => {
    if (!realBin || !fs.existsSync(realBin) || isForbiddenDaemonTarget(realBin)) return;
    if (!isCoveredBySystemRo(realBin)) rawReadOnly.push(realBin);

    if (logicalBin && path.isAbsolute(logicalBin)) {
      try {
        const lst = fs.lstatSync(logicalBin);
        if (lst.isSymbolicLink()) {
          const parentReal = safeRealpath(path.dirname(logicalBin));
          const linkDest = path.join(parentReal, path.basename(logicalBin));
          candidateFileSymlinks.push({ dest: linkDest, target: fs.readlinkSync(logicalBin), parentReal });
        }
      } catch {
        // ignore stat error on logical path
      }
    }

    if (isCoveredBySystemRo(realBin)) return;

    const isSafePkgDir = (dir: string): boolean => {
      if (!dir || dir === resolvedRoot || isBroadOrUnsafeAutoMount(dir) || isCoveredBySystemRo(dir)) return false;
      // 严禁因 bin/guard/lark-cli 等内部路径意外把整个 Avatar 仓库挂载进来
      if (isPathInsideOrEqual(resolvedRoot, dir)) return false;
      return true;
    };

    const findNpmPackageRoot = (filePath: string): { pkgRoot: string; fromNodeModules: boolean } | undefined => {
      const norm = path.resolve(filePath);
      const parts = norm.split(path.sep).filter(Boolean);
      const lastNm = parts.lastIndexOf("node_modules");
      if (lastNm >= 0 && lastNm + 1 < parts.length) {
        const firstSeg = parts[lastNm + 1];
        if (firstSeg.startsWith("@") && lastNm + 2 < parts.length) {
          const pkgRoot = path.sep + parts.slice(0, lastNm + 3).join(path.sep);
          if (fs.existsSync(pkgRoot) && fs.statSync(pkgRoot).isDirectory()) {
            return { pkgRoot: safeRealpath(pkgRoot), fromNodeModules: true };
          }
        } else if (!firstSeg.startsWith(".")) {
          const pkgRoot = path.sep + parts.slice(0, lastNm + 2).join(path.sep);
          if (fs.existsSync(pkgRoot) && fs.statSync(pkgRoot).isDirectory()) {
            return { pkgRoot: safeRealpath(pkgRoot), fromNodeModules: true };
          }
        }
      }
      // 独立安装的包目录（非 node_modules 布局）：向上最多查找 4 层 package.json，绝不跨越 ROOT 或 $HOME
      let cur = path.dirname(norm);
      for (let depth = 0; depth < 4; depth++) {
        if (!cur || cur === path.dirname(cur) || cur === resolvedRoot || isBroadOrUnsafeAutoMount(cur)) break;
        const pj = path.join(cur, "package.json");
        try {
          if (fs.existsSync(pj) && fs.statSync(pj).isFile()) {
            return { pkgRoot: safeRealpath(cur), fromNodeModules: false };
          }
        } catch {
          break;
        }
        cur = path.dirname(cur);
      }
      return undefined;
    };

    const found = findNpmPackageRoot(realBin);
    if (!found) {
      // 非 npm 包的独立封装脚本（如 ~/scripts/tool 调同目录 tool.mjs）：仅当父目录窄且安全（绝非 ROOT、$HOME、/tmp、dataDir 且不含 config.yaml）时只读挂载该父目录
      const binDir = path.dirname(realBin);
      if (isSafePkgDir(binDir) && !fs.existsSync(path.join(binDir, "config.yaml"))) {
        rawReadOnly.push(binDir);
      }
      return;
    }
    const { pkgRoot } = found;
    if (!isSafePkgDir(pkgRoot)) return;

    const visitedPkgs = new Set<string>();
    const queue: string[] = [pkgRoot];
    const MAX_PKG_VISITS = 512;

    const resolveDepInAncestors = (fromPkgDir: string, depName: string): { logical: string; real: string } | undefined => {
      const depSegments = depName.split("/");
      let cur = fromPkgDir;
      for (let depth = 0; depth < 12; depth++) {
        const cand = path.join(cur, "node_modules", ...depSegments);
        try {
          if (fs.existsSync(cand) && fs.statSync(cand).isDirectory()) {
            return { logical: cand, real: safeRealpath(cand) };
          }
        } catch {
          // try parent
        }
        const parent = path.dirname(cur);
        if (!parent || parent === cur || isBroadOrUnsafeAutoMount(parent)) break;
        cur = parent;
      }
      return undefined;
    };

    while (queue.length > 0 && visitedPkgs.size < MAX_PKG_VISITS) {
      const curPkg = queue.shift()!;
      if (visitedPkgs.has(curPkg) || !isSafePkgDir(curPkg)) continue;
      visitedPkgs.add(curPkg);
      rawReadOnly.push(curPkg);

      // 若该包位于 pnpm `.pnpm/<id>/node_modules/<pkg>` 中，顺带放行其同级 `.pnpm/<id>/node_modules` 以便符号链接可见
      const nmParent = path.basename(path.dirname(curPkg)).startsWith("@")
        ? path.dirname(path.dirname(curPkg))
        : path.dirname(curPkg);
      if (path.basename(nmParent) === "node_modules" && nmParent.includes(`${path.sep}.pnpm${path.sep}`)) {
        if (isSafePkgDir(nmParent)) rawReadOnly.push(nmParent);
      }

      // 扫描包内自带 node_modules 的外部符号链接（兼容 pnpm / workspace 链接）
      const nestedNm = path.join(curPkg, "node_modules");
      try {
        if (fs.existsSync(nestedNm) && fs.statSync(nestedNm).isDirectory()) {
          for (const ent of fs.readdirSync(nestedNm, { withFileTypes: true })) {
            const p = path.join(nestedNm, ent.name);
            if (ent.name.startsWith("@")) {
              try {
                if (fs.statSync(p).isDirectory()) {
                  for (const sub of fs.readdirSync(p, { withFileTypes: true })) {
                    const sp = path.join(p, sub.name);
                    try {
                      if (fs.lstatSync(sp).isSymbolicLink() && fs.statSync(sp).isDirectory()) {
                        const sr = safeRealpath(sp);
                        if (!visitedPkgs.has(sr)) queue.push(sr);
                      }
                    } catch {
                      // ignore broken link
                    }
                  }
                }
              } catch {
                // ignore
              }
            } else {
              try {
                if (fs.lstatSync(p).isSymbolicLink() && fs.statSync(p).isDirectory()) {
                  const r = safeRealpath(p);
                  if (!visitedPkgs.has(r)) queue.push(r);
                }
              } catch {
                // ignore
              }
            }
          }
        }
      } catch {
        // ignore unreadable nested node_modules
      }

      // 递归解析 package.json 中的运行时依赖（dependencies / optionalDependencies / peerDependencies）
      const pjPath = path.join(curPkg, "package.json");
      try {
        const pjSt = fs.statSync(pjPath);
        if (pjSt.isFile() && pjSt.size <= 1024 * 1024) {
          const pj = JSON.parse(fs.readFileSync(pjPath, "utf8")) as Record<string, unknown>;
          const depNames = new Set<string>();
          for (const field of ["dependencies", "optionalDependencies", "peerDependencies"] as const) {
            const block = pj[field];
            if (block && typeof block === "object" && !Array.isArray(block)) {
              for (const k of Object.keys(block as Record<string, unknown>)) {
                if (k && !k.includes("..") && !path.isAbsolute(k)) depNames.add(k);
              }
            }
          }
          for (const depName of depNames) {
            const resolvedDep = resolveDepInAncestors(curPkg, depName);
            if (!resolvedDep) continue;
            if (resolvedDep.logical !== resolvedDep.real) {
              const depNmDir = depName.includes("/")
                ? path.dirname(path.dirname(resolvedDep.logical))
                : path.dirname(resolvedDep.logical);
              if (isSafePkgDir(depNmDir)) {
                try {
                  const lst = fs.lstatSync(resolvedDep.logical);
                  if (lst.isSymbolicLink()) {
                    const pReal = safeRealpath(path.dirname(resolvedDep.logical));
                    candidateFileSymlinks.push({
                      dest: path.join(pReal, path.basename(resolvedDep.logical)),
                      target: fs.readlinkSync(resolvedDep.logical),
                      parentReal: pReal,
                    });
                  }
                } catch {
                  // ignore
                }
              }
            }
            if (!visitedPkgs.has(resolvedDep.real)) queue.push(resolvedDep.real);
          }
        }
      } catch {
        // ignore missing or unparseable package.json
      }
    }
  };

  const pathEnv = rawEnv.PATH || process.env.PATH || "";
  const resolvedExec = safeRealpath(process.execPath);
  if (fs.existsSync(resolvedExec) && !isCoveredBySystemRo(resolvedExec)) {
    const execParent = path.dirname(resolvedExec);
    const execPrefix = path.basename(execParent) === "bin" ? path.dirname(execParent) : execParent;
    if (!isBroadOrUnsafeAutoMount(execPrefix)) rawReadOnly.push(execPrefix);
    else if (!isBroadOrUnsafeAutoMount(execParent)) rawReadOnly.push(execParent);
    else if (!isForbiddenDaemonTarget(resolvedExec)) rawReadOnly.push(resolvedExec);
  }

  const resolvedCmdLogical = resolveBinInPath(cmd, pathEnv);
  const resolvedCmdReal = resolvedCmdLogical ? safeRealpath(resolvedCmdLogical) : undefined;
  collectExecutableRuntimeDeps(resolvedCmdLogical, resolvedCmdReal);

  const extraCmdLogical = opts?.cmdPath ? resolveBinInPath(opts.cmdPath, pathEnv) : undefined;
  const extraCmdReal = extraCmdLogical ? safeRealpath(extraCmdLogical) : undefined;
  collectExecutableRuntimeDeps(extraCmdLogical, extraCmdReal);

  const extraCmdLogicalList: (string | undefined)[] = [];
  for (const rawExtraCmd of opts?.extraCmdPaths ?? []) {
    const l = rawExtraCmd ? resolveBinInPath(rawExtraCmd, pathEnv) : undefined;
    const r = l ? safeRealpath(l) : undefined;
    extraCmdLogicalList.push(l);
    collectExecutableRuntimeDeps(l, r);
  }

  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir || !path.isAbsolute(dir) || !fs.existsSync(dir)) continue;
    try {
      const realDir = safeRealpath(dir);
      if (!fs.statSync(realDir).isDirectory()) continue;
      if (isCoveredBySystemRo(realDir) || isBroadOrUnsafeAutoMount(realDir)) continue;
      let candidate = realDir;
      if (resolvedHome && isPathInsideOrEqual(realDir, resolvedHome)) {
        const matchedSub = USER_TOOLCHAIN_SUBDIRS.find((sub) => {
          const subReal = safeRealpath(path.join(resolvedHome, sub));
          return isPathInsideOrEqual(realDir, subReal);
        });
        if (matchedSub) {
          const subReal = safeRealpath(path.join(resolvedHome, matchedSub));
          if (!isBroadOrUnsafeAutoMount(subReal)) candidate = subReal;
        }
      }
      if (!isBroadOrUnsafeAutoMount(candidate)) {
        rawReadOnly.push(candidate);
      }
    } catch {
      // skip unreadable PATH entry
    }
  }

  const readOnlyPaths = dedupeSorted(rawReadOnly).filter((p) => !writableSet.has(p) && !isCoveredBySystemRo(p));

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

  const extraBindMounts: { mode: "ro" | "rw"; src: string; dest: string }[] = [];
  const seenExtraBindDests = new Set<string>();
  for (const rawEntry of opts?.extraBindMounts ?? []) {
    if (!rawEntry?.src || !rawEntry?.dest) continue;
    if (!fs.existsSync(rawEntry.src)) continue;
    const realSrc = safeRealpath(rawEntry.src);
    if (isForbiddenDaemonTarget(realSrc)) continue;
    const realDest = resolveMountDestRealpath(rawEntry.dest);
    if (!realDest || realDest === "/") continue;
    if (resolvedDataDir && (realDest === resolvedDataDir || isPathInsideOrEqual(realDest, resolvedDataDir))) {
      continue;
    }
    if (seenExtraBindDests.has(realDest)) continue;
    seenExtraBindDests.add(realDest);
    extraBindMounts.push({ mode: rawEntry.mode, src: realSrc, dest: realDest });
  }
  extraBindMounts.sort((a, b) => a.dest.length - b.dest.length || a.dest.localeCompare(b.dest));

  // 收集逻辑路径上的目录符号链接（例如 /home/<user> -> /data00/home/<user>），
  // 在空白 tmpfs 根中重建它们使逻辑路径与 realpath 均可用，且绝不暴露未挂载的同级工作区文件。
  const allRealMountTargets = [
    ...systemRoDirs,
    ...systemRoFiles,
    ...runtimeMaskDirs,
    ...preMounts.map((m) => m.path),
    ...(resolvedDataDir ? [resolvedDataDir] : []),
    ...postMounts.map((m) => m.path),
    ...extraBindMounts.map((m) => m.dest),
  ];
  const symlinkMap = new Map<string, string>();
  for (const s of systemSymlinks) symlinkMap.set(s.dest, s.target);
  const logicalCandidates: (string | undefined)[] = [
    rawHome,
    os.homedir(),
    opts?.cwd,
    opts?.dataDir,
    resolvedCmdLogical,
    extraCmdLogical,
    ...extraCmdLogicalList,
    ...(opts?.writablePaths ?? []),
    ...(opts?.readOnlyPaths ?? []),
    ...(opts?.extraSymlinks ?? []).map((s) => s.dest),
    ...(opts?.extraBindMounts ?? []).map((m) => m.dest),
    ...pathEnv.split(path.delimiter).filter((d) => path.isAbsolute(d)),
  ];
  for (const [dest, target] of collectDirectorySymlinksAlongPaths(logicalCandidates)) {
    if (symlinkMap.has(dest)) continue;
    // 确保符号链接位置不与任何真实挂载点或其祖先冲突
    if (allRealMountTargets.some((mp) => mp === dest || isPathInsideOrEqual(mp, dest))) continue;
    symlinkMap.set(dest, target);
  }
  const dirSymlinks = [...symlinkMap.entries()]
    .map(([dest, target]) => ({ dest, target }))
    .sort((a, b) => a.dest.length - b.dest.length || a.dest.localeCompare(b.dest));

  // 补建未被挂载目录覆盖的可执行/依赖/配置文件符号链接（如绝对路径调用 npm 全局命令或 dotfiles ~/.gitconfig）；
  // 在 bwrap 中必须放在 --tmpfs /tmp 与 dataDir tmpfs 之后创建，防止 /tmp 下的文件符号链接被 --tmpfs /tmp 抹除。
  const fileSymlinkMap = new Map<string, string>();
  const allFileSymlinkCandidates: { dest: string; target: string }[] = [
    ...candidateFileSymlinks,
    ...(opts?.extraSymlinks ?? []),
  ];
  for (const fsym of allFileSymlinkCandidates) {
    if (symlinkMap.has(fsym.dest) || fileSymlinkMap.has(fsym.dest)) continue;
    if (allRealMountTargets.some((mp) => isPathInsideOrEqual(fsym.dest, mp) || isPathInsideOrEqual(mp, fsym.dest))) {
      continue;
    }
    fileSymlinkMap.set(fsym.dest, fsym.target);
  }
  const fileSymlinks = [...fileSymlinkMap.entries()]
    .map(([dest, target]) => ({ dest, target }))
    .sort((a, b) => a.dest.length - b.dest.length || a.dest.localeCompare(b.dest));
  const allSymlinks = [...dirSymlinks, ...fileSymlinks];

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
  const isReExposedByExtraBind = (p: string): boolean =>
    extraBindMounts.some((m) => isPathInsideOrEqual(p, m.dest));
  const maskFiles = [...new Set(rawMasks.map((m) => safeRealpath(m)).filter((m) => fs.existsSync(m)))].filter((m) => {
    // 位于 dataDir 内的文件已被空 tmpfs 遮蔽，仅当被 postMounts 重新暴露时才需额外 /dev/null 遮罩
    if (resolvedDataDir && isPathInsideOrEqual(m, resolvedDataDir)) {
      return isReExposedBy(m, postMounts);
    }
    // 位于 /tmp、/dev/shm 或已遮蔽用户运行时目录内的文件已被空 tmpfs 隐藏，仅当被 preMounts 或 extraBindMounts 重新暴露时才需额外 /dev/null 遮罩
    if (isHiddenByEphemeralTmpfs(m)) {
      return isReExposedBy(m, preMounts) || isReExposedByExtraBind(m);
    }
    // 空白根下只有落入系统只读根、preMounts、postMounts 或 extraBindMounts 内的文件才可见，才需要叠加 /dev/null 遮罩
    return isCoveredBySystemRo(m) || isReExposedBy(m, preMounts) || isReExposedBy(m, postMounts) || isReExposedByExtraBind(m);
  });

  const systemRoAll = [...systemRoDirs, ...systemRoFiles];
  const backend = opts?.forceBackend ?? probeMountMaskBackend();
  if (backend.kind === "bwrap") {
    const bwrapArgs: string[] = ["--die-with-parent"];
    for (const p of systemRoAll) {
      bwrapArgs.push("--ro-bind", p, p);
    }
    for (const s of dirSymlinks) {
      bwrapArgs.push("--symlink", s.target, s.dest);
    }
    bwrapArgs.push("--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--tmpfs", "/tmp");
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
    for (const em of extraBindMounts) {
      bwrapArgs.push(em.mode === "ro" ? "--ro-bind" : "--bind", em.src, em.dest);
    }
    for (const s of fileSymlinks) {
      bwrapArgs.push("--symlink", s.target, s.dest);
    }
    if (resolvedDataDir) {
      bwrapArgs.push("--remount-ro", resolvedDataDir);
    }
    for (const mf of maskFiles) {
      bwrapArgs.push("--bind", "/dev/null", mf);
    }
    bwrapArgs.push("--remount-ro", "/");
    if (resolvedCwd) {
      bwrapArgs.push("--chdir", resolvedCwd);
    }
    return { cmd: backend.bin, args: [...bwrapArgs, "--", cmd, ...args], isolated: true };
  }
  if (backend.kind === "unshare") {
    if (!backend.setprivBin || !backend.pivotRootBin) {
      throw new Error("unshare 回退缺少 setpriv 或 pivot_root，无法构建最小只读根挂载视图并永久剥离权限，已按安全策略拒绝执行");
    }
    const shBin = backend.shBin ?? resolveTrustedSystemBin("sh") ?? "/bin/sh";
    const flatten = (list: MountEntry[]): string[] => list.flatMap((m) => [m.mode, m.path]);
    const flattenExtra = (list: { mode: "ro" | "rw"; src: string; dest: string }[]): string[] =>
      list.flatMap((m) => [m.mode, m.src, m.dest]);
    const flattenSyms = (list: { target: string; dest: string }[]): string[] => list.flatMap((s) => [s.target, s.dest]);
    const unshareArgs = [
      "--user",
      "--map-root-user",
      "--mount",
      "--pid",
      "--fork",
      "--mount-proc",
      ...(backend.killChild !== false ? ["--kill-child"] : []),
      "--",
      shBin,
      "-c",
      UNSHARE_ISOLATION_SCRIPT,
      "_",
      backend.pivotRootBin,
      backend.setprivBin,
      resolvedDataDir,
      resolvedCwd,
      String(systemRoAll.length),
      String(allSymlinks.length),
      String(runtimeMaskDirs.length),
      String(preMounts.length),
      String(postMounts.length),
      String(extraBindMounts.length),
      String(maskFiles.length),
      ...systemRoAll,
      ...flattenSyms(allSymlinks),
      ...runtimeMaskDirs,
      ...flatten(preMounts),
      ...flatten(postMounts),
      ...flattenExtra(extraBindMounts),
      ...maskFiles,
      cmd,
      ...args,
    ];
    return { cmd: backend.bin, args: unshareArgs, isolated: true };
  }
  throw new Error(
    "检测到当前环境持有个人 Web 加密密钥或工作区存在个人 Web/私有上下文状态，" +
      "但宿主机不支持 bwrap 或带 pivot_root+setpriv 降权的 unshare PID+最小只读根挂载命名空间隔离；" +
      "为防止同 UID 子进程读写本工作区或其他工作区的 dataDir/state.db、读取密钥文件或通过 /proc/<daemon-pid> 检查常驻进程，已拒绝执行。请安装 bubblewrap 或将不可信 worker 运行在独立 OS 用户身份下。",
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

/** 创建 0700 临时凭据投影目录（优先放入易失 tmpfs，不可用时回退 os.tmpdir()），并注册进程退出兜底清理 */
export function createScopedSecretDir(
  prefix: string,
  env: NodeJS.ProcessEnv = process.env,
): { dir: string; cleanup: () => void } {
  const base = findVolatileTmpfsBase(env) ?? os.tmpdir();
  const dir = safeRealpath(fs.mkdtempSync(path.join(base, prefix)));
  fs.chmodSync(dir, 0o700);
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    process.off("exit", cleanup);
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  };
  process.once("exit", cleanup);
  return { dir, cleanup };
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
  opts?: { tmpfsCandidates?: string[]; preserveSshAgent?: boolean; preserveDbusSession?: boolean },
): { env: NodeJS.ProcessEnv; cleanup: () => void } {
  const clean: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(env)) {
    if (k.startsWith("PA_FEISHU_WEB_")) continue;
    if (STRIPPED_HOST_SOCKET_ENVS.has(k)) {
      if (k === "DBUS_SESSION_BUS_ADDRESS" && opts?.preserveDbusSession) {
        clean[k] = v;
      }
      continue;
    }
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

const NON_OPENAI_BUILTIN_CODEX_PROVIDERS = new Set(["ollama", "lmstudio", "amazon-bedrock", "gcp"]);
const AUTH_HEADER_NAME_RE = /^(authorization|x-api-key|api-key)$/i;

/**
 * 区分「配置文件确实不存在（ENOENT）」与「配置目录/文件本身是损坏符号链接、不可读、非普通文件或过大」：
 * 绝不使用 existsSync 静默把损坏的 dotfiles 符号链接当作缺省配置处理（防止私聊误发往默认 OpenAI 供应商）。
 */
function inspectCodexConfigPath(
  codexHome: string,
  configPath: string,
): { exists: boolean; rawContent?: string; error?: string } {
  try {
    const homeLst = fs.lstatSync(codexHome);
    try {
      const homeSt = fs.statSync(codexHome);
      if (!homeSt.isDirectory()) {
        return { exists: true, error: `Codex 配置目录 (${codexHome}) 不是目录` };
      }
    } catch (err) {
      const why = homeLst.isSymbolicLink() ? "符号链接目标不可达或已损坏" : "不可访问";
      return { exists: true, error: `Codex 配置目录 (${codexHome}) ${why}：${errMsg(err)}` };
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === "ENOENT" || code === "ENOTDIR") return { exists: false };
    return { exists: true, error: `无法访问 Codex 配置目录 (${codexHome})：${errMsg(err)}` };
  }

  let lst: fs.Stats;
  try {
    lst = fs.lstatSync(configPath);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === "ENOENT" || code === "ENOTDIR") return { exists: false };
    return { exists: true, error: `无法访问 Codex 配置文件 (${configPath})：${errMsg(err)}` };
  }

  let st: fs.Stats;
  try {
    st = fs.statSync(configPath);
  } catch (err) {
    const why = lst.isSymbolicLink() ? "符号链接目标不可达或已损坏" : "无法读取文件状态";
    return { exists: true, error: `Codex 配置文件 (${configPath}) ${why}：${errMsg(err)}` };
  }

  if (!st.isFile() || st.size > MAX_CODEX_CONFIG_BYTES) {
    return { exists: true, error: `Codex 配置文件 (${configPath}) 不是合法普通文件或体积超过限制` };
  }

  try {
    return { exists: true, rawContent: fs.readFileSync(configPath, "utf8") };
  } catch (err) {
    return { exists: true, error: `无法读取 Codex 配置文件 (${configPath})：${errMsg(err)}` };
  }
}

/**
 * 轻量解析某组 env + extraArgs 下 Codex 生效的凭据存储、供应商及是否真正依赖 OpenAI/ChatGPT keyring 登录态
 * （供 Linux 隔离沙箱预检、runCodexExec 与 doctor 共用）。
 */
export function resolveEffectiveCodexCredentialStore(
  env: NodeJS.ProcessEnv,
  extraArgs: string[],
  opts?: { ignoreProfiles?: boolean },
): {
  store?: string;
  codexHome: string;
  hasConfig: boolean;
  provider: string;
  profile?: string;
  forcedLoginMethod?: string;
  needsCredentialStore: boolean;
  awsProfile?: string;
  configError?: string;
} {
  const effectiveHome = env.HOME?.trim() || os.homedir();
  const codexHome = env.CODEX_HOME?.trim() || path.join(effectiveHome, ".codex");
  const configPath = path.join(codexHome, "config.toml");

  let cliProfile: string | undefined;
  let extraConfigProfile: string | undefined;
  let extraStore: string | undefined;
  let extraProvider: string | undefined;
  let extraForcedLogin: string | undefined;
  const extraProviders = new Map<string, TomlTable>();
  const ensureExtra = (name: string): TomlTable => {
    let t = extraProviders.get(name);
    if (!t) {
      t = Object.create(null) as TomlTable;
      extraProviders.set(name, t);
    }
    return t;
  };
  const mergeSub = (target: TomlTable, subKey: string, entries: TomlTable) => {
    const cur = target[subKey];
    const sub: TomlTable = isPlainTable(cur) ? cur : (Object.create(null) as TomlTable);
    for (const [k, v] of Object.entries(entries)) sub[k] = v;
    target[subKey] = sub;
  };
  const mergeProviderInto = (dst: TomlTable, src: TomlTable | undefined) => {
    if (!src) return;
    for (const [k, v] of Object.entries(src)) {
      if (isPlainTable(v)) mergeSub(dst, k, v);
      else dst[k] = v;
    }
  };

  const scanExpr = (expr: string) => {
    const parsed = parseCliConfigAssignment(expr);
    if (!parsed) return;
    try {
      const segs = parseTomlKeyPath(parsed.key);
      const val = parseCliTomlOrLiteral(parsed.key, parsed.value);
      if (segs.length === 1) {
        if (segs[0] === "cli_auth_credentials_store" && typeof val === "string") extraStore = val.trim();
        else if (segs[0] === "model_provider" && typeof val === "string" && val.trim()) extraProvider = val.trim();
        else if (segs[0] === "forced_login_method" && typeof val === "string" && val.trim()) extraForcedLogin = val.trim();
        else if (segs[0] === "profile" && typeof val === "string" && val.trim()) extraConfigProfile = val.trim();
        else if (segs[0] === "model_providers" && isPlainTable(val)) {
          for (const [pName, pDef] of Object.entries(val)) {
            if (!isPlainTable(pDef)) continue;
            mergeProviderInto(ensureExtra(pName), pDef);
          }
        }
      } else if (segs[0] === "model_providers" && segs.length >= 3) {
        const dst = ensureExtra(segs[1]);
        const field = segs[2];
        if (segs.length === 3) {
          if (isPlainTable(val)) mergeSub(dst, field, val);
          else dst[field] = val;
        } else if (segs.length === 4 && (field === "http_headers" || field === "env_http_headers" || field === "aws")) {
          mergeSub(dst, field, { [segs[3]]: val });
        }
      }
    } catch {
      // 语法错误由严格提取阶段统一报错
    }
  };
  for (let i = 0; i < extraArgs.length; i++) {
    const a = extraArgs[i];
    if ((a === "-c" || a === "--config") && extraArgs[i + 1]) {
      scanExpr(extraArgs[++i]);
    } else if (a.startsWith("--config=")) {
      scanExpr(a.slice("--config=".length));
    } else if ((a === "-p" || a === "--profile") && extraArgs[i + 1]) {
      const p = extraArgs[++i].trim();
      if (p) cliProfile = p;
    } else if (a.startsWith("--profile=")) {
      const p = a.slice("--profile=".length).trim();
      if (p) cliProfile = p;
    }
  }

  let doc: TomlTable | undefined;
  const inspected = inspectCodexConfigPath(codexHome, configPath);
  const hasConfig = inspected.exists;
  let configError = inspected.error;
  if (inspected.exists && inspected.rawContent !== undefined) {
    try {
      doc = parseToml(inspected.rawContent);
    } catch {
      doc = undefined;
    }
  }

  const configDefaultProfile =
    typeof doc?.profile === "string" && doc.profile.trim() ? doc.profile.trim() : undefined;
  const effectiveProfile = opts?.ignoreProfiles ? undefined : (cliProfile ?? extraConfigProfile ?? configDefaultProfile);

  // 解析选中的 profile（先读 config.toml 的 [profiles.<name>]，再叠加同目录 <name>.config.toml，损坏链接 fail-closed）
  let profileTable: TomlTable | undefined;
  let sidecarDoc: TomlTable | undefined;
  if (effectiveProfile) {
    const profilesRoot = isPlainTable(doc?.profiles) ? doc.profiles : undefined;
    if (profilesRoot && isPlainTable(profilesRoot[effectiveProfile])) {
      profileTable = profilesRoot[effectiveProfile];
    }
    const safeProfileSeg =
      !effectiveProfile.includes("/") &&
      !effectiveProfile.includes("\\") &&
      !effectiveProfile.includes("\0") &&
      effectiveProfile !== "." &&
      effectiveProfile !== "..";
    if (safeProfileSeg) {
      const sidecarPath = path.join(codexHome, `${effectiveProfile}.config.toml`);
      const sidecarInspected = inspectCodexConfigPath(codexHome, sidecarPath);
      if (sidecarInspected.error && !configError) {
        configError = sidecarInspected.error;
      } else if (sidecarInspected.exists && sidecarInspected.rawContent !== undefined) {
        try {
          sidecarDoc = parseToml(sidecarInspected.rawContent);
        } catch (err) {
          if (!configError) {
            configError = `Codex profile 配置文件 (${sidecarPath}) 解析失败：${errMsg(err)}`;
          }
        }
      }
    }
  }

  const strOf = (t: TomlTable | undefined, key: string): string | undefined => {
    const v = t?.[key];
    return typeof v === "string" && v.trim() ? v.trim() : undefined;
  };

  const store =
    extraStore ??
    strOf(sidecarDoc, "cli_auth_credentials_store") ??
    strOf(profileTable, "cli_auth_credentials_store") ??
    strOf(doc, "cli_auth_credentials_store") ??
    undefined;
  const provider =
    extraProvider ??
    strOf(sidecarDoc, "model_provider") ??
    strOf(profileTable, "model_provider") ??
    strOf(doc, "model_provider") ??
    "openai";
  const forcedLoginMethod =
    extraForcedLogin ??
    strOf(sidecarDoc, "forced_login_method") ??
    strOf(profileTable, "forced_login_method") ??
    strOf(doc, "forced_login_method");

  const mergedProviderTable: TomlTable = Object.create(null) as TomlTable;
  const getProviderFrom = (root: TomlTable | undefined): TomlTable | undefined => {
    const providersRoot = isPlainTable(root?.model_providers) ? root.model_providers : undefined;
    return providersRoot && isPlainTable(providersRoot[provider]) ? providersRoot[provider] : undefined;
  };
  mergeProviderInto(mergedProviderTable, getProviderFrom(doc));
  mergeProviderInto(mergedProviderTable, getProviderFrom(profileTable));
  mergeProviderInto(mergedProviderTable, getProviderFrom(sidecarDoc));
  mergeProviderInto(mergedProviderTable, extraProviders.get(provider));

  const awsTable = isPlainTable(mergedProviderTable.aws) ? mergedProviderTable.aws : undefined;
  const explicitAwsProfile = typeof awsTable?.profile === "string" && awsTable.profile.trim() ? awsTable.profile.trim() : undefined;
  const envAwsProfile = env.AWS_PROFILE?.trim() || env.AWS_DEFAULT_PROFILE?.trim() || undefined;
  const hasExplicitAwsStaticEnv = !!env.AWS_ACCESS_KEY_ID?.trim() && !!env.AWS_SECRET_ACCESS_KEY?.trim();
  const awsProfile =
    explicitAwsProfile ??
    (provider === "amazon-bedrock" || awsTable
      ? envAwsProfile ?? (!hasExplicitAwsStaticEnv ? "default" : undefined)
      : undefined);

  let needsCredentialStore = true;
  if (NON_OPENAI_BUILTIN_CODEX_PROVIDERS.has(provider)) {
    needsCredentialStore = false;
  } else if (provider !== "openai") {
    // 自定义供应商默认使用 env_key / 请求头认证，仅显式 requires_openai_auth = true 时才可能读取 OpenAI/ChatGPT 凭据库
    needsCredentialStore = mergedProviderTable.requires_openai_auth === true;
  } else if (mergedProviderTable.requires_openai_auth === false) {
    needsCredentialStore = false;
  }

  if (needsCredentialStore && forcedLoginMethod !== "chatgpt") {
    const envKeyName = typeof mergedProviderTable.env_key === "string" ? mergedProviderTable.env_key.trim() : "";
    const hasCustomEnvKey = !!envKeyName && !!env[envKeyName]?.trim();
    const hasOpenAiEnvKey =
      provider === "openai" && (!!env.OPENAI_API_KEY?.trim() || !!env.CODEX_API_KEY?.trim());
    const hasBearer =
      typeof mergedProviderTable.experimental_bearer_token === "string" &&
      !!mergedProviderTable.experimental_bearer_token.trim();
    const hasStaticAuthHeader =
      isPlainTable(mergedProviderTable.http_headers) &&
      Object.entries(mergedProviderTable.http_headers).some(
        ([k, v]) => typeof v === "string" && !!v.trim() && AUTH_HEADER_NAME_RE.test(k.trim()),
      );
    const hasEnvAuthHeader =
      isPlainTable(mergedProviderTable.env_http_headers) &&
      Object.entries(mergedProviderTable.env_http_headers).some(
        ([k, v]) =>
          typeof v === "string" &&
          !!v.trim() &&
          AUTH_HEADER_NAME_RE.test(k.trim()) &&
          !!env[v.trim()]?.trim(),
      );
    if (hasCustomEnvKey || hasOpenAiEnvKey || hasBearer || hasStaticAuthHeader || hasEnvAuthHeader) {
      needsCredentialStore = false;
    }
  }

  return {
    store,
    codexHome,
    hasConfig,
    provider,
    ...(effectiveProfile ? { profile: effectiveProfile } : {}),
    forcedLoginMethod,
    needsCredentialStore,
    ...(awsProfile ? { awsProfile } : {}),
    ...(configError ? { configError } : {}),
  };
}

export interface StagedAwsProfile {
  dir: string;
  configFile: string;
  credentialsFile: string;
  extraReadOnlyPaths: string[];
  cleanup: () => void;
}

interface IniSection {
  header: string;
  lines: string[];
  props: Map<string, string>;
}

function parseAwsIniSections(rawText: string): IniSection[] {
  const sections: IniSection[] = [];
  let cur: IniSection | undefined;
  for (const rawLine of rawText.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";")) continue;
    const hdr = trimmed.match(/^\[([^\]]+)\]$/);
    if (hdr) {
      cur = { header: hdr[1].trim(), lines: [], props: new Map() };
      sections.push(cur);
      continue;
    }
    if (!cur) continue;
    cur.lines.push(rawLine);
    // 仅记录顶层（无前导缩进）的 key = value，供追踪 source_profile / sso_session / services / 文件路径引用
    if (!/^\s/.test(rawLine)) {
      const eq = rawLine.indexOf("=");
      if (eq > 0) {
        const k = rawLine.slice(0, eq).trim().toLowerCase();
        const v = rawLine.slice(eq + 1).trim();
        if (k) cur.props.set(k, v);
      }
    }
  }
  return sections;
}

function serializeAwsIniSections(sections: IniSection[]): string {
  if (!sections.length) return "";
  return sections.map((s) => `[${s.header}]\n${s.lines.join("\n")}`).join("\n\n") + "\n";
}

/**
 * 为隔离沙箱中的 Bedrock / AWS Codex 仅投影选中的单个 AWS profile（及其传递依赖的 source_profile / sso-session / services），
 * 绝不把整个 ~/.aws 目录或其他无关 AWS 账号凭据暴露给子进程。
 */
export function stageIsolatedAwsProfile(
  profileName: string,
  hostEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
): StagedAwsProfile | undefined {
  const target = profileName.trim();
  if (!target) return undefined;
  const hostHome = hostEnv.HOME?.trim() || os.homedir();
  const hostAwsDir = hostHome ? path.join(hostHome, ".aws") : "";
  const hostConfigPath = hostEnv.AWS_CONFIG_FILE?.trim() || (hostAwsDir ? path.join(hostAwsDir, "config") : "");
  const hostCredsPath =
    hostEnv.AWS_SHARED_CREDENTIALS_FILE?.trim() || (hostAwsDir ? path.join(hostAwsDir, "credentials") : "");

  const resolvedData = dataDir && fs.existsSync(dataDir) ? safeRealpath(dataDir) : "";
  const isOutsideDataDir = (p: string): boolean => {
    if (!resolvedData) return true;
    const real = safeRealpath(p);
    return !isPathInsideOrEqual(real, resolvedData) && !isPathInsideOrEqual(resolvedData, real);
  };
  const readHostIni = (filePath: string): IniSection[] => {
    if (!filePath || !fs.existsSync(filePath) || !isOutsideDataDir(filePath)) return [];
    try {
      const st = fs.statSync(filePath);
      if (!st.isFile() || st.size > 4 * 1024 * 1024) return [];
      return parseAwsIniSections(fs.readFileSync(filePath, "utf8"));
    } catch {
      return [];
    }
  };

  const configSections = readHostIni(hostConfigPath);
  const credsSections = readHostIni(hostCredsPath);
  if (configSections.length === 0 && credsSections.length === 0) return undefined;

  const findConfigProfile = (name: string): IniSection | undefined => {
    if (name === "default") {
      return configSections.find((s) => s.header === "default" || s.header === "profile default");
    }
    return configSections.find((s) => {
      const m = s.header.match(/^profile\s+(.+)$/);
      return (m && m[1].trim() === name) || s.header === name;
    });
  };
  const findCredsProfile = (name: string): IniSection | undefined =>
    credsSections.find((s) => s.header === name);
  const findConfigTagged = (prefix: string, name: string): IniSection | undefined =>
    configSections.find((s) => {
      const re = new RegExp(`^${prefix}\\s+(.+)$`);
      const m = s.header.match(re);
      return !!m && m[1].trim() === name;
    });

  const selectedConfig: IniSection[] = [];
  const selectedCreds: IniSection[] = [];
  const visitedProfiles = new Set<string>();
  const visitedSso = new Set<string>();
  const visitedServices = new Set<string>();
  const extraReadOnlyPaths = new Set<string>();
  const queue: { name: string; depth: number }[] = [{ name: target, depth: 0 }];

  const addRefPath = (rawPath: string | undefined) => {
    if (!rawPath) return;
    const expanded = rawPath.startsWith("~/") && hostHome ? path.join(hostHome, rawPath.slice(2)) : rawPath;
    if (!path.isAbsolute(expanded)) return;
    try {
      if (fs.existsSync(expanded) && isOutsideDataDir(expanded)) {
        extraReadOnlyPaths.add(safeRealpath(expanded));
      }
    } catch {
      // ignore
    }
  };

  let needsSsoCache = false;
  while (queue.length > 0) {
    const { name, depth } = queue.shift()!;
    if (depth > 6 || visitedProfiles.has(name)) continue;
    visitedProfiles.add(name);

    const cfgSec = findConfigProfile(name);
    const credSec = findCredsProfile(name);
    if (cfgSec) selectedConfig.push(cfgSec);
    if (credSec) selectedCreds.push(credSec);

    for (const sec of [cfgSec, credSec]) {
      if (!sec) continue;
      const srcProfile = sec.props.get("source_profile");
      if (srcProfile && !visitedProfiles.has(srcProfile)) {
        queue.push({ name: srcProfile, depth: depth + 1 });
      }
      const ssoSession = sec.props.get("sso_session");
      if (ssoSession) {
        needsSsoCache = true;
        if (!visitedSso.has(ssoSession)) {
          visitedSso.add(ssoSession);
          const ssoSec = findConfigTagged("sso-session", ssoSession);
          if (ssoSec) selectedConfig.push(ssoSec);
        }
      }
      if (sec.props.has("sso_start_url") || sec.props.has("sso_account_id")) {
        needsSsoCache = true;
      }
      const svc = sec.props.get("services");
      if (svc && !visitedServices.has(svc)) {
        visitedServices.add(svc);
        const svcSec = findConfigTagged("services", svc);
        if (svcSec) selectedConfig.push(svcSec);
      }
      addRefPath(sec.props.get("web_identity_token_file"));
      addRefPath(sec.props.get("ca_bundle"));
    }
  }

  if (selectedConfig.length === 0 && selectedCreds.length === 0) return undefined;

  if (needsSsoCache && hostAwsDir) {
    const ssoCacheDir = path.join(hostAwsDir, "sso", "cache");
    if (fs.existsSync(ssoCacheDir) && isOutsideDataDir(ssoCacheDir)) {
      extraReadOnlyPaths.add(safeRealpath(ssoCacheDir));
    }
  }

  const scoped = createScopedSecretDir("pa-aws-profile-", hostEnv);
  const configFile = path.join(scoped.dir, "config");
  const credentialsFile = path.join(scoped.dir, "credentials");
  try {
    fs.writeFileSync(configFile, serializeAwsIniSections(selectedConfig), { mode: 0o600 });
    fs.writeFileSync(credentialsFile, serializeAwsIniSections(selectedCreds), { mode: 0o600 });
    return {
      dir: scoped.dir,
      configFile,
      credentialsFile,
      extraReadOnlyPaths: [...extraReadOnlyPaths],
      cleanup: scoped.cleanup,
    };
  } catch (err) {
    scoped.cleanup();
    throw err;
  }
}

export interface CodexKeyringConflict {
  severity: "error" | "warn";
  message: string;
  fix: string;
}

/**
 * 检测 Linux 隔离沙箱与 Codex `cli_auth_credentials_store = "keyring"`（或缺少文件凭据的 `"auto"`）的冲突：
 * 隔离沙箱会屏蔽宿主机 D-Bus 会话总线与 XDG_RUNTIME_DIR，导致容器内无法访问 Secret Service keyring；
 * 若当前所选供应商/认证方式走 API 密钥（OPENAI_API_KEY / CODEX_API_KEY / 自定义 env_key / 请求头）或非 OpenAI 内置供应商，则无需 keyring。
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
  // 仓库级审查者（includeContextObs: true）在 Linux 上始终启用默认沙箱隔离，不依赖当前工作区状态
  const isoActive =
    opts?.includeContextObs === true ||
    workspaceRequiresIsolation(cfg, rawEnv, { includeContextObs: false });
  if (!isoActive) return undefined;

  const baseEnv: NodeJS.ProcessEnv = opts?.home ? { ...rawEnv, HOME: opts.home } : { ...rawEnv };
  const merged = mergeHarnessEnv(baseEnv, h.env);
  const { store, codexHome, needsCredentialStore } = resolveEffectiveCodexCredentialStore(merged, h.extraArgs, {
    ignoreProfiles: opts?.includeContextObs !== true,
  });
  if (!needsCredentialStore) return undefined;
  const fix =
    '在 ~/.codex/config.toml 中设置 `cli_auth_credentials_store = "file"` 并重新运行 `codex login`，或在常驻进程环境中通过 `OPENAI_API_KEY` / `CODEX_API_KEY` / 自定义供应商 `env_key` 提供 API 密钥';
  if (store === "keyring") {
    return {
      severity: "error",
      message: `执行者 ${harnessName} 配置了 cli_auth_credentials_store="keyring"，但当前 Linux 隔离沙箱已屏蔽宿主机 D-Bus 会话总线与 XDG_RUNTIME_DIR，无法访问 Secret Service；请改用文件凭据或 API 密钥`,
      fix,
    };
  }
  if (store === "auto" && !fs.existsSync(path.join(codexHome, "auth.json"))) {
    return {
      severity: "warn",
      message: `执行者 ${harnessName} 使用 cli_auth_credentials_store="auto" 且 ${codexHome}/auth.json 与 API 密钥均不存在；Linux 隔离沙箱内无法访问宿主机 keyring，若 Codex 登录态仅存于 keyring 将导致鉴权失败`,
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

  // 2) 解析子进程主目录对应的 $CODEX_HOME/config.toml（严格区分缺失与损坏符号链接/不可读文件，绝不静默退化到默认供应商）
  const out: string[] = [];
  const mergedProviders: TomlTable = Object.create(null) as TomlTable;

  const inspectedConfig = inspectCodexConfigPath(codexHome, configPath);
  if (inspectedConfig.error) {
    throw new Error(`${inspectedConfig.error}；为避免将私聊发往默认供应商，已中止 tools=none 执行`);
  }
  if (inspectedConfig.exists && inspectedConfig.rawContent !== undefined) {
    const rawContent = inspectedConfig.rawContent;
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
  let stagedAcpx: StagedAcpxState | undefined;
  let stagedDoubao: StagedDoubaoDataDir | undefined;
  let stagedNpmrc: StagedSanitizedNpmrc | undefined;
  let r: Awaited<ReturnType<typeof runProcess>>;
  try {
    const mode: WorkspaceIsolationMode =
      run.tools === "write" ? "worker-write" : run.tools === "read" ? "worker-ro" : "llm-none";
    const acpxIsolationEnv = mergeHarnessEnv(process.env, h.env);
    const hostHome = acpxIsolationEnv.HOME?.trim() || os.homedir();
    const resolvedDataDir = cfg.dataDir && fs.existsSync(cfg.dataDir) ? safeRealpath(cfg.dataDir) : "";
    const selectedAgentId = resolveSelectedAcpxAgentId(h);
    const isDoubaoAcpx = selectedAgentId === "doubao" || selectedAgentId.startsWith("doubao-");

    stagedAcpx = stageIsolatedAcpxState(h, hostHome, acpxIsolationEnv, cfg.dataDir);
    if (isDoubaoAcpx) {
      stagedDoubao = stageIsolatedDoubaoDataDir(acpxIsolationEnv, cfg.dataDir);
    }
    if (mode !== "llm-none") {
      stagedNpmrc = stageSanitizedNpmrc(acpxIsolationEnv, cfg.dataDir);
    }

    const acpxExtraRo: string[] = [];
    const acpxExtraBindMounts: { src: string; dest: string; mode: "ro" | "rw" }[] = [];
    if (baseEnv.env.CREDENTIALS_DIRECTORY) acpxExtraRo.push(baseEnv.env.CREDENTIALS_DIRECTORY);
    // 仅挂载 bin/guard/lark-cli 运行所需的 4 个精确文件，绝不挂载整个 ROOT（防暴露 ROOT/config.yaml 与 ROOT/.worktrees）
    acpxExtraRo.push(...collectLarkGuardReadOnlyFiles());
    if (run.lark !== "none" && fs.existsSync(realLark)) acpxExtraRo.push(realLark);
    if (stagedAcpx) {
      acpxExtraBindMounts.push({ src: stagedAcpx.dir, dest: stagedAcpx.mountDest, mode: "rw" });
    }
    if (stagedDoubao) {
      acpxExtraBindMounts.push(...stagedDoubao.bindMounts);
    }
    if (stagedNpmrc) {
      acpxExtraRo.push(stagedNpmrc.dir);
      acpxExtraBindMounts.push({ src: stagedNpmrc.file, dest: stagedNpmrc.homeMountDest, mode: "ro" });
    }
    const selectedConfigPaths = [
      ...selectAcpxAgentConfigPaths(h, hostHome, acpxIsolationEnv),
      ...(run.lark !== "none" ? selectLarkCliAuthPaths(acpxIsolationEnv) : []),
    ];
    for (const p of selectedConfigPaths) {
      if (!fs.existsSync(p)) continue;
      const real = safeRealpath(p);
      if (stagedDoubao && isPathInsideOrEqual(real, stagedDoubao.hostDataDir)) {
        continue;
      }
      if (resolvedDataDir && (isPathInsideOrEqual(real, resolvedDataDir) || isPathInsideOrEqual(resolvedDataDir, real))) {
        continue;
      }
      acpxExtraRo.push(real);
    }
    const agentExec = resolveAcpxAgentExecutable(h);
    const acpxExtraCmds = [
      ...(agentExec ? [agentExec] : []),
      ...(stagedAcpx?.extraCmdPaths ?? []),
      ...(run.lark !== "none" ? [realLark] : []),
    ];
    const wrapped = wrapCredentialIsolatedCommand(
      cfg.bins.acpx,
      args,
      acpxIsolationEnv,
      buildWorkspaceIsolation(
        cfg,
        {
          mode,
          cwd: run.cwd,
          cmdPath: cfg.bins.acpx,
          extraCmdPaths: acpxExtraCmds,
          trustedRepoRoot: run.trustedRepoRoot,
          disableGitWorktreeMounts: run.disableGitWorktreeMounts,
          allowGuardLog: run.lark !== "none",
          extraReadOnlyPaths: acpxExtraRo,
          extraBindMounts: acpxExtraBindMounts,
        },
        acpxIsolationEnv,
      ),
    );
    const env: NodeJS.ProcessEnv = {
      ...mergeHarnessEnv(baseEnv.env, h.env),
      PATH: `${path.join(ROOT, "bin", "guard")}${path.delimiter}${process.env.PATH ?? ""}`,
      PA_GUARD_PROFILE: run.lark,
      PA_OWNER_OPEN_ID: cfg.owner.open_id,
      PA_LARK_REAL: realLark,
      PA_GUARD_LOG: path.join(cfg.dataDir, "logs", "guard.log"),
      ...(wrapped.isolated ? isolatedSandboxTempEnv() : {}),
    };
    if (mode !== "llm-none") applySanitizedNpmrcEnv(env, stagedNpmrc, wrapped.isolated);
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
    stagedNpmrc?.cleanup();
    stagedDoubao?.cleanup();
    stagedAcpx?.cleanup();
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

const MAX_CODEX_AUTH_BYTES = 256 * 1024;
const MAX_CODEX_CONFIG_BYTES = 4 * 1024 * 1024;

interface CodexAuthOrigSnapshot {
  hostAuthPath: string;
  resolvedAuthPath: string;
  wasSymlink: boolean;
  origBytes: Buffer;
  origJson: Record<string, unknown>;
  origDev: number;
  origIno: number;
  canSyncBack: boolean;
}

export interface StagedCodexHome {
  scratchDir: string;
  origAuth?: CodexAuthOrigSnapshot;
  /** 保留兼容字段（已废弃：所有工作区统一按规范化目标路径使用跨工作区共享锁目录） */
  lockDir?: string;
  cleanup: () => void;
}

function isPlainJsonRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function hasOAuthRefreshToken(json: Record<string, unknown>): boolean {
  const tokens = isPlainJsonRecord(json.tokens) ? json.tokens : undefined;
  return !!tokens && typeof tokens.refresh_token === "string" && tokens.refresh_token.trim().length > 0;
}

function parseJwtExpMs(token: string): number | undefined {
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[1]) return undefined;
  try {
    const pad = (4 - (parts[1].length % 4)) % 4;
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
    const decoded = JSON.parse(Buffer.from(b64, "base64").toString("utf8")) as unknown;
    if (!isPlainJsonRecord(decoded)) return undefined;
    return typeof decoded.exp === "number" && Number.isFinite(decoded.exp) ? decoded.exp * 1000 : undefined;
  } catch {
    return undefined;
  }
}

/**
 * 判断文件态 Codex OAuth 凭据在本次运行窗口（至少 5 分钟，长任务按运行超时上限计算）内是否可能触发单次 refresh_token 轮换：
 *   - 无 refresh_token 时返回 false；
 *   - access_token 缺失/为空，或为 JWT 且在 `now + runWindowMs` 前过期，或 `now + runWindowMs - last_refresh >= 7 天`：返回 true；
 *   - access_token 非 JWT（不透明令牌）时，若 last_refresh 缺失或 `now + runWindowMs - last_refresh >= 55 分钟`：返回 true。
 */
export function isCodexOAuthRefreshNeeded(
  origJson: Record<string, unknown>,
  now = Date.now(),
  runWindowMs = 5 * 60_000,
): boolean {
  if (!hasOAuthRefreshToken(origJson)) return false;
  const windowMs = Math.max(5 * 60_000, runWindowMs);
  const tokens = origJson.tokens as Record<string, unknown>;
  const accessToken = typeof tokens.access_token === "string" ? tokens.access_token.trim() : "";
  if (!accessToken) return true;
  const lastRefreshMs = typeof origJson.last_refresh === "string" ? Date.parse(origJson.last_refresh) : NaN;
  const expMs = parseJwtExpMs(accessToken);
  if (expMs !== undefined) {
    if (expMs <= now + windowMs) return true;
    if (!Number.isFinite(lastRefreshMs) || now + windowMs - lastRefreshMs >= 7 * 86_400_000) return true;
    return false;
  }
  if (!Number.isFinite(lastRefreshMs)) return true;
  return now + windowMs - lastRefreshMs >= 55 * 60_000;
}

function isCurrentUidOwner(st: fs.Stats): boolean {
  return typeof process.getuid !== "function" || st.uid === process.getuid();
}

function isPidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === "EPERM";
  }
}

/**
 * 将 Codex OAuth 刷新协调 SQLite 锁放在规范化 `resolvedAuthPath` 同目录下，
 * 彻底独立于各进程的 `TMPDIR` 或 systemd `PrivateTmp=yes` 私有临时挂载，确保共享同一 `auth.json` 的所有进程命中同一把锁。
 */
export function canonicalCodexLockFilePath(resolvedAuthPath: string): string {
  const realAuth = safeRealpath(resolvedAuthPath);
  const dir = path.dirname(realAuth);
  const base = path.basename(realAuth);
  return path.join(dir, `.${base}.pa-refresh.lock.db`);
}

function openCodexLockDb(resolvedAuthPath: string): DatabaseSync {
  const lockFile = canonicalCodexLockFilePath(resolvedAuthPath);
  const lockDir = path.dirname(lockFile);
  const dirSt = fs.lstatSync(lockDir);
  if (dirSt.isSymbolicLink() || !dirSt.isDirectory() || !isCurrentUidOwner(dirSt)) {
    throw new Error(`Codex 凭据同步锁目录不安全：${lockDir}`);
  }
  try {
    const existingSt = fs.lstatSync(lockFile);
    if (existingSt.isSymbolicLink() || !existingSt.isFile() || !isCurrentUidOwner(existingSt)) {
      throw new Error(`Codex 凭据同步锁文件不安全：${lockFile}`);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code !== "ENOENT") throw err;
  }
  const db = new DatabaseSync(lockFile);
  try {
    fs.chmodSync(lockFile, 0o600);
  } catch {
    // ignore chmod error on non-POSIX fs
  }
  db.exec("PRAGMA busy_timeout = 5000");
  db.exec(`
    CREATE TABLE IF NOT EXISTS refresh_lease (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      holder TEXT NOT NULL,
      pid INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )
  `);
  return db;
}

function copyRegularTreeShallow(
  srcDir: string,
  dstDir: string,
  depth = 0,
  visitedRealDirs: Set<string> = new Set(),
): void {
  if (depth > 4) return;
  let realSrc: string;
  try {
    realSrc = fs.realpathSync(srcDir);
  } catch {
    return;
  }
  if (visitedRealDirs.has(realSrc)) return;
  visitedRealDirs.add(realSrc);
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(srcDir, { withFileTypes: true });
  } catch {
    return;
  }
  fs.mkdirSync(dstDir, { recursive: true, mode: 0o700 });
  for (const ent of entries) {
    const srcPath = path.join(srcDir, ent.name);
    const dstPath = path.join(dstDir, ent.name);
    let st: fs.Stats;
    try {
      st = fs.statSync(srcPath);
    } catch {
      continue;
    }
    if (st.isFile()) {
      try {
        if (st.size > 1024 * 1024) continue;
        fs.writeFileSync(dstPath, fs.readFileSync(srcPath), { mode: 0o600 });
      } catch {
        // ignore unreadable auxiliary rule file
      }
    } else if (st.isDirectory()) {
      copyRegularTreeShallow(srcPath, dstPath, depth + 1, visitedRealDirs);
    }
  }
}

function withCodexAuthSyncLock<T>(resolvedAuthPath: string, fn: (db: DatabaseSync) => T): T {
  const db = openCodexLockDb(resolvedAuthPath);
  try {
    db.exec("BEGIN IMMEDIATE");
    try {
      const res = fn(db);
      db.exec("COMMIT");
      return res;
    } catch (err) {
      try {
        db.exec("ROLLBACK");
      } catch {
        // ignore
      }
      throw err;
    }
  } finally {
    try {
      db.close();
    } catch {
      // ignore
    }
  }
}

function inspectHostCodexAuth(hostAuthPath: string):
  | { kind: "absent" }
  | { kind: "broken_symlink"; error: string }
  | { kind: "unreadable"; error: string }
  | {
      kind: "ok";
      hostAuthPath: string;
      resolvedAuthPath: string;
      wasSymlink: boolean;
      origBytes: Buffer;
      origJson?: Record<string, unknown>;
      origDev: number;
      origIno: number;
      canSyncBack: boolean;
      unwritableReason?: string;
    } {
  let lst: fs.Stats;
  try {
    lst = fs.lstatSync(hostAuthPath);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === "ENOENT" || code === "ENOTDIR") return { kind: "absent" };
    return { kind: "unreadable", error: `无法访问宿主机 Codex 凭据 (${hostAuthPath})：${errMsg(err)}` };
  }

  const wasSymlink = lst.isSymbolicLink();
  let resolvedAuthPath: string;
  try {
    resolvedAuthPath = fs.realpathSync(hostAuthPath);
  } catch (err) {
    if (wasSymlink) {
      return {
        kind: "broken_symlink",
        error: `宿主机 Codex 凭据 (${hostAuthPath}) 是损坏的符号链接，无法读取或回写刷新后的 OAuth Token：${errMsg(err)}`,
      };
    }
    return { kind: "unreadable", error: `无法解析宿主机 Codex 凭据路径 (${hostAuthPath})：${errMsg(err)}` };
  }

  let st: fs.Stats;
  try {
    st = fs.lstatSync(resolvedAuthPath);
  } catch (err) {
    return { kind: "unreadable", error: `无法读取宿主机 Codex 凭据状态 (${resolvedAuthPath})：${errMsg(err)}` };
  }
  if (!st.isFile() || st.size <= 0 || st.size > MAX_CODEX_AUTH_BYTES) {
    return { kind: "unreadable", error: `宿主机 Codex 凭据 (${resolvedAuthPath}) 不是合法普通文件或体积异常` };
  }

  let origBytes: Buffer;
  try {
    origBytes = fs.readFileSync(resolvedAuthPath);
  } catch (err) {
    return { kind: "unreadable", error: `无法读取宿主机 Codex 凭据 (${resolvedAuthPath})：${errMsg(err)}` };
  }

  let origJson: Record<string, unknown> | undefined;
  try {
    const parsed = JSON.parse(origBytes.toString("utf8")) as unknown;
    if (isPlainJsonRecord(parsed)) origJson = parsed;
  } catch {
    origJson = undefined;
  }

  let canSyncBack = false;
  let unwritableReason: string | undefined;
  const parentDir = path.dirname(resolvedAuthPath);
  if (!isCurrentUidOwner(st)) {
    unwritableReason = `凭据文件 (${resolvedAuthPath}) 不属于当前 OS 用户`;
  } else {
    try {
      fs.accessSync(resolvedAuthPath, fs.constants.R_OK | fs.constants.W_OK);
      const pSt = fs.lstatSync(parentDir);
      if (!pSt.isDirectory() || !isCurrentUidOwner(pSt)) {
        unwritableReason = `凭据所在目录 (${parentDir}) 非当前用户拥有的目录，无法原子替换写回`;
      } else {
        fs.accessSync(parentDir, fs.constants.W_OK | fs.constants.X_OK);
        canSyncBack = true;
      }
    } catch {
      unwritableReason = `凭据文件 (${resolvedAuthPath}) 或其目录不可写，无法原子写回刷新后的 OAuth Token`;
    }
  }

  return {
    kind: "ok",
    hostAuthPath,
    resolvedAuthPath,
    wasSymlink,
    origBytes,
    origJson,
    origDev: Number(st.dev),
    origIno: Number(st.ino),
    canSyncBack,
    unwritableReason,
  };
}

function sleepAbortableMs(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.reject(new Error("aborted"));
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      clearTimeout(t);
      reject(new Error("aborted"));
    };
    const t = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    t.unref?.();
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export interface CodexOAuthRefreshLease {
  held: boolean;
  resolvedAuthPath?: string;
  release: () => void;
}

/**
 * 在拷贝 `auth.json` 启动隔离 `codex exec` 之前，按规范化目标路径跨进程、跨工作区协调 OAuth 刷新租约：
 *   - 若另一活跃进程正在持有刷新租约（可能即将轮换单次 refresh_token），本调用方等待其写回并释放后再重新读取宿主机 `auth.json`；
 *   - 若当前凭据可能需要刷新（JWT 即将/已过期、非 JWT 刷新时间陈旧），获取独占刷新租约并附带心跳续期，直到本进程完成写回后释放；
 *   - 若凭据新鲜且无在途刷新租约，立刻返回 `held: false`，多个隔离 worker 可完全并发执行。
 */
export async function coordinateCodexOAuthRefresh(
  hostCodexHome: string,
  opts?: {
    needsCredentialStore?: boolean;
    signal?: AbortSignal;
    leaseTtlMs?: number;
    pollIntervalMs?: number;
    maxWaitMs?: number;
    /** 本次运行的预期最持续时长（毫秒）：若令牌可能在该窗口内过期，提前进入刷新协调锁，避免并发拷贝同时旋转 refresh_token */
    runWindowMs?: number;
  },
): Promise<CodexOAuthRefreshLease> {
  if (opts?.needsCredentialStore === false) {
    return { held: false, release: () => undefined };
  }
  const hostAuthPath = path.join(hostCodexHome, "auth.json");
  const initial = inspectHostCodexAuth(hostAuthPath);
  if (initial.kind === "broken_symlink") {
    throw new Error(initial.error);
  }
  if (initial.kind !== "ok" || !initial.origJson || !hasOAuthRefreshToken(initial.origJson)) {
    return { held: false, release: () => undefined };
  }
  if (!initial.canSyncBack) {
    throw new Error(
      `宿主机 Codex OAuth 凭据不可安全写回（${initial.unwritableReason ?? "权限不足"}）；为防止隔离沙箱消耗单次 refresh_token 后丢失新令牌，已中止执行`,
    );
  }

  const resolvedAuthPath = initial.resolvedAuthPath;
  const leaseTtlMs = opts?.leaseTtlMs ?? 60_000;
  const pollMs = opts?.pollIntervalMs ?? 120;
  const deadline = Date.now() + (opts?.maxWaitMs ?? 180_000);
  const holder = `${process.pid}:${randomUUID().slice(0, 8)}`;

  for (;;) {
    if (opts?.signal?.aborted) throw new Error("aborted");
    const attempt = withCodexAuthSyncLock(resolvedAuthPath, (db) => {
      const now = Date.now();
      const row = db
        .prepare("SELECT holder, pid, expires_at FROM refresh_lease WHERE id = 1")
        .get() as { holder: string; pid: number; expires_at: number } | undefined;
      if (row && row.expires_at > now && isPidAlive(row.pid)) {
        return { action: "wait" as const };
      }
      // 若此前租约已过期或持有者进程已退出，清除陈旧租约并重新检查宿主机最新 auth.json
      const cur = inspectHostCodexAuth(hostAuthPath);
      if (cur.kind === "broken_symlink") {
        throw new Error(cur.error);
      }
      if (cur.kind !== "ok" || !cur.origJson || !hasOAuthRefreshToken(cur.origJson)) {
        if (row) db.prepare("DELETE FROM refresh_lease WHERE id = 1").run();
        return { action: "proceed_unlocked" as const };
      }
      if (!cur.canSyncBack) {
        throw new Error(
          `宿主机 Codex OAuth 凭据不可安全写回（${cur.unwritableReason ?? "权限不足"}）；已中止执行`,
        );
      }
      if (!isCodexOAuthRefreshNeeded(cur.origJson, now, opts?.runWindowMs)) {
        if (row) db.prepare("DELETE FROM refresh_lease WHERE id = 1").run();
        return { action: "proceed_unlocked" as const };
      }
      db.prepare(
        "INSERT OR REPLACE INTO refresh_lease (id, holder, pid, expires_at) VALUES (1, ?, ?, ?)",
      ).run(holder, process.pid, now + leaseTtlMs);
      return { action: "acquired" as const };
    });

    if (attempt.action === "proceed_unlocked") {
      return { held: false, resolvedAuthPath, release: () => undefined };
    }
    if (attempt.action === "acquired") {
      let released = false;
      const heartbeat = setInterval(() => {
        if (released) return;
        try {
          withCodexAuthSyncLock(resolvedAuthPath, (db) => {
            db.prepare("UPDATE refresh_lease SET expires_at = ? WHERE id = 1 AND holder = ?").run(
              Date.now() + leaseTtlMs,
              holder,
            );
          });
        } catch {
          // best-effort heartbeat
        }
      }, Math.max(500, Math.floor(leaseTtlMs / 3)));
      heartbeat.unref?.();

      const release = () => {
        if (released) return;
        released = true;
        clearInterval(heartbeat);
        process.off("exit", release);
        try {
          withCodexAuthSyncLock(resolvedAuthPath, (db) => {
            db.prepare("DELETE FROM refresh_lease WHERE id = 1 AND holder = ?").run(holder);
          });
        } catch {
          // ignore release failure on exit
        }
      };
      process.once("exit", release);
      return { held: true, resolvedAuthPath, release };
    }

    if (Date.now() >= deadline) {
      throw new Error(`等待宿主机 Codex OAuth 刷新协调锁超时 (${resolvedAuthPath})，为避免重复消费 refresh_token 已中止执行`);
    }
    await sleepAbortableMs(pollMs, opts?.signal);
  }
}

/**
 * 为隔离沙箱中的 `codex exec` 准备私有临时 `CODEX_HOME`：
 *   - 宿主机真实 `~/.codex` 保持只读，防止沙箱内进程篡改 `config.toml` / `hooks` / `plugins` / `skills`；
 *   - 将 `auth.json` 以 0600 拷贝到临时 `CODEX_HOME`，支持安全解引用 dotfiles 符号链接目标并提前校验其归属与可写性：
 *     若文件态 OAuth 凭据（含 refresh_token）为损坏符号链接或目标不可写/非当前用户所有，在启动子进程前即 fail-closed 拒绝，
 *     防止子进程旋转消耗单次 refresh_token 后无法写回宿主机；
 *   - 非 `tools="none"` 模式下按解引用后的真实内容拷贝 `config.toml`、`*.config.toml`、`instructions.md`、`AGENTS.md`、`rules/`；
 *     若 `codexHome`、`config.toml` 或 `*.config.toml` 存在但无法安全载入（损坏链接/不可读/过大），立即 fail-closed 抛错。
 */
export function stageIsolatedCodexHome(
  hostCodexHome: string,
  opts: { copyUserConfig: boolean; lockDir?: string; needsCredentialStore?: boolean },
): StagedCodexHome {
  const scratchDir = safeRealpath(fs.mkdtempSync(path.join(os.tmpdir(), "pa-codex-home-")));
  fs.chmodSync(scratchDir, 0o700);
  let origAuth: CodexAuthOrigSnapshot | undefined;

  const cleanup = () => {
    fs.rmSync(scratchDir, { recursive: true, force: true });
  };

  try {
    // 先校验 hostCodexHome 若存在是否为合法目录（阻止损坏 dotfiles 符号链接被静默忽略）
    let homeExists = false;
    try {
      const hLst = fs.lstatSync(hostCodexHome);
      try {
        const hSt = fs.statSync(hostCodexHome);
        if (!hSt.isDirectory()) {
          throw new Error(`宿主机 Codex 配置目录 (${hostCodexHome}) 不是合法目录；为避免退化到默认供应商，已中止执行`);
        }
        homeExists = true;
      } catch (err) {
        if (err instanceof Error && err.message.includes("不是合法目录")) throw err;
        const why = hLst.isSymbolicLink() ? "符号链接目标不可达或已损坏" : "不可访问";
        throw new Error(`宿主机 Codex 配置目录 (${hostCodexHome}) ${why}：${errMsg(err)}；为避免退化到默认供应商，已中止执行`);
      }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === "ENOENT" || code === "ENOTDIR") {
        homeExists = false;
      } else {
        throw err;
      }
    }

    // 当生效供应商不依赖宿主机 OpenAI/ChatGPT 登录态（如本地模型、Bedrock 或显式 API Key）时，
    // 绝不检查或拷贝宿主机 auth.json，防止把无关的 ChatGPT refresh_token 暴露给隔离子进程或残留在临时目录中
    if (opts.needsCredentialStore !== false) {
      const hostAuthPath = path.join(hostCodexHome, "auth.json");
      const authInspected = inspectHostCodexAuth(hostAuthPath);
      if (authInspected.kind === "broken_symlink") {
        throw new Error(authInspected.error);
      } else if (authInspected.kind === "ok") {
        const isOAuth = !!authInspected.origJson && hasOAuthRefreshToken(authInspected.origJson);
        if (isOAuth && !authInspected.canSyncBack) {
          throw new Error(
            `宿主机 Codex OAuth 凭据不可安全写回（${authInspected.unwritableReason ?? "权限不足"}）；为防止隔离沙箱消耗单次 refresh_token 后丢失新令牌，已中止执行`,
          );
        }
        fs.writeFileSync(path.join(scratchDir, "auth.json"), authInspected.origBytes, { mode: 0o600 });
        if (authInspected.origJson) {
          origAuth = {
            hostAuthPath: authInspected.hostAuthPath,
            resolvedAuthPath: authInspected.resolvedAuthPath,
            wasSymlink: authInspected.wasSymlink,
            origBytes: authInspected.origBytes,
            origJson: authInspected.origJson,
            origDev: authInspected.origDev,
            origIno: authInspected.origIno,
            canSyncBack: authInspected.canSyncBack,
          };
        }
      }
    }

    if (opts.copyUserConfig) {
      if (homeExists) {
        let entries: fs.Dirent[];
        try {
          entries = fs.readdirSync(hostCodexHome, { withFileTypes: true });
        } catch (err) {
          throw new Error(
            `无法读取宿主机 Codex 配置目录 (${hostCodexHome})：${errMsg(err)}；为避免将代码误发往默认供应商，已中止执行`,
          );
        }
        for (const ent of entries) {
          const srcPath = path.join(hostCodexHome, ent.name);
          const dstPath = path.join(scratchDir, ent.name);
          const isRequiredConfig = ent.name === "config.toml" || ent.name.endsWith(".config.toml");
          const isOptionalDoc = ent.name === "instructions.md" || ent.name === "AGENTS.md";
          if (isRequiredConfig) {
            let st: fs.Stats;
            try {
              st = fs.statSync(srcPath);
            } catch (err) {
              throw new Error(
                `无法解析宿主机 Codex 配置文件 (${srcPath})：${errMsg(err)}；为避免将代码误发往默认供应商，已中止执行`,
              );
            }
            if (!st.isFile() || st.size > MAX_CODEX_CONFIG_BYTES) {
              throw new Error(
                `宿主机 Codex 配置文件 (${srcPath}) 不是合法普通文件或体积超过限制；为避免将代码误发往默认供应商，已中止执行`,
              );
            }
            try {
              fs.writeFileSync(dstPath, fs.readFileSync(srcPath), { mode: 0o600 });
            } catch (err) {
              throw new Error(
                `无法载入宿主机 Codex 配置文件 (${srcPath}) 至隔离目录：${errMsg(err)}；为避免将代码误发往默认供应商，已中止执行`,
              );
            }
          } else if (isOptionalDoc) {
            try {
              const st = fs.statSync(srcPath);
              if (st.isFile() && st.size <= 1024 * 1024) {
                fs.writeFileSync(dstPath, fs.readFileSync(srcPath), { mode: 0o600 });
              }
            } catch {
              // 忽略可选说明文档读取异常
            }
          } else if (ent.name === "rules") {
            try {
              const st = fs.statSync(srcPath);
              if (st.isDirectory()) {
                copyRegularTreeShallow(srcPath, dstPath, 0, new Set());
              }
            } catch {
              // 忽略可选规则目录读取异常
            }
          }
        }
      }
    }

    return {
      scratchDir,
      origAuth,
      lockDir: opts.lockDir,
      cleanup,
    };
  } catch (err) {
    cleanup();
    throw err;
  }
}

function fsyncDirectoryBestEffort(dirPath: string): void {
  let fd: number | undefined;
  try {
    fd = fs.openSync(dirPath, fs.constants.O_RDONLY);
    fs.fsyncSync(fd);
  } catch {
    // ignore on filesystems that disallow directory fsync
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
    }
  }
}

/**
 * 在可信父进程侧校验临时 `CODEX_HOME/auth.json` 中的 OAuth 刷新结果并原子条件写回宿主机目标文件（0600）：
 *   - 仅当宿主机原有合法可写文件态 OAuth 登录（含已校验归属与可写性的符号链接目标）、临时文件为非符号链接普通文件、
 *     账号 ID 与 auth_mode 一致、access_token/refresh_token 有效且刷新时间未回滚时才允许回写；
 *   - 通过规范化跨工作区共享 SQLite 锁串行化并发 Avatar 进程；
 *   - 核验原始 `hostAuthPath` 未被登出删除或重定向且目标 `resolvedAuthPath` 的 `(dev, ino)` 未被外部 `codex login` 替换；
 *   - 通过同目录 0600 临时文件 + `fsync` + 换名前二次校验 `(dev, ino, size, mtimeMs)` + `renameSync` + `fsyncDir` 原子更新，
 *     杜绝原位截断写导致并发读取半截 JSON 或 I/O 失败损坏原文件。
 */
export function syncRefreshedCodexAuth(staged: StagedCodexHome): boolean {
  const snap = staged.origAuth;
  if (!snap || !snap.canSyncBack) return false;
  const origTokens = isPlainJsonRecord(snap.origJson.tokens) ? snap.origJson.tokens : undefined;
  if (
    !origTokens ||
    ((typeof origTokens.refresh_token !== "string" || !origTokens.refresh_token.trim()) &&
      (typeof origTokens.access_token !== "string" || !origTokens.access_token.trim()))
  ) {
    return false;
  }

  const scratchAuthPath = path.join(staged.scratchDir, "auth.json");
  let nextBytes: Buffer;
  try {
    const lst = fs.lstatSync(scratchAuthPath);
    if (lst.isSymbolicLink() || !lst.isFile() || lst.size <= 0 || lst.size > MAX_CODEX_AUTH_BYTES) {
      return false;
    }
    nextBytes = fs.readFileSync(scratchAuthPath);
  } catch {
    return false;
  }
  if (nextBytes.equals(snap.origBytes)) return false;

  let nextJson: Record<string, unknown>;
  try {
    const parsed = JSON.parse(nextBytes.toString("utf8")) as unknown;
    if (!isPlainJsonRecord(parsed)) return false;
    nextJson = parsed;
  } catch {
    return false;
  }

  const nextTokens = isPlainJsonRecord(nextJson.tokens) ? nextJson.tokens : undefined;
  if (
    !nextTokens ||
    typeof nextTokens.access_token !== "string" ||
    !nextTokens.access_token.trim() ||
    typeof nextTokens.refresh_token !== "string" ||
    !nextTokens.refresh_token.trim()
  ) {
    return false;
  }
  if (typeof snap.origJson.auth_mode === "string" && snap.origJson.auth_mode) {
    if (nextJson.auth_mode !== snap.origJson.auth_mode) return false;
  }
  if (typeof origTokens.account_id === "string" && origTokens.account_id) {
    if (nextTokens.account_id !== origTokens.account_id) return false;
  }

  const origRefreshMs = typeof snap.origJson.last_refresh === "string" ? Date.parse(snap.origJson.last_refresh) : NaN;
  const nextRefreshMs = typeof nextJson.last_refresh === "string" ? Date.parse(nextJson.last_refresh) : NaN;
  if (Number.isFinite(origRefreshMs) && Number.isFinite(nextRefreshMs) && nextRefreshMs < origRefreshMs) {
    return false;
  }
  const tokensChanged =
    nextTokens.access_token !== origTokens.access_token ||
    nextTokens.refresh_token !== origTokens.refresh_token ||
    (typeof nextTokens.id_token === "string" && nextTokens.id_token !== origTokens.id_token);
  const refreshAdvanced = Number.isFinite(nextRefreshMs) && (!Number.isFinite(origRefreshMs) || nextRefreshMs > origRefreshMs);
  if (!tokensChanged && !refreshAdvanced) return false;

  const sanitizedTokens: Record<string, unknown> = {
    ...(typeof origTokens.id_token === "string" ? { id_token: origTokens.id_token } : {}),
    ...(typeof nextTokens.id_token === "string" ? { id_token: nextTokens.id_token } : {}),
    access_token: nextTokens.access_token,
    refresh_token: nextTokens.refresh_token,
    ...(typeof nextTokens.account_id === "string"
      ? { account_id: nextTokens.account_id }
      : typeof origTokens.account_id === "string"
        ? { account_id: origTokens.account_id }
        : {}),
  };
  const nextLastRefresh =
    typeof nextJson.last_refresh === "string" && nextJson.last_refresh.trim()
      ? nextJson.last_refresh
      : new Date().toISOString();
  const mergedPayload: Record<string, unknown> = {
    ...snap.origJson,
    tokens: sanitizedTokens,
    last_refresh: nextLastRefresh,
  };
  const outBuf = Buffer.from(`${JSON.stringify(mergedPayload, null, 2)}\n`, "utf8");

  const verifyEntryPointsToTarget = (): boolean => {
    try {
      const entryLst = fs.lstatSync(snap.hostAuthPath);
      if (snap.wasSymlink) {
        if (!entryLst.isSymbolicLink()) return false;
        return fs.realpathSync(snap.hostAuthPath) === snap.resolvedAuthPath;
      }
      return (
        !entryLst.isSymbolicLink() &&
        entryLst.isFile() &&
        Number(entryLst.dev) === snap.origDev &&
        Number(entryLst.ino) === snap.origIno
      );
    } catch {
      return false;
    }
  };

  try {
    return withCodexAuthSyncLock(snap.resolvedAuthPath, () => {
      if (!verifyEntryPointsToTarget()) return false;

      const roFlags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
      let readFd: number;
      try {
        readFd = fs.openSync(snap.resolvedAuthPath, roFlags);
      } catch {
        return false;
      }
      let beforeStat: fs.Stats;
      let curHostBytes: Buffer;
      try {
        beforeStat = fs.fstatSync(readFd);
        if (
          !beforeStat.isFile() ||
          !isCurrentUidOwner(beforeStat) ||
          beforeStat.size > MAX_CODEX_AUTH_BYTES ||
          Number(beforeStat.dev) !== snap.origDev ||
          Number(beforeStat.ino) !== snap.origIno
        ) {
          return false;
        }
        const buf = Buffer.allocUnsafe(beforeStat.size);
        let readOff = 0;
        while (readOff < beforeStat.size) {
          const n = fs.readSync(readFd, buf, readOff, beforeStat.size - readOff, readOff);
          if (n <= 0) break;
          readOff += n;
        }
        curHostBytes = buf.subarray(0, readOff);
      } finally {
        try {
          fs.closeSync(readFd);
        } catch {
          // ignore
        }
      }

      if (!curHostBytes.equals(snap.origBytes)) {
        try {
          const curHostJson = JSON.parse(curHostBytes.toString("utf8")) as unknown;
          if (!isPlainJsonRecord(curHostJson) || !isPlainJsonRecord(curHostJson.tokens)) return false;
          if (
            typeof snap.origJson.auth_mode === "string" &&
            snap.origJson.auth_mode &&
            curHostJson.auth_mode !== snap.origJson.auth_mode
          ) {
            return false;
          }
          if (
            typeof origTokens.account_id === "string" &&
            origTokens.account_id &&
            curHostJson.tokens.account_id !== origTokens.account_id
          ) {
            return false;
          }
          const curHostRefreshMs = typeof curHostJson.last_refresh === "string" ? Date.parse(curHostJson.last_refresh) : NaN;
          if (!Number.isFinite(nextRefreshMs) || !Number.isFinite(curHostRefreshMs) || nextRefreshMs <= curHostRefreshMs) {
            return false;
          }
        } catch {
          return false;
        }
      }

      // 写入同目录独立 0600 临时文件并 fsync，成功后再二次核验目标未变并原子 rename 替换（出错时原文件完好无损）
      const targetDir = path.dirname(snap.resolvedAuthPath);
      const dirSt = fs.lstatSync(targetDir);
      if (!dirSt.isDirectory() || !isCurrentUidOwner(dirSt)) return false;
      const tmpPath = path.join(
        targetDir,
        `.${path.basename(snap.resolvedAuthPath)}.pa-tmp-${process.pid}-${Date.now()}-${randomUUID().slice(0, 8)}`,
      );
      const tmpFlags =
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0);
      let tmpFd: number | undefined;
      try {
        tmpFd = fs.openSync(tmpPath, tmpFlags, 0o600);
        let written = 0;
        while (written < outBuf.length) {
          const n = fs.writeSync(tmpFd, outBuf, written, outBuf.length - written, written);
          if (n <= 0) throw new Error("short write to temporary auth.json");
          written += n;
        }
        try {
          fs.fchmodSync(tmpFd, 0o600);
        } catch {
          // ignore on fs without fchmod
        }
        fs.fsyncSync(tmpFd);
        fs.closeSync(tmpFd);
        tmpFd = undefined;

        // 原子换名前再次校验入口未登出/重定向且目标 inode、大小、修改时间未变化
        if (!verifyEntryPointsToTarget()) {
          fs.rmSync(tmpPath, { force: true });
          return false;
        }
        const preRenameStat = fs.lstatSync(snap.resolvedAuthPath);
        if (
          preRenameStat.isSymbolicLink() ||
          !preRenameStat.isFile() ||
          !isCurrentUidOwner(preRenameStat) ||
          Number(preRenameStat.dev) !== snap.origDev ||
          Number(preRenameStat.ino) !== snap.origIno ||
          preRenameStat.size !== beforeStat.size ||
          preRenameStat.mtimeMs !== beforeStat.mtimeMs
        ) {
          fs.rmSync(tmpPath, { force: true });
          return false;
        }

        fs.renameSync(tmpPath, snap.resolvedAuthPath);
        fsyncDirectoryBestEffort(targetDir);
        return true;
      } catch (err) {
        if (tmpFd !== undefined) {
          try {
            fs.closeSync(tmpFd);
          } catch {
            // ignore
          }
        }
        try {
          fs.rmSync(tmpPath, { force: true });
        } catch {
          // ignore
        }
        throw err;
      }
    });
  } catch (err) {
    log("warn", "写回刷新后的 Codex auth.json 失败（保留原文件）", { err: errMsg(err) });
    return false;
  }
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
  let stagedCodexHome: StagedCodexHome | undefined;
  let stagedAws: StagedAwsProfile | undefined;
  let stagedNpmrc: StagedSanitizedNpmrc | undefined;
  let oauthLease: CodexOAuthRefreshLease | undefined;
  let r: Awaited<ReturnType<typeof runProcess>>;
  let text = "";
  let args: string[] = [];
  try {
    let finalEnv = mergeHarnessEnv(baseEnv.env, h.env);
    // 在覆盖为临时 CODEX_HOME 前，基于宿主机真实 CODEX_HOME 与原始 extraArgs 解析生效的认证策略与供应商配置
    const effectiveCredInfo = resolveEffectiveCodexCredentialStore(finalEnv, h.extraArgs, {
      ignoreProfiles: run.tools === "none",
    });
    if (effectiveCredInfo.configError) {
      throw new Error(`${effectiveCredInfo.configError}；为避免将私聊或代码误发往默认供应商，已中止执行`);
    }
    const hostCodexHome = effectiveCredInfo.codexHome;
    args = ["exec", "--skip-git-repo-check", "--sandbox", "read-only", "--ephemeral", "--color", "never", "-o", outArg];
    let extraToPass = h.extraArgs;
    if (run.tools === "none") {
      // 彻底隔离用户配置（包括 ~/.codex/config.toml 中配置的任意 MCP Server / 插件 / 钩子）与执行规则，
      // 仅保留认证与提取后的安全供应商/模型参数；静态 http_headers 改走环境变量引用，并严格过滤 extraArgs。
      const safeCfg = extractSafeCodexProviderConfig(finalEnv, h.extraArgs, !!h.model);
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

    const codexIsolationEnv = mergeHarnessEnv(process.env, h.env);
    const baseIsoPlan = buildWorkspaceIsolation(
      cfg,
      {
        mode: run.tools === "none" ? "llm-none" : "codex-exec",
        cwd: execCwd,
        cmdPath: cmd,
        trustedRepoRoot: run.trustedRepoRoot,
        disableGitWorktreeMounts: run.disableGitWorktreeMounts,
        extraWritablePaths: [...(isolatedTmp ? [isolatedTmp] : []), ...(readOutDir ? [readOutDir] : [])],
        extraReadOnlyPaths: [
          ...(run.tools !== "none" && fs.existsSync(hostCodexHome) ? [hostCodexHome] : []),
          ...(baseEnv.env.CREDENTIALS_DIRECTORY ? [baseEnv.env.CREDENTIALS_DIRECTORY] : []),
        ],
      },
      codexIsolationEnv,
    );
    const runTimeoutMs = (run.timeoutSec + 60) * 1000;
    const willIsolate = willIsolateCommand(codexIsolationEnv, baseIsoPlan);
    if (willIsolate) {
      if (process.platform === "linux" && effectiveCredInfo.needsCredentialStore && effectiveCredInfo.store === "keyring") {
        throw new Error(
          `执行者 ${run.harness} 配置了 cli_auth_credentials_store="keyring"，但当前 Linux 隔离沙箱已屏蔽宿主机 D-Bus 会话总线与 XDG_RUNTIME_DIR，无法访问 Secret Service；请在 ~/.codex/config.toml 中改用 cli_auth_credentials_store="file" 并重新运行 codex login，或通过 OPENAI_API_KEY / CODEX_API_KEY / 供应商 env_key 提供 API 密钥`,
        );
      }
      // 先按规范化目标路径跨进程/跨工作区协调 OAuth 刷新租约（覆盖整个运行超时窗口），再拷贝最新 auth.json，防止并发隔离 worker 重复消费单次 refresh_token
      oauthLease = await coordinateCodexOAuthRefresh(hostCodexHome, {
        needsCredentialStore: effectiveCredInfo.needsCredentialStore,
        signal: run.signal,
        runWindowMs: runTimeoutMs + 60_000,
        maxWaitMs: Math.max(180_000, runTimeoutMs + 30_000),
      });
      stagedCodexHome = stageIsolatedCodexHome(hostCodexHome, {
        copyUserConfig: run.tools !== "none",
        needsCredentialStore: effectiveCredInfo.needsCredentialStore,
      });
      if (effectiveCredInfo.awsProfile) {
        stagedAws = stageIsolatedAwsProfile(effectiveCredInfo.awsProfile, finalEnv, cfg.dataDir);
      }
      if (run.tools !== "none") {
        stagedNpmrc = stageSanitizedNpmrc(codexIsolationEnv, cfg.dataDir);
      }
      finalEnv = {
        ...finalEnv,
        ...isolatedSandboxTempEnv(),
        CODEX_HOME: stagedCodexHome.scratchDir,
        ...(stagedAws
          ? {
              AWS_CONFIG_FILE: stagedAws.configFile,
              AWS_SHARED_CREDENTIALS_FILE: stagedAws.credentialsFile,
            }
          : {}),
      };
      if (run.tools !== "none") applySanitizedNpmrcEnv(finalEnv, stagedNpmrc, true);
    } else if (
      process.platform === "linux" &&
      effectiveCredInfo.needsCredentialStore &&
      process.env.DBUS_SESSION_BUS_ADDRESS &&
      !finalEnv.DBUS_SESSION_BUS_ADDRESS
    ) {
      // 非隔离运行且 Codex 依赖 OpenAI/ChatGPT keyring 登录态时，保留宿主机 D-Bus 会话总线地址以访问 Secret Service
      finalEnv = {
        ...finalEnv,
        DBUS_SESSION_BUS_ADDRESS: process.env.DBUS_SESSION_BUS_ADDRESS,
      };
    }

    const extraRo = [
      ...(run.tools !== "none" && !stagedCodexHome && fs.existsSync(hostCodexHome) ? [hostCodexHome] : []),
      ...(baseEnv.env.CREDENTIALS_DIRECTORY ? [baseEnv.env.CREDENTIALS_DIRECTORY] : []),
      ...(stagedAws ? [stagedAws.dir, ...stagedAws.extraReadOnlyPaths] : []),
      ...(stagedNpmrc ? [stagedNpmrc.dir] : []),
    ];
    const extraRw = [
      ...(isolatedTmp ? [isolatedTmp] : []),
      ...(readOutDir ? [readOutDir] : []),
      ...(stagedCodexHome ? [stagedCodexHome.scratchDir] : []),
    ];
    const extraBindMounts = stagedNpmrc
      ? [{ src: stagedNpmrc.file, dest: stagedNpmrc.homeMountDest, mode: "ro" as const }]
      : [];
    const wrapped = wrapCredentialIsolatedCommand(
      cmd,
      args,
      codexIsolationEnv,
      buildWorkspaceIsolation(
        cfg,
        {
          mode: run.tools === "none" ? "llm-none" : "codex-exec",
          cwd: execCwd,
          cmdPath: cmd,
          trustedRepoRoot: run.trustedRepoRoot,
          disableGitWorktreeMounts: run.disableGitWorktreeMounts,
          extraWritablePaths: extraRw,
          extraReadOnlyPaths: extraRo,
          extraBindMounts,
        },
        codexIsolationEnv,
      ),
    );
    r = await runProcess(wrapped.cmd, wrapped.args, {
      cwd: execCwd,
      env: finalEnv,
      input: run.prompt,
      timeoutMs: runTimeoutMs,
      group: true,
      signal: run.signal,
      onSpawn: run.onSpawn,
    });
    if (stagedCodexHome) {
      syncRefreshedCodexAuth(stagedCodexHome);
    }
    try {
      text = fs.readFileSync(outFile, "utf8").trim();
      fs.rmSync(outFile, { force: true });
    } catch {
      text = r.stdout.trim();
    }
  } finally {
    oauthLease?.release();
    baseEnv.cleanup();
    stagedNpmrc?.cleanup();
    stagedCodexHome?.cleanup();
    stagedAws?.cleanup();
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
  let stagedDoubao: StagedDoubaoDataDir | undefined;
  let stagedNpmrc: StagedSanitizedNpmrc | undefined;
  let r: Awaited<ReturnType<typeof runProcess>>;
  try {
    const mode: WorkspaceIsolationMode =
      run.tools === "write" ? "worker-write" : run.tools === "read" ? "worker-ro" : "llm-none";
    const doubaoIsolationEnv = mergeHarnessEnv(process.env, h.env);
    const resolvedDataDir = cfg.dataDir && fs.existsSync(cfg.dataDir) ? safeRealpath(cfg.dataDir) : "";
    stagedDoubao = stageIsolatedDoubaoDataDir(doubaoIsolationEnv, cfg.dataDir);
    if (mode !== "llm-none") {
      stagedNpmrc = stageSanitizedNpmrc(doubaoIsolationEnv, cfg.dataDir);
    }
    const doubaoExtraRo: string[] = [];
    const doubaoExtraBindMounts: { src: string; dest: string; mode: "ro" | "rw" }[] = [];
    if (baseEnv.env.CREDENTIALS_DIRECTORY) doubaoExtraRo.push(baseEnv.env.CREDENTIALS_DIRECTORY);
    doubaoExtraRo.push(...collectLarkGuardReadOnlyFiles());
    if (run.lark !== "none" && fs.existsSync(realLark)) doubaoExtraRo.push(realLark);
    if (stagedDoubao) {
      doubaoExtraBindMounts.push(...stagedDoubao.bindMounts);
    }
    if (stagedNpmrc) {
      doubaoExtraRo.push(stagedNpmrc.dir);
      doubaoExtraBindMounts.push({ src: stagedNpmrc.file, dest: stagedNpmrc.homeMountDest, mode: "ro" });
    }
    const doubaoPaths = [
      ...selectDoubaoRuntimePaths(doubaoIsolationEnv),
      ...(run.lark !== "none" ? selectLarkCliAuthPaths(doubaoIsolationEnv) : []),
    ];
    for (const p of doubaoPaths) {
      if (!fs.existsSync(p)) continue;
      const real = safeRealpath(p);
      if (stagedDoubao && isPathInsideOrEqual(real, stagedDoubao.hostDataDir)) {
        continue;
      }
      if (resolvedDataDir && (isPathInsideOrEqual(real, resolvedDataDir) || isPathInsideOrEqual(resolvedDataDir, real))) {
        continue;
      }
      doubaoExtraRo.push(real);
    }
    const wrapped = wrapCredentialIsolatedCommand(
      cmd,
      args,
      doubaoIsolationEnv,
      buildWorkspaceIsolation(
        cfg,
        {
          mode,
          cwd: run.cwd,
          cmdPath: cmd,
          extraCmdPaths: run.lark !== "none" ? [realLark] : [],
          trustedRepoRoot: run.trustedRepoRoot,
          disableGitWorktreeMounts: run.disableGitWorktreeMounts,
          allowGuardLog: run.lark !== "none",
          extraReadOnlyPaths: doubaoExtraRo,
          extraBindMounts: doubaoExtraBindMounts,
        },
        doubaoIsolationEnv,
      ),
    );
    const env: NodeJS.ProcessEnv = {
      ...mergeHarnessEnv(baseEnv.env, h.env),
      DOUBAO_CLI_NO_UPDATE_CHECK: "1",
      PATH: `${path.join(ROOT, "bin", "guard")}${path.delimiter}${process.env.PATH ?? ""}`,
      PA_GUARD_PROFILE: run.lark,
      PA_OWNER_OPEN_ID: cfg.owner.open_id,
      PA_LARK_REAL: realLark,
      PA_GUARD_LOG: path.join(cfg.dataDir, "logs", "guard.log"),
      ...(wrapped.isolated ? isolatedSandboxTempEnv() : {}),
    };
    if (mode !== "llm-none") applySanitizedNpmrcEnv(env, stagedNpmrc, wrapped.isolated);
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
    stagedNpmrc?.cleanup();
    stagedDoubao?.cleanup();
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
