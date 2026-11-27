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
  | {
      kind: "unshare";
      bin: string;
      setprivBin: string;
      pivotRootBin?: string;
      shBin?: string;
      killChild?: boolean;
      restoreUserMap?: boolean;
    }
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

export interface StagedSanitizedGitConfig {
  dir: string;
  file: string;
  homeMountDest: string;
  bindMounts: { src: string; dest: string; mode: "ro" | "rw" }[];
  extraReadOnlyPaths: string[];
  symlinks: { dest: string; target: string }[];
  cleanup: () => void;
}

const SAFE_GIT_CONFIG_EXACT_KEYS = new Set([
  "user.name",
  "user.email",
  "user.useconfigonly",
  "core.autocrlf",
  "core.eol",
  "core.excludesfile",
  "core.attributesfile",
  "core.filemode",
  "core.ignorecase",
  "core.quotepath",
  "core.precomposeunicode",
  "core.longpaths",
  "core.safecrlf",
  "core.editor",
  "core.pager",
  "init.defaultbranch",
  "merge.conflictstyle",
  "merge.ff",
  "pull.rebase",
  "pull.ff",
  "push.default",
  "push.autosetupremote",
  "fetch.prune",
  "branch.autosetuprebase",
  "branch.sort",
  "log.date",
  "log.decorate",
  "status.showuntrackedfiles",
  "status.short",
  "safe.directory",
]);

const SAFE_GIT_DIFF_KEYS = new Set([
  "diff.algorithm",
  "diff.colormoved",
  "diff.colormovedws",
  "diff.context",
  "diff.mnemonicprefix",
  "diff.noprefix",
  "diff.renames",
  "diff.renamelimit",
  "diff.submodule",
  "diff.wsErrorHighlight".toLowerCase(),
]);

const SAFE_REMOTE_HTTP_GENERIC_KEYS = new Set([
  "http.sslverify",
  "http.sslcainfo",
  "http.sslcapath",
  "http.sslbackend",
  "http.proxy",
  "http.postbuffer",
  "http.version",
  "http.lowspeedlimit",
  "http.lowspeedtime",
  "http.followredirects",
  "http.maxrequests",
]);

const SAFE_REMOTE_CREDENTIAL_GENERIC_KEYS = new Set([
  "credential.usehttppath",
  "credential.username",
]);

function isSafeGitLfsFilterEntry(rawKey: string, rawValue: string): boolean {
  const lk = rawKey.trim().toLowerCase();
  const v = rawValue.trim();
  if (!v || /[\r\n\0]/.test(v)) return false;
  if (lk === "filter.lfs.clean") return /^git-lfs\s+clean(?:\s+--)?\s+%f$/.test(v);
  if (lk === "filter.lfs.smudge") return /^git-lfs\s+smudge(?:\s+--skip)?(?:\s+--)?\s+%f$/.test(v);
  if (lk === "filter.lfs.process") return /^git-lfs\s+filter-process(?:\s+--skip)?$/.test(v);
  if (lk === "filter.lfs.required") return /^(?:true|false|yes|no|1|0)$/i.test(v);
  return false;
}

export function gitUrlPrefixMatchesTarget(sectionPattern: string, targetRaw: string): boolean {
  const pat = sectionPattern.trim();
  const tgt = targetRaw.trim();
  if (!pat || !tgt) return false;
  let patUrl: URL;
  let tgtUrl: URL;
  try {
    patUrl = new URL(pat);
    tgtUrl = new URL(tgt);
  } catch {
    return false;
  }
  if (patUrl.protocol !== tgtUrl.protocol) return false;
  // 按 Git urlmatch 规则校验用户名：配置段含用户名时仅匹配同一用户名目标，绝不把 A 账号的凭据/extraHeader 投影给 B 账号或无用户名请求
  if (patUrl.username) {
    if (!tgtUrl.username) return false;
    let patUser = patUrl.username;
    let tgtUser = tgtUrl.username;
    try {
      patUser = decodeURIComponent(patUser);
    } catch {
      // keep raw
    }
    try {
      tgtUser = decodeURIComponent(tgtUser);
    } catch {
      // keep raw
    }
    if (patUser !== tgtUser) return false;
  }
  const patHost = patUrl.hostname.toLowerCase();
  const tgtHost = tgtUrl.hostname.toLowerCase();
  if (!patHost || !tgtHost) return false;
  if (patHost.startsWith("*.")) {
    // 按 Git urlmatch 规范：`*.example.com` 仅匹配单个主机名标签（如 `a.example.com`），绝不匹配多级子域（`x.a.example.com`）或裸域（`example.com`）
    const suffix = patHost.slice(1);
    if (!tgtHost.endsWith(suffix) || tgtHost.length <= suffix.length) return false;
    const wildcardLabel = tgtHost.slice(0, tgtHost.length - suffix.length);
    if (!wildcardLabel || wildcardLabel.includes(".")) return false;
  } else if (patHost !== tgtHost) {
    return false;
  }
  const defPort = (p: string) => (p === "https:" ? "443" : p === "http:" ? "80" : "");
  const patPort = patUrl.port || defPort(patUrl.protocol);
  const tgtPort = tgtUrl.port || defPort(tgtUrl.protocol);
  if (patPort !== tgtPort) return false;
  const patPath = patUrl.pathname.replace(/\/+$/, "");
  if (!patPath) return true;
  const tgtPath = tgtUrl.pathname.replace(/\/+$/, "");
  return tgtPath === patPath || tgtPath.startsWith(`${patPath}/`);
}

function isSafeGitConfigKey(rawKey: string): boolean {
  const lk = rawKey.trim().toLowerCase();
  if (!lk) return false;
  if (SAFE_GIT_CONFIG_EXACT_KEYS.has(lk)) return true;
  if (SAFE_GIT_DIFF_KEYS.has(lk)) return true;
  if (lk.startsWith("color.") || lk.startsWith("i18n.")) return true;
  return false;
}

function isSafeGitConfigValue(rawValue: string): boolean {
  if (/[\r\n\0]/.test(rawValue)) return false;
  if (/:\/\/[^/\s@]+@/.test(rawValue)) return false;
  if (/\b(?:authorization\s*:|bearer\s+\S|basic\s+[A-Za-z0-9+/=]{8,})/i.test(rawValue)) return false;
  return true;
}

function escapeGitConfigValue(val: string): string {
  const escaped = val.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  return `"${escaped}"`;
}

function isAllowedRemoteGitConfigEntry(key: string, value: string, allowedRemoteUrls: string[]): boolean {
  if (/[\r\n\0]/.test(value)) return false;
  const trimmedKey = key.trim();
  const lk = trimmedKey.toLowerCase();
  const hasHttpRemote = allowedRemoteUrls.some((u) => /^https?:\/\//i.test(u.trim()));
  const hasNonHttpRemote = allowedRemoteUrls.some((u) => !/^https?:\/\//i.test(u.trim()));
  if (SAFE_REMOTE_HTTP_GENERIC_KEYS.has(lk)) {
    return hasHttpRemote && isSafeGitConfigValue(value);
  }
  if (SAFE_REMOTE_CREDENTIAL_GENERIC_KEYS.has(lk)) {
    return hasHttpRemote && isSafeGitConfigValue(value);
  }
  if (lk === "core.sshcommand") {
    return hasNonHttpRemote && isSafeGitConfigValue(value);
  }
  const firstDot = trimmedKey.indexOf(".");
  const lastDot = trimmedKey.lastIndexOf(".");
  if (firstDot <= 0) return false;
  const section = trimmedKey.slice(0, firstDot).toLowerCase();
  const subsection = lastDot > firstDot ? trimmedKey.slice(firstDot + 1, lastDot) : "";
  const varName = trimmedKey.slice(lastDot + 1).toLowerCase();

  if (section === "lfs") {
    if (!isSafeGitConfigValue(value)) return false;
    if (!subsection) return true;
    return allowedRemoteUrls.some((u) => gitUrlPrefixMatchesTarget(subsection, u));
  }
  if (!subsection) return false;

  if (section === "http") {
    if (!hasHttpRemote) return false;
    // 严格仅保留命中目标远端 URL 的 http.<url>.*（如目标域名的 extraHeader / sslVerify / proxy），绝不暴露其他主机的 extraHeader
    return allowedRemoteUrls.some((u) => gitUrlPrefixMatchesTarget(subsection, u));
  }
  if (section === "credential") {
    if (!hasHttpRemote) return false;
    // credential.helper 始终由宿主机 prepareScopedGitHttpCredentials 窄范围解析，绝不把宿主机原始 helper/内联脚本透传进沙箱
    if (varName !== "usehttppath" && varName !== "username") return false;
    if (!isSafeGitConfigValue(value)) return false;
    return allowedRemoteUrls.some((u) => gitUrlPrefixMatchesTarget(subsection, u));
  }
  if (section === "url" && (varName === "insteadof" || varName === "pushinsteadof")) {
    // 无内嵌凭据的 URL 重写规则或明确指向当前已授权目标 URL 的重写规则才允许保留
    if (isSafeGitConfigValue(subsection) && isSafeGitConfigValue(value)) return true;
    return allowedRemoteUrls.some((u) => gitUrlPrefixMatchesTarget(subsection, u) || u.startsWith(subsection));
  }
  return false;
}

/**
 * 仅保留全局 Git 配置中的非敏感本地偏好（`user.name/email`、`core.autocrlf`、`color.*`、`init.defaultBranch`、`safe.directory`、标准 `filter.lfs.*` 等），
 * 彻底剥离 `http.*`（含 `extraHeader`）、`credential.*`、`url.*`（可能含带令牌的 `insteadOf`）、`alias.*`、`core.sshCommand`、`include*` 等一切凭据或命令注入项。
 * 若传入 `opts.allowedRemoteUrls`（仅限受信任远程 Git 传输），按目标 URL 窄范围附加匹配目标域的 `http.<url>.*`、`credential.<url>.username/useHttpPath` 与 `url.*` 重写。
 */
export function sanitizeGitConfigEntries(
  entries: { key: string; value: string }[],
  opts?: { allowedRemoteUrls?: string[] },
): string {
  const allowedRemoteUrls = (opts?.allowedRemoteUrls ?? []).filter(Boolean);
  const bySection = new Map<string, { name: string; value: string }[]>();
  for (const { key, value } of entries) {
    const trimmedKey = key.trim();
    const keepLocal =
      (isSafeGitConfigKey(trimmedKey) && isSafeGitConfigValue(value)) || isSafeGitLfsFilterEntry(trimmedKey, value);
    const keepRemote =
      !keepLocal &&
      allowedRemoteUrls.length > 0 &&
      isAllowedRemoteGitConfigEntry(trimmedKey, value, allowedRemoteUrls);
    if (!keepLocal && !keepRemote) continue;
    const firstDot = trimmedKey.indexOf(".");
    const lastDot = trimmedKey.lastIndexOf(".");
    if (firstDot <= 0) continue;
    const section = trimmedKey.slice(0, firstDot).toLowerCase();
    const subsection = lastDot > firstDot ? trimmedKey.slice(firstDot + 1, lastDot) : "";
    const varName = trimmedKey.slice(lastDot + 1);
    if (!section || !varName || /[\r\n\0\[\]"]/.test(section) || /[\r\n\0"]/.test(subsection) || !/^[A-Za-z0-9-]+$/.test(varName)) {
      continue;
    }
    const header = subsection ? `[${section} "${subsection.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"]` : `[${section}]`;
    const list = bySection.get(header) ?? [];
    list.push({ name: varName, value });
    bySection.set(header, list);
  }
  if (bySection.size === 0) return "";
  const lines: string[] = [];
  for (const [header, items] of bySection) {
    lines.push(header);
    for (const item of items) {
      lines.push(`\t${item.name} = ${escapeGitConfigValue(item.value)}`);
    }
  }
  return `${lines.join("\n")}\n`;
}

function parseRawGitConfigEntries(filePath: string): { key: string; value: string }[] {
  const entries: { key: string; value: string }[] = [];
  let text: string;
  try {
    const st = fs.statSync(filePath);
    if (!st.isFile() || st.size > 512 * 1024) return entries;
    text = fs.readFileSync(filePath, "utf8");
  } catch {
    return entries;
  }
  let curPrefix = "";
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const sec = line.match(/^\[([A-Za-z0-9.-]+)(?:\s+"((?:\\.|[^"\\])*)")?\]$/);
    if (sec) {
      const s = sec[1].toLowerCase();
      const sub = sec[2] ? sec[2].replace(/\\(.)/g, "$1") : "";
      curPrefix = sub ? `${s}.${sub}` : s;
      continue;
    }
    if (!curPrefix) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const varName = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1).replace(/\\(.)/g, "$1");
    }
    entries.push({ key: `${curPrefix}.${varName}`, value: val });
  }
  return entries;
}

interface EffectiveGlobalGitConfigDiscovery {
  resolvedHome: string;
  xdgConfigBase: string;
  explicitGlobalConfig?: string;
  entries: { key: string; value: string }[];
  readOnlyPaths: string[];
  symlinks: { dest: string; target: string }[];
}

function resolveExplicitGitConfigGlobal(rawEnv: NodeJS.ProcessEnv, resolvedHome: string): string | undefined {
  const raw = rawEnv.GIT_CONFIG_GLOBAL?.trim();
  if (!raw || raw === "/dev/null") return undefined;
  if (raw === "~") return resolvedHome || undefined;
  if (raw.startsWith("~/")) return resolvedHome ? path.join(resolvedHome, raw.slice(2)) : undefined;
  return path.resolve(raw);
}

/**
 * 统一的宿主机全局 Git 配置发现器（同时供 `collectSafeGitConfigMounts` 与 `stageSanitizedGitConfig` 复用）：
 *   - 严格遵守 `GIT_CONFIG_GLOBAL`（覆写默认 `~/.gitconfig` 与 `$XDG_CONFIG_HOME/git/config`）；
 *   - 优先经受信任系统 `git config --includes --show-scope --show-origin --null --list` 解析生效的 global 配置及其全部 `include`/`includeIf`（含 `gitdir`/`onbranch`/`hasconfig`）；
 *   - 静态解析器兜底，排除 `dataDir`、`.git-credentials` 与 `git/credentials`。
 */
function discoverEffectiveGlobalGitConfig(
  rawEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
  opts?: { cwd?: string; includeStaticFallbackEntries?: boolean },
): EffectiveGlobalGitConfigDiscovery | undefined {
  const rawHome = rawEnv.HOME?.trim() || os.homedir();
  if (!rawHome) return undefined;
  const resolvedHome = safeRealpath(rawHome);
  const resolvedData = dataDir && fs.existsSync(dataDir) ? safeRealpath(dataDir) : "";
  const rawXdgConfig = rawEnv.XDG_CONFIG_HOME?.trim();
  const xdgConfigBase = rawXdgConfig ? safeRealpath(rawXdgConfig) : path.join(resolvedHome, ".config");
  const rawGitGlobal = rawEnv.GIT_CONFIG_GLOBAL?.trim();
  const explicitGlobalConfig = resolveExplicitGitConfigGlobal(rawEnv, resolvedHome);

  const readOnlyPaths: string[] = [];
  const symlinks: { dest: string; target: string }[] = [];
  const addedFiles = new Set<string>();
  const addedSymlinks = new Set<string>();
  const entries: { key: string; value: string }[] = [];

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
  const staticEntryFiles: string[] = [];
  const parseStaticIncludes = (logicalCfgPath: string, depth: number) => {
    if (depth > 4) return;
    const real = addLogicalFile(logicalCfgPath);
    if (!real || visitedStatic.has(real)) return;
    visitedStatic.add(real);
    staticEntryFiles.push(real);
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

  if (rawGitGlobal === "/dev/null") {
    // 显式禁用全局配置
  } else if (explicitGlobalConfig) {
    parseStaticIncludes(explicitGlobalConfig, 0);
  } else {
    parseStaticIncludes(path.join(resolvedHome, ".gitconfig"), 0);
    parseStaticIncludes(path.join(xdgConfigBase, "git", "config"), 0);
  }

  const repoScopedDirs: string[] = [];
  if (opts?.cwd && fs.existsSync(opts.cwd)) {
    repoScopedDirs.push(safeRealpath(opts.cwd));
    const wt = detectGitWorktreeDirs(opts.cwd);
    if (wt.gitDir) repoScopedDirs.push(safeRealpath(wt.gitDir));
    if (wt.commonDir) repoScopedDirs.push(safeRealpath(wt.commonDir));
  }
  const isSafeExternalRepoIncludeTarget = (realPath: string): boolean => {
    // 绝不把仓库自身 .git/config 或 config.worktree 以只读叠加到可写仓库/工作树目录之上（否则 git config 写入会 EROFS 失败）
    if (repoScopedDirs.some((d) => isPathInsideOrEqual(realPath, d))) return false;
    if (!isSafeGitConfigIncludeTarget(realPath, resolvedData)) return false;
    for (const sensitiveSub of [
      ".ssh",
      ".aws",
      ".gnupg",
      ".codex",
      ".claude",
      ".gemini",
      ".acpx",
      path.join(".config", "opencode"),
      path.join(".local", "share", "opencode"),
    ]) {
      const sensitiveDir = path.join(resolvedHome, sensitiveSub);
      if (isPathInsideOrEqual(realPath, sensitiveDir)) return false;
    }
    return true;
  };

  let usedGit = false;
  const gitBin = resolveTrustedSystemBin("git");
  if (gitBin && (rawGitGlobal !== "/dev/null" || (opts?.cwd && fs.existsSync(opts.cwd)))) {
    try {
      const gitEnv: NodeJS.ProcessEnv = {
        PATH: TRUSTED_BOOTSTRAP_PATH,
        LC_ALL: "C",
        HOME: rawHome,
        GIT_TERMINAL_PROMPT: "0",
        ...(rawXdgConfig ? { XDG_CONFIG_HOME: rawXdgConfig } : {}),
        ...(rawGitGlobal ? { GIT_CONFIG_GLOBAL: rawGitGlobal } : {}),
      };
      const cwdArg = opts?.cwd && fs.existsSync(opts.cwd) ? ["-C", opts.cwd] : [];
      const r = spawnSync(
        gitBin,
        [
          ...cwdArg,
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
      if (r.status === 0) {
        usedGit = true;
        if (r.stdout) {
          const tokens = r.stdout.split("\0");
          for (let i = 0; i + 2 < tokens.length; i += 3) {
            const scope = tokens[i];
            const origin = tokens[i + 1];
            const rec = tokens[i + 2];
            if (!rec) continue;
            if (scope === "local" || scope === "worktree") {
              if (origin.startsWith("file:")) {
                const rawOrigin = origin.slice("file:".length);
                if (rawOrigin) {
                  const absOrigin =
                    path.isAbsolute(rawOrigin) || !opts?.cwd ? path.resolve(rawOrigin) : path.resolve(opts.cwd, rawOrigin);
                  if (fs.existsSync(absOrigin) && isSafeExternalRepoIncludeTarget(safeRealpath(absOrigin))) {
                    addLogicalFile(absOrigin);
                  }
                }
              }
              continue;
            }
            if (scope !== "global") continue;
            if (origin.startsWith("file:")) {
              const rawOrigin = origin.slice("file:".length);
              if (rawOrigin) {
                const absOrigin =
                  path.isAbsolute(rawOrigin) || !opts?.cwd ? path.resolve(rawOrigin) : path.resolve(opts.cwd, rawOrigin);
                if (fs.existsSync(absOrigin) && !isSafeGitConfigIncludeTarget(safeRealpath(absOrigin), resolvedData)) {
                  continue;
                }
                addLogicalFile(absOrigin);
              }
            }
            const nl = rec.indexOf("\n");
            if (nl <= 0) continue;
            entries.push({ key: rec.slice(0, nl), value: rec.slice(nl + 1) });
          }
        }
      }
    } catch {
      // 回退静态解析
    }
  }
  if (!usedGit && opts?.includeStaticFallbackEntries) {
    for (const f of staticEntryFiles) {
      entries.push(...parseRawGitConfigEntries(f));
    }
  }

  return {
    resolvedHome,
    xdgConfigBase,
    explicitGlobalConfig,
    entries,
    readOnlyPaths,
    symlinks,
  };
}

const SENSITIVE_GIT_AUX_HOME_SUBDIRS = [
  ".ssh",
  ".gnupg",
  ".aws",
  ".codex",
  ".claude",
  ".gemini",
  ".acpx",
  ".doubao",
  ".lark-cli",
  path.join(".config", "opencode"),
  path.join(".local", "share", "opencode"),
];

const SENSITIVE_GIT_AUX_BASENAMES = new Set([
  ".git-credentials",
  ".netrc",
  ".npmrc",
  ".gitconfig",
  "auth.json",
  ".credentials.json",
  "credentials.json",
]);

function isSafeGitAuxTargetPath(
  realPath: string,
  resolvedHome: string,
  resolvedData: string,
  kind: "file" | "dir",
): boolean {
  if (!isSafeGitConfigIncludeTarget(realPath, resolvedData)) return false;
  if (kind === "dir") {
    if (realPath === path.parse(realPath).root) return false;
    if (resolvedHome) {
      const forbiddenAncestors = [
        resolvedHome,
        path.join(resolvedHome, ".config"),
        path.join(resolvedHome, ".local"),
        path.join(resolvedHome, ".config", "git"),
      ];
      for (const anc of forbiddenAncestors) {
        if (isPathInsideOrEqual(anc, realPath)) return false;
      }
      for (const sub of SENSITIVE_GIT_AUX_HOME_SUBDIRS) {
        const sensitive = path.join(resolvedHome, sub);
        if (isPathInsideOrEqual(realPath, sensitive) || isPathInsideOrEqual(sensitive, realPath)) return false;
      }
    }
    return true;
  }
  const base = path.basename(realPath).toLowerCase();
  if (SENSITIVE_GIT_AUX_BASENAMES.has(base)) return false;
  if (resolvedHome) {
    for (const sub of SENSITIVE_GIT_AUX_HOME_SUBDIRS) {
      const sensitive = path.join(resolvedHome, sub);
      if (isPathInsideOrEqual(realPath, sensitive)) return false;
    }
  }
  return true;
}

function resolveValidatedGitAuxMount(
  rawValue: string,
  resolvedHome: string,
  resolvedData: string,
  kind: "file" | "dir",
  maxBytes: number,
): { safe: boolean; rewriteValue?: string; readOnlyPaths: string[]; symlinks: { dest: string; target: string }[] } {
  const trimmed = rawValue.trim();
  if (!trimmed) return { safe: true, readOnlyPaths: [], symlinks: [] };
  if (/[\r\n\0]/.test(trimmed)) return { safe: false, readOnlyPaths: [], symlinks: [] };
  let logicalPath: string;
  if (trimmed === "~") {
    return { safe: false, readOnlyPaths: [], symlinks: [] };
  } else if (trimmed.startsWith("~/")) {
    if (!resolvedHome) return { safe: false, readOnlyPaths: [], symlinks: [] };
    logicalPath = path.join(resolvedHome, trimmed.slice(2));
  } else if (path.isAbsolute(trimmed)) {
    logicalPath = path.resolve(trimmed);
  } else {
    // 相对路径（如仓库内路径）不需要宿主机外部挂载
    return { safe: true, readOnlyPaths: [], symlinks: [] };
  }

  let lst: fs.Stats;
  try {
    lst = fs.lstatSync(logicalPath);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === "ENOENT" || code === "ENOTDIR") {
      return {
        safe: isSafeGitAuxTargetPath(path.resolve(logicalPath), resolvedHome, resolvedData, kind),
        readOnlyPaths: [],
        symlinks: [],
      };
    }
    return { safe: false, readOnlyPaths: [], symlinks: [] };
  }

  let st: fs.Stats;
  let real: string;
  try {
    st = fs.statSync(logicalPath);
    real = fs.realpathSync(logicalPath);
  } catch {
    return { safe: false, readOnlyPaths: [], symlinks: [] };
  }
  if (kind === "file") {
    if (!st.isFile() || st.size > maxBytes) return { safe: false, readOnlyPaths: [], symlinks: [] };
  } else {
    if (!st.isDirectory()) return { safe: false, readOnlyPaths: [], symlinks: [] };
  }
  if (!isSafeGitAuxTargetPath(real, resolvedHome, resolvedData, kind)) {
    return { safe: false, readOnlyPaths: [], symlinks: [] };
  }

  const readOnlyPaths = [real];
  const symlinks: { dest: string; target: string }[] = [];
  if (lst.isSymbolicLink()) {
    const logicalDest = path.join(safeRealpath(path.dirname(logicalPath)), path.basename(logicalPath));
    if (logicalDest !== real) symlinks.push({ dest: logicalDest, target: real });
  }
  if (kind === "dir") {
    // 若 CA 目录内含指向外部单个证书文件的符号链接（如 openssl rehash），仅安全投影合规只读目标文件
    try {
      const ents = fs.readdirSync(real, { withFileTypes: true }).slice(0, 256);
      for (const ent of ents) {
        if (!ent.isSymbolicLink()) continue;
        const p = path.join(real, ent.name);
        try {
          const tSt = fs.statSync(p);
          if (!tSt.isFile() || tSt.size > maxBytes) continue;
          const tReal = fs.realpathSync(p);
          if (isPathInsideOrEqual(tReal, real)) continue;
          if (!isSafeGitAuxTargetPath(tReal, resolvedHome, resolvedData, "file")) continue;
          readOnlyPaths.push(tReal);
        } catch {
          // ignore broken cert symlink
        }
      }
    } catch {
      // ignore readdir failure
    }
  }
  return { safe: true, rewriteValue: real, readOnlyPaths, symlinks };
}

/**
 * 为不可信仓库工人、代码审查、校验命令及本地/受控远程 Git 投影脱敏的全局 Git 配置（遵守 `GIT_CONFIG_GLOBAL`）：
 *   - 默认（无 `allowedRemoteUrls`）：彻底剥离 `http.extraHeader`、带令牌 `url.*.insteadOf` 与 `credential.*`，避免仓库 clean/smudge 过滤器或不可信工人读取无关凭据；
 *     同时保留经校验的全局 `core.excludesFile` / `core.attributesFile` 并只读挂载其目标文件，确保 `git add -A` 遵守宿主机全局忽略规则；
 *   - 受信任远程 Git（传入 `allowedRemoteUrls`）：按目标 URL 仅投影匹配该目标的 `http.<url>.*`、`credential.<url>.*` 与 `url.*` 重写，
 *     并将生效的 `http.sslCAInfo` / `http.sslCAPath`（含按目标 URL 匹配段）目标以只读方式挂载进隔离沙箱。
 */
export function stageSanitizedGitConfig(
  rawEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
  opts?: { cwd?: string; allowedRemoteUrls?: string[] },
): StagedSanitizedGitConfig | undefined {
  const discovered = discoverEffectiveGlobalGitConfig(rawEnv, dataDir, {
    cwd: opts?.cwd,
    includeStaticFallbackEntries: true,
  });
  if (!discovered) return undefined;

  const resolvedData = dataDir && fs.existsSync(dataDir) ? safeRealpath(dataDir) : "";
  const allowedRemoteUrls = (opts?.allowedRemoteUrls ?? []).filter(Boolean);
  const extraReadOnlyPaths: string[] = [];
  const symlinks: { dest: string; target: string }[] = [];
  const seenRo = new Set<string>();
  const seenSym = new Set<string>();
  const addAuxMounts = (ro: string[], syms: { dest: string; target: string }[]) => {
    for (const p of ro) {
      if (!seenRo.has(p)) {
        seenRo.add(p);
        extraReadOnlyPaths.push(p);
      }
    }
    for (const s of syms) {
      const k = `${s.dest}=>${s.target}`;
      if (!seenSym.has(k)) {
        seenSym.add(k);
        symlinks.push(s);
      }
    }
  };

  // 预扫各辅助路径键的最后生效下标（Git 单值配置遵循后写覆盖），避免把被覆盖的旧路径也挂载进沙箱
  const lastAuxIdx = new Map<string, number>();
  const auxSpecForEntry = (key: string, value: string): { kind: "file" | "dir"; maxBytes: number; dedupKey: string } | undefined => {
    const trimmed = key.trim();
    const lk = trimmed.toLowerCase();
    if (lk === "core.excludesfile" || lk === "core.attributesfile") {
      return { kind: "file", maxBytes: 512 * 1024, dedupKey: lk };
    }
    if (allowedRemoteUrls.length > 0 && isAllowedRemoteGitConfigEntry(trimmed, value, allowedRemoteUrls)) {
      const firstDot = trimmed.indexOf(".");
      const lastDot = trimmed.lastIndexOf(".");
      if (firstDot > 0) {
        const section = trimmed.slice(0, firstDot).toLowerCase();
        const varName = trimmed.slice(lastDot + 1).toLowerCase();
        if (section === "http" && varName === "sslcainfo") {
          return { kind: "file", maxBytes: 4 * 1024 * 1024, dedupKey: lk };
        }
        if (section === "http" && varName === "sslcapath") {
          return { kind: "dir", maxBytes: 4 * 1024 * 1024, dedupKey: lk };
        }
      }
    }
    return undefined;
  };
  discovered.entries.forEach((entry, idx) => {
    const spec = auxSpecForEntry(entry.key, entry.value);
    if (spec) lastAuxIdx.set(spec.dedupKey, idx);
  });

  const filteredEntries: { key: string; value: string }[] = [];
  discovered.entries.forEach((entry, idx) => {
    const spec = auxSpecForEntry(entry.key, entry.value);
    if (!spec) {
      filteredEntries.push(entry);
      return;
    }
    if (lastAuxIdx.get(spec.dedupKey) !== idx) return;
    const validated = resolveValidatedGitAuxMount(
      entry.value,
      discovered.resolvedHome,
      resolvedData,
      spec.kind,
      spec.maxBytes,
    );
    if (!validated.safe) return;
    addAuxMounts(validated.readOnlyPaths, validated.symlinks);
    filteredEntries.push({
      key: entry.key,
      value: validated.rewriteValue ?? entry.value,
    });
  });

  const sanitized = sanitizeGitConfigEntries(filteredEntries, {
    allowedRemoteUrls: opts?.allowedRemoteUrls,
  });
  if (!sanitized) return undefined;
  const scoped = createScopedSecretDir("pa-git-cfg-", rawEnv);
  try {
    const file = path.join(scoped.dir, "gitconfig");
    fs.writeFileSync(file, sanitized, { mode: 0o600 });
    const homeMountDest = path.join(discovered.resolvedHome, ".gitconfig");
    const bindMounts: { src: string; dest: string; mode: "ro" | "rw" }[] = [
      { src: file, dest: homeMountDest, mode: "ro" },
    ];
    if (discovered.explicitGlobalConfig && safeRealpath(discovered.explicitGlobalConfig) !== safeRealpath(homeMountDest)) {
      bindMounts.push({ src: file, dest: discovered.explicitGlobalConfig, mode: "ro" });
    }
    return {
      dir: scoped.dir,
      file,
      homeMountDest,
      bindMounts,
      extraReadOnlyPaths,
      symlinks,
      cleanup: scoped.cleanup,
    };
  } catch (err) {
    scoped.cleanup();
    throw err;
  }
}

export function applySanitizedGitConfigEnv(
  env: NodeJS.ProcessEnv,
  staged: StagedSanitizedGitConfig | undefined,
  isolated: boolean,
): void {
  if (!isolated) return;
  if (staged) {
    env.GIT_CONFIG_GLOBAL = staged.file;
  } else {
    env.GIT_CONFIG_GLOBAL = "/dev/null";
  }
}

/** 仅收集全局只读 Git 辅助规则文件（`git/ignore` 与 `git/attributes`，绝不含任何配置或凭据，供不可信仓库工人与校验命令使用）。 */
export function collectSafeGitIgnoreAndAttrMounts(
  rawEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
): { readOnlyPaths: string[]; symlinks: { dest: string; target: string }[] } {
  const readOnlyPaths: string[] = [];
  const symlinks: { dest: string; target: string }[] = [];
  const rawHome = rawEnv.HOME?.trim() || os.homedir();
  if (!rawHome) return { readOnlyPaths, symlinks };
  const resolvedHome = safeRealpath(rawHome);
  const resolvedData = dataDir && fs.existsSync(dataDir) ? safeRealpath(dataDir) : "";
  const rawXdgConfig = rawEnv.XDG_CONFIG_HOME?.trim();
  const xdgConfigBase = rawXdgConfig ? safeRealpath(rawXdgConfig) : path.join(resolvedHome, ".config");
  for (const logicalPath of [
    path.join(xdgConfigBase, "git", "ignore"),
    path.join(xdgConfigBase, "git", "attributes"),
  ]) {
    try {
      const lst = fs.lstatSync(logicalPath);
      const st = fs.statSync(logicalPath);
      if (!st.isFile() || st.size > 512 * 1024) continue;
      const real = fs.realpathSync(logicalPath);
      if (!isSafeGitConfigIncludeTarget(real, resolvedData)) continue;
      readOnlyPaths.push(real);
      if (lst.isSymbolicLink()) {
        const logicalDest = path.join(safeRealpath(path.dirname(logicalPath)), path.basename(logicalPath));
        if (logicalDest !== real) symlinks.push({ dest: logicalDest, target: real });
      }
    } catch {
      // ignore missing/broken file
    }
  }
  return { readOnlyPaths, symlinks };
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
 * 仅收集安全的 Git 只读配置文件（共享 `discoverEffectiveGlobalGitConfig`，完整遵守 `GIT_CONFIG_GLOBAL` 与适用 `[include]`/`[includeIf]`，
 * 绝不挂载整个 `~/.config/git` 目录、`~/.config/git/credentials`、`~/.git-credentials` 或原始 `~/.npmrc`），
 * 并为符号链接 dotfiles（如 `~/.gitconfig -> ~/dotfiles/gitconfig`）保留逻辑路径符号链接，避免 Git 丢失配置且不暴露 dotfiles 其余文件。
 */
export function collectSafeGitConfigMounts(
  rawEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
  opts?: { cwd?: string },
): { readOnlyPaths: string[]; symlinks: { dest: string; target: string }[] } {
  const discovered = discoverEffectiveGlobalGitConfig(rawEnv, dataDir, {
    cwd: opts?.cwd,
    includeStaticFallbackEntries: true,
  });
  if (!discovered) return { readOnlyPaths: [], symlinks: [] };
  const resolvedData = dataDir && fs.existsSync(dataDir) ? safeRealpath(dataDir) : "";
  const rules = collectSafeGitIgnoreAndAttrMounts(rawEnv, dataDir);
  const auxRo: string[] = [];
  const auxSym: { dest: string; target: string }[] = [];
  for (const key of ["core.excludesfile", "core.attributesfile"] as const) {
    let lastVal: string | undefined;
    for (const e of discovered.entries) {
      if (e.key.trim().toLowerCase() === key) lastVal = e.value;
    }
    if (lastVal) {
      const validated = resolveValidatedGitAuxMount(lastVal, discovered.resolvedHome, resolvedData, "file", 512 * 1024);
      if (validated.safe) {
        auxRo.push(...validated.readOnlyPaths);
        auxSym.push(...validated.symlinks);
      }
    }
  }
  const readOnlyPaths = [...new Set([...discovered.readOnlyPaths, ...rules.readOnlyPaths, ...auxRo])];
  const seenSym = new Set<string>();
  const symlinks: { dest: string; target: string }[] = [];
  for (const s of [...discovered.symlinks, ...rules.symlinks, ...auxSym]) {
    if (seenSym.has(s.dest)) continue;
    seenSym.add(s.dest);
    symlinks.push(s);
  }
  return { readOnlyPaths, symlinks };
}

const INTERPRETER_EXECUTABLES = new Set([
  "node",
  "nodejs",
  "python",
  "python3",
  "bun",
  "deno",
  "tsx",
  "ts-node",
  "npx",
  "uv",
  "bash",
  "sh",
  "zsh",
  "dash",
  "ruby",
  "perl",
  "env",
]);

const ACPX_PROVIDER_AUTH_ALLOWLIST: Record<string, ReadonlySet<string>> = {
  claude: new Set(["claude", "anthropic"]),
  codex: new Set(["codex", "openai", "chatgpt"]),
  gemini: new Set(["gemini", "google", "vertex"]),
  doubao: new Set(["doubao", "volc", "volcengine", "ark"]),
  opencode: new Set(["opencode"]),
  copilot: new Set(["copilot", "github"]),
};

const ALL_KNOWN_AUTH_PROVIDER_TOKENS = new Set(
  Object.values(ACPX_PROVIDER_AUTH_ALLOWLIST).flatMap((set) => [...set]),
);

/** 按 POSIX 单引号/双引号/反斜杠语义拆分 shell 命令参数（不执行任何展开） */
export function parseShellCommandTokens(cmdStr: string): string[] {
  const tokens: string[] = [];
  let cur = "";
  let inToken = false;
  let quote: "'" | '"' | undefined;
  for (let i = 0; i < cmdStr.length; i++) {
    const ch = cmdStr[i];
    if (quote === "'") {
      if (ch === "'") quote = undefined;
      else cur += ch;
      inToken = true;
      continue;
    }
    if (quote === '"') {
      if (ch === '"') {
        quote = undefined;
      } else if (ch === "\\" && i + 1 < cmdStr.length && ['"', "\\", "$", "`"].includes(cmdStr[i + 1])) {
        cur += cmdStr[++i];
      } else {
        cur += ch;
      }
      inToken = true;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      inToken = true;
      continue;
    }
    if (ch === "\\" && i + 1 < cmdStr.length) {
      cur += cmdStr[++i];
      inToken = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (inToken) {
        tokens.push(cur);
        cur = "";
        inToken = false;
      }
      continue;
    }
    cur += ch;
    inToken = true;
  }
  if (inToken) tokens.push(cur);
  return tokens;
}

function extractCommandExecAndScriptTokens(tokens: string[]): {
  execToken?: string;
  scriptCandidates: string[];
} {
  let idx = 0;
  // 跳过前导 VAR=val 赋值与 `env [opts] [VAR=val]` 包装
  while (idx < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[idx])) {
    idx++;
  }
  if (idx < tokens.length && path.basename(tokens[idx]).toLowerCase() === "env") {
    idx++;
    while (idx < tokens.length) {
      const t = tokens[idx];
      if (t === "--") {
        idx++;
        break;
      }
      if (t === "-u" || t === "-C" || t === "-S") {
        idx += 2;
        continue;
      }
      if (t.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) {
        idx++;
        continue;
      }
      break;
    }
  }
  if (idx >= tokens.length) return { scriptCandidates: [] };
  const execToken = tokens[idx];
  const scriptCandidates: string[] = [];
  const skipNextForFlags = new Set(["-e", "--eval", "-p", "--print", "-c", "-m", "--cwd", "--port", "--host", "--model"]);
  for (let i = idx + 1; i < tokens.length; i++) {
    const tok = tokens[i];
    if (!tok) continue;
    if (tok === "--") continue;
    if (skipNextForFlags.has(tok)) {
      i++;
      continue;
    }
    if (tok.startsWith("-")) {
      const eq = tok.indexOf("=");
      if (eq > 1) {
        const rhs = tok.slice(eq + 1);
        if (rhs.startsWith("/") || rhs.startsWith("~/")) {
          scriptCandidates.push(rhs);
        }
      }
      continue;
    }
    if (tok.startsWith("/") || tok.startsWith("~/")) {
      scriptCandidates.push(tok);
    }
  }
  return { execToken, scriptCandidates };
}

function resolveSelectedAcpxAgentId(h: Pick<Config["harnesses"][string], "agent" | "agentCommand">): string {
  const agentRaw = (h.agent?.trim() || "").toLowerCase();
  if (agentRaw) return agentRaw;
  if (!h.agentCommand?.trim()) return "";
  const { execToken, scriptCandidates } = extractCommandExecAndScriptTokens(parseShellCommandTokens(h.agentCommand));
  const execBase = execToken ? path.basename(execToken).toLowerCase() : "";
  if (execBase && !INTERPRETER_EXECUTABLES.has(execBase)) return execBase;
  if (scriptCandidates.length > 0) {
    const base = path.basename(scriptCandidates[0]).toLowerCase();
    const stem = base.replace(/\.(?:[cm]?[jt]s|py|sh|rb|pl)$/i, "");
    if (stem && !INTERPRETER_EXECUTABLES.has(stem)) return stem;
  }
  return execBase;
}

function resolveKnownAcpxProviderFamily(selectedId: string): string | undefined {
  if (!selectedId) return undefined;
  for (const fam of Object.keys(ACPX_PROVIDER_AUTH_ALLOWLIST)) {
    if (selectedId === fam || selectedId === `${fam}-code` || selectedId.startsWith(`${fam}-`) || selectedId.startsWith(`${fam}_`)) {
      return fam;
    }
  }
  return undefined;
}

/**
 * 严格白名单判断 ACP `config.json` 中的 `auth` 凭据条目是否明确属于当前选定的适配器：
 *   - 绝不把未识别的自定义/Copilot 凭据默认视为共享并泄露给其他适配器；
 *   - 仅允许选定 agent 显式引用的 method ID、所属已知提供方家族词元、或以选定自定义 agent ID 精确匹配/前缀命名的条目。
 */
export function isAuthMethodAllowedForAcpxAgent(
  methodId: string,
  selectedId: string,
  explicitAuthMethods?: ReadonlySet<string>,
): boolean {
  if (explicitAuthMethods?.has(methodId)) return true;
  if (!selectedId || INTERPRETER_EXECUTABLES.has(selectedId)) return false;
  const lk = methodId.toLowerCase().trim();
  if (!lk) return false;
  const segments = lk.split(/[^a-z0-9]+/).filter(Boolean);
  const family = resolveKnownAcpxProviderFamily(selectedId);
  if (family) {
    const allowed = ACPX_PROVIDER_AUTH_ALLOWLIST[family];
    const hasOwnToken = segments.some((seg) => allowed.has(seg));
    if (!hasOwnToken) return false;
    const hasForeignToken = segments.some((seg) => ALL_KNOWN_AUTH_PROVIDER_TOKENS.has(seg) && !allowed.has(seg));
    return !hasForeignToken;
  }
  // 自定义适配器：仅精确匹配或以 `<selectedId><sep>` 为前缀（绝不放行无关未知 method ID）
  return (
    lk === selectedId ||
    lk.startsWith(`${selectedId}-`) ||
    lk.startsWith(`${selectedId}_`) ||
    lk.startsWith(`${selectedId}.`) ||
    lk.startsWith(`${selectedId}:`)
  );
}

export interface StagedAcpxState {
  dir: string;
  mountDest: string;
  extraCmdPaths: string[];
  /** 位于 `~/.acpx` 之外的解释器入口脚本或其静态相对依赖（需以只读挂载入沙箱） */
  extraReadOnlyPaths: string[];
  /** 宿主机 `~/.acpx/config.json` 已显式定义当前选中 agent 的覆盖命令 */
  usedHostAgentOverride?: boolean;
  /** `tools === "none"` 时提供的空 MCP 配置文件路径（用于 `--mcp-config`，屏蔽全局与项目 `.acpxrc.json` 中的全部 MCP Server） */
  emptyMcpConfigFile?: string;
  /** 同上，映射到沙箱挂载点下的路径 */
  emptyMcpConfigMountedPath?: string;
  cleanup: () => void;
}

function extractFirstShellCommandToken(cmdStr: string): string {
  const tokens = parseShellCommandTokens(cmdStr);
  return tokens[0] || "";
}

const RELATIVE_MODULE_SPECIFIER_RE =
  /(?:(?:import|export)\s+(?:[^"'`]*?\s+from\s+)?|import\s*\(\s*|require\s*\(\s*)["'](\.\.?\/[^"'`\r\n]+)["']/g;

function resolveRelativeScriptImport(fromFile: string, spec: string): string | undefined {
  const base = path.resolve(path.dirname(fromFile), spec);
  const candidates = [
    base,
    `${base}.mjs`,
    `${base}.js`,
    `${base}.cjs`,
    `${base}.ts`,
    `${base}.mts`,
    `${base}.cts`,
    `${base}.json`,
    path.join(base, "index.mjs"),
    path.join(base, "index.js"),
    path.join(base, "index.cjs"),
    path.join(base, "index.ts"),
  ];
  for (const cand of candidates) {
    try {
      const st = fs.statSync(cand);
      if (st.isFile() && st.size <= 4 * 1024 * 1024) return fs.realpathSync(cand);
    } catch {
      // try next extension
    }
  }
  return undefined;
}

/**
 * 收集入口脚本经静态相对 `import`/`require` 引用的依赖文件（限定在 `boundaryDir` 内且绝不越界到禁止目录或 dataDir）。
 */
function collectStaticRelativeScriptDeps(
  entryFile: string,
  boundaryDir: string,
  resolvedDataDir: string,
  forbiddenTopDirs?: ReadonlySet<string>,
): string[] {
  const found: string[] = [];
  const visited = new Set<string>();
  const queue: { file: string; depth: number }[] = [{ file: entryFile, depth: 0 }];
  while (queue.length > 0 && visited.size < 64) {
    const cur = queue.shift()!;
    if (visited.has(cur.file)) continue;
    visited.add(cur.file);
    found.push(cur.file);
    if (cur.depth >= 5) continue;
    if (!/\.(?:[cm]?js|[cm]?ts)$/i.test(cur.file)) continue;
    let src: string;
    try {
      const st = fs.statSync(cur.file);
      if (!st.isFile() || st.size > 1024 * 1024) continue;
      src = fs.readFileSync(cur.file, "utf8");
    } catch {
      continue;
    }
    RELATIVE_MODULE_SPECIFIER_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = RELATIVE_MODULE_SPECIFIER_RE.exec(src)) !== null) {
      const target = resolveRelativeScriptImport(cur.file, m[1]);
      if (!target || visited.has(target)) continue;
      if (!isPathInsideOrEqual(target, boundaryDir)) continue;
      if (resolvedDataDir && isPathInsideOrEqual(target, resolvedDataDir)) continue;
      if (forbiddenTopDirs) {
        const rel = path.relative(boundaryDir, target);
        const top = rel.split(path.sep)[0];
        if (!rel || rel.startsWith("..") || forbiddenTopDirs.has(top)) continue;
      }
      queue.push({ file: target, depth: cur.depth + 1 });
    }
  }
  return found;
}

/**
 * 为一次性 `acpx exec` 调用分配私有 `0700` 状态目录并绑定挂载到 `~/.acpx`：
 *   - 绝不暴露宿主机 `~/.acpx/sessions` 或 `~/.acpx/queues` 中的跨仓库历史会话；
 *   - 当显式指定 `agentCommand` 时，省略 `config.json` 中全部无关 `agents` 定义，仅暂存该显式适配器命令及解释器入口脚本与声明的运行时文件；
 *   - `auth` 仅按严格白名单投影明确属于当前选定适配器的凭据，绝不复制无关或未知 method ID；
 *   - 当 `tools === "none"` 时强制剥离 `mcpServers` 并生成空 MCP 配置文件（`{"mcpServers":[]}`）供 `--mcp-config` 禁用全局与项目 MCP 服务器。
 */
export function stageIsolatedAcpxState(
  h: Pick<Config["harnesses"][string], "agent" | "agentCommand">,
  hostHome: string,
  rawEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
  opts?: { tools?: "none" | "read" | "write"; builtinAdapterCommand?: string },
): StagedAcpxState | undefined {
  if (!hostHome) return undefined;
  const resolvedHome = safeRealpath(hostHome);
  const resolvedData = dataDir && fs.existsSync(dataDir) ? safeRealpath(dataDir) : "";
  const hostAcpxDir = path.join(resolvedHome, ".acpx");
  const realHostAcpxDir = fs.existsSync(hostAcpxDir) ? safeRealpath(hostAcpxDir) : hostAcpxDir;
  const selectedId = resolveSelectedAcpxAgentId(h);
  const hasExplicitAgentCmd = !!(h.agentCommand && h.agentCommand.trim());
  const disableMcp = opts?.tools === "none";
  const scoped = createScopedSecretDir("pa-acpx-state-", rawEnv);
  const extraCmdPaths: string[] = [];
  const extraReadOnlyPaths: string[] = [];

  try {
    const stateDir = path.join(scoped.dir, "acpx");
    fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    const adapterCmdTokensList: string[][] = [];
    const explicitAuthMethods = new Set<string>();
    if (hasExplicitAgentCmd) {
      const toks = parseShellCommandTokens(h.agentCommand!);
      if (toks.length > 0) adapterCmdTokensList.push(toks);
    }

    const hostCfgPath = path.join(hostAcpxDir, "config.json");
    let wroteConfig = false;
    let usedHostAgentOverride = false;
    const outCfg: Record<string, unknown> = {};
    if (
      fs.existsSync(hostCfgPath) &&
      !(resolvedData && isPathInsideOrEqual(safeRealpath(hostCfgPath), resolvedData))
    ) {
      try {
        const st = fs.statSync(hostCfgPath);
        if (st.isFile() && st.size <= 256 * 1024) {
          const parsed = JSON.parse(fs.readFileSync(hostCfgPath, "utf8")) as Record<string, unknown>;
          if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
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
              ...(disableMcp ? [] : ["mcpServers"]),
            ]) {
              if (Object.prototype.hasOwnProperty.call(parsed, key)) {
                outCfg[key] = parsed[key];
              }
            }
            if (disableMcp) {
              outCfg.mcpServers = [];
            }
            // 仅在未指定显式 agentCommand 时从 config.json 投影选定的单一 named agent；显式 agentCommand 绝不带入其他无关适配器
            if (!hasExplicitAgentCmd && parsed.agents && typeof parsed.agents === "object" && !Array.isArray(parsed.agents)) {
              const filteredAgents: Record<string, unknown> = {};
              const agentEntries = Object.entries(parsed.agents as Record<string, unknown>);
              for (const [name, def] of agentEntries) {
                const lowerName = name.toLowerCase();
                if (selectedId && lowerName !== selectedId) continue;
                filteredAgents[name] = def;
                usedHostAgentOverride = true;
                if (def && typeof def === "object" && !Array.isArray(def)) {
                  const rec = def as Record<string, unknown>;
                  if (typeof rec.command === "string" && rec.command.trim()) {
                    const toks = parseShellCommandTokens(rec.command);
                    if (toks.length > 0) adapterCmdTokensList.push(toks);
                  } else if (Array.isArray(rec.argv)) {
                    const toks = rec.argv.filter((a): a is string => typeof a === "string" && a.trim().length > 0);
                    if (toks.length > 0) adapterCmdTokensList.push(toks);
                  }
                  if (typeof rec.authMethod === "string" && rec.authMethod.trim()) {
                    explicitAuthMethods.add(rec.authMethod.trim());
                  }
                  if (Array.isArray(rec.authMethods)) {
                    for (const am of rec.authMethods) {
                      if (typeof am === "string" && am.trim()) explicitAuthMethods.add(am.trim());
                    }
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
                if (!isAuthMethodAllowedForAcpxAgent(k, selectedId, explicitAuthMethods)) continue;
                filteredAuth[k] = v;
              }
              if (Object.keys(filteredAuth).length > 0) {
                outCfg.auth = filteredAuth;
              }
            }
            wroteConfig = true;
          }
        }
      } catch {
        // 忽略损坏的 config.json，保持空白私有状态目录
      }
    }

    if (disableMcp && !Object.prototype.hasOwnProperty.call(outCfg, "mcpServers")) {
      outCfg.mcpServers = [];
      wroteConfig = true;
    }
    // 当用户未在 harness 或宿主机 ~/.acpx/config.json 覆盖当前内置适配器，且已定位到宿主机已安装或缓存的单一适配器二进制时，
    // 直接在暂存 config.json 中指向该二进制，绕开 acpx 回退到 npm exec 联网查 registry 与在只读 _npx 槽位写锁的问题。
    if (!hasExplicitAgentCmd && !usedHostAgentOverride && selectedId && opts?.builtinAdapterCommand?.trim()) {
      outCfg.agents = {
        ...(isPlainJsonRecord(outCfg.agents) ? outCfg.agents : {}),
        [selectedId]: { command: opts.builtinAdapterCommand.trim() },
      };
      wroteConfig = true;
    }
    if (wroteConfig) {
      fs.writeFileSync(path.join(stateDir, "config.json"), `${JSON.stringify(outCfg, null, 2)}\n`, {
        mode: 0o600,
      });
    }

    let emptyMcpConfigFile: string | undefined;
    let emptyMcpConfigMountedPath: string | undefined;
    if (disableMcp) {
      emptyMcpConfigFile = path.join(stateDir, "no-mcp.json");
      emptyMcpConfigMountedPath = path.join(hostAcpxDir, "no-mcp.json");
      fs.writeFileSync(emptyMcpConfigFile, `${JSON.stringify({ mcpServers: [] }, null, 2)}\n`, {
        mode: 0o600,
      });
    }

    // 仅复制被选定 agent 或显式 agentCommand 引用的可执行文件、入口脚本及其声明/静态依赖的运行时文件（绝不触及 sessions/queues/logs/cache/history 或兄弟适配器）
    const forbiddenTopDirs = new Set(["sessions", "queues", "logs", "cache", "history"]);
    const copyFileIntoStagedAcpx = (realSrcFile: string) => {
      if (!fs.existsSync(hostAcpxDir) || !isPathInsideOrEqual(realSrcFile, realHostAcpxDir)) return;
      if (resolvedData && isPathInsideOrEqual(realSrcFile, resolvedData)) return;
      const rel = path.relative(realHostAcpxDir, realSrcFile);
      const top = rel.split(path.sep)[0];
      if (!rel || rel.startsWith("..") || forbiddenTopDirs.has(top)) return;
      try {
        const cst = fs.statSync(realSrcFile);
        if (!cst.isFile() || cst.size > 4 * 1024 * 1024) return;
        const dst = path.join(stateDir, rel);
        fs.mkdirSync(path.dirname(dst), { recursive: true, mode: 0o700 });
        fs.writeFileSync(dst, fs.readFileSync(realSrcFile), { mode: cst.mode & 0o111 ? 0o700 : 0o600 });
      } catch {
        // ignore unreadable adapter file
      }
    };

    const stageAcpxScriptAndDeps = (realScriptFile: string) => {
      if (!fs.existsSync(hostAcpxDir) || !isPathInsideOrEqual(realScriptFile, realHostAcpxDir)) {
        // 位于 `~/.acpx` 之外的解释器入口脚本：放入 extraCmdPaths（自动挂载自身与独立包依赖）并补齐同目录静态相对依赖
        if (!(resolvedData && isPathInsideOrEqual(realScriptFile, resolvedData))) {
          extraCmdPaths.push(realScriptFile);
          const scriptDir = path.dirname(realScriptFile);
          for (const dep of collectStaticRelativeScriptDeps(realScriptFile, scriptDir, resolvedData)) {
            if (dep !== realScriptFile) extraReadOnlyPaths.push(dep);
          }
          const siblingPkgJson = path.join(scriptDir, "package.json");
          if (fs.existsSync(siblingPkgJson)) {
            const realPj = safeRealpath(siblingPkgJson);
            if (!(resolvedData && isPathInsideOrEqual(realPj, resolvedData))) {
              extraReadOnlyPaths.push(realPj);
            }
          }
        }
        return;
      }

      const rel = path.relative(realHostAcpxDir, realScriptFile);
      const relParts = rel.split(path.sep);
      const top = relParts[0];
      if (!rel || rel.startsWith("..") || forbiddenTopDirs.has(top)) return;

      // 1) 复制入口脚本及同目录下的静态相对 import/require 依赖
      const scriptDir = path.dirname(realScriptFile);
      for (const dep of collectStaticRelativeScriptDeps(realScriptFile, realHostAcpxDir, resolvedData, forbiddenTopDirs)) {
        copyFileIntoStagedAcpx(dep);
      }

      // 2) 若入口脚本父目录存在 package.json（确保 ESM `"type":"module"` 等声明生效），复制该 package.json；
      //    若处于专属适配器子目录（如 `~/.acpx/adapters/my-bot/package.json`，深度 >= 3）则按白名单复制该子目录内声明的运行时文件
      const dirPkgJson = path.join(scriptDir, "package.json");
      if (fs.existsSync(dirPkgJson)) {
        const realPj = safeRealpath(dirPkgJson);
        copyFileIntoStagedAcpx(realPj);
        if (relParts.length >= 3) {
          // 专属适配器目录（如 adapters/<name>/...）：安全复制该子目录，绝不暴露兄弟适配器目录
          copyTreeBounded(scriptDir, path.join(stateDir, path.relative(realHostAcpxDir, scriptDir)), realHostAcpxDir, resolvedData, {
            skipNames: new Set([".env", ".git", "sessions", "queues", "logs", "cache", "history"]),
          });
        }
      }
    };

    for (const tokens of adapterCmdTokensList) {
      const { execToken, scriptCandidates } = extractCommandExecAndScriptTokens(tokens);
      if (execToken) {
        const expanded = execToken.startsWith("~/") ? path.join(resolvedHome, execToken.slice(2)) : execToken;
        if (!path.isAbsolute(expanded)) {
          extraCmdPaths.push(execToken);
        } else if (fs.existsSync(expanded)) {
          const realCmd = safeRealpath(expanded);
          if (fs.existsSync(hostAcpxDir) && isPathInsideOrEqual(realCmd, realHostAcpxDir)) {
            stageAcpxScriptAndDeps(realCmd);
          } else {
            extraCmdPaths.push(realCmd);
          }
        }
      }
      for (const rawScript of scriptCandidates) {
        const expanded = rawScript.startsWith("~/") ? path.join(resolvedHome, rawScript.slice(2)) : rawScript;
        if (!path.isAbsolute(expanded) || !fs.existsSync(expanded)) continue;
        const realScript = safeRealpath(expanded);
        try {
          const st = fs.statSync(realScript);
          if (st.isFile()) {
            stageAcpxScriptAndDeps(realScript);
          }
        } catch {
          // ignore unreadable candidate
        }
      }
    }

    return {
      dir: stateDir,
      mountDest: hostAcpxDir,
      extraCmdPaths: [...new Set(extraCmdPaths)],
      extraReadOnlyPaths: [...new Set(extraReadOnlyPaths)],
      ...(usedHostAgentOverride ? { usedHostAgentOverride: true } : {}),
      ...(emptyMcpConfigFile ? { emptyMcpConfigFile, emptyMcpConfigMountedPath } : {}),
      cleanup: scoped.cleanup,
    };
  } catch (err) {
    scoped.cleanup();
    throw err;
  }
}

const SAFE_CLAUDE_JSON_KEYS = new Set([
  "oauthAccount",
  "userID",
  "hasCompletedOnboarding",
  "lastOnboardingVersion",
  "primaryApiKey",
  "customApiKeyResponses",
  "bypassPermissionsModeAccepted",
  "hasAvailableSubscription",
  "theme",
  "preferredNotifChannel",
  "shiftEnterKeyBindingInstalled",
  "installMethod",
  "autoUpdates",
  "hasTrustDialogAccepted",
  "firstStartTime",
  "numStartups",
]);

function sanitizeClaudeJsonContent(raw: string, opts?: { tools?: "none" | "read" | "write" }): string {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return "{}\n";
    const src = parsed as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of SAFE_CLAUDE_JSON_KEYS) {
      if (Object.prototype.hasOwnProperty.call(src, key)) {
        out[key] = src[key];
      }
    }
    if (opts?.tools !== "none" && Object.prototype.hasOwnProperty.call(src, "mcpServers")) {
      out.mcpServers = src.mcpServers;
    }
    // 明确置空 projects，彻底隐藏宿主机其他仓库会话记录、提示历史与项目级 MCP 配置
    out.projects = {};
    return `${JSON.stringify(out, null, 2)}\n`;
  } catch {
    return "{}\n";
  }
}

function sanitizeClaudeSettingsForNoTools(raw: string): string | undefined {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
    const src = parsed as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of ["model", "forceLoginMethod", "forceLoginOrgUUID"] as const) {
      if (typeof src[key] === "string" && src[key].trim()) {
        out[key] = src[key];
      }
    }
    if (src.env && typeof src.env === "object" && !Array.isArray(src.env)) {
      const safeEnv: Record<string, string> = {};
      for (const [k, v] of Object.entries(src.env as Record<string, unknown>)) {
        if (typeof v !== "string") continue;
        if (k.startsWith("PA_FEISHU_WEB_") || k === "CREDENTIALS_DIRECTORY") continue;
        safeEnv[k] = v;
      }
      if (Object.keys(safeEnv).length > 0) out.env = safeEnv;
    }
    return Object.keys(out).length > 0 ? `${JSON.stringify(out, null, 2)}\n` : undefined;
  } catch {
    return undefined;
  }
}

export interface ClaudeCredsOrigSnapshot {
  hostCredPath: string;
  resolvedCredPath: string;
  credFileName: string;
  wasSymlink: boolean;
  origBytes: Buffer;
  origJson: Record<string, unknown>;
  origDev: number;
  origIno: number;
  canSyncBack: boolean;
}

export interface StagedClaudeState {
  hostClaudeDir: string;
  hostClaudeJson: string;
  dir: string;
  claudeJsonFile: string;
  origCreds?: ClaudeCredsOrigSnapshot;
  bindMounts: { src: string; dest: string; mode: "ro" | "rw" }[];
  symlinks: { dest: string; target: string }[];
  /** 写回宿主机发生可重试 I/O 或锁错误且暂存目录含已轮换令牌时置为 true，cleanup() 将保留受保护恢复副本 */
  retainScratchForRecovery?: boolean;
  cleanup: () => void;
}

function hasClaudeOAuthRefreshToken(json: Record<string, unknown>): boolean {
  const oauth = isPlainJsonRecord(json.claudeAiOauth) ? json.claudeAiOauth : undefined;
  return !!oauth && typeof oauth.refreshToken === "string" && oauth.refreshToken.trim().length > 0;
}

function parseClaudeExpiresAtMs(oauth: Record<string, unknown> | undefined): number | undefined {
  if (!oauth) return undefined;
  const raw = oauth.expiresAt;
  if (typeof raw === "number" && Number.isFinite(raw)) {
    return raw < 1e12 ? raw * 1000 : raw;
  }
  if (typeof raw === "string" && raw.trim()) {
    const num = Number(raw);
    if (Number.isFinite(num)) return num < 1e12 ? num * 1000 : num;
    const parsed = Date.parse(raw);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

export function isClaudeOAuthRefreshNeeded(
  origJson: Record<string, unknown>,
  now = Date.now(),
  runWindowMs = 5 * 60_000,
): boolean {
  if (!hasClaudeOAuthRefreshToken(origJson)) return false;
  const oauth = origJson.claudeAiOauth as Record<string, unknown>;
  const accessToken = typeof oauth.accessToken === "string" ? oauth.accessToken.trim() : "";
  if (!accessToken) return true;
  const expMs = parseClaudeExpiresAtMs(oauth);
  if (expMs === undefined) return true;
  const windowMs = Math.max(5 * 60_000, runWindowMs);
  return expMs <= now + windowMs;
}

function resolveHostClaudeCredPath(hostClaudeDir: string): { hostCredPath: string; credFileName: string } {
  const dotPath = path.join(hostClaudeDir, ".credentials.json");
  if (fs.existsSync(dotPath)) return { hostCredPath: dotPath, credFileName: ".credentials.json" };
  const plainPath = path.join(hostClaudeDir, "credentials.json");
  if (fs.existsSync(plainPath)) return { hostCredPath: plainPath, credFileName: "credentials.json" };
  return { hostCredPath: dotPath, credFileName: ".credentials.json" };
}

function isSafeClaudeScratchDirForCleanup(scratchDir: string): boolean {
  if (!scratchDir || !path.isAbsolute(scratchDir)) return false;
  const base = path.basename(scratchDir);
  if (!base.startsWith(".pa-claude-state-") && !base.startsWith("pa-claude-state-")) return false;
  try {
    const lst = fs.lstatSync(scratchDir);
    return !lst.isSymbolicLink() && lst.isDirectory() && isCurrentUidOwner(lst);
  } catch {
    return false;
  }
}

interface ClaudeSyncTargetMeta {
  hostCredPath: string;
  resolvedCredPath: string;
  wasSymlink: boolean;
  origDev: number;
  origIno: number;
  origSha256: string;
  origExpiresAtMs?: number;
  origOrgUuid?: string;
  origJson?: Record<string, unknown>;
}

function applyValidatedClaudeAuthSyncLocked(meta: ClaudeSyncTargetMeta, scratchCredPath: string): boolean {
  let nextBytes: Buffer;
  try {
    const lst = fs.lstatSync(scratchCredPath);
    if (
      lst.isSymbolicLink() ||
      !lst.isFile() ||
      !isCurrentUidOwner(lst) ||
      lst.size <= 0 ||
      lst.size > MAX_CODEX_AUTH_BYTES
    ) {
      return false;
    }
    nextBytes = fs.readFileSync(scratchCredPath);
  } catch {
    return false;
  }
  if (sha256Hex(nextBytes) === meta.origSha256) return false;

  let nextJson: Record<string, unknown>;
  try {
    const parsed = JSON.parse(nextBytes.toString("utf8")) as unknown;
    if (!isPlainJsonRecord(parsed)) return false;
    nextJson = parsed;
  } catch {
    return false;
  }
  const nextOauth = isPlainJsonRecord(nextJson.claudeAiOauth) ? nextJson.claudeAiOauth : undefined;
  if (
    !nextOauth ||
    typeof nextOauth.accessToken !== "string" ||
    !nextOauth.accessToken.trim() ||
    typeof nextOauth.refreshToken !== "string" ||
    !nextOauth.refreshToken.trim()
  ) {
    return false;
  }
  if (
    meta.origOrgUuid &&
    typeof nextOauth.organizationUuid === "string" &&
    nextOauth.organizationUuid &&
    nextOauth.organizationUuid !== meta.origOrgUuid
  ) {
    return false;
  }
  const nextExpMs = parseClaudeExpiresAtMs(nextOauth);
  if (meta.origExpiresAtMs !== undefined && nextExpMs !== undefined && nextExpMs < meta.origExpiresAtMs) {
    return false;
  }

  const verifyEntryPointsToTarget = (): boolean => {
    try {
      const entryLst = fs.lstatSync(meta.hostCredPath);
      if (meta.wasSymlink) {
        if (!entryLst.isSymbolicLink()) return false;
        return fs.realpathSync(meta.hostCredPath) === meta.resolvedCredPath;
      }
      return (
        !entryLst.isSymbolicLink() &&
        entryLst.isFile() &&
        Number(entryLst.dev) === meta.origDev &&
        Number(entryLst.ino) === meta.origIno
      );
    } catch {
      return false;
    }
  };
  if (!verifyEntryPointsToTarget()) return false;

  const roFlags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  let readFd: number;
  try {
    readFd = fs.openSync(meta.resolvedCredPath, roFlags);
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
      Number(beforeStat.dev) !== meta.origDev ||
      Number(beforeStat.ino) !== meta.origIno
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

  let curHostJson: Record<string, unknown> | undefined;
  try {
    const parsedCur = JSON.parse(curHostBytes.toString("utf8")) as unknown;
    if (isPlainJsonRecord(parsedCur)) curHostJson = parsedCur;
  } catch {
    curHostJson = undefined;
  }

  if (sha256Hex(curHostBytes) !== meta.origSha256) {
    if (!curHostJson || !isPlainJsonRecord(curHostJson.claudeAiOauth)) return false;
    const curHostOauth = curHostJson.claudeAiOauth;
    if (
      meta.origOrgUuid &&
      typeof curHostOauth.organizationUuid === "string" &&
      curHostOauth.organizationUuid &&
      curHostOauth.organizationUuid !== meta.origOrgUuid
    ) {
      return false;
    }
    const curHostExpMs = parseClaudeExpiresAtMs(curHostOauth);
    if (nextExpMs === undefined || curHostExpMs === undefined || nextExpMs <= curHostExpMs) {
      return false;
    }
  }

  const baseJson = meta.origJson ?? curHostJson;
  if (!baseJson || !isPlainJsonRecord(baseJson.claudeAiOauth)) return false;
  const baseOauth = baseJson.claudeAiOauth;
  const tokensChanged =
    nextOauth.accessToken !== baseOauth.accessToken || nextOauth.refreshToken !== baseOauth.refreshToken;
  const expAdvanced = nextExpMs !== undefined && (meta.origExpiresAtMs === undefined || nextExpMs > meta.origExpiresAtMs);
  if (!tokensChanged && !expAdvanced) return false;

  const mergedOauth: Record<string, unknown> = {
    ...baseOauth,
    accessToken: nextOauth.accessToken,
    refreshToken: nextOauth.refreshToken,
    ...(nextOauth.expiresAt !== undefined ? { expiresAt: nextOauth.expiresAt } : {}),
    ...(Array.isArray(nextOauth.scopes) ? { scopes: nextOauth.scopes } : {}),
    ...(typeof nextOauth.subscriptionType === "string" ? { subscriptionType: nextOauth.subscriptionType } : {}),
    ...(typeof nextOauth.rateLimitTier === "string" ? { rateLimitTier: nextOauth.rateLimitTier } : {}),
  };
  const mergedPayload: Record<string, unknown> = {
    ...baseJson,
    claudeAiOauth: mergedOauth,
  };
  const outBuf = Buffer.from(`${JSON.stringify(mergedPayload, null, 2)}\n`, "utf8");

  const targetDir = path.dirname(meta.resolvedCredPath);
  const dirSt = fs.lstatSync(targetDir);
  if (!dirSt.isDirectory() || !isCurrentUidOwner(dirSt)) return false;
  const tmpPath = path.join(
    targetDir,
    `.${path.basename(meta.resolvedCredPath)}.pa-tmp-${process.pid}-${Date.now()}-${randomUUID().slice(0, 8)}`,
  );
  const tmpFlags =
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0);
  let tmpFd: number | undefined;
  try {
    tmpFd = fs.openSync(tmpPath, tmpFlags, 0o600);
    let written = 0;
    while (written < outBuf.length) {
      const n = fs.writeSync(tmpFd, outBuf, written, outBuf.length - written, written);
      if (n <= 0) throw new Error("short write to temporary Claude credentials");
      written += n;
    }
    try {
      fs.fchmodSync(tmpFd, 0o600);
    } catch {
      // ignore
    }
    fs.fsyncSync(tmpFd);
    fs.closeSync(tmpFd);
    tmpFd = undefined;

    if (!verifyEntryPointsToTarget()) {
      fs.rmSync(tmpPath, { force: true });
      return false;
    }
    const preRenameStat = fs.lstatSync(meta.resolvedCredPath);
    if (
      preRenameStat.isSymbolicLink() ||
      !preRenameStat.isFile() ||
      !isCurrentUidOwner(preRenameStat) ||
      Number(preRenameStat.dev) !== meta.origDev ||
      Number(preRenameStat.ino) !== meta.origIno ||
      preRenameStat.size !== beforeStat.size ||
      preRenameStat.mtimeMs !== beforeStat.mtimeMs
    ) {
      fs.rmSync(tmpPath, { force: true });
      return false;
    }
    fs.renameSync(tmpPath, meta.resolvedCredPath);
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
}

function hasRotatedClaudeScratchAuth(staged: StagedClaudeState): boolean {
  const snap = staged.origCreds;
  if (!snap || !snap.canSyncBack || !hasClaudeOAuthRefreshToken(snap.origJson)) return false;
  const scratchCredPath = path.join(staged.dir, snap.credFileName);
  try {
    const st = fs.lstatSync(scratchCredPath);
    if (st.isSymbolicLink() || !st.isFile() || st.size === 0 || st.size > 512 * 1024) return false;
    const raw = fs.readFileSync(scratchCredPath);
    if (sha256Hex(raw) === sha256Hex(snap.origBytes)) return false;
    const parsed = JSON.parse(raw.toString("utf8")) as unknown;
    if (!isPlainJsonRecord(parsed) || !isPlainJsonRecord(parsed.claudeAiOauth)) return false;
    const nextOauth = parsed.claudeAiOauth;
    if (typeof nextOauth.accessToken !== "string" || !nextOauth.accessToken.trim()) return false;
    if (typeof nextOauth.refreshToken !== "string" || !nextOauth.refreshToken.trim()) return false;
    const origOauth = isPlainJsonRecord(snap.origJson.claudeAiOauth) ? snap.origJson.claudeAiOauth : undefined;
    if (!origOauth) return false;
    const origOrg = typeof origOauth.organizationUuid === "string" && origOauth.organizationUuid ? origOauth.organizationUuid : undefined;
    if (origOrg && typeof nextOauth.organizationUuid === "string" && nextOauth.organizationUuid && nextOauth.organizationUuid !== origOrg) {
      return false;
    }
    const nextExp = parseClaudeExpiresAtMs(nextOauth);
    const origExp = parseClaudeExpiresAtMs(origOauth);
    const tokensChanged = nextOauth.accessToken !== origOauth.accessToken || nextOauth.refreshToken !== origOauth.refreshToken;
    const expAdvanced = nextExp !== undefined && (origExp === undefined || nextExp > origExp);
    return tokensChanged || expAdvanced;
  } catch {
    return false;
  }
}

function recoverOrphanedClaudeAuthLocked(
  db: DatabaseSync,
  resolvedCredPath: string,
  expiredLeaseHolder?: string,
): boolean {
  const rows = db
    .prepare(
      "SELECT holder, pid, scratch_auth_path, scratch_dir, host_auth_path, was_symlink, orig_dev, orig_ino, orig_sha256, orig_auth_mode, orig_account_id, orig_last_refresh, created_at FROM pending_recovery ORDER BY created_at DESC",
    )
    .all() as unknown as CodexPendingRecoveryRow[];
  let recoveredAny = false;
  for (const rec of rows) {
    const dead = !isOAuthHolderActive(rec.pid, rec.holder);
    const isExpiredHolder = !!expiredLeaseHolder && rec.holder === expiredLeaseHolder;
    if (!dead && !isExpiredHolder) continue;
    let writeFailed = false;
    try {
      const origExpMs = rec.orig_last_refresh ? Number(rec.orig_last_refresh) : undefined;
      const ok = applyValidatedClaudeAuthSyncLocked(
        {
          hostCredPath: rec.host_auth_path,
          resolvedCredPath,
          wasSymlink: rec.was_symlink !== 0,
          origDev: rec.orig_dev,
          origIno: rec.orig_ino,
          origSha256: rec.orig_sha256,
          origOrgUuid: rec.orig_account_id ?? undefined,
          origExpiresAtMs: origExpMs !== undefined && Number.isFinite(origExpMs) ? origExpMs : undefined,
        },
        rec.scratch_auth_path,
      );
      if (ok) {
        recoveredAny = true;
        log("info", "已从遗留暂存 Claude 目录原子恢复刷新后的 OAuth 凭据", {
          holder: rec.holder,
          resolvedCredPath,
        });
      }
    } catch (err) {
      writeFailed = true;
      log("warn", "恢复遗留 Claude OAuth 凭据失败（保留恢复副本与原文件）", {
        holder: rec.holder,
        err: errMsg(err),
      });
    }
    if (dead && !writeFailed) {
      if (isSafeClaudeScratchDirForCleanup(rec.scratch_dir)) {
        try {
          fs.rmSync(rec.scratch_dir, { recursive: true, force: true });
        } catch {
          // ignore
        }
      }
      db.prepare("DELETE FROM pending_recovery WHERE holder = ?").run(rec.holder);
    }
  }
  return recoveredAny;
}

export interface ClaudeOAuthRefreshLease {
  held: boolean;
  resolvedCredPath?: string;
  attachScratch?: (staged: StagedClaudeState) => void;
  release: (opts?: { keepRecoveryRow?: boolean }) => void;
}

/** 跨进程协调 Claude 文件态 OAuth（`.credentials.json`）刷新与崩溃恢复，避免单次 refreshToken 被隔离清理丢弃 */
export async function coordinateClaudeOAuthRefresh(
  hostClaudeDir: string,
  opts?: {
    signal?: AbortSignal;
    leaseTtlMs?: number;
    pollIntervalMs?: number;
    maxWaitMs?: number;
    runWindowMs?: number;
  },
): Promise<ClaudeOAuthRefreshLease> {
  if (!hostClaudeDir || !fs.existsSync(hostClaudeDir)) {
    return { held: false, release: () => undefined };
  }
  const { hostCredPath } = resolveHostClaudeCredPath(hostClaudeDir);
  const initial = inspectHostCodexAuth(hostCredPath);
  if (initial.kind === "broken_symlink") {
    throw new Error(initial.error);
  }
  if (initial.kind !== "ok" || !initial.origJson || !hasClaudeOAuthRefreshToken(initial.origJson)) {
    return { held: false, release: () => undefined };
  }
  if (!initial.canSyncBack) {
    throw new Error(
      `宿主机 Claude OAuth 凭据不可安全写回（${initial.unwritableReason ?? "权限不足"}）；为防止隔离沙箱旋转 refreshToken 后丢失新令牌，已中止执行`,
    );
  }

  const resolvedCredPath = initial.resolvedAuthPath;
  const leaseTtlMs = opts?.leaseTtlMs ?? 60_000;
  const pollMs = opts?.pollIntervalMs ?? 120;
  const deadline = Date.now() + (opts?.maxWaitMs ?? 180_000);
  const holder = `${process.pid}:${randomUUID().slice(0, 8)}`;

  const makeAttachScratch = (): ((staged: StagedClaudeState) => void) => (staged: StagedClaudeState) => {
    const snap = staged.origCreds;
    if (!snap || !snap.canSyncBack || !hasClaudeOAuthRefreshToken(snap.origJson)) return;
    activeOAuthLeaseHolders.add(holder);
    const oauth = isPlainJsonRecord(snap.origJson.claudeAiOauth) ? snap.origJson.claudeAiOauth : undefined;
    const expMs = parseClaudeExpiresAtMs(oauth);
    try {
      withCodexAuthSyncLock(snap.resolvedCredPath, (db) => {
        db.prepare(
          `INSERT OR REPLACE INTO pending_recovery
            (holder, pid, scratch_auth_path, scratch_dir, host_auth_path, was_symlink, orig_dev, orig_ino, orig_sha256, orig_auth_mode, orig_account_id, orig_last_refresh, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).run(
          holder,
          process.pid,
          path.join(staged.dir, snap.credFileName),
          path.dirname(staged.dir),
          snap.hostCredPath,
          snap.wasSymlink ? 1 : 0,
          snap.origDev,
          snap.origIno,
          sha256Hex(snap.origBytes),
          "claude_oauth",
          typeof oauth?.organizationUuid === "string" && oauth.organizationUuid ? oauth.organizationUuid : null,
          expMs !== undefined ? String(expMs) : null,
          Date.now(),
        );
      });
    } catch {
      // best-effort recovery registration
    }
  };

  for (;;) {
    if (opts?.signal?.aborted) throw new Error("aborted");
    const attempt = withCodexAuthSyncLock(resolvedCredPath, (db) => {
      const now = Date.now();
      const row = db
        .prepare("SELECT holder, pid, expires_at FROM refresh_lease WHERE id = 1")
        .get() as { holder: string; pid: number; expires_at: number } | undefined;
      if (row && row.expires_at > now && isOAuthHolderActive(row.pid, row.holder)) {
        return { action: "wait" as const };
      }
      recoverOrphanedClaudeAuthLocked(db, resolvedCredPath, row?.holder);

      const cur = inspectHostCodexAuth(hostCredPath);
      if (cur.kind === "broken_symlink") throw new Error(cur.error);
      if (cur.kind !== "ok" || !cur.origJson || !hasClaudeOAuthRefreshToken(cur.origJson)) {
        if (row) db.prepare("DELETE FROM refresh_lease WHERE id = 1").run();
        return { action: "proceed_unlocked" as const };
      }
      if (!cur.canSyncBack) {
        throw new Error(`宿主机 Claude OAuth 凭据不可安全写回（${cur.unwritableReason ?? "权限不足"}）；已中止执行`);
      }
      if (!isClaudeOAuthRefreshNeeded(cur.origJson, now, opts?.runWindowMs)) {
        if (row) db.prepare("DELETE FROM refresh_lease WHERE id = 1").run();
        return { action: "proceed_unlocked" as const };
      }
      db.prepare("INSERT OR REPLACE INTO refresh_lease (id, holder, pid, expires_at) VALUES (1, ?, ?, ?)").run(
        holder,
        process.pid,
        now + leaseTtlMs,
      );
      return { action: "acquired" as const };
    });

    if (attempt.action === "proceed_unlocked") {
      let released = false;
      const release = (relOpts?: { keepRecoveryRow?: boolean }) => {
        if (released) return;
        released = true;
        activeOAuthLeaseHolders.delete(holder);
        process.off("exit", onExit);
        try {
          withCodexAuthSyncLock(resolvedCredPath, (db) => {
            if (relOpts?.keepRecoveryRow) {
              db.prepare("UPDATE pending_recovery SET pid = 0 WHERE holder = ?").run(holder);
            } else {
              db.prepare("DELETE FROM pending_recovery WHERE holder = ?").run(holder);
            }
          });
        } catch {
          // ignore
        }
      };
      const onExit = () => release({ keepRecoveryRow: true });
      process.once("exit", onExit);
      return { held: false, resolvedCredPath, attachScratch: makeAttachScratch(), release };
    }
    if (attempt.action === "acquired") {
      activeOAuthLeaseHolders.add(holder);
      let released = false;
      const heartbeat = setInterval(() => {
        if (released) return;
        try {
          withCodexAuthSyncLock(resolvedCredPath, (db) => {
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
      const release = (relOpts?: { keepRecoveryRow?: boolean }) => {
        if (released) return;
        released = true;
        activeOAuthLeaseHolders.delete(holder);
        clearInterval(heartbeat);
        process.off("exit", onExit);
        try {
          withCodexAuthSyncLock(resolvedCredPath, (db) => {
            if (relOpts?.keepRecoveryRow) {
              db.prepare("UPDATE pending_recovery SET pid = 0 WHERE holder = ?").run(holder);
            } else {
              db.prepare("DELETE FROM pending_recovery WHERE holder = ?").run(holder);
            }
            db.prepare("DELETE FROM refresh_lease WHERE id = 1 AND holder = ?").run(holder);
          });
        } catch {
          // ignore
        }
      };
      const onExit = () => release({ keepRecoveryRow: true });
      process.once("exit", onExit);
      return { held: true, resolvedCredPath, attachScratch: makeAttachScratch(), release };
    }

    if (Date.now() >= deadline) {
      throw new Error(`等待宿主机 Claude OAuth 刷新协调锁超时 (${resolvedCredPath})，已中止执行`);
    }
    await sleepAbortableMs(pollMs, opts?.signal);
  }
}

/** 在清理暂存 Claude 目录前，条件验证并原子写回旋转后的 Claude OAuth `.credentials.json`（绝不覆盖更新的宿主机登录）；遇可重试写回错误且暂存含已轮换令牌时保留受保护恢复副本 */
export function syncRefreshedClaudeAuth(staged: StagedClaudeState): boolean {
  const snap = staged.origCreds;
  if (!snap || !snap.canSyncBack || !hasClaudeOAuthRefreshToken(snap.origJson)) return false;
  const oauth = isPlainJsonRecord(snap.origJson.claudeAiOauth) ? snap.origJson.claudeAiOauth : undefined;
  const scratchCredPath = path.join(staged.dir, snap.credFileName);
  try {
    return withCodexAuthSyncLock(snap.resolvedCredPath, () =>
      applyValidatedClaudeAuthSyncLocked(
        {
          hostCredPath: snap.hostCredPath,
          resolvedCredPath: snap.resolvedCredPath,
          wasSymlink: snap.wasSymlink,
          origDev: snap.origDev,
          origIno: snap.origIno,
          origSha256: sha256Hex(snap.origBytes),
          origExpiresAtMs: parseClaudeExpiresAtMs(oauth),
          origOrgUuid: typeof oauth?.organizationUuid === "string" && oauth.organizationUuid ? oauth.organizationUuid : undefined,
          origJson: snap.origJson,
        },
        scratchCredPath,
      ),
    );
  } catch (err) {
    if (hasRotatedClaudeScratchAuth(staged)) {
      staged.retainScratchForRecovery = true;
      log("warn", "写回刷新后的 Claude .credentials.json 失败，已保留受保护恢复副本待后续自动重试", {
        scratchDir: path.dirname(staged.dir),
        err: errMsg(err),
      });
    } else {
      log("warn", "写回刷新后的 Claude .credentials.json 失败（保留原文件）", { err: errMsg(err) });
    }
    return false;
  }
}

/**
 * 为隔离运行的 Claude ACP 工人构造按次隔离的 `0700` 配置目录与脱敏 `~/.claude.json`：
 *   - 仅拷贝运行所需的凭据与设置（`.credentials.json`、`credentials.json`，以及非 `tools="none"` 时的 `settings.json`/`settings.local.json`/`CLAUDE.md`；`tools="none"` 时仅保留安全模型与路由环境变量，剔除 hooks/mcpServers/apiKeyHelper）；
 *   - 对可写 OAuth 凭据使用持久化 scratch 目录并记录原始快照，支持刷新后原子写回宿主机与崩溃恢复；
 *   - 绝不挂载或复制宿主机 `~/.claude/projects/`、`history.jsonl`、`file-history/`、`todos/`、`debug/`、`session-env/` 等跨仓库会话记录，也剥离 `~/.claude.json` 中的 `projects` 字段。
 */
export function stageIsolatedClaudeState(
  hostHome: string,
  effectiveEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
  opts?: { tools?: "none" | "read" | "write" },
): StagedClaudeState | undefined {
  const effectiveHome = effectiveEnv.HOME?.trim() || hostHome || os.homedir();
  if (!effectiveHome) return undefined;
  const resolvedHome = safeRealpath(effectiveHome);
  const resolvedData = dataDir && fs.existsSync(dataDir) ? safeRealpath(dataDir) : "";
  const explicitDir = effectiveEnv.CLAUDE_CONFIG_DIR?.trim();
  const logicalClaudeDir = explicitDir
    ? (path.isAbsolute(explicitDir) ? explicitDir : path.join(resolvedHome, explicitDir))
    : path.join(resolvedHome, ".claude");
  const hostClaudeDir = fs.existsSync(logicalClaudeDir) ? safeRealpath(logicalClaudeDir) : logicalClaudeDir;
  const logicalClaudeJson = path.join(resolvedHome, ".claude.json");
  const hostClaudeJson = fs.existsSync(logicalClaudeJson) ? safeRealpath(logicalClaudeJson) : logicalClaudeJson;

  const isSafeSource = (realPath: string): boolean =>
    !(resolvedData && (isPathInsideOrEqual(realPath, resolvedData) || isPathInsideOrEqual(resolvedData, realPath)));

  // 检查宿主机是否存有文件态 OAuth refreshToken（若有，优先尝试恢复任何已死进程遗留的刷新结果，并在持久化状态目录下创建 scratch 避免 PrivateTmp 丢失）
  let credInspected: ReturnType<typeof inspectHostCodexAuth> = { kind: "absent" };
  let credFileName = ".credentials.json";
  if (fs.existsSync(hostClaudeDir) && isSafeSource(hostClaudeDir)) {
    const resolvedCred = resolveHostClaudeCredPath(hostClaudeDir);
    credFileName = resolvedCred.credFileName;
    credInspected = inspectHostCodexAuth(resolvedCred.hostCredPath);
    if (credInspected.kind === "broken_symlink") {
      throw new Error(credInspected.error);
    }
    if (
      credInspected.kind === "ok" &&
      credInspected.canSyncBack &&
      credInspected.origJson &&
      hasClaudeOAuthRefreshToken(credInspected.origJson) &&
      fs.existsSync(canonicalCodexLockFilePath(credInspected.resolvedAuthPath))
    ) {
      const targetResolved = credInspected.resolvedAuthPath;
      try {
        const recovered = withCodexAuthSyncLock(targetResolved, (db) => {
          const row = db
            .prepare("SELECT holder, pid, expires_at FROM refresh_lease WHERE id = 1")
            .get() as { holder: string; pid: number; expires_at: number } | undefined;
          if (row && row.expires_at > Date.now() && isOAuthHolderActive(row.pid, row.holder)) return false;
          return recoverOrphanedClaudeAuthLocked(db, targetResolved, row?.holder);
        });
        if (recovered) {
          credInspected = inspectHostCodexAuth(resolvedCred.hostCredPath);
          if (credInspected.kind === "broken_symlink") throw new Error(credInspected.error);
        }
      } catch {
        // best-effort pre-stage recovery
      }
    }
  }

  const hasWritableOAuth =
    credInspected.kind === "ok" &&
    credInspected.canSyncBack &&
    !!credInspected.origJson &&
    hasClaudeOAuthRefreshToken(credInspected.origJson);
  if (
    credInspected.kind === "ok" &&
    !!credInspected.origJson &&
    hasClaudeOAuthRefreshToken(credInspected.origJson) &&
    !credInspected.canSyncBack
  ) {
    throw new Error(
      `宿主机 Claude OAuth 凭据不可安全写回（${credInspected.unwritableReason ?? "权限不足"}）；为防止隔离沙箱旋转 refreshToken 后丢失新令牌，已中止执行`,
    );
  }

  let scopedDir = "";
  let cleanupScoped: () => void;
  if (hasWritableOAuth && credInspected.kind === "ok") {
    const persistentBase = resolvePersistentOAuthScratchBase(
      "claude-scratch",
      credInspected.resolvedAuthPath,
      hostClaudeDir,
      resolvedData,
    );
    scopedDir = safeRealpath(fs.mkdtempSync(path.join(persistentBase, ".pa-claude-state-")));
    fs.chmodSync(scopedDir, 0o700);
    cleanupScoped = () => fs.rmSync(scopedDir, { recursive: true, force: true });
  } else {
    const scoped = createScopedSecretDir("pa-claude-state-", effectiveEnv);
    scopedDir = scoped.dir;
    cleanupScoped = scoped.cleanup;
  }

  try {
    const stageDir = path.join(scopedDir, "claude");
    fs.mkdirSync(stageDir, { recursive: true, mode: 0o700 });
    let origCreds: ClaudeCredsOrigSnapshot | undefined;

    const copyAllowedFile = (srcFile: string, dstFile: string, maxBytes: number) => {
      try {
        const st = fs.statSync(srcFile);
        if (!st.isFile() || st.size > maxBytes) return;
        const realSrc = fs.realpathSync(srcFile);
        if (!isSafeSource(realSrc)) return;
        fs.writeFileSync(dstFile, fs.readFileSync(realSrc), { mode: 0o600 });
      } catch {
        // ignore missing or unreadable optional file
      }
    };

    if (fs.existsSync(hostClaudeDir) && isSafeSource(hostClaudeDir)) {
      try {
        if (fs.statSync(hostClaudeDir).isDirectory()) {
          if (credInspected.kind === "ok" && isSafeSource(credInspected.resolvedAuthPath)) {
            fs.writeFileSync(path.join(stageDir, credFileName), credInspected.origBytes, { mode: 0o600 });
            if (credInspected.origJson) {
              origCreds = {
                hostCredPath: credInspected.hostAuthPath,
                resolvedCredPath: credInspected.resolvedAuthPath,
                credFileName,
                wasSymlink: credInspected.wasSymlink,
                origBytes: credInspected.origBytes,
                origJson: credInspected.origJson,
                origDev: credInspected.origDev,
                origIno: credInspected.origIno,
                canSyncBack: credInspected.canSyncBack,
              };
            }
          }
          const otherCredName = credFileName === ".credentials.json" ? "credentials.json" : ".credentials.json";
          copyAllowedFile(path.join(hostClaudeDir, otherCredName), path.join(stageDir, otherCredName), 256 * 1024);

          if (opts?.tools === "none") {
            const settingsSrc = path.join(hostClaudeDir, "settings.json");
            try {
              const st = fs.statSync(settingsSrc);
              if (st.isFile() && st.size <= 512 * 1024) {
                const realSettings = fs.realpathSync(settingsSrc);
                if (isSafeSource(realSettings)) {
                  const sanitized = sanitizeClaudeSettingsForNoTools(fs.readFileSync(realSettings, "utf8"));
                  if (sanitized) {
                    fs.writeFileSync(path.join(stageDir, "settings.json"), sanitized, { mode: 0o600 });
                  }
                }
              }
            } catch {
              // ignore missing/invalid settings.json
            }
          } else {
            copyAllowedFile(path.join(hostClaudeDir, "settings.json"), path.join(stageDir, "settings.json"), 512 * 1024);
            copyAllowedFile(path.join(hostClaudeDir, "settings.local.json"), path.join(stageDir, "settings.local.json"), 512 * 1024);
            copyAllowedFile(path.join(hostClaudeDir, "CLAUDE.md"), path.join(stageDir, "CLAUDE.md"), 1024 * 1024);
          }

          // 若 CLAUDE_CONFIG_DIR 内部自身存有 .claude.json，也做同样脱敏投影
          const innerClaudeJson = path.join(hostClaudeDir, ".claude.json");
          try {
            const st = fs.statSync(innerClaudeJson);
            if (st.isFile() && st.size <= 4 * 1024 * 1024) {
              const realInner = fs.realpathSync(innerClaudeJson);
              if (isSafeSource(realInner)) {
                const sanitized = sanitizeClaudeJsonContent(fs.readFileSync(realInner, "utf8"), opts);
                fs.writeFileSync(path.join(stageDir, ".claude.json"), sanitized, { mode: 0o600 });
              }
            }
          } catch {
            // ignore missing inner .claude.json
          }
        }
      } catch {
        // ignore non-directory hostClaudeDir
      }
    }

    const claudeJsonFile = path.join(scopedDir, "claude.json");
    let sanitizedHomeJson = "{}\n";
    try {
      const st = fs.statSync(logicalClaudeJson);
      if (st.isFile() && st.size <= 4 * 1024 * 1024) {
        const realJson = fs.realpathSync(logicalClaudeJson);
        if (isSafeSource(realJson)) {
          sanitizedHomeJson = sanitizeClaudeJsonContent(fs.readFileSync(realJson, "utf8"), opts);
        }
      }
    } catch {
      // absent or unreadable ~/.claude.json -> empty sanitized object
    }
    fs.writeFileSync(claudeJsonFile, sanitizedHomeJson, { mode: 0o600 });

    const bindMounts: { src: string; dest: string; mode: "ro" | "rw" }[] = [
      { src: stageDir, dest: logicalClaudeDir, mode: "rw" },
      { src: claudeJsonFile, dest: logicalClaudeJson, mode: "rw" },
    ];
    const symlinks: { dest: string; target: string }[] = [];
    try {
      const jsonLst = fs.lstatSync(logicalClaudeJson);
      if (jsonLst.isSymbolicLink()) {
        const logicalDest = path.join(safeRealpath(path.dirname(logicalClaudeJson)), path.basename(logicalClaudeJson));
        if (logicalDest !== hostClaudeJson) {
          symlinks.push({ dest: logicalDest, target: hostClaudeJson });
        }
      }
    } catch {
      // not a symlink
    }

    const state: StagedClaudeState = {
      hostClaudeDir,
      hostClaudeJson,
      dir: stageDir,
      claudeJsonFile,
      origCreds,
      bindMounts,
      symlinks,
      retainScratchForRecovery: false,
      cleanup: () => {
        if (state.retainScratchForRecovery) return;
        cleanupScoped();
      },
    };
    return state;
  } catch (err) {
    cleanupScoped();
    throw err;
  }
}

export interface StagedAgentState {
  hostDirsToSkip: string[];
  bindMounts: { src: string; dest: string; mode: "ro" | "rw" }[];
  cleanup: () => void;
}

function sanitizeGeminiSettingsForNoTools(raw: string): string | undefined {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
    const src = parsed as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of ["selectedAuthType", "model", "theme"] as const) {
      if (Object.prototype.hasOwnProperty.call(src, key)) out[key] = src[key];
    }
    if (isPlainJsonRecord(src.security) && isPlainJsonRecord(src.security.auth)) {
      out.security = { auth: src.security.auth };
    }
    return Object.keys(out).length > 0 ? `${JSON.stringify(out, null, 2)}\n` : undefined;
  } catch {
    return undefined;
  }
}

/**
 * 为隔离运行的 Gemini ACP 工人构造按次隔离的 `0700` 可写配置目录：
 *   - 仅复制运行所需的凭据与设置（`oauth_creds.json`、`google_accounts.json`、`installation_id`、`settings.json`，以及非 `tools="none"` 时的 `GEMINI.md`、`mcp-oauth-tokens.json`）；
 *   - 绝不暴露宿主机 `~/.gemini/tmp/`（跨项目对话历史与检查点）、`history/`、`sessions/`、`logs/`、`antigravity/` 等历史数据。
 */
export function stageIsolatedGeminiState(
  hostHome: string,
  effectiveEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
  opts?: { tools?: "none" | "read" | "write" },
): StagedAgentState | undefined {
  const effectiveHome = effectiveEnv.HOME?.trim() || hostHome || os.homedir();
  if (!effectiveHome) return undefined;
  const resolvedHome = safeRealpath(effectiveHome);
  const resolvedData = dataDir && fs.existsSync(dataDir) ? safeRealpath(dataDir) : "";
  const isSafeSource = (realPath: string): boolean =>
    !(resolvedData && (isPathInsideOrEqual(realPath, resolvedData) || isPathInsideOrEqual(resolvedData, realPath)));

  const rawGeminiHome = effectiveEnv.GEMINI_CLI_HOME?.trim();
  const logicalBase = rawGeminiHome
    ? (path.isAbsolute(rawGeminiHome) ? rawGeminiHome : path.join(resolvedHome, rawGeminiHome))
    : path.join(resolvedHome, ".gemini");
  // 若 GEMINI_CLI_HOME 内部存在 `.gemini` 子目录（Gemini CLI 将 GEMINI_CLI_HOME 视作替代 HOME），则目标目录为 `<GEMINI_CLI_HOME>/.gemini`
  const logicalGeminiDir =
    rawGeminiHome && fs.existsSync(path.join(logicalBase, ".gemini"))
      ? path.join(logicalBase, ".gemini")
      : logicalBase;
  const hostGeminiDir = fs.existsSync(logicalGeminiDir) ? safeRealpath(logicalGeminiDir) : logicalGeminiDir;
  const hostBaseDir = fs.existsSync(logicalBase) ? safeRealpath(logicalBase) : logicalBase;

  const scoped = createScopedSecretDir("pa-gemini-state-", effectiveEnv);
  try {
    const stageDir = path.join(scoped.dir, "gemini");
    fs.mkdirSync(stageDir, { recursive: true, mode: 0o700 });

    const copyAllowed = (name: string, maxBytes: number) => {
      const src = path.join(hostGeminiDir, name);
      try {
        const st = fs.statSync(src);
        if (!st.isFile() || st.size > maxBytes) return;
        const realSrc = fs.realpathSync(src);
        if (!isSafeSource(realSrc)) return;
        fs.writeFileSync(path.join(stageDir, name), fs.readFileSync(realSrc), { mode: 0o600 });
      } catch {
        // ignore missing optional file
      }
    };

    if (fs.existsSync(hostGeminiDir) && isSafeSource(hostGeminiDir)) {
      try {
        if (fs.statSync(hostGeminiDir).isDirectory()) {
          copyAllowed("oauth_creds.json", 256 * 1024);
          copyAllowed("google_accounts.json", 256 * 1024);
          copyAllowed("installation_id", 16 * 1024);
          if (opts?.tools === "none") {
            const settingsSrc = path.join(hostGeminiDir, "settings.json");
            try {
              const st = fs.statSync(settingsSrc);
              if (st.isFile() && st.size <= 512 * 1024) {
                const realSettings = fs.realpathSync(settingsSrc);
                if (isSafeSource(realSettings)) {
                  const sanitized = sanitizeGeminiSettingsForNoTools(fs.readFileSync(realSettings, "utf8"));
                  if (sanitized) fs.writeFileSync(path.join(stageDir, "settings.json"), sanitized, { mode: 0o600 });
                }
              }
            } catch {
              // ignore
            }
          } else {
            copyAllowed("settings.json", 512 * 1024);
            copyAllowed("mcp-oauth-tokens.json", 256 * 1024);
            copyAllowed("GEMINI.md", 1024 * 1024);
          }
        }
      } catch {
        // ignore
      }
    }

    return {
      hostDirsToSkip: [...new Set([hostGeminiDir, hostBaseDir])],
      bindMounts: [{ src: stageDir, dest: logicalGeminiDir, mode: "rw" }],
      cleanup: scoped.cleanup,
    };
  } catch (err) {
    scoped.cleanup();
    throw err;
  }
}

/**
 * 字符串感知的 JSONC 解析器（零外部运行时依赖）：
 *   - 完整保留字符串字面量内部的 `//`、`/*` 与引号转义（如 `"baseURL": "https://api.corp.example/v1"`）；
 *   - 正确剥离行尾 `// ...` 注释、块注释 `/* ... *\/`（未闭合块注释显式抛错）以及对象/数组尾随逗号；
 *   - 解析失败时直接抛错以便调用方 fail-closed，绝不静默丢弃配置文件导致切换默认供应商。
 */
export function parseJsonc(raw: string): unknown {
  const src = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
  const n = src.length;
  let out = "";
  let i = 0;
  let inString = false;
  let escaped = false;

  const skipWhitespaceAndComments = (pos: number): number => {
    let j = pos;
    while (j < n) {
      const ch = src[j];
      if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") {
        j++;
      } else if (ch === "/" && src[j + 1] === "/") {
        j += 2;
        while (j < n && src[j] !== "\n") j++;
      } else if (ch === "/" && src[j + 1] === "*") {
        const end = src.indexOf("*/", j + 2);
        if (end < 0) throw new SyntaxError("JSONC 中存在未闭合的块注释");
        j = end + 2;
      } else {
        break;
      }
    }
    return j;
  };

  while (i < n) {
    const ch = src[i];
    if (inString) {
      out += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      i++;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      i++;
      continue;
    }
    if (ch === "/" && src[i + 1] === "/") {
      i += 2;
      while (i < n && src[i] !== "\n") i++;
      continue;
    }
    if (ch === "/" && src[i + 1] === "*") {
      const end = src.indexOf("*/", i + 2);
      if (end < 0) throw new SyntaxError("JSONC 中存在未闭合的块注释");
      i = end + 2;
      continue;
    }
    if (ch === ",") {
      const next = skipWhitespaceAndComments(i + 1);
      if (next < n && (src[next] === "}" || src[next] === "]")) {
        i++;
        continue;
      }
    }
    out += ch;
    i++;
  }
  return JSON.parse(out) as unknown;
}

export function sanitizeOpenCodeConfigForNoTools(raw: string): string {
  const parsed = parseJsonc(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("OpenCode 配置文件根节点必须是 JSON 对象");
  }
  const src = parsed as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of ["$schema", "model", "small_model", "provider", "disabled_providers", "enabled_providers"] as const) {
    if (Object.prototype.hasOwnProperty.call(src, key)) out[key] = src[key];
  }
  return `${JSON.stringify(out, null, 2)}\n`;
}

interface OpenCodeOAuthEntry {
  refresh: string;
  access: string;
  expiresMs?: number;
}

function parseOpenCodeOAuthEntry(val: unknown): OpenCodeOAuthEntry | undefined {
  if (!isPlainJsonRecord(val)) return undefined;
  const refresh =
    (typeof val.refresh === "string" && val.refresh.trim()) ||
    (typeof val.refresh_token === "string" && val.refresh_token.trim()) ||
    (typeof val.refreshToken === "string" && val.refreshToken.trim()) ||
    "";
  if (!refresh) return undefined;
  const access =
    (typeof val.access === "string" && val.access.trim()) ||
    (typeof val.access_token === "string" && val.access_token.trim()) ||
    (typeof val.accessToken === "string" && val.accessToken.trim()) ||
    "";
  const rawExp = val.expires ?? val.expires_at ?? val.expiresAt;
  let expiresMs: number | undefined;
  if (typeof rawExp === "number" && Number.isFinite(rawExp) && rawExp > 0) {
    expiresMs = rawExp < 1e12 ? rawExp * 1000 : rawExp;
  } else if (typeof rawExp === "string" && rawExp.trim()) {
    const num = Number(rawExp.trim());
    if (Number.isFinite(num) && num > 0) expiresMs = num < 1e12 ? num * 1000 : num;
    else {
      const parsed = Date.parse(rawExp.trim());
      if (Number.isFinite(parsed) && parsed > 0) expiresMs = parsed;
    }
  }
  return { refresh, access, expiresMs };
}

function extractOpenCodeOAuthProviders(obj: Record<string, unknown>): Map<string, OpenCodeOAuthEntry> {
  const out = new Map<string, OpenCodeOAuthEntry>();
  for (const [providerId, val] of Object.entries(obj)) {
    const entry = parseOpenCodeOAuthEntry(val);
    if (entry) out.set(providerId, entry);
  }
  return out;
}

function hasOpenCodeOAuthRefreshToken(obj: Record<string, unknown>): boolean {
  return extractOpenCodeOAuthProviders(obj).size > 0;
}

export function isOpenCodeOAuthRefreshNeeded(
  authJson: Record<string, unknown>,
  nowMs = Date.now(),
  runWindowMs = 0,
): boolean {
  const providers = extractOpenCodeOAuthProviders(authJson);
  if (providers.size === 0) return false;
  const safetyBufferMs = 10 * 60_000 + Math.max(0, runWindowMs);
  for (const entry of providers.values()) {
    if (entry.expiresMs === undefined) return true;
    if (entry.expiresMs <= nowMs + safetyBufferMs) return true;
  }
  return false;
}

interface OpenCodeAuthOrigSnapshot {
  hostAuthPath: string;
  resolvedAuthPath: string;
  wasSymlink: boolean;
  origBytes: Buffer;
  origJson: Record<string, unknown>;
  origDev: number;
  origIno: number;
  canSyncBack: boolean;
}

export interface StagedOpenCodeState extends StagedAgentState {
  stageDataDir: string;
  origAuth?: OpenCodeAuthOrigSnapshot;
  /** 写回宿主机发生可重试 I/O 或锁错误且暂存目录含已轮换令牌时置为 true，cleanup() 将保留受保护恢复副本 */
  retainScratchForRecovery?: boolean;
}

export interface OpenCodeOAuthRefreshLease {
  held: boolean;
  resolvedAuthPath?: string;
  attachScratch?: (staged: StagedOpenCodeState) => void;
  release: (opts?: { keepRecoveryRow?: boolean }) => void;
}

function applyValidatedOpenCodeAuthSyncLocked(
  meta: {
    hostAuthPath: string;
    resolvedAuthPath: string;
    wasSymlink: boolean;
    origDev: number;
    origIno: number;
    origJson: Record<string, unknown>;
  },
  scratchAuthPath: string,
): boolean {
  if (!fs.existsSync(scratchAuthPath)) return false;
  let scratchBytes: Buffer;
  try {
    const st = fs.lstatSync(scratchAuthPath);
    if (st.isSymbolicLink() || !st.isFile() || st.size === 0 || st.size > 512 * 1024) return false;
    scratchBytes = fs.readFileSync(scratchAuthPath);
  } catch {
    return false;
  }
  let scratchJson: Record<string, unknown>;
  try {
    const parsed = JSON.parse(scratchBytes.toString("utf8")) as unknown;
    if (!isPlainJsonRecord(parsed)) return false;
    scratchJson = parsed;
  } catch {
    return false;
  }

  const origProviders = extractOpenCodeOAuthProviders(meta.origJson);
  const scratchProviders = extractOpenCodeOAuthProviders(scratchJson);
  const changedProviders = new Map<string, Record<string, unknown>>();
  for (const [pid, origEntry] of origProviders) {
    const nextEntry = scratchProviders.get(pid);
    if (!nextEntry) continue;
    const rawNext = scratchJson[pid];
    if (!isPlainJsonRecord(rawNext)) continue;
    const changed =
      nextEntry.refresh !== origEntry.refresh ||
      nextEntry.access !== origEntry.access ||
      nextEntry.expiresMs !== origEntry.expiresMs;
    if (!changed) continue;
    if (origEntry.expiresMs !== undefined && nextEntry.expiresMs !== undefined && nextEntry.expiresMs < origEntry.expiresMs) {
      continue;
    }
    changedProviders.set(pid, rawNext);
  }
  if (changedProviders.size === 0) return false;

  const verifyEntryPointsToTarget = (): boolean => {
    try {
      const entryLst = fs.lstatSync(meta.hostAuthPath);
      if (meta.wasSymlink) {
        if (!entryLst.isSymbolicLink()) return false;
        if (fs.realpathSync(meta.hostAuthPath) !== meta.resolvedAuthPath) return false;
      } else {
        if (entryLst.isSymbolicLink() || !entryLst.isFile()) return false;
        if (fs.realpathSync(meta.hostAuthPath) !== meta.resolvedAuthPath) return false;
      }
      return true;
    } catch {
      return false;
    }
  };
  if (!verifyEntryPointsToTarget()) return false;

  let beforeStat: fs.Stats;
  let hostCurJson: Record<string, unknown>;
  try {
    beforeStat = fs.lstatSync(meta.resolvedAuthPath);
    if (beforeStat.isSymbolicLink() || !beforeStat.isFile() || !isCurrentUidOwner(beforeStat)) return false;
    if (beforeStat.size === 0 || beforeStat.size > 512 * 1024) return false;
    const curParsed = JSON.parse(fs.readFileSync(meta.resolvedAuthPath, "utf8")) as unknown;
    if (!isPlainJsonRecord(curParsed)) return false;
    hostCurJson = curParsed;
  } catch {
    return false;
  }

  // 逐供应商合并：仅写回宿主机上未被并发改写/重登的 OAuth 供应商凭据，保留宿主机其他供应商及更新登录
  const merged: Record<string, unknown> = { ...hostCurJson };
  let appliedCount = 0;
  for (const [pid, nextVal] of changedProviders) {
    const origRaw = meta.origJson[pid];
    const hostRaw = hostCurJson[pid];
    if (JSON.stringify(hostRaw) !== JSON.stringify(origRaw)) {
      continue;
    }
    merged[pid] = nextVal;
    appliedCount++;
  }
  if (appliedCount === 0) return false;

  const outBuf = Buffer.from(`${JSON.stringify(merged, null, 2)}\n`, "utf8");
  const targetDir = path.dirname(meta.resolvedAuthPath);
  const dirSt = fs.lstatSync(targetDir);
  if (!dirSt.isDirectory() || !isCurrentUidOwner(dirSt)) return false;
  const tmpPath = path.join(
    targetDir,
    `.${path.basename(meta.resolvedAuthPath)}.pa-tmp-${process.pid}-${Date.now()}-${randomUUID().slice(0, 8)}`,
  );
  const tmpFlags =
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0);
  let tmpFd: number | undefined;
  try {
    tmpFd = fs.openSync(tmpPath, tmpFlags, 0o600);
    let written = 0;
    while (written < outBuf.length) {
      const n = fs.writeSync(tmpFd, outBuf, written, outBuf.length - written, written);
      if (n <= 0) throw new Error("short write to temporary OpenCode auth.json");
      written += n;
    }
    try {
      fs.fchmodSync(tmpFd, 0o600);
    } catch {
      // ignore
    }
    fs.fsyncSync(tmpFd);
    fs.closeSync(tmpFd);
    tmpFd = undefined;

    if (!verifyEntryPointsToTarget()) {
      fs.rmSync(tmpPath, { force: true });
      return false;
    }
    const preRenameStat = fs.lstatSync(meta.resolvedAuthPath);
    if (
      preRenameStat.isSymbolicLink() ||
      !preRenameStat.isFile() ||
      !isCurrentUidOwner(preRenameStat) ||
      Number(preRenameStat.dev) !== Number(beforeStat.dev) ||
      Number(preRenameStat.ino) !== Number(beforeStat.ino) ||
      preRenameStat.size !== beforeStat.size ||
      preRenameStat.mtimeMs !== beforeStat.mtimeMs
    ) {
      fs.rmSync(tmpPath, { force: true });
      return false;
    }
    fs.renameSync(tmpPath, meta.resolvedAuthPath);
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
}

function hasRotatedOpenCodeScratchAuth(staged: StagedOpenCodeState): boolean {
  const snap = staged.origAuth;
  if (!snap || !snap.canSyncBack || !hasOpenCodeOAuthRefreshToken(snap.origJson)) return false;
  const scratchAuthPath = path.join(staged.stageDataDir, "auth.json");
  try {
    const st = fs.lstatSync(scratchAuthPath);
    if (st.isSymbolicLink() || !st.isFile() || st.size === 0 || st.size > 512 * 1024) return false;
    const raw = fs.readFileSync(scratchAuthPath);
    if (sha256Hex(raw) === sha256Hex(snap.origBytes)) return false;
    const parsed = JSON.parse(raw.toString("utf8")) as unknown;
    if (!isPlainJsonRecord(parsed)) return false;
    for (const [pid, nextVal] of Object.entries(parsed)) {
      if (!isPlainJsonRecord(nextVal) || nextVal.type !== "oauth") continue;
      if (typeof nextVal.refresh !== "string" || !nextVal.refresh.trim()) continue;
      if (typeof nextVal.access !== "string" || !nextVal.access.trim()) continue;
      const origVal = snap.origJson[pid];
      if (!isPlainJsonRecord(origVal) || origVal.type !== "oauth") continue;
      if (JSON.stringify(origVal) !== JSON.stringify(nextVal)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

function recoverOrphanedOpenCodeAuthLocked(
  db: DatabaseSync,
  resolvedAuthPath: string,
  expiredLeaseHolder?: string,
): boolean {
  const rows = db
    .prepare(
      "SELECT holder, pid, scratch_auth_path, scratch_dir, host_auth_path, was_symlink, orig_dev, orig_ino, orig_sha256, orig_auth_mode, orig_account_id, orig_last_refresh, created_at FROM pending_recovery WHERE orig_auth_mode = 'opencode_oauth' ORDER BY created_at DESC",
    )
    .all() as unknown as CodexPendingRecoveryRow[];
  let recoveredAny = false;
  for (const rec of rows) {
    const dead = !isOAuthHolderActive(rec.pid, rec.holder);
    const isExpiredHolder = !!expiredLeaseHolder && rec.holder === expiredLeaseHolder;
    if (!dead && !isExpiredHolder) continue;
    let writeFailed = false;
    try {
      const origSnapFile = path.join(rec.scratch_dir, "orig-auth.json");
      if (fs.existsSync(origSnapFile)) {
        const origParsed = JSON.parse(fs.readFileSync(origSnapFile, "utf8")) as unknown;
        if (isPlainJsonRecord(origParsed)) {
          const ok = applyValidatedOpenCodeAuthSyncLocked(
            {
              hostAuthPath: rec.host_auth_path,
              resolvedAuthPath,
              wasSymlink: rec.was_symlink !== 0,
              origDev: rec.orig_dev,
              origIno: rec.orig_ino,
              origJson: origParsed,
            },
            rec.scratch_auth_path,
          );
          if (ok) recoveredAny = true;
        }
      }
    } catch (err) {
      writeFailed = true;
      log("warn", "恢复遗留 OpenCode OAuth 凭据失败（保留恢复副本与原文件）", {
        holder: rec.holder,
        err: errMsg(err),
      });
    }
    if (dead && !writeFailed) {
      try {
        if (rec.scratch_dir && path.basename(rec.scratch_dir).startsWith(".pa-opencode-state-")) {
          fs.rmSync(rec.scratch_dir, { recursive: true, force: true });
        }
      } catch {
        // ignore cleanup error
      }
      db.prepare("DELETE FROM pending_recovery WHERE holder = ?").run(rec.holder);
    }
  }
  return recoveredAny;
}

/** 跨进程协调 OpenCode 文件态 OAuth（`auth.json`）刷新与崩溃恢复，仅写回变更供应商凭据，绝不持久化会话历史 */
export async function coordinateOpenCodeOAuthRefresh(
  hostDataDir: string,
  opts?: {
    signal?: AbortSignal;
    leaseTtlMs?: number;
    pollIntervalMs?: number;
    maxWaitMs?: number;
    runWindowMs?: number;
  },
): Promise<OpenCodeOAuthRefreshLease> {
  if (!hostDataDir || !fs.existsSync(hostDataDir)) {
    return { held: false, release: () => undefined };
  }
  const hostAuthPath = path.join(hostDataDir, "auth.json");
  const initial = inspectHostCodexAuth(hostAuthPath);
  if (initial.kind === "broken_symlink") {
    throw new Error(initial.error);
  }
  if (initial.kind !== "ok" || !initial.origJson || !hasOpenCodeOAuthRefreshToken(initial.origJson)) {
    return { held: false, release: () => undefined };
  }
  if (!initial.canSyncBack) {
    throw new Error(
      `宿主机 OpenCode OAuth 凭据不可安全写回（${initial.unwritableReason ?? "权限不足"}）；为防止隔离沙箱旋转 refresh 令牌后丢失新令牌，已中止执行`,
    );
  }

  const resolvedAuthPath = initial.resolvedAuthPath;
  const leaseTtlMs = opts?.leaseTtlMs ?? 60_000;
  const pollMs = opts?.pollIntervalMs ?? 120;
  const deadline = Date.now() + (opts?.maxWaitMs ?? 180_000);
  const holder = `${process.pid}:${randomUUID().slice(0, 8)}`;

  const makeAttachScratch = (): ((staged: StagedOpenCodeState) => void) => (staged: StagedOpenCodeState) => {
    const snap = staged.origAuth;
    if (!snap || !snap.canSyncBack || !hasOpenCodeOAuthRefreshToken(snap.origJson)) return;
    activeOAuthLeaseHolders.add(holder);
    try {
      const scratchRoot = path.dirname(staged.stageDataDir);
      fs.writeFileSync(path.join(scratchRoot, "orig-auth.json"), snap.origBytes, { mode: 0o600 });
      withCodexAuthSyncLock(snap.resolvedAuthPath, (db) => {
        db.prepare(
          `INSERT OR REPLACE INTO pending_recovery
            (holder, pid, scratch_auth_path, scratch_dir, host_auth_path, was_symlink, orig_dev, orig_ino, orig_sha256, orig_auth_mode, orig_account_id, orig_last_refresh, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).run(
          holder,
          process.pid,
          path.join(staged.stageDataDir, "auth.json"),
          scratchRoot,
          snap.hostAuthPath,
          snap.wasSymlink ? 1 : 0,
          snap.origDev,
          snap.origIno,
          sha256Hex(snap.origBytes),
          "opencode_oauth",
          null,
          null,
          Date.now(),
        );
      });
    } catch {
      // best-effort recovery registration
    }
  };

  for (;;) {
    if (opts?.signal?.aborted) throw new Error("aborted");
    const attempt = withCodexAuthSyncLock(resolvedAuthPath, (db) => {
      const now = Date.now();
      const row = db
        .prepare("SELECT holder, pid, expires_at FROM refresh_lease WHERE id = 1")
        .get() as { holder: string; pid: number; expires_at: number } | undefined;
      if (row && row.expires_at > now && isOAuthHolderActive(row.pid, row.holder)) {
        return { action: "wait" as const };
      }
      recoverOrphanedOpenCodeAuthLocked(db, resolvedAuthPath, row?.holder);

      const cur = inspectHostCodexAuth(hostAuthPath);
      if (cur.kind === "broken_symlink") throw new Error(cur.error);
      if (cur.kind !== "ok" || !cur.origJson || !hasOpenCodeOAuthRefreshToken(cur.origJson)) {
        if (row) db.prepare("DELETE FROM refresh_lease WHERE id = 1").run();
        return { action: "proceed_unlocked" as const };
      }
      if (!cur.canSyncBack) {
        throw new Error(`宿主机 OpenCode OAuth 凭据不可安全写回（${cur.unwritableReason ?? "权限不足"}）；已中止执行`);
      }
      if (!isOpenCodeOAuthRefreshNeeded(cur.origJson, now, opts?.runWindowMs)) {
        if (row) db.prepare("DELETE FROM refresh_lease WHERE id = 1").run();
        return { action: "proceed_unlocked" as const };
      }
      db.prepare("INSERT OR REPLACE INTO refresh_lease (id, holder, pid, expires_at) VALUES (1, ?, ?, ?)").run(
        holder,
        process.pid,
        now + leaseTtlMs,
      );
      return { action: "acquired" as const };
    });

    if (attempt.action === "proceed_unlocked") {
      let released = false;
      const release = (relOpts?: { keepRecoveryRow?: boolean }) => {
        if (released) return;
        released = true;
        activeOAuthLeaseHolders.delete(holder);
        process.off("exit", onExit);
        try {
          withCodexAuthSyncLock(resolvedAuthPath, (db) => {
            if (relOpts?.keepRecoveryRow) {
              db.prepare("UPDATE pending_recovery SET pid = 0 WHERE holder = ?").run(holder);
            } else {
              db.prepare("DELETE FROM pending_recovery WHERE holder = ?").run(holder);
            }
          });
        } catch {
          // ignore
        }
      };
      const onExit = () => release({ keepRecoveryRow: true });
      process.once("exit", onExit);
      return { held: false, resolvedAuthPath, attachScratch: makeAttachScratch(), release };
    }
    if (attempt.action === "acquired") {
      activeOAuthLeaseHolders.add(holder);
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
      const release = (relOpts?: { keepRecoveryRow?: boolean }) => {
        if (released) return;
        released = true;
        activeOAuthLeaseHolders.delete(holder);
        clearInterval(heartbeat);
        process.off("exit", onExit);
        try {
          withCodexAuthSyncLock(resolvedAuthPath, (db) => {
            if (relOpts?.keepRecoveryRow) {
              db.prepare("UPDATE pending_recovery SET pid = 0 WHERE holder = ?").run(holder);
            } else {
              db.prepare("DELETE FROM pending_recovery WHERE holder = ?").run(holder);
            }
            db.prepare("DELETE FROM refresh_lease WHERE id = 1 AND holder = ?").run(holder);
          });
        } catch {
          // ignore
        }
      };
      const onExit = () => release({ keepRecoveryRow: true });
      process.once("exit", onExit);
      return { held: true, resolvedAuthPath, attachScratch: makeAttachScratch(), release };
    }

    if (Date.now() >= deadline) {
      throw new Error(`等待宿主机 OpenCode OAuth 刷新协调锁超时 (${resolvedAuthPath})，已中止执行`);
    }
    await sleepAbortableMs(pollMs, opts?.signal);
  }
}

/** 在清理暂存 OpenCode 目录前，逐供应商条件验证并原子写回旋转后的 OAuth `auth.json`（绝不写回会话数据库或覆盖宿主机更新登录）；遇可重试写回错误且暂存含已轮换令牌时保留受保护恢复副本 */
export function syncRefreshedOpenCodeAuth(staged: StagedOpenCodeState): boolean {
  const snap = staged.origAuth;
  if (!snap || !snap.canSyncBack || !hasOpenCodeOAuthRefreshToken(snap.origJson)) return false;
  const scratchAuthPath = path.join(staged.stageDataDir, "auth.json");
  try {
    return withCodexAuthSyncLock(snap.resolvedAuthPath, () =>
      applyValidatedOpenCodeAuthSyncLocked(
        {
          hostAuthPath: snap.hostAuthPath,
          resolvedAuthPath: snap.resolvedAuthPath,
          wasSymlink: snap.wasSymlink,
          origDev: snap.origDev,
          origIno: snap.origIno,
          origJson: snap.origJson,
        },
        scratchAuthPath,
      ),
    );
  } catch (err) {
    if (hasRotatedOpenCodeScratchAuth(staged)) {
      staged.retainScratchForRecovery = true;
      log("warn", "写回刷新后的 OpenCode auth.json 失败，已保留受保护恢复副本待后续自动重试", {
        scratchDir: path.dirname(staged.stageDataDir),
        err: errMsg(err),
      });
    } else {
      log("warn", "写回刷新后的 OpenCode auth.json 失败（保留原文件）", { err: errMsg(err) });
    }
    return false;
  }
}

/**
 * 为隔离运行的 OpenCode ACP 工人构造按次隔离的 `0700` 可写配置与数据目录：
 *   - 配置目录仅复制 `opencode.json` / `opencode.jsonc` / `config.json`（`tools="none"` 时按 JSONC 完整解析并剥离 `mcp`/`tools`/`plugin`/`agent`/`permission`；解析失败时 fail-closed 报错以防静默切换供应商）及非 `tools="none"` 时的 `AGENTS.md`；
 *   - 数据目录仅复制 `auth.json`（含 OAuth 刷新令牌时启用持久化 scratch 与崩溃可恢复写回），绝不暴露宿主机 `storage/`、`opencode.db`、`sessions/`、`snapshot/`、`log/` 等跨项目会话数据库。
 */
export function stageIsolatedOpenCodeState(
  hostHome: string,
  effectiveEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
  opts?: { tools?: "none" | "read" | "write" },
): StagedOpenCodeState | undefined {
  const effectiveHome = effectiveEnv.HOME?.trim() || hostHome || os.homedir();
  if (!effectiveHome) return undefined;
  const resolvedHome = safeRealpath(effectiveHome);
  const resolvedData = dataDir && fs.existsSync(dataDir) ? safeRealpath(dataDir) : "";
  const isSafeSource = (realPath: string): boolean =>
    !(resolvedData && (isPathInsideOrEqual(realPath, resolvedData) || isPathInsideOrEqual(resolvedData, realPath)));

  const xdgConfig = effectiveEnv.XDG_CONFIG_HOME?.trim() || path.join(resolvedHome, ".config");
  const xdgData = effectiveEnv.XDG_DATA_HOME?.trim() || path.join(resolvedHome, ".local", "share");
  const logicalConfigDir = path.join(xdgConfig, "opencode");
  const logicalDataDir = path.join(xdgData, "opencode");
  const hostConfigDir = fs.existsSync(logicalConfigDir) ? safeRealpath(logicalConfigDir) : logicalConfigDir;
  const hostDataDir = fs.existsSync(logicalDataDir) ? safeRealpath(logicalDataDir) : logicalDataDir;

  let authInspected: ReturnType<typeof inspectHostCodexAuth> = { kind: "absent" };
  if (fs.existsSync(hostDataDir) && isSafeSource(hostDataDir)) {
    const hostAuthPath = path.join(hostDataDir, "auth.json");
    authInspected = inspectHostCodexAuth(hostAuthPath);
    if (authInspected.kind === "broken_symlink") {
      throw new Error(authInspected.error);
    }
    if (
      authInspected.kind === "ok" &&
      authInspected.canSyncBack &&
      authInspected.origJson &&
      hasOpenCodeOAuthRefreshToken(authInspected.origJson) &&
      fs.existsSync(canonicalCodexLockFilePath(authInspected.resolvedAuthPath))
    ) {
      const targetResolved = authInspected.resolvedAuthPath;
      try {
        const recovered = withCodexAuthSyncLock(targetResolved, (db) => {
          const row = db
            .prepare("SELECT holder, pid, expires_at FROM refresh_lease WHERE id = 1")
            .get() as { holder: string; pid: number; expires_at: number } | undefined;
          if (row && row.expires_at > Date.now() && isOAuthHolderActive(row.pid, row.holder)) return false;
          return recoverOrphanedOpenCodeAuthLocked(db, targetResolved, row?.holder);
        });
        if (recovered) {
          authInspected = inspectHostCodexAuth(hostAuthPath);
          if (authInspected.kind === "broken_symlink") throw new Error(authInspected.error);
        }
      } catch {
        // best-effort pre-stage recovery
      }
    }
  }

  const hasWritableOAuth =
    authInspected.kind === "ok" &&
    authInspected.canSyncBack &&
    !!authInspected.origJson &&
    hasOpenCodeOAuthRefreshToken(authInspected.origJson);
  if (
    authInspected.kind === "ok" &&
    !!authInspected.origJson &&
    hasOpenCodeOAuthRefreshToken(authInspected.origJson) &&
    !authInspected.canSyncBack
  ) {
    throw new Error(
      `宿主机 OpenCode OAuth 凭据不可安全写回（${authInspected.unwritableReason ?? "权限不足"}）；为防止隔离沙箱旋转 refresh 令牌后丢失新令牌，已中止执行`,
    );
  }

  let scopedDir = "";
  let cleanupScoped: () => void;
  if (hasWritableOAuth && authInspected.kind === "ok") {
    const persistentBase = resolvePersistentOAuthScratchBase(
      "opencode-scratch",
      authInspected.resolvedAuthPath,
      hostDataDir,
      resolvedData,
    );
    scopedDir = safeRealpath(fs.mkdtempSync(path.join(persistentBase, ".pa-opencode-state-")));
    fs.chmodSync(scopedDir, 0o700);
    cleanupScoped = () => fs.rmSync(scopedDir, { recursive: true, force: true });
  } else {
    const scoped = createScopedSecretDir("pa-opencode-state-", effectiveEnv);
    scopedDir = scoped.dir;
    cleanupScoped = scoped.cleanup;
  }

  try {
    const stageConfigDir = path.join(scopedDir, "config");
    const stageDataDir = path.join(scopedDir, "data");
    fs.mkdirSync(stageConfigDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(stageDataDir, { recursive: true, mode: 0o700 });
    let origAuth: OpenCodeAuthOrigSnapshot | undefined;

    const copySafe = (src: string, dst: string, maxBytes: number) => {
      try {
        const st = fs.statSync(src);
        if (!st.isFile() || st.size > maxBytes) return;
        const realSrc = fs.realpathSync(src);
        if (!isSafeSource(realSrc)) return;
        fs.writeFileSync(dst, fs.readFileSync(realSrc), { mode: 0o600 });
      } catch {
        // ignore
      }
    };

    if (fs.existsSync(hostConfigDir) && isSafeSource(hostConfigDir)) {
      let isDir = false;
      try {
        isDir = fs.statSync(hostConfigDir).isDirectory();
      } catch {
        isDir = false;
      }
      if (isDir) {
        for (const cfgName of ["opencode.json", "opencode.jsonc", "config.json"]) {
          const src = path.join(hostConfigDir, cfgName);
          let exists = false;
          try {
            fs.lstatSync(src);
            exists = true;
          } catch {
            exists = false;
          }
          if (!exists) continue;
          if (opts?.tools === "none") {
            let st: fs.Stats;
            let realSrc: string;
            try {
              st = fs.statSync(src);
              realSrc = fs.realpathSync(src);
            } catch (err) {
              throw new Error(
                `宿主机 OpenCode 配置文件 (${src}) 不可访问或符号链接已损坏：${errMsg(err)}；为避免无工具模式下静默切换模型供应商，已中止执行`,
              );
            }
            if (!st.isFile() || st.size > 512 * 1024) {
              throw new Error(
                `宿主机 OpenCode 配置文件 (${src}) 非合法常规文件或超过 512KB；为避免无工具模式下静默切换模型供应商，已中止执行`,
              );
            }
            if (!isSafeSource(realSrc)) continue;
            let sanitized: string;
            try {
              sanitized = sanitizeOpenCodeConfigForNoTools(fs.readFileSync(realSrc, "utf8"));
            } catch (err) {
              throw new Error(
                `宿主机 OpenCode 配置文件 (${src}) 解析脱敏失败：${errMsg(err)}；为避免无工具模式下静默切换模型供应商，已中止执行`,
              );
            }
            fs.writeFileSync(path.join(stageConfigDir, cfgName), sanitized, { mode: 0o600 });
          } else {
            copySafe(src, path.join(stageConfigDir, cfgName), 512 * 1024);
          }
        }
        if (opts?.tools !== "none") {
          copySafe(path.join(hostConfigDir, "AGENTS.md"), path.join(stageConfigDir, "AGENTS.md"), 1024 * 1024);
        }
      }
    }

    if (fs.existsSync(hostDataDir) && isSafeSource(hostDataDir)) {
      try {
        if (fs.statSync(hostDataDir).isDirectory()) {
          if (authInspected.kind === "ok" && isSafeSource(authInspected.resolvedAuthPath)) {
            fs.writeFileSync(path.join(stageDataDir, "auth.json"), authInspected.origBytes, { mode: 0o600 });
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
      } catch {
        // ignore
      }
    }

    const state: StagedOpenCodeState = {
      hostDirsToSkip: [...new Set([hostConfigDir, hostDataDir])],
      stageDataDir,
      origAuth,
      bindMounts: [
        { src: stageConfigDir, dest: logicalConfigDir, mode: "rw" },
        { src: stageDataDir, dest: logicalDataDir, mode: "rw" },
      ],
      retainScratchForRecovery: false,
      cleanup: () => {
        if (state.retainScratchForRecovery) return;
        cleanupScoped();
      },
    };
    return state;
  } catch (err) {
    cleanupScoped();
    throw err;
  }
}

interface BuiltinAcpxAdapterSpec {
  family: string;
  binName: string;
  extraArgs: readonly string[];
  packageNames: readonly string[];
}

const ACPX_BUILTIN_ADAPTERS: Record<string, BuiltinAcpxAdapterSpec> = {
  claude: {
    family: "claude",
    binName: "claude-agent-acp",
    extraArgs: [],
    packageNames: ["@agentclientprotocol/claude-agent-acp", "@zed-industries/claude-agent-acp"],
  },
  codex: {
    family: "codex",
    binName: "codex-acp",
    extraArgs: [],
    packageNames: ["@agentclientprotocol/codex-acp", "@zed-industries/codex-acp"],
  },
  pi: {
    family: "pi",
    binName: "pi-acp",
    extraArgs: [],
    packageNames: ["pi-acp"],
  },
  opencode: {
    family: "opencode",
    binName: "opencode",
    extraArgs: ["acp"],
    packageNames: ["opencode-ai"],
  },
};

export interface ScopedAcpxAdapterCache {
  extraCmdPaths: string[];
  prependPathDirs: string[];
  bindMounts: { src: string; dest: string; mode: "ro" | "rw" }[];
  /** 直接写入暂存 `~/.acpx/config.json` 以跳过 `npm exec` 联网解析的适配器命令 */
  agentCommand?: string;
}

function acpxBundlesAdapterPackage(acpxBin: string | undefined, packageNames: readonly string[], pathEnv: string): boolean {
  if (!acpxBin?.trim()) return false;
  const resolved = resolveBinInPath(acpxBin.trim(), pathEnv);
  if (!resolved) return false;
  let cursor = path.dirname(safeRealpath(resolved));
  for (let depth = 0; depth < 8; depth += 1) {
    for (const pkg of packageNames) {
      const manifest = path.join(cursor, "node_modules", ...pkg.split("/"), "package.json");
      try {
        if (fs.existsSync(manifest) && fs.statSync(manifest).isFile()) return true;
      } catch {
        // ignore
      }
    }
    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  return false;
}

function findCachedNpxAdapterEntry(
  npmCacheRoot: string,
  spec: BuiltinAcpxAdapterSpec,
  resolvedDataDir: string,
): { entryDir: string; hash: string; mtimeMs: number } | undefined {
  const npxRoot = path.join(npmCacheRoot, "_npx");
  if (!fs.existsSync(npxRoot)) return undefined;
  let best: { entryDir: string; hash: string; mtimeMs: number } | undefined;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(npxRoot, { withFileTypes: true });
  } catch {
    return undefined;
  }
  for (const ent of entries) {
    if (!ent.isDirectory() || ent.isSymbolicLink()) continue;
    const entryDir = path.join(npxRoot, ent.name);
    const pjPath = path.join(entryDir, "package.json");
    const binPath = path.join(entryDir, "node_modules", ".bin", spec.binName);
    try {
      if (!fs.existsSync(pjPath) || !fs.existsSync(binPath)) continue;
      const realEntry = fs.realpathSync(entryDir);
      if (resolvedDataDir && (isPathInsideOrEqual(realEntry, resolvedDataDir) || isPathInsideOrEqual(resolvedDataDir, realEntry))) {
        continue;
      }
      const pjSt = fs.statSync(pjPath);
      if (!pjSt.isFile() || pjSt.size > 256 * 1024) continue;
      const pj = JSON.parse(fs.readFileSync(pjPath, "utf8")) as Record<string, unknown>;
      const deps = isPlainJsonRecord(pj.dependencies) ? pj.dependencies : undefined;
      if (!deps) continue;
      const matched = spec.packageNames.some((pkg) => Object.prototype.hasOwnProperty.call(deps, pkg));
      if (!matched) continue;
      const binSt = fs.statSync(binPath);
      const mtimeMs = Math.max(pjSt.mtimeMs, binSt.mtimeMs);
      if (!best || mtimeMs > best.mtimeMs) {
        best = { entryDir: realEntry, hash: ent.name, mtimeMs };
      }
    } catch {
      // ignore unreadable _npx slot
    }
  }
  return best;
}

/**
 * 为隔离运行的内置 acpx 适配器（claude / codex / pi / opencode）复用已安装或已缓存的单一适配器，避免每次隔离运行重新联网下载：
 *   1. 若 `acpx` 自身 `node_modules` 已内置该包，直接交由 `acpx` 离线直启，不做额外覆盖；
 *   2. 若宿主机 PATH 已全局安装对应适配器二进制（如 `claude-agent-acp` / `codex-acp` / `opencode`），将其加入 `extraCmdPaths` 按只读挂载并注入暂存 `config.json` 跳过 `npm exec`；
 *   3. 否则仅在宿主机 npm 缓存（`${NPM_CONFIG_CACHE:-~/.npm}/_npx/*`）与受控每适配器状态缓存中检索与当前所选包名精确匹配的单个 `_npx/<hash>` 目录，
 *      将其以只读方式绑定挂载至 `/tmp/.pa-npm-cache/_npx/<hash>`，并通过暂存 `config.json` 直接启动其 `node_modules/.bin/<binName>`（既 100% 离线、避免 `npm exec` 在只读槽位写锁，也防止工人投毒缓存，绝不暴露宿主机完整 `~/.npm`）；
 *   4. 若尚未存在任何缓存且当前为无工具模式（`tools === "none"`），绑定专属按适配器隔离的持久化缓存目录以供后续所有隔离工人离线只读复用。
 */
export function stageScopedAcpxAdapterCache(
  selectedId: string,
  hostEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
  opts?: { tools?: "none" | "read" | "write"; acpxBin?: string },
): ScopedAcpxAdapterCache | undefined {
  const family =
    resolveKnownAcpxProviderFamily(selectedId) ??
    (selectedId === "pi" || selectedId.startsWith("pi-") ? "pi" : undefined);
  if (!family) return undefined;
  const spec = ACPX_BUILTIN_ADAPTERS[family];
  if (!spec) return undefined;

  const extraCmdPaths: string[] = [];
  const prependPathDirs: string[] = [];
  const bindMounts: { src: string; dest: string; mode: "ro" | "rw" }[] = [];

  const pathEnv = hostEnv.PATH || process.env.PATH || "";
  if (acpxBundlesAdapterPackage(opts?.acpxBin, spec.packageNames, pathEnv)) {
    return undefined;
  }

  const installedBin = resolveBinInPath(spec.binName, pathEnv);
  if (installedBin) {
    extraCmdPaths.push(spec.binName);
    const agentCommand = [spec.binName, ...spec.extraArgs].join(" ");
    return { extraCmdPaths, prependPathDirs, bindMounts, agentCommand };
  }

  const hostHome = hostEnv.HOME?.trim() || os.homedir();
  const resolvedHome = hostHome ? safeRealpath(hostHome) : "";
  const resolvedData = dataDir && fs.existsSync(dataDir) ? safeRealpath(dataDir) : "";
  const hostNpmCache =
    hostEnv.NPM_CONFIG_CACHE?.trim() ||
    hostEnv.npm_config_cache?.trim() ||
    (resolvedHome ? path.join(resolvedHome, ".npm") : "");
  const persistentAdapterCache = resolvedHome
    ? path.join(resolvedHome, ".local", "state", "personal-agent", "acpx-adapter-cache", spec.family)
    : "";

  const searchRoots = [persistentAdapterCache, hostNpmCache].filter(Boolean);
  let bestHit: { entryDir: string; hash: string; mtimeMs: number } | undefined;
  for (const root of searchRoots) {
    const hit = findCachedNpxAdapterEntry(root, spec, resolvedData);
    if (hit && (!bestHit || hit.mtimeMs > bestHit.mtimeMs)) {
      bestHit = hit;
    }
  }
  if (bestHit) {
    const mountedNpxDir = `/tmp/.pa-npm-cache/_npx/${bestHit.hash}`;
    const mountedBinDir = `${mountedNpxDir}/node_modules/.bin`;
    const mountedBinPath = `${mountedBinDir}/${spec.binName}`;
    bindMounts.push({ src: bestHit.entryDir, dest: mountedNpxDir, mode: "ro" });
    prependPathDirs.push(mountedBinDir);
    const agentCommand = [mountedBinPath, ...spec.extraArgs].join(" ");
    return { extraCmdPaths, prependPathDirs, bindMounts, agentCommand };
  }

  // 首次运行且尚未缓存：仅在无工具模式（无 shell/文件写能力，防不可信仓库工人投毒）下挂载按适配器分区的持久化缓存供后续只读复用
  if (opts?.tools === "none" && persistentAdapterCache) {
    const collidesData =
      !!resolvedData &&
      (isPathInsideOrEqual(persistentAdapterCache, resolvedData) || isPathInsideOrEqual(resolvedData, persistentAdapterCache));
    if (!collidesData) {
      try {
        fs.mkdirSync(persistentAdapterCache, { recursive: true, mode: 0o700 });
        const st = fs.lstatSync(persistentAdapterCache);
        if (!st.isSymbolicLink() && st.isDirectory() && isCurrentUidOwner(st)) {
          fs.chmodSync(persistentAdapterCache, 0o700);
          bindMounts.push({ src: safeRealpath(persistentAdapterCache), dest: "/tmp/.pa-npm-cache", mode: "rw" });
          return { extraCmdPaths, prependPathDirs, bindMounts };
        }
      } catch {
        // fallback to ephemeral tmpfs npm cache
      }
    }
  }
  return undefined;
}

/**
 * 按 acpx 实际选中的 agent 仅暴露该单一提供方的配置目录（从单次合并展开后的子进程环境解析，
 * 绝不重复展开 `${VAR}`、绝不挂载整个 `~/.acpx` 或向 Claude 工人暴露 `~/.codex` 等其他提供方凭据）。
 */
export function selectAcpxAgentConfigPaths(
  h: Pick<Config["harnesses"][string], "agent" | "agentCommand" | "env">,
  hostHome: string,
  hostEnv: NodeJS.ProcessEnv = process.env,
  opts?: { alreadyMerged?: boolean },
): string[] {
  const effectiveEnv = opts?.alreadyMerged ? hostEnv : mergeHarnessEnv(hostEnv, h.env);
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
    const { execToken } = extractCommandExecAndScriptTokens(parseShellCommandTokens(h.agentCommand));
    return execToken || extractFirstShellCommandToken(h.agentCommand) || undefined;
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
    /** 仅对受信任配置探测/远程 Git 放行原始全局配置；本地 Git 操作（add/commit/checkout/worktree）传 true 隐藏原始 ~/.gitconfig 中的 http.extraHeader 等凭据 */
    sanitizeGitConfig?: boolean;
    extraWritablePaths?: string[];
    extraReadOnlyPaths?: string[];
    extraSymlinks?: { dest: string; target: string }[];
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

  // 最小化允许的个人 Git 配置文件：
  //   - 仅受信任 Git 传输（git-rw / git-ro）挂载完整全局配置与适用 include（保留 url.*.pushInsteadOf、credential.* 等交付设置）；
  //   - 不可信仓库工人、审查与校验命令（verify / worker-write / worker-ro / codex-exec）只挂载无凭据的 git/ignore 与 git/attributes，
  //     脱敏后的全局偏好由调用方通过 stageSanitizedGitConfig 单独投影，绝不把 ~/.gitconfig 中的 http.extraHeader 或带令牌 URL 暴露给工人。
  const extraSymlinks: { dest: string; target: string }[] = [...(opts.extraSymlinks ?? [])];
  if ((opts.mode === "git-rw" || opts.mode === "git-ro") && !opts.sanitizeGitConfig) {
    const gitCfgMounts = collectSafeGitConfigMounts(rawEnv, dataDir, { cwd: resolvedCwd });
    readOnlyPaths.push(...gitCfgMounts.readOnlyPaths);
    extraSymlinks.push(...gitCfgMounts.symlinks);
  } else if (opts.mode !== "llm-none") {
    const gitRuleMounts = collectSafeGitIgnoreAndAttrMounts(rawEnv, dataDir);
    readOnlyPaths.push(...gitRuleMounts.readOnlyPaths);
    extraSymlinks.push(...gitRuleMounts.symlinks);
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
      const origUid = typeof process.getuid === "function" ? process.getuid() : 0;
      const origGid = typeof process.getgid === "function" ? process.getgid() : 0;
      const buildProbeScript = (withUserRestore: boolean) =>
        [
          "set -e",
          `export PATH="${TRUSTED_BOOTSTRAP_PATH}"`,
          'UNSHARE_BIN="$1"; PIVOT="$2"; SP="$3"; U="$4"; G="$5"',
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
          withUserRestore
            ? 'exec "$UNSHARE_BIN" --user --map-user="$U" --map-group="$G" -- "$SP" --bounding-set -all --inh-caps -all --ambient-caps -all --no-new-privs sh -c \'test "$(id -u)" = "$1"\' _ "$U"'
            : 'exec "$SP" --bounding-set -all --inh-caps -all --ambient-caps -all --no-new-privs true',
        ].join("\n");

      const runUnshareProbe = (killChild: boolean, restoreUserMap: boolean): boolean => {
        const probeArgs = [
          "--user",
          "--map-root-user",
          "--mount",
          "--pid",
          "--fork",
          "--mount-proc",
          ...(killChild ? ["--kill-child"] : []),
          "--",
          shBin,
          "-c",
          buildProbeScript(restoreUserMap),
          "_",
          unshareBin,
          pivotRootBin,
          setprivBin,
          String(origUid),
          String(origGid),
        ];
        const r = spawnSync(unshareBin, probeArgs, {
          env: TRUSTED_BOOTSTRAP_ENV,
          timeout: 3_000,
          stdio: "ignore",
        });
        return r.status === 0;
      };

      const tryOrder: { killChild: boolean; restoreUserMap: boolean }[] =
        origUid > 0
          ? [
              { killChild: true, restoreUserMap: true },
              { killChild: false, restoreUserMap: true },
              { killChild: true, restoreUserMap: false },
              { killChild: false, restoreUserMap: false },
            ]
          : [
              { killChild: true, restoreUserMap: false },
              { killChild: false, restoreUserMap: false },
            ];
      for (const opt of tryOrder) {
        if (runUnshareProbe(opt.killChild, opt.restoreUserMap)) {
          cachedMountMaskBackend = {
            kind: "unshare",
            bin: unshareBin,
            setprivBin,
            pivotRootBin,
            shBin,
            killChild: opt.killChild,
            restoreUserMap: opt.restoreUserMap,
          };
          return cachedMountMaskBackend;
        }
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
  'UNSHARE_BIN="$1"; PIVOT_ROOT="$2"; SETPRIV="$3"; ORIG_UID="$4"; ORIG_GID="$5"; DD="$6"; CWD="$7"; SYS_COUNT="$8"; SYM_COUNT="$9"; TM_COUNT="${10}"; PRE_COUNT="${11}"; POST_COUNT="${12}"; EXTRA_COUNT="${13}"; M_COUNT="${14}"',
  "shift 14",
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
  // 非 root 调用者在完成挂载与 pivot_root 后再嵌套一层无特权用户命名空间还原真实 UID/GID，
  // 使 OpenSSH getpwuid(getuid())->pw_dir 与文件属主校验（0600 密钥）指向调用者的真实宿主目录而非 /root。
  'if [ -n "$UNSHARE_BIN" ] && [ -n "$ORIG_UID" ] && [ "$ORIG_UID" != "0" ]; then exec "$UNSHARE_BIN" --user --map-user="$ORIG_UID" --map-group="$ORIG_GID" -- "$SETPRIV" --bounding-set -all --inh-caps -all --ambient-caps -all --no-new-privs "$@"; fi',
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
    GOPATH: "/tmp/.pa-go",
    GOMODCACHE: "/tmp/.pa-gomodcache",
    GOCACHE: "/tmp/.pa-gocache",
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
  const isInsideTmpfsMask = (p: string): boolean =>
    isHiddenByEphemeralTmpfs(p) || (!!resolvedDataDir && isPathInsideOrEqual(p, resolvedDataDir));
  const preTmpfsDirSymlinks = dirSymlinks.filter((s) => !isInsideTmpfsMask(s.dest));
  const postTmpfsSymlinks = [...dirSymlinks.filter((s) => isInsideTmpfsMask(s.dest)), ...fileSymlinks].sort(
    (a, b) => a.dest.length - b.dest.length || a.dest.localeCompare(b.dest),
  );
  const allSymlinks = [...preTmpfsDirSymlinks, ...postTmpfsSymlinks];

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
    for (const s of preTmpfsDirSymlinks) {
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
    for (const s of postTmpfsSymlinks) {
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
    const origUid = typeof process.getuid === "function" ? process.getuid() : 0;
    const origGid = typeof process.getgid === "function" ? process.getgid() : 0;
    const restoreUnshareBin = origUid > 0 && backend.restoreUserMap !== false ? backend.bin : "";
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
      restoreUnshareBin,
      backend.pivotRootBin,
      backend.setprivBin,
      String(origUid),
      String(origGid),
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
  bindMounts: { src: string; dest: string; mode: "ro" | "rw" }[];
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
  const selectedSsoSessions = new Set<string>();
  const selectedSsoStartUrls = new Set<string>();
  const normStartUrl = (u: string) => u.trim().replace(/\/+$/, "").toLowerCase();
  const recordStartUrl = (u: string | undefined) => {
    const clean = u?.trim();
    if (clean) {
      selectedSsoStartUrls.add(clean);
      selectedSsoStartUrls.add(normStartUrl(clean));
    }
  };

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
        selectedSsoSessions.add(ssoSession.trim());
        if (!visitedSso.has(ssoSession)) {
          visitedSso.add(ssoSession);
          const ssoSec = findConfigTagged("sso-session", ssoSession);
          if (ssoSec) {
            selectedConfig.push(ssoSec);
            recordStartUrl(ssoSec.props.get("sso_start_url"));
          }
        }
      }
      if (sec.props.has("sso_start_url") || sec.props.has("sso_account_id")) {
        needsSsoCache = true;
        recordStartUrl(sec.props.get("sso_start_url"));
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

  const scoped = createScopedSecretDir("pa-aws-profile-", hostEnv);
  const configFile = path.join(scoped.dir, "config");
  const credentialsFile = path.join(scoped.dir, "credentials");
  const bindMounts: { src: string; dest: string; mode: "ro" | "rw" }[] = [];
  try {
    fs.writeFileSync(configFile, serializeAwsIniSections(selectedConfig), { mode: 0o600 });
    fs.writeFileSync(credentialsFile, serializeAwsIniSections(selectedCreds), { mode: 0o600 });

    // 严格仅投影当前选中 profile 及其 source_profile 链引用的 SSO 会话缓存文件（绝不整目录挂载 ~/.aws/sso/cache 泄露其他 SSO 会话令牌）
    if (needsSsoCache && hostAwsDir) {
      const ssoCacheDir = path.join(hostAwsDir, "sso", "cache");
      if (fs.existsSync(ssoCacheDir) && isOutsideDataDir(ssoCacheDir)) {
        const expectedFilenames = new Set<string>();
        const sha1 = (s: string) => createHash("sha1").update(s, "utf8").digest("hex");
        for (const sess of selectedSsoSessions) {
          if (sess) expectedFilenames.add(`${sha1(sess)}.json`);
        }
        for (const url of selectedSsoStartUrls) {
          if (url) expectedFilenames.add(`${sha1(url)}.json`);
        }
        const stagedSsoDir = path.join(scoped.dir, "sso-cache");
        fs.mkdirSync(stagedSsoDir, { recursive: true, mode: 0o700 });

        interface ParsedSsoEntry {
          name: string;
          buf: Buffer;
          json?: Record<string, unknown>;
        }
        const candidates: ParsedSsoEntry[] = [];
        try {
          for (const ent of fs.readdirSync(ssoCacheDir, { withFileTypes: true })) {
            if (!ent.isFile() || ent.isSymbolicLink() || !ent.name.endsWith(".json")) continue;
            const full = path.join(ssoCacheDir, ent.name);
            if (!isOutsideDataDir(full)) continue;
            try {
              const st = fs.statSync(full);
              if (!st.isFile() || st.size > 256 * 1024) continue;
              const buf = fs.readFileSync(full);
              let json: Record<string, unknown> | undefined;
              try {
                const p = JSON.parse(buf.toString("utf8")) as unknown;
                if (isPlainJsonRecord(p)) json = p;
              } catch {
                // ignore unparseable json
              }
              candidates.push({ name: ent.name, buf, json });
            } catch {
              // ignore unreadable cache file
            }
          }
        } catch {
          // ignore unreadable sso cache dir
        }

        const matchedNames = new Set<string>();
        const referencedClientIds = new Set<string>();
        for (const c of candidates) {
          const entryStartUrl = typeof c.json?.startUrl === "string" ? normStartUrl(c.json.startUrl) : "";
          const matchesByHash = expectedFilenames.has(c.name);
          const matchesByUrl = !!entryStartUrl && selectedSsoStartUrls.has(entryStartUrl);
          if (matchesByHash || matchesByUrl) {
            matchedNames.add(c.name);
            if (typeof c.json?.clientId === "string" && c.json.clientId.trim()) {
              referencedClientIds.add(c.json.clientId.trim());
            }
          }
        }
        // 附带所选会话 token 引用的 OIDC 客户端注册缓存（无 startUrl，但 clientId 匹配）
        for (const c of candidates) {
          if (matchedNames.has(c.name)) continue;
          const entryStartUrl = typeof c.json?.startUrl === "string" ? c.json.startUrl.trim() : "";
          const entryClientId = typeof c.json?.clientId === "string" ? c.json.clientId.trim() : "";
          if (!entryStartUrl && entryClientId && referencedClientIds.has(entryClientId)) {
            matchedNames.add(c.name);
          }
        }
        for (const c of candidates) {
          if (!matchedNames.has(c.name)) continue;
          fs.writeFileSync(path.join(stagedSsoDir, c.name), c.buf, { mode: 0o600 });
        }
        bindMounts.push({ src: stagedSsoDir, dest: ssoCacheDir, mode: "ro" });
      }
    }

    return {
      dir: scoped.dir,
      configFile,
      credentialsFile,
      extraReadOnlyPaths: [...extraReadOnlyPaths],
      bindMounts,
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

/**
 * 将 `extractSafeCodexProviderConfig` 提取的安全路由、供应商与账号限制参数渲染为标准 `config.toml`，
 * 供隔离无工具模式的 Codex ACP（`agent: codex` + `tools: none`）在临时 `CODEX_HOME` 中生效，
 * 绝不复制宿主机 `mcp_servers`、`hooks`、`plugins`、`profiles` 或工具权限配置。
 */
export function renderSafeCodexConfigToml(safeCfg: SafeCodexProviderConfig): string {
  const topLines: string[] = [];
  const sectionBlocks: string[] = [];
  for (let i = 0; i < safeCfg.args.length; i += 2) {
    if (safeCfg.args[i] !== "-c") continue;
    const expr = safeCfg.args[i + 1];
    if (!expr) continue;
    const parsed = parseCliConfigAssignment(expr);
    if (!parsed) continue;
    if (parsed.key === "model_providers") {
      const providersVal = parseTomlValue(parsed.value);
      if (isPlainTable(providersVal)) {
        for (const [pName, pDef] of Object.entries(providersVal)) {
          if (!isPlainTable(pDef)) continue;
          const pSeg = formatTomlKeySegment(pName);
          const pLines: string[] = [`[model_providers.${pSeg}]`];
          const subBlocks: string[] = [];
          for (const [k, v] of Object.entries(pDef)) {
            const kSeg = formatTomlKeySegment(k);
            if (isPlainTable(v)) {
              const sLines: string[] = [`[model_providers.${pSeg}.${kSeg}]`];
              for (const [sk, sv] of Object.entries(v)) {
                sLines.push(`${formatTomlKeySegment(sk)} = ${serializeTomlInlineValue(sv)}`);
              }
              subBlocks.push(sLines.join("\n"));
            } else {
              pLines.push(`${kSeg} = ${serializeTomlInlineValue(v)}`);
            }
          }
          sectionBlocks.push(pLines.join("\n"), ...subBlocks);
        }
      }
      continue;
    }
    topLines.push(`${formatTomlKeySegment(parsed.key)} = ${parsed.value}`);
  }
  topLines.push("sandbox_permissions = []");
  topLines.push('web_search = "disabled"');
  const allParts = [topLines.join("\n"), ...sectionBlocks].filter(Boolean);
  return `${allParts.join("\n\n")}\n`;
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
  if (run.tools === "none") args.push("--no-terminal", "--no-fs");
  if (h.model) args.push("--model", h.model);
  args.push(...h.extraArgs);

  fs.mkdirSync(run.cwd, { recursive: true });
  // 先解析可执行路径再准备临时凭据环境，确保 resolveBin 异常不会泄漏易失目录
  const realLark = resolveBin(cfg.bins.lark);
  const baseEnv = prepareHarnessEnv();
  const started = new Date().toISOString();
  let stagedAcpx: StagedAcpxState | undefined;
  let stagedClaude: StagedClaudeState | undefined;
  let stagedGemini: StagedAgentState | undefined;
  let stagedOpenCode: StagedOpenCodeState | undefined;
  let stagedAdapterCache: ScopedAcpxAdapterCache | undefined;
  let stagedDoubao: StagedDoubaoDataDir | undefined;
  let stagedNpmrc: StagedSanitizedNpmrc | undefined;
  let stagedGitCfg: StagedSanitizedGitConfig | undefined;
  let stagedCodexHome: StagedCodexHome | undefined;
  let stagedAws: StagedAwsProfile | undefined;
  let oauthLease: CodexOAuthRefreshLease | undefined;
  let claudeOAuthLease: ClaudeOAuthRefreshLease | undefined;
  let openCodeOAuthLease: OpenCodeOAuthRefreshLease | undefined;
  let syncedCodexAuth = false;
  let syncedClaudeAuth = false;
  let syncedOpenCodeAuth = false;
  let r: Awaited<ReturnType<typeof runProcess>>;
  try {
    const mode: WorkspaceIsolationMode =
      run.tools === "write" ? "worker-write" : run.tools === "read" ? "worker-ro" : "llm-none";
    const acpxIsolationEnv = mergeHarnessEnv(process.env, h.env);
    const childMergedEnv = mergeHarnessEnv(baseEnv.env, h.env);
    const hostHome = acpxIsolationEnv.HOME?.trim() || os.homedir();
    const resolvedDataDir = cfg.dataDir && fs.existsSync(cfg.dataDir) ? safeRealpath(cfg.dataDir) : "";
    const selectedAgentId = resolveSelectedAcpxAgentId(h);
    const isClaudeAcpx =
      selectedAgentId === "claude" || selectedAgentId === "claude-code" || selectedAgentId.startsWith("claude-");
    const isDoubaoAcpx = selectedAgentId === "doubao" || selectedAgentId.startsWith("doubao-");
    const isCodexAcpx = selectedAgentId === "codex" || selectedAgentId.startsWith("codex-");
    const isGeminiAcpx = selectedAgentId === "gemini" || selectedAgentId.startsWith("gemini-");
    const isOpenCodeAcpx = selectedAgentId === "opencode" || selectedAgentId.startsWith("opencode-");
    const acpxTimeoutMs = (run.timeoutSec + 120) * 1000;

    if (isDoubaoAcpx) {
      stagedDoubao = stageIsolatedDoubaoDataDir(acpxIsolationEnv, cfg.dataDir);
    }
    if (mode !== "llm-none") {
      stagedNpmrc = stageSanitizedNpmrc(acpxIsolationEnv, cfg.dataDir);
      stagedGitCfg = stageSanitizedGitConfig(acpxIsolationEnv, cfg.dataDir, { cwd: run.cwd });
    }

    const basePlan = buildWorkspaceIsolation(
      cfg,
      {
        mode,
        cwd: run.cwd,
        cmdPath: cfg.bins.acpx,
        trustedRepoRoot: run.trustedRepoRoot,
        disableGitWorktreeMounts: run.disableGitWorktreeMounts,
        allowGuardLog: run.lark !== "none",
      },
      acpxIsolationEnv,
    );
    const willIsolate = willIsolateCommand(acpxIsolationEnv, basePlan);

    if (willIsolate && !h.agentCommand?.trim()) {
      stagedAdapterCache = stageScopedAcpxAdapterCache(selectedAgentId, acpxIsolationEnv, cfg.dataDir, {
        tools: run.tools,
        acpxBin: cfg.bins.acpx,
      });
    }
    stagedAcpx = stageIsolatedAcpxState(h, hostHome, acpxIsolationEnv, cfg.dataDir, {
      tools: run.tools,
      builtinAdapterCommand: willIsolate ? stagedAdapterCache?.agentCommand : undefined,
    });
    if (stagedAcpx?.usedHostAgentOverride) {
      stagedAdapterCache = undefined;
    }

    // 隔离模式下为 Claude / Gemini / OpenCode 工人暂存仅含凭据与设置的私有目录，彻底隔离跨项目会话历史，并为 Claude 协调 OAuth 刷新写回
    if (isClaudeAcpx && willIsolate) {
      const effectiveClaudeHome = acpxIsolationEnv.HOME?.trim() || hostHome || os.homedir();
      if (effectiveClaudeHome) {
        const resolvedClaudeHome = safeRealpath(effectiveClaudeHome);
        const explicitClaudeDir = acpxIsolationEnv.CLAUDE_CONFIG_DIR?.trim();
        const logicalClaudeDir = explicitClaudeDir
          ? (path.isAbsolute(explicitClaudeDir) ? explicitClaudeDir : path.join(resolvedClaudeHome, explicitClaudeDir))
          : path.join(resolvedClaudeHome, ".claude");
        const realClaudeDir = fs.existsSync(logicalClaudeDir) ? safeRealpath(logicalClaudeDir) : logicalClaudeDir;
        const collidesData =
          !!resolvedDataDir &&
          (isPathInsideOrEqual(realClaudeDir, resolvedDataDir) || isPathInsideOrEqual(resolvedDataDir, realClaudeDir));
        if (!collidesData) {
          claudeOAuthLease = await coordinateClaudeOAuthRefresh(realClaudeDir, {
            signal: run.signal,
            runWindowMs: acpxTimeoutMs + 60_000,
            maxWaitMs: Math.max(180_000, acpxTimeoutMs + 30_000),
          });
        }
      }
      stagedClaude = stageIsolatedClaudeState(hostHome, acpxIsolationEnv, cfg.dataDir, { tools: run.tools });
      if (stagedClaude) claudeOAuthLease?.attachScratch?.(stagedClaude);
    }
    if (isGeminiAcpx && willIsolate) {
      stagedGemini = stageIsolatedGeminiState(hostHome, acpxIsolationEnv, cfg.dataDir, { tools: run.tools });
    }
    if (isOpenCodeAcpx && willIsolate) {
      const effectiveOcHome = acpxIsolationEnv.HOME?.trim() || hostHome || os.homedir();
      if (effectiveOcHome) {
        const resolvedOcHome = safeRealpath(effectiveOcHome);
        const xdgOcData = acpxIsolationEnv.XDG_DATA_HOME?.trim() || path.join(resolvedOcHome, ".local", "share");
        const logicalOcDataDir = path.join(xdgOcData, "opencode");
        const realOcDataDir = fs.existsSync(logicalOcDataDir) ? safeRealpath(logicalOcDataDir) : logicalOcDataDir;
        const collidesData =
          !!resolvedDataDir &&
          (isPathInsideOrEqual(realOcDataDir, resolvedDataDir) || isPathInsideOrEqual(resolvedDataDir, realOcDataDir));
        if (!collidesData) {
          openCodeOAuthLease = await coordinateOpenCodeOAuthRefresh(realOcDataDir, {
            signal: run.signal,
            runWindowMs: acpxTimeoutMs + 60_000,
            maxWaitMs: Math.max(180_000, acpxTimeoutMs + 30_000),
          });
        }
      }
      stagedOpenCode = stageIsolatedOpenCodeState(hostHome, acpxIsolationEnv, cfg.dataDir, { tools: run.tools });
      if (stagedOpenCode) openCodeOAuthLease?.attachScratch?.(stagedOpenCode);
    }

    // tools === "none" 时显式传入空 --mcp-config，阻断宿主机全局配置与项目 .acpxrc.json 注入 MCP 服务器
    if (run.tools === "none" && stagedAcpx?.emptyMcpConfigFile) {
      const mcpCfgArg = willIsolate
        ? (stagedAcpx.emptyMcpConfigMountedPath ?? stagedAcpx.emptyMcpConfigFile)
        : stagedAcpx.emptyMcpConfigFile;
      args.push("--mcp-config", mcpCfgArg);
    }
    if (h.agentCommand) args.push("--agent", h.agentCommand, "exec", "--file", "-");
    else args.push(h.agent!, "exec", "--file", "-");

    // 对 Codex ACP 复用与 codex-exec 相同的私有可写 CODEX_HOME 暂存、无工具安全供应商配置渲染、AWS profile 投影与跨进程 OAuth 写回协调，
    // 绝不把宿主机整个 ~/.codex（含跨仓库 sessions 历史）挂载给一次性 ACP 工人，且支持刷新后的文件凭据崩溃可恢复安全写回。
    let codexHostHomeToSkip: string | undefined;
    let codexNeedsCredentialStore = false;
    let safeCodexExtraEnv: Record<string, string> = {};
    if (isCodexAcpx) {
      const effectiveCredInfo = resolveEffectiveCodexCredentialStore(childMergedEnv, [], {
        ignoreProfiles: run.tools === "none",
      });
      if (effectiveCredInfo.configError) {
        throw new Error(`${effectiveCredInfo.configError}；为避免将私聊或代码误发往默认供应商，已中止执行`);
      }
      codexNeedsCredentialStore = effectiveCredInfo.needsCredentialStore;
      if (willIsolate) {
        if (process.platform === "linux" && effectiveCredInfo.needsCredentialStore && effectiveCredInfo.store === "keyring") {
          throw new Error(
            `执行者 ${run.harness} 配置了 cli_auth_credentials_store="keyring"，但当前 Linux 隔离沙箱已屏蔽宿主机 D-Bus 会话总线与 XDG_RUNTIME_DIR，无法访问 Secret Service；请在 ~/.codex/config.toml 中改用 cli_auth_credentials_store="file" 并重新运行 codex login，或通过 OPENAI_API_KEY / CODEX_API_KEY / 供应商 env_key 提供 API 密钥`,
          );
        }
        const safeCodexCfg =
          run.tools === "none" ? extractSafeCodexProviderConfig(childMergedEnv, [], !!h.model) : undefined;
        if (safeCodexCfg) {
          safeCodexExtraEnv = safeCodexCfg.extraEnv;
        }
        codexHostHomeToSkip = safeRealpath(effectiveCredInfo.codexHome);
        oauthLease = await coordinateCodexOAuthRefresh(effectiveCredInfo.codexHome, {
          needsCredentialStore: effectiveCredInfo.needsCredentialStore,
          signal: run.signal,
          runWindowMs: acpxTimeoutMs + 60_000,
          maxWaitMs: Math.max(180_000, acpxTimeoutMs + 30_000),
        });
        stagedCodexHome = stageIsolatedCodexHome(effectiveCredInfo.codexHome, {
          copyUserConfig: run.tools !== "none",
          needsCredentialStore: effectiveCredInfo.needsCredentialStore,
          dataDir: cfg.dataDir,
        });
        if (safeCodexCfg) {
          // 隔离 tools="none" 仅将经过校验的路由/供应商/工作区限制写入暂存 config.toml，绝不复制 hooks/tools/MCP
          fs.writeFileSync(
            path.join(stagedCodexHome.scratchDir, "config.toml"),
            renderSafeCodexConfigToml(safeCodexCfg),
            { mode: 0o600 },
          );
        }
        oauthLease.attachScratch?.(stagedCodexHome);
        if (effectiveCredInfo.awsProfile) {
          stagedAws = stageIsolatedAwsProfile(effectiveCredInfo.awsProfile, childMergedEnv, cfg.dataDir);
        }
      }
    }

    const acpxExtraRo: string[] = [];
    const acpxExtraRw: string[] = [];
    const acpxExtraSymlinks: { dest: string; target: string }[] = [];
    const acpxExtraBindMounts: { src: string; dest: string; mode: "ro" | "rw" }[] = [];
    if (baseEnv.env.CREDENTIALS_DIRECTORY) acpxExtraRo.push(baseEnv.env.CREDENTIALS_DIRECTORY);
    // 仅挂载 bin/guard/lark-cli 运行所需的 4 个精确文件，绝不挂载整个 ROOT（防暴露 ROOT/config.yaml 与 ROOT/.worktrees）
    acpxExtraRo.push(...collectLarkGuardReadOnlyFiles());
    if (run.lark !== "none" && fs.existsSync(realLark)) acpxExtraRo.push(realLark);
    if (stagedAcpx) {
      acpxExtraBindMounts.push({ src: stagedAcpx.dir, dest: stagedAcpx.mountDest, mode: "rw" });
      acpxExtraRo.push(...stagedAcpx.extraReadOnlyPaths);
    }
    if (stagedClaude) {
      acpxExtraBindMounts.push(...stagedClaude.bindMounts);
      acpxExtraSymlinks.push(...stagedClaude.symlinks);
    }
    if (stagedGemini) {
      acpxExtraBindMounts.push(...stagedGemini.bindMounts);
    }
    if (stagedOpenCode) {
      acpxExtraBindMounts.push(...stagedOpenCode.bindMounts);
    }
    if (stagedAdapterCache) {
      acpxExtraBindMounts.push(...stagedAdapterCache.bindMounts);
    }
    if (stagedDoubao) {
      acpxExtraBindMounts.push(...stagedDoubao.bindMounts);
    }
    if (stagedNpmrc) {
      acpxExtraRo.push(stagedNpmrc.dir);
      acpxExtraBindMounts.push({ src: stagedNpmrc.file, dest: stagedNpmrc.homeMountDest, mode: "ro" });
    }
    if (stagedGitCfg) {
      acpxExtraRo.push(stagedGitCfg.dir, ...stagedGitCfg.extraReadOnlyPaths);
      acpxExtraBindMounts.push(...stagedGitCfg.bindMounts);
      acpxExtraSymlinks.push(...stagedGitCfg.symlinks);
    }
    if (stagedCodexHome) {
      acpxExtraRw.push(stagedCodexHome.scratchDir);
    }
    if (stagedAws) {
      acpxExtraRo.push(stagedAws.dir, ...stagedAws.extraReadOnlyPaths);
      acpxExtraBindMounts.push(...stagedAws.bindMounts);
    }
    const selectedConfigPaths = [
      // acpxIsolationEnv 已完成一次 mergeHarnessEnv 展开，绝不二次展开 ${VAR}
      ...selectAcpxAgentConfigPaths(h, hostHome, acpxIsolationEnv, { alreadyMerged: true }),
      ...(run.lark !== "none" ? selectLarkCliAuthPaths(acpxIsolationEnv) : []),
    ];
    for (const p of selectedConfigPaths) {
      if (!fs.existsSync(p)) continue;
      const real = safeRealpath(p);
      if (stagedClaude && (isPathInsideOrEqual(real, stagedClaude.hostClaudeDir) || real === stagedClaude.hostClaudeJson)) {
        continue;
      }
      if (stagedGemini && stagedGemini.hostDirsToSkip.some((d) => isPathInsideOrEqual(real, d))) {
        continue;
      }
      if (stagedOpenCode && stagedOpenCode.hostDirsToSkip.some((d) => isPathInsideOrEqual(real, d))) {
        continue;
      }
      if (stagedDoubao && isPathInsideOrEqual(real, stagedDoubao.hostDataDir)) {
        continue;
      }
      if (codexHostHomeToSkip && isPathInsideOrEqual(real, codexHostHomeToSkip)) {
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
      ...(stagedAdapterCache?.extraCmdPaths ?? []),
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
          extraWritablePaths: acpxExtraRw,
          extraReadOnlyPaths: acpxExtraRo,
          extraSymlinks: acpxExtraSymlinks,
          extraBindMounts: acpxExtraBindMounts,
        },
        acpxIsolationEnv,
      ),
    );
    const restoreCodexDbus =
      isCodexAcpx &&
      !wrapped.isolated &&
      process.platform === "linux" &&
      codexNeedsCredentialStore &&
      !!process.env.DBUS_SESSION_BUS_ADDRESS &&
      !childMergedEnv.DBUS_SESSION_BUS_ADDRESS;
    const adapterPathPrefix =
      wrapped.isolated && stagedAdapterCache?.prependPathDirs.length
        ? `${stagedAdapterCache.prependPathDirs.join(path.delimiter)}${path.delimiter}`
        : "";
    const env: NodeJS.ProcessEnv = {
      ...childMergedEnv,
      ...safeCodexExtraEnv,
      PATH: `${path.join(ROOT, "bin", "guard")}${path.delimiter}${adapterPathPrefix}${childMergedEnv.PATH ?? process.env.PATH ?? ""}`,
      PA_GUARD_PROFILE: run.lark,
      PA_OWNER_OPEN_ID: cfg.owner.open_id,
      PA_LARK_REAL: realLark,
      PA_GUARD_LOG: path.join(cfg.dataDir, "logs", "guard.log"),
      ...(wrapped.isolated ? isolatedSandboxTempEnv() : {}),
      ...(restoreCodexDbus ? { DBUS_SESSION_BUS_ADDRESS: process.env.DBUS_SESSION_BUS_ADDRESS } : {}),
      ...(stagedCodexHome ? { CODEX_HOME: stagedCodexHome.scratchDir } : {}),
      ...(stagedAws
        ? {
            AWS_CONFIG_FILE: stagedAws.configFile,
            AWS_SHARED_CREDENTIALS_FILE: stagedAws.credentialsFile,
          }
        : {}),
    };
    if (mode !== "llm-none") {
      applySanitizedNpmrcEnv(env, stagedNpmrc, wrapped.isolated);
      applySanitizedGitConfigEnv(env, stagedGitCfg, wrapped.isolated);
    }
    r = await runProcess(wrapped.cmd, wrapped.args, {
      cwd: run.cwd,
      env,
      input: run.prompt,
      // acpx 自己有 --timeout；这里多留 2 分钟兜底，防止进程卡死
      timeoutMs: acpxTimeoutMs,
      group: true,
      signal: run.signal,
      onSpawn: run.onSpawn,
    });
    if (stagedCodexHome && !syncedCodexAuth) {
      syncedCodexAuth = true;
      syncRefreshedCodexAuth(stagedCodexHome);
    }
    if (stagedClaude && !syncedClaudeAuth) {
      syncedClaudeAuth = true;
      syncRefreshedClaudeAuth(stagedClaude);
    }
    if (stagedOpenCode && !syncedOpenCodeAuth) {
      syncedOpenCodeAuth = true;
      syncRefreshedOpenCodeAuth(stagedOpenCode);
    }
  } finally {
    if (stagedCodexHome && !syncedCodexAuth) {
      syncedCodexAuth = true;
      syncRefreshedCodexAuth(stagedCodexHome);
    }
    if (stagedClaude && !syncedClaudeAuth) {
      syncedClaudeAuth = true;
      syncRefreshedClaudeAuth(stagedClaude);
    }
    if (stagedOpenCode && !syncedOpenCodeAuth) {
      syncedOpenCodeAuth = true;
      syncRefreshedOpenCodeAuth(stagedOpenCode);
    }
    stagedCodexHome?.cleanup();
    oauthLease?.release({ keepRecoveryRow: !!stagedCodexHome?.retainScratchForRecovery });
    stagedAws?.cleanup();
    stagedGitCfg?.cleanup();
    stagedNpmrc?.cleanup();
    stagedDoubao?.cleanup();
    stagedOpenCode?.cleanup();
    openCodeOAuthLease?.release({ keepRecoveryRow: !!stagedOpenCode?.retainScratchForRecovery });
    stagedGemini?.cleanup();
    stagedClaude?.cleanup();
    claudeOAuthLease?.release({ keepRecoveryRow: !!stagedClaude?.retainScratchForRecovery });
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
  /** 写回宿主机发生可重试 I/O 或锁错误且暂存目录含已轮换令牌时置为 true，cleanup() 将保留受保护恢复副本 */
  retainScratchForRecovery?: boolean;
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

const activeOAuthLeaseHolders = new Set<string>();

function isPidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === "EPERM";
  }
}

/** 判断 OAuth 刷新租约或待恢复记录持有者是否仍活跃：pid<=0 表示显式保留待恢复；同进程内以 activeOAuthLeaseHolders 精确判定 */
function isOAuthHolderActive(pid: number, holder: string): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  if (pid === process.pid) return activeOAuthLeaseHolders.has(holder);
  return isPidAlive(pid);
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
  // 崩溃可恢复登记表：仅存非敏感元数据与暂存目录路径（绝不存原始令牌），
  // 当常驻进程在 Codex 轮换单次 refresh_token 后异常崩溃时，下次调用在读取宿主机旧令牌前先原子恢复新令牌。
  db.exec(`
    CREATE TABLE IF NOT EXISTS pending_recovery (
      holder TEXT PRIMARY KEY,
      pid INTEGER NOT NULL,
      scratch_auth_path TEXT NOT NULL,
      scratch_dir TEXT NOT NULL,
      host_auth_path TEXT NOT NULL,
      was_symlink INTEGER NOT NULL,
      orig_dev INTEGER NOT NULL,
      orig_ino INTEGER NOT NULL,
      orig_sha256 TEXT NOT NULL,
      orig_auth_mode TEXT,
      orig_account_id TEXT,
      orig_last_refresh TEXT,
      created_at INTEGER NOT NULL
    )
  `);
  return db;
}

interface CodexPendingRecoveryRow {
  holder: string;
  pid: number;
  scratch_auth_path: string;
  scratch_dir: string;
  host_auth_path: string;
  was_symlink: number;
  orig_dev: number;
  orig_ino: number;
  orig_sha256: string;
  orig_auth_mode: string | null;
  orig_account_id: string | null;
  orig_last_refresh: string | null;
  created_at: number;
}

function sha256Hex(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

function isSafeCodexScratchDirForCleanup(scratchDir: string): boolean {
  if (!scratchDir || !path.isAbsolute(scratchDir)) return false;
  const base = path.basename(scratchDir);
  if (!base.startsWith(".pa-codex-home-") && !base.startsWith("pa-codex-home-")) return false;
  try {
    const lst = fs.lstatSync(scratchDir);
    return !lst.isSymbolicLink() && lst.isDirectory() && isCurrentUidOwner(lst);
  } catch {
    return false;
  }
}

interface CodexSyncTargetMeta {
  hostAuthPath: string;
  resolvedAuthPath: string;
  wasSymlink: boolean;
  origDev: number;
  origIno: number;
  origSha256: string;
  origAuthMode?: string;
  origAccountId?: string;
  origLastRefresh?: string;
  origJson?: Record<string, unknown>;
}

function applyValidatedCodexAuthSyncLocked(meta: CodexSyncTargetMeta, scratchAuthPath: string): boolean {
  let nextBytes: Buffer;
  try {
    const lst = fs.lstatSync(scratchAuthPath);
    if (
      lst.isSymbolicLink() ||
      !lst.isFile() ||
      !isCurrentUidOwner(lst) ||
      lst.size <= 0 ||
      lst.size > MAX_CODEX_AUTH_BYTES
    ) {
      return false;
    }
    nextBytes = fs.readFileSync(scratchAuthPath);
  } catch {
    return false;
  }
  if (sha256Hex(nextBytes) === meta.origSha256) return false;

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
  if (meta.origAuthMode && nextJson.auth_mode !== meta.origAuthMode) return false;
  if (meta.origAccountId && nextTokens.account_id !== meta.origAccountId) return false;

  const origRefreshMs = meta.origLastRefresh ? Date.parse(meta.origLastRefresh) : NaN;
  const nextRefreshMs = typeof nextJson.last_refresh === "string" ? Date.parse(nextJson.last_refresh) : NaN;
  if (Number.isFinite(origRefreshMs) && Number.isFinite(nextRefreshMs) && nextRefreshMs < origRefreshMs) {
    return false;
  }

  const verifyEntryPointsToTarget = (): boolean => {
    try {
      const entryLst = fs.lstatSync(meta.hostAuthPath);
      if (meta.wasSymlink) {
        if (!entryLst.isSymbolicLink()) return false;
        return fs.realpathSync(meta.hostAuthPath) === meta.resolvedAuthPath;
      }
      return (
        !entryLst.isSymbolicLink() &&
        entryLst.isFile() &&
        Number(entryLst.dev) === meta.origDev &&
        Number(entryLst.ino) === meta.origIno
      );
    } catch {
      return false;
    }
  };

  if (!verifyEntryPointsToTarget()) return false;

  const roFlags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  let readFd: number;
  try {
    readFd = fs.openSync(meta.resolvedAuthPath, roFlags);
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
      Number(beforeStat.dev) !== meta.origDev ||
      Number(beforeStat.ino) !== meta.origIno
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

  let curHostJson: Record<string, unknown> | undefined;
  try {
    const parsedCur = JSON.parse(curHostBytes.toString("utf8")) as unknown;
    if (isPlainJsonRecord(parsedCur)) curHostJson = parsedCur;
  } catch {
    curHostJson = undefined;
  }

  if (sha256Hex(curHostBytes) !== meta.origSha256) {
    if (!curHostJson || !isPlainJsonRecord(curHostJson.tokens)) return false;
    if (meta.origAuthMode && curHostJson.auth_mode !== meta.origAuthMode) return false;
    if (meta.origAccountId && curHostJson.tokens.account_id !== meta.origAccountId) return false;
    const curHostRefreshMs = typeof curHostJson.last_refresh === "string" ? Date.parse(curHostJson.last_refresh) : NaN;
    if (!Number.isFinite(nextRefreshMs) || !Number.isFinite(curHostRefreshMs) || nextRefreshMs <= curHostRefreshMs) {
      return false;
    }
  }

  const baseJson = meta.origJson ?? curHostJson;
  if (!baseJson || !isPlainJsonRecord(baseJson.tokens)) return false;
  const baseTokens = baseJson.tokens;
  const tokensChanged =
    nextTokens.access_token !== baseTokens.access_token ||
    nextTokens.refresh_token !== baseTokens.refresh_token ||
    (typeof nextTokens.id_token === "string" && nextTokens.id_token !== baseTokens.id_token);
  const refreshAdvanced = Number.isFinite(nextRefreshMs) && (!Number.isFinite(origRefreshMs) || nextRefreshMs > origRefreshMs);
  if (!tokensChanged && !refreshAdvanced) return false;

  const sanitizedTokens: Record<string, unknown> = {
    ...(typeof baseTokens.id_token === "string" ? { id_token: baseTokens.id_token } : {}),
    ...(typeof nextTokens.id_token === "string" ? { id_token: nextTokens.id_token } : {}),
    access_token: nextTokens.access_token,
    refresh_token: nextTokens.refresh_token,
    ...(typeof nextTokens.account_id === "string"
      ? { account_id: nextTokens.account_id }
      : typeof baseTokens.account_id === "string"
        ? { account_id: baseTokens.account_id }
        : {}),
  };
  const nextLastRefresh =
    typeof nextJson.last_refresh === "string" && nextJson.last_refresh.trim()
      ? nextJson.last_refresh
      : new Date().toISOString();
  const mergedPayload: Record<string, unknown> = {
    ...baseJson,
    tokens: sanitizedTokens,
    last_refresh: nextLastRefresh,
  };
  const outBuf = Buffer.from(`${JSON.stringify(mergedPayload, null, 2)}\n`, "utf8");

  // 写入同目录独立 0600 临时文件并 fsync，成功后再二次核验目标未变并原子 rename 替换（出错时原文件完好无损）
  const targetDir = path.dirname(meta.resolvedAuthPath);
  const dirSt = fs.lstatSync(targetDir);
  if (!dirSt.isDirectory() || !isCurrentUidOwner(dirSt)) return false;
  const tmpPath = path.join(
    targetDir,
    `.${path.basename(meta.resolvedAuthPath)}.pa-tmp-${process.pid}-${Date.now()}-${randomUUID().slice(0, 8)}`,
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

    if (!verifyEntryPointsToTarget()) {
      fs.rmSync(tmpPath, { force: true });
      return false;
    }
    const preRenameStat = fs.lstatSync(meta.resolvedAuthPath);
    if (
      preRenameStat.isSymbolicLink() ||
      !preRenameStat.isFile() ||
      !isCurrentUidOwner(preRenameStat) ||
      Number(preRenameStat.dev) !== meta.origDev ||
      Number(preRenameStat.ino) !== meta.origIno ||
      preRenameStat.size !== beforeStat.size ||
      preRenameStat.mtimeMs !== beforeStat.mtimeMs
    ) {
      fs.rmSync(tmpPath, { force: true });
      return false;
    }

    fs.renameSync(tmpPath, meta.resolvedAuthPath);
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
}

function hasRotatedCodexScratchAuth(staged: StagedCodexHome): boolean {
  const snap = staged.origAuth;
  if (!snap || !snap.canSyncBack) return false;
  const origTokens = isPlainJsonRecord(snap.origJson.tokens) ? snap.origJson.tokens : undefined;
  if (!origTokens) return false;
  const scratchAuthPath = path.join(staged.scratchDir, "auth.json");
  try {
    const st = fs.lstatSync(scratchAuthPath);
    if (st.isSymbolicLink() || !st.isFile() || st.size === 0 || st.size > 512 * 1024) return false;
    const raw = fs.readFileSync(scratchAuthPath);
    if (sha256Hex(raw) === sha256Hex(snap.origBytes)) return false;
    const parsed = JSON.parse(raw.toString("utf8")) as unknown;
    if (!isPlainJsonRecord(parsed) || !isPlainJsonRecord(parsed.tokens)) return false;
    const nextTokens = parsed.tokens;
    if (typeof nextTokens.access_token !== "string" || !nextTokens.access_token.trim()) return false;
    if (typeof nextTokens.refresh_token !== "string" || !nextTokens.refresh_token.trim()) return false;
    if (typeof snap.origJson.auth_mode === "string" && snap.origJson.auth_mode && parsed.auth_mode !== snap.origJson.auth_mode) {
      return false;
    }
    const origAcc = typeof origTokens.account_id === "string" && origTokens.account_id ? origTokens.account_id : undefined;
    if (origAcc && typeof nextTokens.account_id === "string" && nextTokens.account_id && nextTokens.account_id !== origAcc) {
      return false;
    }
    const nextRefreshMs = typeof parsed.last_refresh === "string" ? Date.parse(parsed.last_refresh) : NaN;
    const origRefreshMs = typeof snap.origJson.last_refresh === "string" ? Date.parse(snap.origJson.last_refresh) : NaN;
    if (Number.isFinite(origRefreshMs) && Number.isFinite(nextRefreshMs) && nextRefreshMs < origRefreshMs) {
      return false;
    }
    const tokensChanged =
      nextTokens.access_token !== origTokens.access_token ||
      nextTokens.refresh_token !== origTokens.refresh_token ||
      (typeof nextTokens.id_token === "string" && nextTokens.id_token !== origTokens.id_token);
    const refreshAdvanced = Number.isFinite(nextRefreshMs) && (!Number.isFinite(origRefreshMs) || nextRefreshMs > origRefreshMs);
    return tokensChanged || refreshAdvanced;
  } catch {
    return false;
  }
}

/**
 * 在持锁状态下扫描并恢复已死亡进程、写回失败保留或已过期租约持有者遗留的暂存 `auth.json` 轮换结果，
 * 确保后续工作进程不会重新读取并消费已作废的旧单次 refresh_token。
 */
function recoverOrphanedCodexAuthLocked(
  db: DatabaseSync,
  resolvedAuthPath: string,
  expiredLeaseHolder?: string,
): boolean {
  const rows = db
    .prepare(
      "SELECT holder, pid, scratch_auth_path, scratch_dir, host_auth_path, was_symlink, orig_dev, orig_ino, orig_sha256, orig_auth_mode, orig_account_id, orig_last_refresh, created_at FROM pending_recovery ORDER BY created_at DESC",
    )
    .all() as unknown as CodexPendingRecoveryRow[];
  let recoveredAny = false;
  for (const rec of rows) {
    const dead = !isOAuthHolderActive(rec.pid, rec.holder);
    const isExpiredHolder = !!expiredLeaseHolder && rec.holder === expiredLeaseHolder;
    if (!dead && !isExpiredHolder) continue;
    let writeFailed = false;
    try {
      const ok = applyValidatedCodexAuthSyncLocked(
        {
          hostAuthPath: rec.host_auth_path,
          resolvedAuthPath,
          wasSymlink: rec.was_symlink !== 0,
          origDev: rec.orig_dev,
          origIno: rec.orig_ino,
          origSha256: rec.orig_sha256,
          origAuthMode: rec.orig_auth_mode ?? undefined,
          origAccountId: rec.orig_account_id ?? undefined,
          origLastRefresh: rec.orig_last_refresh ?? undefined,
        },
        rec.scratch_auth_path,
      );
      if (ok) {
        recoveredAny = true;
        log("info", "已从遗留暂存 CODEX_HOME 原子恢复刷新后的 OAuth 凭据", {
          holder: rec.holder,
          resolvedAuthPath,
        });
      }
    } catch (err) {
      writeFailed = true;
      log("warn", "恢复遗留 Codex OAuth 凭据失败（保留恢复副本与原文件）", {
        holder: rec.holder,
        err: errMsg(err),
      });
    }
    if (dead && !writeFailed) {
      if (isSafeCodexScratchDirForCleanup(rec.scratch_dir)) {
        try {
          fs.rmSync(rec.scratch_dir, { recursive: true, force: true });
        } catch {
          // ignore cleanup error
        }
      }
      db.prepare("DELETE FROM pending_recovery WHERE holder = ?").run(rec.holder);
    }
  }
  return recoveredAny;
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
  /** 在启动隔离子进程前登记暂存目录，确保若常驻进程在轮换单次 refresh_token 后异常崩溃或写回失败，下次调用先原子恢复新令牌再复用宿主机凭据 */
  attachScratch?: (staged: StagedCodexHome) => void;
  release: (opts?: { keepRecoveryRow?: boolean }) => void;
}

/**
 * 在拷贝 `auth.json` 启动隔离 `codex exec` / Codex ACP 之前，按规范化目标路径跨进程、跨工作区协调 OAuth 刷新租约：
 *   - 若另一活跃进程正在持有刷新租约（可能即将轮换单次 refresh_token），本调用方等待其写回并释放后再重新读取宿主机 `auth.json`；
 *   - 若此前持有者已崩溃或租约已过期，先从其登记的暂存目录原子恢复已轮换的新令牌，避免后续工人重用已消耗的旧 refresh_token；
 *   - 若当前凭据可能需要刷新（JWT 即将/已过期、非 JWT 刷新时间陈旧），获取独占刷新租约并附带心跳续期，直到本进程完成写回后释放；
 *   - 无论是否获取独占租约，均返回 `attachScratch` 以登记本次暂存目录，保证意外崩溃后刷新结果可恢复。
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

  const makeAttachScratch = (): ((staged: StagedCodexHome) => void) => (staged: StagedCodexHome) => {
    const snap = staged.origAuth;
    if (!snap || !snap.canSyncBack || !hasOAuthRefreshToken(snap.origJson)) return;
    activeOAuthLeaseHolders.add(holder);
    const origTokens = isPlainJsonRecord(snap.origJson.tokens) ? snap.origJson.tokens : undefined;
    try {
      withCodexAuthSyncLock(snap.resolvedAuthPath, (db) => {
        db.prepare(
          `INSERT OR REPLACE INTO pending_recovery
            (holder, pid, scratch_auth_path, scratch_dir, host_auth_path, was_symlink, orig_dev, orig_ino, orig_sha256, orig_auth_mode, orig_account_id, orig_last_refresh, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).run(
          holder,
          process.pid,
          path.join(staged.scratchDir, "auth.json"),
          staged.scratchDir,
          snap.hostAuthPath,
          snap.wasSymlink ? 1 : 0,
          snap.origDev,
          snap.origIno,
          sha256Hex(snap.origBytes),
          typeof snap.origJson.auth_mode === "string" && snap.origJson.auth_mode ? snap.origJson.auth_mode : null,
          typeof origTokens?.account_id === "string" && origTokens.account_id ? origTokens.account_id : null,
          typeof snap.origJson.last_refresh === "string" && snap.origJson.last_refresh ? snap.origJson.last_refresh : null,
          Date.now(),
        );
      });
    } catch {
      // best-effort recovery registration
    }
  };

  for (;;) {
    if (opts?.signal?.aborted) throw new Error("aborted");
    const attempt = withCodexAuthSyncLock(resolvedAuthPath, (db) => {
      const now = Date.now();
      const row = db
        .prepare("SELECT holder, pid, expires_at FROM refresh_lease WHERE id = 1")
        .get() as { holder: string; pid: number; expires_at: number } | undefined;
      if (row && row.expires_at > now && isOAuthHolderActive(row.pid, row.holder)) {
        return { action: "wait" as const };
      }
      // 在重新检查宿主机 auth.json 前，先从死亡进程、写回失败保留或过期租约遗留的暂存目录原子恢复已轮换的新令牌
      recoverOrphanedCodexAuthLocked(db, resolvedAuthPath, row?.holder);

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
      let released = false;
      const release = (relOpts?: { keepRecoveryRow?: boolean }) => {
        if (released) return;
        released = true;
        activeOAuthLeaseHolders.delete(holder);
        process.off("exit", onExit);
        try {
          withCodexAuthSyncLock(resolvedAuthPath, (db) => {
            if (relOpts?.keepRecoveryRow) {
              db.prepare("UPDATE pending_recovery SET pid = 0 WHERE holder = ?").run(holder);
            } else {
              db.prepare("DELETE FROM pending_recovery WHERE holder = ?").run(holder);
            }
          });
        } catch {
          // ignore cleanup failure on exit
        }
      };
      const onExit = () => release({ keepRecoveryRow: true });
      process.once("exit", onExit);
      return { held: false, resolvedAuthPath, attachScratch: makeAttachScratch(), release };
    }
    if (attempt.action === "acquired") {
      activeOAuthLeaseHolders.add(holder);
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

      const release = (relOpts?: { keepRecoveryRow?: boolean }) => {
        if (released) return;
        released = true;
        activeOAuthLeaseHolders.delete(holder);
        clearInterval(heartbeat);
        process.off("exit", onExit);
        try {
          withCodexAuthSyncLock(resolvedAuthPath, (db) => {
            if (relOpts?.keepRecoveryRow) {
              db.prepare("UPDATE pending_recovery SET pid = 0 WHERE holder = ?").run(holder);
            } else {
              db.prepare("DELETE FROM pending_recovery WHERE holder = ?").run(holder);
            }
            db.prepare("DELETE FROM refresh_lease WHERE id = 1 AND holder = ?").run(holder);
          });
        } catch {
          // ignore release failure on exit
        }
      };
      const onExit = () => release({ keepRecoveryRow: true });
      process.once("exit", onExit);
      return { held: true, resolvedAuthPath, attachScratch: makeAttachScratch(), release };
    }

    if (Date.now() >= deadline) {
      throw new Error(`等待宿主机 Codex OAuth 刷新协调锁超时 (${resolvedAuthPath})，为避免重复消费 refresh_token 已中止执行`);
    }
    await sleepAbortableMs(pollMs, opts?.signal);
  }
}

function resolvePersistentOAuthScratchBase(
  subdir: string,
  resolvedAuthPath: string,
  hostDir: string,
  resolvedDataDir: string,
): string {
  const authParent = safeRealpath(path.dirname(resolvedAuthPath));
  const realHostDir = safeRealpath(hostDir);
  const home = os.homedir();
  if (home) {
    const candidate = path.join(safeRealpath(home), ".local", "state", "personal-agent", subdir);
    const collides =
      isPathInsideOrEqual(candidate, realHostDir) ||
      isPathInsideOrEqual(realHostDir, candidate) ||
      isPathInsideOrEqual(candidate, authParent) ||
      isPathInsideOrEqual(authParent, candidate) ||
      (!!resolvedDataDir && (isPathInsideOrEqual(candidate, resolvedDataDir) || isPathInsideOrEqual(resolvedDataDir, candidate)));
    if (!collides) {
      try {
        fs.mkdirSync(candidate, { recursive: true, mode: 0o700 });
        const st = fs.lstatSync(candidate);
        if (!st.isSymbolicLink() && st.isDirectory() && isCurrentUidOwner(st)) {
          fs.chmodSync(candidate, 0o700);
          return safeRealpath(candidate);
        }
      } catch {
        // fallback to os.tmpdir()
      }
    }
  }
  return os.tmpdir();
}

/**
 * 为隔离沙箱中的 `codex exec` / Codex ACP 准备私有临时 `CODEX_HOME`：
 *   - 宿主机真实 `~/.codex` 保持只读，防止沙箱内进程篡改 `config.toml` / `hooks` / `plugins` / `skills`；
 *   - 将 `auth.json` 以 0600 拷贝到临时 `CODEX_HOME`，支持安全解引用 dotfiles 符号链接目标并提前校验其归属与可写性：
 *     若文件态 OAuth 凭据（含 refresh_token）为损坏符号链接或目标不可写/非当前用户所有，在启动子进程前即 fail-closed 拒绝，
 *     防止子进程旋转消耗单次 refresh_token 后无法写回宿主机；
 *   - 非 `tools="none"` 模式下按解引用后的真实内容拷贝 `config.toml`、`*.config.toml`、`instructions.md`、`AGENTS.md`、`rules/`；
 *     若 `codexHome`、`config.toml` 或 `*.config.toml` 存在但无法安全载入（损坏链接/不可读/过大），立即 fail-closed 抛错。
 */
export function stageIsolatedCodexHome(
  hostCodexHome: string,
  opts: { copyUserConfig: boolean; lockDir?: string; needsCredentialStore?: boolean; dataDir?: string },
): StagedCodexHome {
  let scratchDir = "";
  let origAuth: CodexAuthOrigSnapshot | undefined;

  const cleanup = () => {
    if (scratchDir) fs.rmSync(scratchDir, { recursive: true, force: true });
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

    const resolvedData = opts.dataDir && fs.existsSync(opts.dataDir) ? safeRealpath(opts.dataDir) : "";
    let authInspected: ReturnType<typeof inspectHostCodexAuth> = { kind: "absent" };
    // 当生效供应商不依赖宿主机 OpenAI/ChatGPT 登录态（如本地模型、Bedrock 或显式 API Key）时，
    // 绝不检查或拷贝宿主机 auth.json，防止把无关的 ChatGPT refresh_token 暴露给隔离子进程或残留在临时目录中
    if (opts.needsCredentialStore !== false) {
      const hostAuthPath = path.join(hostCodexHome, "auth.json");
      authInspected = inspectHostCodexAuth(hostAuthPath);
      if (authInspected.kind === "broken_symlink") {
        throw new Error(authInspected.error);
      }
      // 若宿主机已有协同锁库，先恢复任何已崩溃进程遗留的 OAuth 刷新结果，再重新读取最新宿主机 auth.json
      if (
        authInspected.kind === "ok" &&
        authInspected.canSyncBack &&
        authInspected.origJson &&
        hasOAuthRefreshToken(authInspected.origJson) &&
        fs.existsSync(canonicalCodexLockFilePath(authInspected.resolvedAuthPath))
      ) {
        const resolvedAuthForRecovery = authInspected.resolvedAuthPath;
        try {
          const recovered = withCodexAuthSyncLock(resolvedAuthForRecovery, (db) => {
            const row = db
              .prepare("SELECT holder, pid, expires_at FROM refresh_lease WHERE id = 1")
              .get() as { holder: string; pid: number; expires_at: number } | undefined;
            if (row && row.expires_at > Date.now() && isOAuthHolderActive(row.pid, row.holder)) return false;
            return recoverOrphanedCodexAuthLocked(db, resolvedAuthForRecovery, row?.holder);
          });
          if (recovered) {
            authInspected = inspectHostCodexAuth(hostAuthPath);
            if (authInspected.kind === "broken_symlink") throw new Error(authInspected.error);
          }
        } catch {
          // best-effort pre-stage recovery
        }
      }
    }

    // 对可写 OAuth 凭据，将暂存目录建在宿主机持久化用户状态目录（~/.local/state/personal-agent/codex-scratch/.pa-codex-home-*），
    // 既独立于 hostCodexHome（不在沙箱内造出 hostCodexHome 祖先目录），又不受 systemd PrivateTmp 重启清除，
    // 使常驻进程在轮换单次 refresh_token 后崩溃也能被下次启动原子恢复。
    let scratchBase = os.tmpdir();
    let scratchPrefix = "pa-codex-home-";
    if (
      authInspected.kind === "ok" &&
      authInspected.canSyncBack &&
      authInspected.origJson &&
      hasOAuthRefreshToken(authInspected.origJson)
    ) {
      scratchBase = resolvePersistentOAuthScratchBase(
        "codex-scratch",
        authInspected.resolvedAuthPath,
        hostCodexHome,
        resolvedData,
      );
      scratchPrefix = ".pa-codex-home-";
    }
    scratchDir = safeRealpath(fs.mkdtempSync(path.join(scratchBase, scratchPrefix)));
    fs.chmodSync(scratchDir, 0o700);

    if (authInspected.kind === "ok") {
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

    const state: StagedCodexHome = {
      scratchDir,
      origAuth,
      lockDir: opts.lockDir,
      retainScratchForRecovery: false,
      cleanup: () => {
        if (state.retainScratchForRecovery) return;
        cleanup();
      },
    };
    return state;
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
  try {
    return withCodexAuthSyncLock(snap.resolvedAuthPath, () =>
      applyValidatedCodexAuthSyncLocked(
        {
          hostAuthPath: snap.hostAuthPath,
          resolvedAuthPath: snap.resolvedAuthPath,
          wasSymlink: snap.wasSymlink,
          origDev: snap.origDev,
          origIno: snap.origIno,
          origSha256: sha256Hex(snap.origBytes),
          origAuthMode: typeof snap.origJson.auth_mode === "string" && snap.origJson.auth_mode ? snap.origJson.auth_mode : undefined,
          origAccountId: typeof origTokens.account_id === "string" && origTokens.account_id ? origTokens.account_id : undefined,
          origLastRefresh:
            typeof snap.origJson.last_refresh === "string" && snap.origJson.last_refresh ? snap.origJson.last_refresh : undefined,
          origJson: snap.origJson,
        },
        scratchAuthPath,
      ),
    );
  } catch (err) {
    if (hasRotatedCodexScratchAuth(staged)) {
      staged.retainScratchForRecovery = true;
      log("warn", "写回刷新后的 Codex auth.json 失败，已保留受保护恢复副本待后续自动重试", {
        scratchDir: staged.scratchDir,
        err: errMsg(err),
      });
    } else {
      log("warn", "写回刷新后的 Codex auth.json 失败（保留原文件）", { err: errMsg(err) });
    }
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
  let stagedGitCfg: StagedSanitizedGitConfig | undefined;
  let oauthLease: CodexOAuthRefreshLease | undefined;
  let syncedCodexAuth = false;
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
        dataDir: cfg.dataDir,
      });
      oauthLease.attachScratch?.(stagedCodexHome);
      if (effectiveCredInfo.awsProfile) {
        stagedAws = stageIsolatedAwsProfile(effectiveCredInfo.awsProfile, finalEnv, cfg.dataDir);
      }
      if (run.tools !== "none") {
        stagedNpmrc = stageSanitizedNpmrc(codexIsolationEnv, cfg.dataDir);
        stagedGitCfg = stageSanitizedGitConfig(codexIsolationEnv, cfg.dataDir, { cwd: execCwd });
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
      if (run.tools !== "none") {
        applySanitizedNpmrcEnv(finalEnv, stagedNpmrc, true);
        applySanitizedGitConfigEnv(finalEnv, stagedGitCfg, true);
      }
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
      ...(stagedGitCfg ? [stagedGitCfg.dir, ...stagedGitCfg.extraReadOnlyPaths] : []),
    ];
    const extraRw = [
      ...(isolatedTmp ? [isolatedTmp] : []),
      ...(readOutDir ? [readOutDir] : []),
      ...(stagedCodexHome ? [stagedCodexHome.scratchDir] : []),
    ];
    const extraBindMounts = [
      ...(stagedAws ? stagedAws.bindMounts : []),
      ...(stagedNpmrc ? [{ src: stagedNpmrc.file, dest: stagedNpmrc.homeMountDest, mode: "ro" as const }] : []),
      ...(stagedGitCfg ? stagedGitCfg.bindMounts : []),
    ];
    const extraSymlinks = [...(stagedGitCfg ? stagedGitCfg.symlinks : [])];
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
          ...(extraSymlinks.length ? { extraSymlinks } : {}),
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
    if (stagedCodexHome && !syncedCodexAuth) {
      syncedCodexAuth = true;
      syncRefreshedCodexAuth(stagedCodexHome);
    }
    try {
      text = fs.readFileSync(outFile, "utf8").trim();
      fs.rmSync(outFile, { force: true });
    } catch {
      text = r.stdout.trim();
    }
  } finally {
    if (stagedCodexHome && !syncedCodexAuth) {
      syncedCodexAuth = true;
      syncRefreshedCodexAuth(stagedCodexHome);
    }
    stagedCodexHome?.cleanup();
    oauthLease?.release({ keepRecoveryRow: !!stagedCodexHome?.retainScratchForRecovery });
    baseEnv.cleanup();
    stagedGitCfg?.cleanup();
    stagedNpmrc?.cleanup();
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
  let stagedGitCfg: StagedSanitizedGitConfig | undefined;
  let r: Awaited<ReturnType<typeof runProcess>>;
  try {
    const mode: WorkspaceIsolationMode =
      run.tools === "write" ? "worker-write" : run.tools === "read" ? "worker-ro" : "llm-none";
    const doubaoIsolationEnv = mergeHarnessEnv(process.env, h.env);
    const resolvedDataDir = cfg.dataDir && fs.existsSync(cfg.dataDir) ? safeRealpath(cfg.dataDir) : "";
    stagedDoubao = stageIsolatedDoubaoDataDir(doubaoIsolationEnv, cfg.dataDir);
    if (mode !== "llm-none") {
      stagedNpmrc = stageSanitizedNpmrc(doubaoIsolationEnv, cfg.dataDir);
      stagedGitCfg = stageSanitizedGitConfig(doubaoIsolationEnv, cfg.dataDir, { cwd: run.cwd });
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
    if (stagedGitCfg) {
      doubaoExtraRo.push(stagedGitCfg.dir, ...stagedGitCfg.extraReadOnlyPaths);
      doubaoExtraBindMounts.push(...stagedGitCfg.bindMounts);
    }
    const doubaoExtraSymlinks = [...(stagedGitCfg ? stagedGitCfg.symlinks : [])];
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
          ...(doubaoExtraSymlinks.length ? { extraSymlinks: doubaoExtraSymlinks } : {}),
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
    if (mode !== "llm-none") {
      applySanitizedNpmrcEnv(env, stagedNpmrc, wrapped.isolated);
      applySanitizedGitConfigEnv(env, stagedGitCfg, wrapped.isolated);
    }
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
    stagedGitCfg?.cleanup();
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
