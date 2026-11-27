import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import type { Config } from "../config.ts";
import {
  applySanitizedGitConfigEnv,
  buildWorkspaceIsolation,
  collectSafeGitConfigMounts,
  collectSafeGitIgnoreAndAttrMounts,
  createScopedSecretDir,
  detectGitWorktreeDirs,
  gitUrlPrefixMatchesTarget,
  prepareHarnessEnv,
  resolveTrustedSystemBin,
  stageSanitizedGitConfig,
  willIsolateCommand,
  workspaceRequiresIsolation,
  wrapCredentialIsolatedCommand,
  type IsolationOptions,
  type StagedSanitizedGitConfig,
} from "../harness.ts";
import { errMsg, killGroup, runProcess, type ProcResult } from "../util.ts";

function killChildGroup(child: { pid?: number; kill: (sig?: NodeJS.Signals) => boolean }): void {
  if (child.pid) killGroup(child.pid, "SIGKILL");
  try {
    child.kill("SIGKILL");
  } catch {
    // ignore
  }
}

/**
 * 交付用到的 git 操作：
 *   - 显式指定 -C 目录，不依赖进程当前目录；
 *   - 关闭交互认证、禁用仓库级 hooks / fsmonitor / external diff（防不可信仓库配置执行任意代码）；
 *   - 剥离个人 Web 凭据环境，并在需要隔离的工作区或持钥环境下通过内核 PID + 只读根挂载命名空间隐藏 dataDir 与密钥文件；
 *   - 仅对明确需要远程传输的 git 子命令（push/fetch/ls-remote/pull/clone/lfs）窄范围透传单个 SSH_AUTH_SOCK 套接字，绝不暴露给普通 worker 或本地 git 命令。
 */

const GIT_SAFE_ARGS = [
  "-c", "user.name=personal-agent",
  "-c", "user.email=personal-agent@localhost",
  "-c", "core.hooksPath=/dev/null",
  "-c", "core.fsmonitor=false",
  "-c", "core.pager=cat",
];

const REMOTE_GIT_SUBCMDS = new Set(["push", "fetch", "ls-remote", "pull", "clone", "lfs"]);

export interface GitRunOpts {
  input?: string | Buffer;
  timeoutMs?: number;
  cfg?: Pick<Config, "dataDir" | "context">;
  readOnly?: boolean;
  /** 受信任的派单仓库根目录（用于严格校核 worktree `.git` / `commondir`，防止 worker 篡改元数据） */
  trustedRepoRoot?: string;
  /** 显式禁止挂载任何外部 worktree `.git` 目录 */
  disableGitWorktreeMounts?: boolean;
  extraWritablePaths?: string[];
  extraReadOnlyPaths?: string[];
  extraSymlinks?: { dest: string; target: string }[];
  extraBindMounts?: { src: string; dest: string; mode: "ro" | "rw" }[];
  extraCmdPaths?: string[];
  extraGitConfigArgs?: string[];
  /** 仅限仓库级显式要求 SSH 提交签名且公钥/加密私钥依赖代理时，为单次 `git commit` 窄范围透传 SSH_AUTH_SOCK */
  allowCommitSigningSshSock?: boolean;
  extraEnv?: Record<string, string>;
}

function resolveValidatedSshAuthSock(
  rawEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
): string | undefined {
  const rawSock = rawEnv.SSH_AUTH_SOCK?.trim();
  if (!rawSock) return undefined;
  try {
    if (!fs.statSync(rawSock).isSocket()) return undefined;
    const realSock = fs.realpathSync(rawSock);
    if (dataDir) {
      const realData = fs.existsSync(dataDir) ? fs.realpathSync(dataDir) : path.resolve(dataDir);
      const rel = path.relative(realData, realSock);
      if (rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel))) return undefined;
    }
    return realSock;
  } catch {
    return undefined;
  }
}

/** 仅对授权的远程 Git 传输子命令解析并校验单个 SSH 代理 Unix 套接字路径（绝不开放给普通 worker 或本地 git 命令） */
export function resolveAuthorizedSshAuthSock(
  args: string[],
  rawEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
): string | undefined {
  if (!REMOTE_GIT_SUBCMDS.has(args[0] ?? "")) return undefined;
  return resolveValidatedSshAuthSock(rawEnv, dataDir);
}

/**
 * 统一解析 scp 风格的 SSH Git 远端地址，同时支持相对路径（`git@host:org/repo.git`）与绝对路径（`git@host:/srv/project.git`）
 * 以及方括号 IPv6 主机（`git@[::1]:/srv/repo.git`）；若传了 `cwd` 且本地恰好存在同名含冒号路径则视为本地目录返回 undefined。
 */
export function parseScpGitUrl(
  rawUrl: string,
  cwd?: string,
): { user?: string; host: string; path: string } | undefined {
  const u = rawUrl.trim();
  if (!u || u === "." || u === "..") return undefined;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) return undefined;
  if (u.startsWith("/") || u.startsWith("./") || u.startsWith("../") || /^[a-z]:\\/i.test(u)) return undefined;
  const m = u.match(/^(?:([^@/:]+)@)?(\[[^\]]+\]|[^/:]+):(.+)$/);
  if (!m) return undefined;
  if (cwd) {
    try {
      if (fs.existsSync(path.resolve(cwd, u))) return undefined;
    } catch {
      // ignore
    }
  }
  const rawHost = m[2];
  const host = (rawHost.startsWith("[") && rawHost.endsWith("]") ? rawHost.slice(1, -1) : rawHost).toLowerCase();
  if (!host) return undefined;
  return { user: m[1] || undefined, host, path: m[3] };
}

/** 分类 Git 远端地址的实际传输协议（绝不把 HTTPS 或本地 `git fetch .` 误判为 SSH，也绝不把 `git@host:/srv/repo.git` 误判为本地） */
export function classifyGitRemoteTransport(cwd: string, rawUrl: string): "ssh" | "http" | "local" | "other" {
  const u = rawUrl.trim();
  if (!u || u === "." || u === "..") return "local";
  if (/^https?:\/\//i.test(u)) return "http";
  if (/^(?:ssh|git\+ssh|ssh\+git):\/\//i.test(u)) return "ssh";
  if (/^file:\/\//i.test(u)) return "local";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) return "other";
  if (u.startsWith("/") || u.startsWith("./") || u.startsWith("../") || /^[a-z]:\\/i.test(u)) return "local";
  if (parseScpGitUrl(u, cwd)) return "ssh";
  return "local";
}

export interface SshRemoteTarget {
  host: string;
  user?: string;
  port?: string;
}

function extractSshTarget(rawUrl: string, cwd?: string): SshRemoteTarget | undefined {
  const u = rawUrl.trim();
  if (/^(?:ssh|git\+ssh|ssh\+git):\/\//i.test(u)) {
    try {
      const normalized = u.replace(/^(?:git\+ssh|ssh\+git):\/\//i, "ssh://");
      const parsed = new URL(normalized);
      const host = parsed.hostname.toLowerCase();
      if (!host) return undefined;
      let user: string | undefined;
      if (parsed.username) {
        try {
          user = decodeURIComponent(parsed.username);
        } catch {
          user = parsed.username;
        }
      }
      return { host, ...(user ? { user } : {}), ...(parsed.port ? { port: parsed.port } : {}) };
    } catch {
      return undefined;
    }
  }
  const scp = parseScpGitUrl(u, cwd);
  if (!scp) return undefined;
  return { host: scp.host, ...(scp.user ? { user: scp.user } : {}) };
}

function sshPatternMatch(pattern: string, host: string): boolean {
  const esc = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${esc}$`, "i").test(host);
}

function sshHostClauseMatches(patterns: string[], host: string): boolean {
  let matchedPositive = false;
  for (const raw of patterns) {
    if (!raw) continue;
    if (raw.startsWith("!")) {
      if (sshPatternMatch(raw.slice(1), host)) return false;
    } else if (sshPatternMatch(raw, host)) {
      matchedPositive = true;
    }
  }
  return matchedPositive;
}

interface SshTokenContext {
  hostHome: string;
  origHost?: string;
  hostName?: string;
  remoteUser?: string;
  localUser?: string;
  port?: string;
}

function getLocalUsername(rawEnv: NodeJS.ProcessEnv): string {
  const envUser = rawEnv.USER?.trim() || rawEnv.LOGNAME?.trim();
  if (envUser) return envUser;
  try {
    return os.userInfo().username || "";
  } catch {
    return "";
  }
}

/** 按 OpenSSH `ssh_config(5)` 语义展开路径占位符（支持 `%%`、`%d`、`%h`、`%n`、`%r`、`%u`、`%p`、`%i`、`%L`、`%l`）；遇未知占位符保守返回 undefined */
function expandSshTokens(raw: string, ctx?: SshTokenContext): string | undefined {
  if (!raw.includes("%")) return raw;
  const localHost = os.hostname() || "";
  const shortLocalHost = localHost.split(".")[0] || "";
  const uidStr = typeof process.getuid === "function" ? String(process.getuid()) : "";
  let out = "";
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch !== "%") {
      out += ch;
      continue;
    }
    if (i + 1 >= raw.length) return undefined;
    const tok = raw[++i];
    if (tok === "%") {
      out += "%";
    } else if (tok === "d") {
      if (!ctx?.hostHome) return undefined;
      out += ctx.hostHome;
    } else if (tok === "h") {
      const v = ctx?.hostName || ctx?.origHost;
      if (!v) return undefined;
      out += v;
    } else if (tok === "n") {
      if (!ctx?.origHost) return undefined;
      out += ctx.origHost;
    } else if (tok === "r") {
      const v = ctx?.remoteUser || ctx?.localUser;
      if (!v) return undefined;
      out += v;
    } else if (tok === "u") {
      if (!ctx?.localUser) return undefined;
      out += ctx.localUser;
    } else if (tok === "p") {
      out += ctx?.port || "22";
    } else if (tok === "i") {
      if (!uidStr) return undefined;
      out += uidStr;
    } else if (tok === "L") {
      if (!shortLocalHost) return undefined;
      out += shortLocalHost;
    } else if (tok === "l") {
      if (!localHost) return undefined;
      out += localHost;
    } else {
      return undefined;
    }
  }
  return out;
}

function expandSshPath(raw: string, hostHome: string, tokenCtx?: SshTokenContext): string | undefined {
  let s = raw.trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    s = s.slice(1, -1).trim();
  }
  if (!s) return undefined;
  const expandedTokens = expandSshTokens(s, tokenCtx ? { ...tokenCtx, hostHome } : undefined);
  if (!expandedTokens || /%[a-zA-Z%]/.test(expandedTokens)) return undefined;
  s = expandedTokens;
  if (s === "~") return hostHome || undefined;
  if (s.startsWith("~/")) return hostHome ? path.join(hostHome, s.slice(2)) : undefined;
  return path.isAbsolute(s) ? s : hostHome ? path.join(hostHome, ".ssh", s) : undefined;
}

function sshGlobSegmentMatches(pattern: string, name: string): boolean {
  if (name.startsWith(".") && !pattern.startsWith(".")) return false;
  let re = "^";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === "*") {
      re += ".*";
    } else if (ch === "?") {
      re += ".";
    } else if (ch === "[") {
      const close = pattern.indexOf("]", i + 1);
      if (close > i + 1) {
        let cls = pattern.slice(i + 1, close);
        if (cls.startsWith("!")) cls = `^${cls.slice(1)}`;
        re += `[${cls.replace(/\\/g, "\\\\")}]`;
        i = close;
      } else {
        re += "\\[";
      }
    } else if (/[.+^${}()|\\]/.test(ch)) {
      re += `\\${ch}`;
    } else {
      re += ch;
    }
  }
  re += "$";
  try {
    return new RegExp(re).test(name);
  } catch {
    return false;
  }
}

/** 按 OpenSSH Include 语义安全展开通配路径（相对路径基于 `~/.ssh`，按字典序返回，跳过 dataDir 内文件并限制展开上限） */
function expandSshIncludePattern(
  rawPattern: string,
  hostHome: string,
  isOutsideData: (p: string) => boolean,
): string[] {
  const expanded = expandSshPath(rawPattern, hostHome);
  if (!expanded) return [];
  if (!/[*?[\]]/.test(expanded)) {
    return fs.existsSync(expanded) && isOutsideData(expanded) ? [expanded] : [];
  }
  const norm = path.resolve(expanded);
  const parts = norm.split(path.sep).filter(Boolean);
  const results: string[] = [];
  const MAX_MATCHES = 256;

  const walk = (baseDir: string, segIdx: number) => {
    if (results.length >= MAX_MATCHES) return;
    if (segIdx >= parts.length) {
      try {
        if (fs.statSync(baseDir).isFile() && isOutsideData(baseDir)) {
          results.push(baseDir);
        }
      } catch {
        // ignore
      }
      return;
    }
    const seg = parts[segIdx];
    if (!/[*?[\]]/.test(seg)) {
      const next = path.join(baseDir, seg);
      if (!fs.existsSync(next)) return;
      walk(next, segIdx + 1);
      return;
    }
    let entries: string[];
    try {
      entries = fs.readdirSync(baseDir).sort((a, b) => a.localeCompare(b));
    } catch {
      return;
    }
    for (const name of entries) {
      if (results.length >= MAX_MATCHES) break;
      if (!sshGlobSegmentMatches(seg, name)) continue;
      const next = path.join(baseDir, name);
      if (segIdx + 1 < parts.length) {
        try {
          if (!fs.statSync(next).isDirectory()) continue;
        } catch {
          continue;
        }
      }
      walk(next, segIdx + 1);
    }
  };

  walk(path.sep, 0);
  return results;
}

function extractSshPublicKeyFingerprintLine(rawText: string): string | undefined {
  for (const rawLine of rawText.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const parts = line.split(/\s+/);
    if (parts.length >= 2 && parts[0] && parts[1]) {
      return `${parts[0]} ${parts[1]}`;
    }
  }
  return undefined;
}

function querySshAgentLoadedKeys(sshSock: string): Set<string> {
  const keys = new Set<string>();
  if (!sshSock) return keys;
  const sshAddBin = resolveTrustedSystemBin("ssh-add");
  if (!sshAddBin) return keys;
  try {
    const r = spawnSync(sshAddBin, ["-L"], {
      env: { PATH: "/usr/sbin:/usr/bin:/sbin:/bin", LC_ALL: "C", SSH_AUTH_SOCK: sshSock },
      timeout: 2_000,
      encoding: "utf8",
    });
    if (r.status !== 0 || !r.stdout) return keys;
    for (const rawLine of r.stdout.split(/\r?\n/)) {
      const fp = extractSshPublicKeyFingerprintLine(rawLine);
      if (fp) keys.add(fp);
    }
  } catch {
    // 探测失败按未命中处理，允许回退到默认磁盘私钥
  }
  return keys;
}

/**
 * 仅为实际使用 SSH 传输的受信任远程 Git 操作收集最小化的只读 SSH 挂载（绝不整目录挂载 ~/.ssh）：
 *   - 仅挂载 `~/.ssh/config`、`~/.ssh/known_hosts*` 以及 `Include`（含 `config.d/*.conf` 等通配模式）中实际命中目标主机的配置片段；
 *   - 按目标 SSH 主机解析 `~/.ssh/config` 及匹配片段中生效的 Host 块，仅挂载该主机引用的 IdentityFile / CertificateFile / UserKnownHostsFile（及 .pub）；
 *   - 未命中显式 IdentityFile 时：按 `ssh-add -L` 检查 SSH 代理是否实际已加载对应默认公钥——仅代理已加载该密钥时才省略磁盘私钥；
 *     若代理为空或未持有该默认密钥，仍以只读方式挂载标准默认密钥对（id_ed25519 / id_rsa / id_ecdsa / id_dsa）以保留 OpenSSH 文件回退，绝不暴露无关命名私钥。
 */
export function collectScopedSshMounts(
  sshHosts: (string | SshRemoteTarget)[],
  rawEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
  hasSshAgentOrSock: boolean | string = false,
): { readOnlyPaths: string[]; symlinks: { dest: string; target: string }[] } {
  const normalizedTargets: SshRemoteTarget[] = sshHosts
    .map((entry) => (typeof entry === "string" ? { host: entry.trim().toLowerCase() } : { ...entry, host: entry.host.trim().toLowerCase() }))
    .filter((t) => !!t.host);
  const localUser = getLocalUsername(rawEnv);
  const sshSockPath =
    typeof hasSshAgentOrSock === "string"
      ? hasSshAgentOrSock.trim()
      : hasSshAgentOrSock
        ? (rawEnv.SSH_AUTH_SOCK?.trim() ?? "")
        : "";
  const hasSshAgent = Boolean(hasSshAgentOrSock);
  const readOnlyPaths: string[] = [];
  const symlinks: { dest: string; target: string }[] = [];
  const hostHome = rawEnv.HOME?.trim() || os.homedir();
  if (!hostHome) return { readOnlyPaths, symlinks };
  const sshDir = path.join(hostHome, ".ssh");
  const realData = dataDir && fs.existsSync(dataDir) ? fs.realpathSync(dataDir) : "";
  const isOutsideData = (p: string): boolean => {
    if (!realData) return true;
    try {
      const real = fs.realpathSync(p);
      const rel = path.relative(realData, real);
      return rel !== "" && (rel.startsWith("..") || path.isAbsolute(rel));
    } catch {
      return false;
    }
  };
  const added = new Set<string>();
  const addSingleFile = (logicalPath: string) => {
    try {
      const lst = fs.lstatSync(logicalPath);
      const st = fs.statSync(logicalPath);
      if (!st.isFile()) return;
      const real = fs.realpathSync(logicalPath);
      if (!isOutsideData(real)) return;
      if (!added.has(real)) {
        added.add(real);
        readOnlyPaths.push(real);
      }
      if (lst.isSymbolicLink()) {
        const logicalDest = path.join(fs.realpathSync(path.dirname(logicalPath)), path.basename(logicalPath));
        if (logicalDest !== real) {
          symlinks.push({ dest: logicalDest, target: real });
        }
      }
    } catch {
      // ignore missing/unreadable file
    }
  };

  // 若 GIT_SSH_COMMAND 显式指定了 -i <identity_file>，仅放行该单个密钥文件
  const gitSshCmd = rawEnv.GIT_SSH_COMMAND?.trim() ?? "";
  if (gitSshCmd) {
    const idMatches = gitSshCmd.matchAll(/(?:^|\s)-i\s*(?:"([^"]+)"|'([^']+)'|(\S+))/g);
    for (const m of idMatches) {
      const rawId = m[1] ?? m[2] ?? m[3] ?? "";
      const targetsForCmd = normalizedTargets.length > 0 ? normalizedTargets : [{ host: "" }];
      for (const t of targetsForCmd) {
        const expanded = expandSshPath(rawId, hostHome, {
          hostHome,
          origHost: t.host || undefined,
          hostName: t.host || undefined,
          remoteUser: t.user,
          localUser,
          port: t.port,
        });
        if (expanded) {
          addSingleFile(expanded);
          addSingleFile(`${expanded}.pub`);
        }
      }
    }
  }

  if (!fs.existsSync(sshDir)) return { readOnlyPaths, symlinks };

  addSingleFile(path.join(sshDir, "known_hosts"));
  addSingleFile(path.join(sshDir, "known_hosts2"));

  const tokenizeSshValues = (val: string): string[] => {
    const out: string[] = [];
    for (const m of val.matchAll(/"([^"]+)"|'([^']+)'|(\S+)/g)) {
      const tok = m[1] ?? m[2] ?? m[3];
      if (tok) out.push(tok);
    }
    return out;
  };

  const matchedIdentityFiles: string[] = [];
  const rootCfgPath = path.join(sshDir, "config");

  // 按 OpenSSH 逐目标先收集生效的 HostName/User/Port（首次命中优先）与全部匹配片段，
  // 再用最终生效的主机/用户/端口展开 IdentityFile / CertificateFile / UserKnownHostsFile 中的 %h/%n/%r/%u/%p/%d 等占位符。
  const evalTargets = normalizedTargets.length > 0 ? normalizedTargets : [{ host: "" }];
  for (const target of evalTargets) {
    let effectiveHostName: string | undefined;
    let effectiveUser: string | undefined = target.user;
    let effectivePort: string | undefined = target.port;
    const rawIdentityFiles: string[] = [];
    const rawCertificateFiles: string[] = [];
    const rawUserKnownHostsFiles: string[] = [];
    const visitedConfigs = new Set<string>();

    const parseSshConfigForTarget = (cfgFile: string, depth: number, isRoot: boolean): boolean => {
      if (depth > 4 || !fs.existsSync(cfgFile)) return false;
      let realCfg: string;
      try {
        const st = fs.statSync(cfgFile);
        if (!st.isFile() || st.size > 256 * 1024) return false;
        realCfg = fs.realpathSync(cfgFile);
      } catch {
        return false;
      }
      if (visitedConfigs.has(realCfg) || !isOutsideData(realCfg)) return false;
      visitedConfigs.add(realCfg);
      if (isRoot) addSingleFile(cfgFile);

      let active = true;
      let matchedAny = false;
      const text = fs.readFileSync(realCfg, "utf8");
      for (const rawLine of text.split(/\r?\n/)) {
        const trimmed = rawLine.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const m = trimmed.match(/^([A-Za-z][A-Za-z0-9]*)(?:\s*=\s*|\s+)(.+)$/);
        if (!m) continue;
        const key = m[1].toLowerCase();
        const val = m[2].trim();
        if (key === "host") {
          const patterns = tokenizeSshValues(val);
          active = !!target.host && sshHostClauseMatches(patterns, target.host);
          if (active) matchedAny = true;
        } else if (key === "match") {
          active = false;
        } else if (key === "include" && active) {
          for (const rawInc of tokenizeSshValues(val)) {
            for (const incPath of expandSshIncludePattern(rawInc, hostHome, isOutsideData)) {
              if (parseSshConfigForTarget(incPath, depth + 1, false)) {
                matchedAny = true;
              }
            }
          }
        } else if (active) {
          matchedAny = true;
          if (key === "hostname" && !effectiveHostName) {
            const firstTok = tokenizeSshValues(val)[0];
            if (firstTok) {
              // OpenSSH 允许 HostName 内部引用 %h（原目标别名）与 %%
              effectiveHostName =
                expandSshTokens(firstTok, { hostHome, origHost: target.host, hostName: target.host }) ?? firstTok;
            }
          } else if (key === "user" && !effectiveUser) {
            const firstTok = tokenizeSshValues(val)[0];
            if (firstTok) effectiveUser = firstTok;
          } else if (key === "port" && !effectivePort) {
            const firstTok = tokenizeSshValues(val)[0];
            if (firstTok) effectivePort = firstTok;
          } else if (key === "identityfile") {
            rawIdentityFiles.push(val);
          } else if (key === "certificatefile") {
            rawCertificateFiles.push(val);
          } else if (key === "userknownhostsfile") {
            rawUserKnownHostsFiles.push(...tokenizeSshValues(val));
          }
        }
      }
      if (!isRoot && matchedAny) {
        addSingleFile(cfgFile);
      }
      return matchedAny;
    };

    parseSshConfigForTarget(rootCfgPath, 0, true);

    const tokenCtx: SshTokenContext = {
      hostHome,
      origHost: target.host || undefined,
      hostName: effectiveHostName || target.host || undefined,
      remoteUser: effectiveUser || localUser || undefined,
      localUser: localUser || undefined,
      port: effectivePort || "22",
    };

    for (const rawId of rawIdentityFiles) {
      const idPath = expandSshPath(rawId, hostHome, tokenCtx);
      if (idPath) matchedIdentityFiles.push(idPath);
    }
    for (const rawCert of rawCertificateFiles) {
      const certPath = expandSshPath(rawCert, hostHome, tokenCtx);
      if (certPath) addSingleFile(certPath);
    }
    for (const rawKh of rawUserKnownHostsFiles) {
      const khPath = expandSshPath(rawKh, hostHome, tokenCtx);
      if (khPath) addSingleFile(khPath);
    }
  }

  if (matchedIdentityFiles.length > 0) {
    for (const idFile of matchedIdentityFiles) {
      addSingleFile(idFile);
      addSingleFile(`${idFile}.pub`);
    }
  } else {
    const agentLoadedKeys = hasSshAgent && sshSockPath ? querySshAgentLoadedKeys(sshSockPath) : new Set<string>();
    for (const defKey of ["id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"]) {
      const full = path.join(sshDir, defKey);
      const pubFile = `${full}.pub`;
      addSingleFile(pubFile);
      let loadedInAgent = false;
      if (agentLoadedKeys.size > 0 && fs.existsSync(pubFile)) {
        try {
          const st = fs.statSync(pubFile);
          if (st.isFile() && st.size <= 64 * 1024) {
            const fp = extractSshPublicKeyFingerprintLine(fs.readFileSync(pubFile, "utf8"));
            if (fp && agentLoadedKeys.has(fp)) loadedInAgent = true;
          }
        } catch {
          // ignore
        }
      }
      if (!loadedInAgent) addSingleFile(full);
    }
  }

  return { readOnlyPaths, symlinks };
}

function buildGitIsolation(
  cwd: string,
  opts: GitRunOpts | undefined,
  filteredCredDir?: string,
  authorizedSshSock?: string,
  sshMounts?: { readOnlyPaths: string[]; symlinks: { dest: string; target: string }[] },
  rawEnv: NodeJS.ProcessEnv = process.env,
  sanitizeGitConfig = false,
  extraBindMounts?: { src: string; dest: string; mode: "ro" | "rw" }[],
): IsolationOptions {
  const extraRw = [
    ...(opts?.extraWritablePaths ?? []),
    ...(authorizedSshSock ? [authorizedSshSock] : []),
  ];
  const extraRo = [
    ...(opts?.extraReadOnlyPaths ?? []),
    ...(filteredCredDir ? [filteredCredDir] : []),
    ...(sshMounts?.readOnlyPaths ?? []),
  ];
  const extraSymlinks = [...(opts?.extraSymlinks ?? []), ...(sshMounts?.symlinks ?? [])];
  const combinedBindMounts = [...(opts?.extraBindMounts ?? []), ...(extraBindMounts ?? [])];
  if (opts?.cfg) {
    const plan = buildWorkspaceIsolation(
      opts.cfg,
      {
        mode: opts.readOnly ? "git-ro" : "git-rw",
        cwd,
        trustedRepoRoot: opts.trustedRepoRoot,
        disableGitWorktreeMounts: opts.disableGitWorktreeMounts,
        sanitizeGitConfig,
        ...(opts.extraCmdPaths?.length ? { extraCmdPaths: opts.extraCmdPaths } : {}),
        extraWritablePaths: extraRw,
        extraReadOnlyPaths: extraRo,
        extraSymlinks,
        ...(combinedBindMounts.length ? { extraBindMounts: combinedBindMounts } : {}),
      },
      rawEnv,
    );
    return plan;
  }
  const isoActive = process.platform === "linux" || workspaceRequiresIsolation(undefined, rawEnv);
  const wt =
    !isoActive || opts?.disableGitWorktreeMounts
      ? {}
      : detectGitWorktreeDirs(cwd, { trustedRepoRoot: opts?.trustedRepoRoot });
  const wtTargets = [wt.commonDir, wt.gitDir].filter((p): p is string => !!p);
  const gitCfg = isoActive
    ? sanitizeGitConfig
      ? collectSafeGitIgnoreAndAttrMounts(rawEnv)
      : collectSafeGitConfigMounts(rawEnv, undefined, { cwd })
    : { readOnlyPaths: [], symlinks: [] };
  const combinedRo = [...gitCfg.readOnlyPaths, ...extraRo];
  const combinedSymlinks = [...gitCfg.symlinks, ...extraSymlinks];
  return {
    cwd,
    requireIsolation: isoActive,
    writablePaths: opts?.readOnly ? extraRw : [cwd, ...wtTargets, ...extraRw],
    readOnlyPaths: opts?.readOnly ? [cwd, ...wtTargets, ...combinedRo] : combinedRo,
    ...(combinedSymlinks.length ? { extraSymlinks: combinedSymlinks } : {}),
    ...(combinedBindMounts.length ? { extraBindMounts: combinedBindMounts } : {}),
  };
}

interface ScopedGitHttpCreds {
  credDir?: string;
  gitConfigArgs: string[];
  cleanup: () => void;
}

function defaultPortForProtocol(proto: string): string {
  return proto === "https:" ? "443" : proto === "http:" ? "80" : "";
}

function parseHttpUrlSafe(raw: string): URL | undefined {
  try {
    const u = new URL(raw.trim());
    if (u.protocol !== "http:" && u.protocol !== "https:") return undefined;
    if (!u.hostname) return undefined;
    return u;
  } catch {
    return undefined;
  }
}

function normalizeCredPath(pathname: string): string {
  const stripped = pathname.replace(/\/+$/, "");
  return stripped === "/" ? "" : stripped;
}

/** 按 Git 凭据协议解码 URL 路径（去除首尾斜杠并还原 %XX 百分号转义，如 `my%20project/repo.git` -> `my project/repo.git`） */
function decodeCredPath(pathname: string): string {
  const stripped = pathname.replace(/^\/+|\/+$/g, "");
  if (!stripped) return "";
  try {
    return decodeURIComponent(stripped);
  } catch {
    return stripped;
  }
}

/** 将凭据协议中的已解码路径按段重新百分号编码，仅供写入 `git-credential-store` URL 行 */
function encodeCredPathForStoreUrl(decodedPath: string): string {
  const trimmed = decodedPath.replace(/^\/+|\/+$/g, "");
  if (!trimmed) return "";
  return trimmed
    .split("/")
    .map((seg) => encodeURIComponent(seg))
    .join("/");
}

function decodeUrlUser(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/**
 * 按原生 `git-credential-store`（`credential_match`）精确匹配语义判断单行凭据是否适用于指定目标 HTTP(S) URL：
 *   - `useHttpPath=true` 时 Git 在查询中携带解码后的完整 `path`，`git-credential-store` 严格要求条目的解码路径与目标完全一致
 *     （既不接受无路径的主机通配条目，也不接受仅匹配上级前缀 `/org` 的条目）；
 *   - `useHttpPath=false` 时 Git 查询不含 `path`，任意路径条目均可匹配同协议/主机/端口/用户名的目标。
 */
export function gitCredentialLineMatchesTarget(
  credLine: string,
  target: URL,
  useHttpPath: boolean,
  effectiveUsername?: string,
): boolean {
  const trimmed = credLine.trim();
  if (!trimmed || trimmed.startsWith("#")) return false;
  const entry = parseHttpUrlSafe(trimmed);
  if (!entry) return false;
  if (entry.protocol !== target.protocol) return false;
  if (entry.hostname.toLowerCase() !== target.hostname.toLowerCase()) return false;
  const targetPort = target.port || defaultPortForProtocol(target.protocol);
  const entryPort = entry.port || defaultPortForProtocol(entry.protocol);
  if (targetPort !== entryPort) return false;
  const wantUser = effectiveUsername || (target.username ? decodeUrlUser(target.username) : "");
  if (wantUser && decodeUrlUser(entry.username) !== wantUser) return false;
  if (useHttpPath) {
    const targetPath = decodeCredPath(target.pathname);
    if (!targetPath) return true;
    const entryPath = decodeCredPath(entry.pathname);
    return entryPath === targetPath;
  }
  return true;
}

function parseStoreHelperFile(
  helperValue: string,
  hostHome: string,
  cwd?: string,
): { isStore: boolean; explicitFile?: string } {
  const v = helperValue.trim();
  if (!v) return { isStore: false };
  if (!/^(?:(?:\/[^\s]*\/)?git-credential-)?store(?:\s|$)/.test(v)) return { isStore: false };
  const eqMatch = v.match(/(?:^|\s)--file=(?:"([^"]+)"|'([^']+)'|(\S+))/);
  const spMatch = v.match(/(?:^|\s)--file\s+(?:"([^"]+)"|'([^']+)'|(\S+))/);
  const rawFile = eqMatch?.[1] ?? eqMatch?.[2] ?? eqMatch?.[3] ?? spMatch?.[1] ?? spMatch?.[2] ?? spMatch?.[3];
  if (!rawFile) return { isStore: true };
  const expanded = rawFile.startsWith("~/") && hostHome ? path.join(hostHome, rawFile.slice(2)) : rawFile;
  return { isStore: true, explicitFile: cwd ? path.resolve(cwd, expanded) : path.resolve(expanded) };
}

function extractRemoteTargetSpec(args: string[]): { mode: "push" | "fetch"; target?: string; explicitUrls: string[] } {
  const sub = args[0] ?? "";
  const explicitUrls: string[] = [];
  const collectUrlIfHttp = (s: string | undefined) => {
    if (s && /^https?:\/\//i.test(s.trim())) explicitUrls.push(s.trim());
  };

  if (sub === "lfs") {
    const lfsSub = args[1] ?? "";
    if (lfsSub === "pre-push") {
      collectUrlIfHttp(args[3]);
      return { mode: "push", target: args[2], explicitUrls };
    }
    const mode = lfsSub === "push" ? "push" : "fetch";
    for (let i = 2; i < args.length; i++) {
      const a = args[i];
      if (!a || a === "--") continue;
      if (a.startsWith("-")) continue;
      collectUrlIfHttp(a);
      return { mode, target: a, explicitUrls };
    }
    return { mode, explicitUrls };
  }

  const valueFlagsBySub: Record<string, Set<string>> = {
    push: new Set(["--repo", "--receive-pack", "--exec", "--push-option", "-o"]),
    "ls-remote": new Set(["--upload-pack", "--sort", "-o", "--server-option"]),
    fetch: new Set(["--depth", "--shallow-since", "--shallow-exclude", "--upload-pack", "-o", "--server-option", "--negotiation-tip"]),
    pull: new Set(["--depth", "--shallow-since", "--shallow-exclude", "--upload-pack", "-o", "--server-option", "-s", "--strategy", "-X", "--strategy-option"]),
    clone: new Set(["-b", "--branch", "-o", "--origin", "--depth", "--reference", "-c", "--config", "--upload-pack", "--separate-git-dir", "--filter"]),
  };
  const valFlags = valueFlagsBySub[sub] ?? new Set<string>();
  const mode = sub === "push" ? "push" : "fetch";
  let target: string | undefined;
  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (a === "--") {
      target = args[i + 1];
      break;
    }
    if (a.startsWith("-")) {
      if (valFlags.has(a)) i++;
      continue;
    }
    target = a;
    break;
  }
  if (!target && (sub === "push" || sub === "fetch" || sub === "pull" || sub === "ls-remote")) {
    target = "origin";
  }
  collectUrlIfHttp(target);
  return { mode, target, explicitUrls };
}

/**
 * 按原生 Git `credential.<pattern>.helper` 匹配规则判断配置段是否适用于目标 HTTP(S) URL：
 *   - 含协议的 URL 模式（如 `https://alice@example.com`、`https://*.example.com/org`）严格遵循 Git `urlmatch` 语义：
 *     含用户名时必须与目标 URL 的用户名精确一致（绝不匹配无用户名目标）；主机通配符 `*.example.com` 仅匹配单个子域标签；
 *   - 无协议的仅主机模式（如 `example.com`、`example.com:8443`、`alice@example.com`）按 Git `credential_match` 仅匹配精确主机（不支持通配符）。
 */
export function gitCredentialSectionMatchesUrl(sectionUrl: string, target: URL): boolean {
  const pat = sectionUrl.trim();
  if (!pat) return false;
  if (pat.includes("://")) {
    return gitUrlPrefixMatchesTarget(pat, target.href);
  }
  // Git 对无协议的 host-only 段（如 `[credential "*.example.com"]`）不支持通配符匹配
  if (pat.includes("*")) return false;
  return gitUrlPrefixMatchesTarget(`${target.protocol}//${pat}`, target.href);
}

/**
 * 原位替换 Git credential helper 链中的条目，按槽位独立映射每个 `store`（绝不合并多个 store 破坏中间 helper 的优先级）
 * 或宿主机预解析的非 store helper（如 `gh auth setup-git` / `git credential-cache`）。
 *
 * `credFileOrResolver` 既支持单个路径字符串（兼容旧调用），也支持按 `(key, helperValue, index)` 返回：
 *   - 非空字符串：替换为该 helper（例如 `store --file=/tmp/...`）；
 *   - `null`：该槽位对目标 URL 无命中，原位省略以便 Git 立即顺序进入下一个 helper；
 *   - `undefined`：原样保留原始 `helperValue`。
 */
export function rewriteGitCredentialHelperChain(
  activeByKey: Map<string, string[]>,
  rewrittenKeys: Set<string>,
  credFileOrResolver: string | ((key: string, helperValue: string, index: number) => string | null | undefined),
  hostHome: string,
): string[] {
  const gitConfigArgs: string[] = [];
  for (const [key, helpers] of activeByKey) {
    if (!rewrittenKeys.has(key)) continue;
    gitConfigArgs.push("-c", `${key}=`);
    for (let i = 0; i < helpers.length; i++) {
      const hv = helpers[i];
      if (typeof credFileOrResolver === "function") {
        const mapped = credFileOrResolver(key, hv, i);
        if (mapped === null) continue;
        if (typeof mapped === "string") {
          gitConfigArgs.push("-c", `${key}=${mapped}`);
        } else {
          gitConfigArgs.push("-c", `${key}=${hv}`);
        }
      } else {
        const parsed = parseStoreHelperFile(hv, hostHome);
        if (parsed.isStore) {
          gitConfigArgs.push("-c", `${key}=store --file=${credFileOrResolver}`);
        } else {
          gitConfigArgs.push("-c", `${key}=${hv}`);
        }
      }
    }
  }
  return gitConfigArgs;
}

/**
 * 按精确优先级读取单个生效的 Git LFS 端点 URL：
 *   - 逐键按顺序先查受信任 Git 配置（`--includes --get`，尊重后写覆盖），未命中时仅对 `git-lfs` 允许的安全键回退查 `.lfsconfig`；
 *   - 命中首个非空键即停止，绝不把被更高优先级覆盖的旧端点或下载端点暴露给上传操作。
 */
async function readFirstLfsEndpointKey(
  cwd: string,
  specs: { key: string; allowLfsConfig: boolean }[],
  opts?: GitRunOpts,
): Promise<string | undefined> {
  if (specs.length === 0) return undefined;
  const lfsConfigPath = path.join(cwd, ".lfsconfig");
  let hasLfsConfig = false;
  try {
    const st = fs.statSync(lfsConfigPath);
    hasLfsConfig = st.isFile() && st.size <= 256 * 1024;
  } catch {
    hasLfsConfig = false;
  }
  const readSingle = async (extraCfgArgs: string[], key: string): Promise<string> => {
    const r = await tryGit(cwd, ["config", ...extraCfgArgs, "--get", key], { ...opts, readOnly: true });
    if (r.code !== 0 || !r.stdout) return "";
    return r.stdout.trim();
  };
  for (const spec of specs) {
    const fromGit = await readSingle(["--includes"], spec.key);
    if (fromGit) return fromGit;
    if (spec.allowLfsConfig && hasLfsConfig) {
      const fromFile = await readSingle(["--file", lfsConfigPath], spec.key);
      if (fromFile) return fromFile;
    }
  }
  return undefined;
}

function looksLikeRemoteName(cwd: string, target: string | undefined): target is string {
  return (
    !!target &&
    target !== "." &&
    target !== ".." &&
    !/^[a-z][a-z0-9+.-]*:\/\//i.test(target) &&
    !target.startsWith("/") &&
    !target.startsWith("./") &&
    !target.startsWith("../") &&
    !parseScpGitUrl(target, cwd)
  );
}

/** 读取命名远端自身的单一显式 LFS 覆盖配置（严格按 `git-lfs` 优先级返回首位命中；`.lfsconfig` 仅允许 `remote.<name>.lfsurl`）。 */
async function resolveNamedRemoteLfsOverrides(
  cwd: string,
  remote: string,
  mode: "push" | "fetch",
  opts?: GitRunOpts,
): Promise<string[]> {
  if (!looksLikeRemoteName(cwd, remote)) return [];
  const specs =
    mode === "push"
      ? [
          { key: `remote.${remote}.lfspushurl`, allowLfsConfig: false },
          { key: `remote.${remote}.lfsurl`, allowLfsConfig: true },
        ]
      : [{ key: `remote.${remote}.lfsurl`, allowLfsConfig: true }];
  const selected = await readFirstLfsEndpointKey(cwd, specs, opts);
  return selected ? [selected] : [];
}

/**
 * 按 `git-lfs` 实际端点优先级解析唯一生效的 LFS 传输端点 URL：
 *   - push：`lfs.pushurl` > `lfs.url` > `remote.<target>.lfspushurl`（仅受信任 Git 配置）> `remote.<target>.lfsurl`；
 *   - fetch：`lfs.url` > `remote.<target>.lfsurl`；
 * 仅返回本次传输真正选中的单个端点，避免在独立下载/上传镜像配置下为未被选中的下载主机授权凭据或可写挂载。
 */
async function resolveEffectiveLfsUrls(
  cwd: string,
  spec: { mode: "push" | "fetch"; target?: string },
  baseUrls: Iterable<string>,
  opts?: GitRunOpts,
): Promise<string[]> {
  const keySpecs: { key: string; allowLfsConfig: boolean }[] = [];
  if (spec.mode === "push") {
    keySpecs.push({ key: "lfs.pushurl", allowLfsConfig: true });
  }
  keySpecs.push({ key: "lfs.url", allowLfsConfig: true });
  if (looksLikeRemoteName(cwd, spec.target)) {
    if (spec.mode === "push") {
      keySpecs.push({ key: `remote.${spec.target}.lfspushurl`, allowLfsConfig: false });
    }
    keySpecs.push({ key: `remote.${spec.target}.lfsurl`, allowLfsConfig: true });
  }

  const selected = await readFirstLfsEndpointKey(cwd, keySpecs, opts);
  if (!selected) return [];

  const baseHttpUrl = [...baseUrls].find((u) => /^https?:\/\//i.test(u.trim()));
  if (
    /^[a-z][a-z0-9+.-]*:\/\//i.test(selected) ||
    selected.startsWith("/") ||
    selected.startsWith("./") ||
    selected.startsWith("../") ||
    parseScpGitUrl(selected, cwd)
  ) {
    return [selected];
  }
  if (baseHttpUrl) {
    try {
      return [new URL(selected, baseHttpUrl.endsWith("/") ? baseHttpUrl : `${baseHttpUrl}/`).href];
    } catch {
      return [];
    }
  }
  return [];
}

async function resolveEffectiveRemoteUrls(
  cwd: string,
  args: string[],
  opts?: GitRunOpts,
): Promise<string[]> {
  if (!REMOTE_GIT_SUBCMDS.has(args[0] ?? "")) return [];
  const spec = extractRemoteTargetSpec(args);
  const rawUrls = new Set<string>(spec.explicitUrls);
  if (spec.target && spec.target !== "." && spec.target !== "..") {
    const looksLikeUrlOrPath =
      /^[a-z][a-z0-9+.-]*:\/\//i.test(spec.target) ||
      spec.target.startsWith("/") ||
      spec.target.startsWith("./") ||
      spec.target.startsWith("../") ||
      !!parseScpGitUrl(spec.target, cwd);
    if (looksLikeUrlOrPath) {
      rawUrls.add(spec.target);
    } else {
      const getUrlArgs =
        spec.mode === "push"
          ? ["remote", "get-url", "--push", "--all", spec.target]
          : ["remote", "get-url", "--all", spec.target];
      const r = await tryGit(cwd, getUrlArgs, { ...opts, readOnly: true });
      if (r.code === 0) {
        for (const line of r.stdout.split("\n")) {
          const u = line.trim();
          if (u) rawUrls.add(u);
        }
      }
    }
  }
  if (args[0] === "lfs") {
    const lfsUrls = await resolveEffectiveLfsUrls(cwd, spec, rawUrls, opts);
    // 当显式 LFS 端点覆盖生效时，git-lfs 仅访问该选中端点，绝不继续为被覆盖的 Git 远端或下载镜像授凭据
    if (lfsUrls.length > 0) return lfsUrls;
  }
  return [...rawUrls];
}

interface HostCredentialState {
  protocol: string;
  host: string;
  path?: string;
  username?: string;
  password?: string;
  authtype?: string;
  credential?: string;
  oauthRefreshToken?: string;
  passwordExpiryUtc?: string;
  ephemeral?: boolean;
  quit?: boolean;
}

function isCredentialExpiryExpired(rawExpiry?: string, nowSec = Math.floor(Date.now() / 1000)): boolean {
  const s = (rawExpiry ?? "").trim();
  if (!s || !/^\d+$/.test(s)) return false;
  const n = Number(s);
  return Number.isFinite(n) && n <= nowSec;
}

function isHostCredentialComplete(state: HostCredentialState): boolean {
  if (state.quit) return true;
  if (isCredentialExpiryExpired(state.passwordExpiryUtc)) return false;
  return (
    (!!state.username && state.password !== undefined && state.password !== "") ||
    (!!state.authtype && !!state.credential)
  );
}

function buildGitCredentialHelperShellCommand(helperValue: string): string {
  const hv = helperValue.trim();
  if (hv.startsWith("!")) return `${hv.slice(1)} get`;
  const firstToken = hv.split(/\s+/)[0] ?? "";
  if (firstToken.includes("/")) return `${hv} get`;
  return `git credential-${hv} get`;
}

function shSingleQuote(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

/**
 * 在受信任宿主机上下文中按 Git `credential_do(helper, "get")` 协议调用单个 global/system 配置的非 store helper，
 * 协商 `capability[]=authtype`、传入已解码的 `path` 与当前累积的部分凭据字段并把输出合并回状态，
 * 允许跨多个 helper 串联补全 `username` + `password` 或 `authtype` + `credential`，并在认证已完整或返回 `quit=1` 时立即停止调用后续 helper。
 */
async function invokeSingleHostCredentialHelper(
  helperValue: string,
  state: HostCredentialState,
  useHttpPath: boolean,
  rawEnv: NodeJS.ProcessEnv,
): Promise<HostCredentialState> {
  const hostPrep = prepareHarnessEnv(rawEnv, { preserveDbusSession: true });
  try {
    const hostEnv: NodeJS.ProcessEnv = {
      ...hostPrep.env,
      GIT_TERMINAL_PROMPT: "0",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
    };
    const lines = ["capability[]=authtype", `protocol=${state.protocol}`, `host=${state.host}`];
    if (useHttpPath && state.path) lines.push(`path=${state.path}`);
    if (state.username) lines.push(`username=${state.username}`);
    if (state.password) lines.push(`password=${state.password}`);
    if (state.oauthRefreshToken) lines.push(`oauth_refresh_token=${state.oauthRefreshToken}`);
    const input = `${lines.join("\n")}\n\n`;
    const r = await runProcess("/bin/sh", ["-c", buildGitCredentialHelperShellCommand(helperValue)], {
      cwd: os.tmpdir(),
      env: hostEnv,
      input,
      timeoutMs: 10_000,
      group: true,
    });
    if (r.code !== 0 || r.timedOut) return state;
    const next: HostCredentialState = { ...state };
    for (const rawLine of r.stdout.split(/\r?\n/)) {
      if (!rawLine) break;
      const eq = rawLine.indexOf("=");
      if (eq <= 0) continue;
      const k = rawLine.slice(0, eq).trim();
      const v = rawLine.slice(eq + 1);
      if (k === "protocol") next.protocol = v.trim() || next.protocol;
      else if (k === "host") next.host = v.trim() || next.host;
      else if (k === "path") next.path = v.replace(/^\/+|\/+$/g, "") || undefined;
      else if (k === "username") next.username = v || undefined;
      else if (k === "password") next.password = v || undefined;
      else if (k === "authtype") next.authtype = v || undefined;
      else if (k === "credential") next.credential = v || undefined;
      else if (k === "oauth_refresh_token") next.oauthRefreshToken = v || undefined;
      else if (k === "password_expiry_utc") next.passwordExpiryUtc = v.trim() || undefined;
      else if (k === "ephemeral") {
        const e = v.trim().toLowerCase();
        next.ephemeral = e === "1" || e === "true" || e === "yes" || e === "on";
      } else if (k === "quit") {
        const q = v.trim().toLowerCase();
        next.quit = q === "1" || q === "true" || q === "yes" || q === "on";
      } else if (k === "url" && v.trim()) {
        const u = parseHttpUrlSafe(v.trim());
        if (u) {
          next.protocol = u.protocol.slice(0, -1);
          next.host = u.host;
          const p = decodeCredPath(u.pathname);
          if (p) next.path = p;
          if (u.username) next.username = decodeUrlUser(u.username);
          if (u.password) next.password = decodeUrlUser(u.password);
        }
      }
    }
    // 对齐 Git credential_read：若 helper 返回的凭据已达 password_expiry_utc 过期时间，丢弃过期密钥（保留 username / oauth_refresh_token）以便后续 helper 续签或提供新凭据
    if (isCredentialExpiryExpired(next.passwordExpiryUtc)) {
      delete next.password;
      delete next.credential;
      delete next.authtype;
      delete next.passwordExpiryUtc;
    }
    return next;
  } finally {
    hostPrep.cleanup();
  }
}

function formatCredentialStoreLine(state: HostCredentialState, target: URL, useHttpPath: boolean): string | undefined {
  if (state.username === undefined || state.password === undefined || (!state.username && !state.password)) {
    return undefined;
  }
  const outProto = (state.protocol || target.protocol.slice(0, -1)).trim();
  const outHost = (state.host || target.host).trim();
  const rawPath = useHttpPath ? (state.path ?? decodeCredPath(target.pathname)) : "";
  const encodedPath = rawPath ? encodeCredPathForStoreUrl(rawPath) : "";
  const pathSuffix = encodedPath ? `/${encodedPath}` : "";
  return `${outProto}://${encodeURIComponent(state.username)}:${encodeURIComponent(state.password)}@${outHost}${pathSuffix}`;
}

/**
 * 在受限秘密目录中写入作用域限定的静态凭据响应脚本（0700）与只读响应体（0600），
 * 用于在隔离沙箱内原位保留宿主机 helper 的 `quit=1` 决策或 `authtype` + `credential`（如 Bearer 令牌），
 * 载荷绝不进入脚本代码或进程参数，并严格校验 protocol / host / 可选 path / 可选 username。
 */
export function writeScopedStaticCredentialHelper(
  dir: string,
  seq: number,
  match: {
    protocol: string;
    hostname: string;
    port: string;
    useHttpPath: boolean;
    decodedPath?: string;
    expectedUsername?: string;
    rejectNonEmptyUser?: boolean;
  },
  responseLines: string[],
): string {
  const safeLines = responseLines.filter((l) => l.length > 0 && !/[\r\n\0]/.test(l));
  const payloadFile = path.join(dir, `helper-resp-${seq}.out`);
  fs.writeFileSync(payloadFile, `${safeLines.join("\n")}\n`, { mode: 0o600 });

  const hostLower = match.hostname.toLowerCase();
  const defPort = defaultPortForProtocol(`${match.protocol}:`);
  const acceptedHosts = new Set<string>();
  if (match.port) {
    acceptedHosts.add(`${hostLower}:${match.port}`);
    if (match.port === defPort) acceptedHosts.add(hostLower);
  } else {
    acceptedHosts.add(hostLower);
    if (defPort) acceptedHosts.add(`${hostLower}:${defPort}`);
  }
  const hostChecks = [...acceptedHosts].map((h) => `[ "$host_lc" = ${shSingleQuote(h)} ]`).join(" || ");

  const scriptLines = [
    "#!/bin/sh",
    '[ "$1" = "get" ] || exit 0',
    'proto=""',
    'host=""',
    'cpath=""',
    'user=""',
    "while IFS= read -r line; do",
    '  [ -z "$line" ] && break',
    '  case "$line" in',
    '    protocol=*) proto="${line#protocol=}" ;;',
    '    host=*) host="${line#host=}" ;;',
    '    path=*) cpath="${line#path=}" ;;',
    '    username=*) user="${line#username=}" ;;',
    "  esac",
    "done",
    `[ "$proto" = ${shSingleQuote(match.protocol)} ] || exit 0`,
    "host_lc=$(printf '%s' \"$host\" | tr 'A-Z' 'a-z')",
    `{ ${hostChecks}; } || exit 0`,
  ];
  if (match.useHttpPath && match.decodedPath) {
    scriptLines.push(
      'while [ "${cpath#/}" != "$cpath" ]; do cpath="${cpath#/}"; done',
      'while [ "${cpath%/}" != "$cpath" ]; do cpath="${cpath%/}"; done',
      `[ "$cpath" = ${shSingleQuote(match.decodedPath)} ] || exit 0`,
    );
  }
  if (match.expectedUsername) {
    scriptLines.push(`[ "$user" = ${shSingleQuote(match.expectedUsername)} ] || exit 0`);
  } else if (match.rejectNonEmptyUser) {
    scriptLines.push('[ -z "$user" ] || exit 0');
  }
  scriptLines.push(
    'while IFS= read -r out_line || [ -n "$out_line" ]; do',
    "  printf '%s\\n' \"$out_line\"",
    `done < ${shSingleQuote(payloadFile)}`,
  );

  const scriptFile = path.join(dir, `helper-resp-${seq}.sh`);
  // 以 0600 写入并经受信任 /bin/sh 解释执行，避免 /dev/shm 等 tmpfs 挂载 noexec 时直接执行脚本报 EACCES
  fs.writeFileSync(scriptFile, `${scriptLines.join("\n")}\n`, { mode: 0o600 });
  const shBin = resolveTrustedSystemBin("sh") ?? "/bin/sh";
  return `!${shSingleQuote(shBin)} ${shSingleQuote(scriptFile)}`;
}

/** 构造 Git `credential.<url>.*` 配置段精确作用域 URL（始终保留完整路径，因为即使 useHttpPath=false，Git 仍按完整远端 URL 匹配 path-scoped 配置段） */
function targetCredentialConfigUrl(t: URL): string {
  const userPart = t.username ? `${t.username}@` : "";
  const normPath = normalizeCredPath(t.pathname);
  return `${t.protocol}//${userPart}${t.host}${normPath}`;
}

function isCompleteStoreCredentialLine(line: string): boolean {
  const m = line.trim().match(/^https?:\/\/([^/@]+)@/i);
  if (!m) return false;
  return m[1].includes(":");
}

/**
 * 仅为处于沙箱隔离下的受信任远程 Git HTTP(S) 操作投影目标域作用域内的凭据：
 *   - 对每个目标 URL 按原始配置顺序跨节重放全部匹配项（含空值 `credential.<url>.helper=` 跨节重置，完全对齐 Git `credential_config_callback`）；
 *   - 跨 helper 保留部分结果（如前一个提供 `username`、后一个提供 `password`），原位保留宿主机 helper 的 `quit=1` 决策与 `authtype`+`credential`（Bearer 令牌）；
 *   - 对每个 `store` 槽位（支持相对 `cwd` 的 `--file`）严格按 `git-credential-store` 语义选取首条有效凭据，绝不把同主机其他账号/路径的令牌一并拷入沙箱；
 *   - 仓库 `local`/`worktree` 自定义 helper 绝不在宿主机执行，原位保留到沙箱内按精确顺序执行。
 */
async function prepareScopedGitHttpCredentials(
  cwd: string,
  httpUrls: string[],
  rawEnv: NodeJS.ProcessEnv,
  opts?: GitRunOpts,
): Promise<ScopedGitHttpCreds | undefined> {
  const targetUrls: URL[] = [];
  for (const u of httpUrls) {
    const parsed = parseHttpUrlSafe(u);
    if (parsed) targetUrls.push(parsed);
  }
  if (targetUrls.length === 0) return undefined;

  const hostHome = rawEnv.HOME?.trim() || os.homedir();
  const xdgConfigHome = rawEnv.XDG_CONFIG_HOME?.trim() || (hostHome ? path.join(hostHome, ".config") : "");
  const defaultStoreFiles = [
    ...(hostHome ? [path.join(hostHome, ".git-credentials")] : []),
    ...(xdgConfigHome ? [path.join(xdgConfigHome, "git", "credentials")] : []),
  ];

  // 读取宿主机/仓库生效的全部 credential.helper 与 credential.<url>.helper（含 --includes、作用域与空值重置，严格保持配置出现顺序）
  const helperCfg = await tryGit(
    cwd,
    ["config", "--includes", "--show-scope", "--null", "--get-regexp", "^credential(\\..+)?\\.helper$"],
    { ...opts, readOnly: true },
  );
  if (helperCfg.code !== 0 || !helperCfg.stdout) return undefined;

  interface RawHelperEntry {
    normKey: string;
    pattern?: string;
    value: string;
    scope: string;
    orderIdx: number;
  }
  const rawHelperEntries: RawHelperEntry[] = [];
  const tokens = helperCfg.stdout.split("\0");
  let orderSeq = 0;
  for (let i = 0; i + 1 < tokens.length; i += 2) {
    const scope = tokens[i].trim();
    const rec = tokens[i + 1];
    if (!rec) continue;
    const nl = rec.indexOf("\n");
    const rawKey = nl === -1 ? rec : rec.slice(0, nl);
    const val = nl === -1 ? "" : rec.slice(nl + 1).trim();
    if (/^credential\.helper$/i.test(rawKey)) {
      rawHelperEntries.push({ normKey: "credential.helper", value: val, scope, orderIdx: orderSeq++ });
    } else {
      const subMatch = rawKey.match(/^credential\.(.+)\.helper$/i);
      if (!subMatch) continue;
      const pattern = subMatch[1];
      rawHelperEntries.push({
        normKey: `credential.${pattern}.helper`,
        pattern,
        value: val,
        scope,
        orderIdx: orderSeq++,
      });
    }
  }
  if (rawHelperEntries.length === 0) return undefined;

  // 检查目标 URL 是否启用 credential.useHttpPath 及 URL 作用域的 credential.<url>.username
  const useHttpPathByTarget = new Map<URL, boolean>();
  const effectiveUsernameByTarget = new Map<URL, string>();
  for (const t of targetUrls) {
    const uhp = await tryGit(cwd, ["config", "--includes", "--bool", "--get-urlmatch", "credential.useHttpPath", t.href], {
      ...opts,
      readOnly: true,
    });
    useHttpPathByTarget.set(t, uhp.code === 0 && uhp.stdout.trim() === "true");
    if (t.username) {
      effectiveUsernameByTarget.set(t, decodeUrlUser(t.username));
    } else {
      const uCfg = await tryGit(cwd, ["config", "--includes", "--get-urlmatch", "credential.username", t.href], {
        ...opts,
        readOnly: true,
      });
      const cfgUser = uCfg.code === 0 ? uCfg.stdout.trim() : "";
      if (cfgUser) effectiveUsernameByTarget.set(t, cfgUser);
    }
  }

  // 按完整目标 URL（含用户名与路径）去重并按从宽到窄排序（无用户名在先、短路径在先），
  // 确保即使 credential.useHttpPath=false，同主机不同路径的 path-scoped helper/username 配置计划仍严格独立，且逐目标重置互不干扰
  const dedupedTargets: { url: URL; scopeUrl: string; useHttpPath: boolean }[] = [];
  const seenScopeUrls = new Set<string>();
  for (const t of targetUrls) {
    const useHttpPath = useHttpPathByTarget.get(t) === true;
    const scopeUrl = targetCredentialConfigUrl(t);
    if (seenScopeUrls.has(scopeUrl)) continue;
    seenScopeUrls.add(scopeUrl);
    dedupedTargets.push({ url: t, scopeUrl, useHttpPath });
  }
  dedupedTargets.sort((a, b) => {
    const userDiff = (a.url.username ? 1 : 0) - (b.url.username ? 1 : 0);
    if (userDiff !== 0) return userDiff;
    const pathLenDiff = normalizeCredPath(a.url.pathname).length - normalizeCredPath(b.url.pathname).length;
    if (pathLenDiff !== 0) return pathLenDiff;
    return a.scopeUrl.localeCompare(b.scopeUrl);
  });

  // 统计同一 (protocol, username, host) 下存在多少个不同路径目标：
  //   - 仅当存在同主机多路径目标或启用 useHttpPath=true 时，将 `-c` 键限定到完整路径，防止同主机多 pushurl 串号；
  //   - 单路径且 useHttpPath=false 时使用主机级键 `credential.<proto>://<user@><host>.helper`，兼容 git-lfs 省略 path 查询 `git credential fill`。
  const hostGroupCount = new Map<string, number>();
  for (const t of dedupedTargets) {
    const hk = `${t.url.protocol}//${t.url.username ? `${t.url.username}@` : ""}${t.url.host}`;
    hostGroupCount.set(hk, (hostGroupCount.get(hk) ?? 0) + 1);
  }
  const emitScopeUrlFor = (t: URL, scopeUrl: string, useHttpPath: boolean): string => {
    const hostScopeUrl = `${t.protocol}//${t.username ? `${t.username}@` : ""}${t.host}`;
    return useHttpPath || (hostGroupCount.get(hostScopeUrl) ?? 0) > 1 ? scopeUrl : hostScopeUrl;
  };

  const dataDir = opts?.cfg?.dataDir;
  const realData = dataDir && fs.existsSync(dataDir) ? fs.realpathSync(dataDir) : "";
  const isOutsideDataDir = (p: string): boolean => {
    if (!realData) return true;
    try {
      const real = fs.realpathSync(p);
      const rel = path.relative(realData, real);
      return rel !== "" && (rel.startsWith("..") || path.isAbsolute(rel));
    } catch {
      return false;
    }
  };

  // 预读 store 文件缓存（避免同一文件对多个目标重复读盘）
  const storeFileLinesCache = new Map<string, string[]>();
  const readStoreFileLines = (file: string): string[] => {
    const cached = storeFileLinesCache.get(file);
    if (cached) return cached;
    const out: string[] = [];
    if (file && fs.existsSync(file) && isOutsideDataDir(file)) {
      try {
        const st = fs.statSync(file);
        if (st.isFile() && st.size <= 4 * 1024 * 1024) {
          for (const rawLine of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
            const line = rawLine.trim();
            if (line && !line.startsWith("#")) out.push(line);
          }
        }
      } catch {
        // ignore unreadable credential file
      }
    }
    storeFileLinesCache.set(file, out);
    return out;
  };

  const findFirstMatchingStoreLine = (
    files: string[],
    target: URL,
    useHttpPath: boolean,
    effectiveUsername?: string,
  ): string | undefined => {
    for (const file of files) {
      for (const line of readStoreFileLines(file)) {
        if (!isCompleteStoreCredentialLine(line)) continue;
        if (gitCredentialLineMatchesTarget(line, target, useHttpPath, effectiveUsername)) {
          return line;
        }
      }
    }
    return undefined;
  };

  type TargetSandboxAction =
    | { kind: "store-line"; prefix: "store" | "helper"; line: string }
    | { kind: "static-responder"; responseLines: string[]; rejectNonEmptyUser: boolean }
    | { kind: "local-helper"; value: string };

  const allMatchingConfigKeys = new Set<string>();
  const localKeysToClear = new Set<string>();
  let anyHostManaged = false;
  const extraUsernameArgs: string[] = [];
  const seenUsernameArgs = new Set<string>();
  const planByTarget: {
    url: URL;
    scopeUrl: string;
    useHttpPath: boolean;
    initialUser: string;
    actions: TargetSandboxAction[];
  }[] = [];

  for (const { url: t, scopeUrl, useHttpPath } of dedupedTargets) {
    // 严格按 Git 出现顺序跨节重放所有适用于该目标的 helper 配置项（空值 `credential.<url>.helper=` 清除此前全部通用/特化 helper）
    const activeForTarget: RawHelperEntry[] = [];
    let sawHostManagedForTarget = false;
    for (const entry of rawHelperEntries) {
      const matches = entry.pattern === undefined || gitCredentialSectionMatchesUrl(entry.pattern, t);
      if (!matches) continue;
      allMatchingConfigKeys.add(entry.normKey);
      if (entry.scope === "local" || entry.scope === "worktree") {
        localKeysToClear.add(entry.normKey);
      }
      if (!entry.value) {
        activeForTarget.length = 0;
        continue;
      }
      activeForTarget.push(entry);
    }

    const initialUser = effectiveUsernameByTarget.get(t) || "";
    const decodedTargetPath = useHttpPath ? decodeCredPath(t.pathname) || undefined : undefined;
    let state: HostCredentialState = {
      protocol: t.protocol.slice(0, -1),
      host: t.host,
      path: decodedTargetPath,
      username: initialUser || undefined,
    };

    const actions: TargetSandboxAction[] = [];
    let encounteredLocalHelper = false;
    for (const entry of activeForTarget) {
      const parsed = parseStoreHelperFile(entry.value, hostHome, cwd);
      if (parsed.isStore) {
        sawHostManagedForTarget = true;
        const filesForSlot = parsed.explicitFile ? [parsed.explicitFile] : defaultStoreFiles;
        const matchedLine = findFirstMatchingStoreLine(filesForSlot, t, useHttpPath, state.username);
        if (matchedLine) {
          actions.push({ kind: "store-line", prefix: "store", line: matchedLine });
          const matchedUrl = parseHttpUrlSafe(matchedLine);
          if (matchedUrl) {
            if (matchedUrl.username) state.username = decodeUrlUser(matchedUrl.username);
            if (matchedUrl.password) state.password = decodeUrlUser(matchedUrl.password);
          }
          if (!encounteredLocalHelper && isHostCredentialComplete(state)) {
            break;
          }
        }
      } else if (entry.scope === "global" || entry.scope === "system") {
        sawHostManagedForTarget = true;
        state = await invokeSingleHostCredentialHelper(entry.value, state, useHttpPath, rawEnv);
        if (state.quit) {
          // 原位保留宿主机 helper 的 quit=1 决策，确保沙箱内 Git 在同一槽位立即中止而绝不继续执行后续仓库本地 helper
          actions.push({
            kind: "static-responder",
            responseLines: ["quit=1"],
            rejectNonEmptyUser: !encounteredLocalHelper && !initialUser,
          });
          break;
        }
        if (isHostCredentialComplete(state)) {
          if (state.authtype && state.credential) {
            const respLines = [
              "capability[]=authtype",
              `authtype=${state.authtype}`,
              `credential=${state.credential}`,
              ...(state.username ? [`username=${state.username}`] : []),
              ...(state.oauthRefreshToken ? [`oauth_refresh_token=${state.oauthRefreshToken}`] : []),
              ...(state.passwordExpiryUtc ? [`password_expiry_utc=${state.passwordExpiryUtc}`] : []),
              ...(state.ephemeral ? ["ephemeral=1"] : []),
            ];
            actions.push({
              kind: "static-responder",
              responseLines: respLines,
              rejectNonEmptyUser: !encounteredLocalHelper && !initialUser,
            });
          } else {
            const line = formatCredentialStoreLine(state, t, useHttpPath);
            if (line) {
              actions.push({ kind: "store-line", prefix: "helper", line });
            }
          }
          if (!encounteredLocalHelper) break;
        }
      } else {
        // 仓库 local/worktree 作用域自定义 helper 不在宿主机执行，保留到沙箱；若前面宿主机 helper 已提供部分 username，则透传给沙箱
        encounteredLocalHelper = true;
        if (state.username && state.username !== initialUser && !t.username) {
          const arg = `credential.${emitScopeUrlFor(t, scopeUrl, useHttpPath)}.username=${state.username}`;
          if (!seenUsernameArgs.has(arg)) {
            seenUsernameArgs.add(arg);
            extraUsernameArgs.push("-c", arg);
          }
        }
        actions.push({ kind: "local-helper", value: entry.value });
      }
    }

    if (sawHostManagedForTarget) anyHostManaged = true;
    planByTarget.push({ url: t, scopeUrl, useHttpPath, initialUser, actions });
  }

  if (allMatchingConfigKeys.size === 0 || !anyHostManaged) {
    return undefined;
  }

  let scoped: { dir: string; cleanup: () => void } | undefined;
  let fileSeq = 0;
  let wroteAnyStagedFile = false;
  const gitConfigArgs: string[] = [];

  try {
    // 1) 清空所有命中过的原始键（含通用 credential.helper 与按 URL 特化的键），消除任何宿主机/本地跨节残留顺序干扰
    for (const key of allMatchingConfigKeys) {
      gitConfigArgs.push("-c", `${key}=`);
    }

    // 2) 按从宽到窄的目标作用域逐一重置并写入精确重放后的沙箱 helper 链
    for (const plan of planByTarget) {
      const targetKey = `credential.${emitScopeUrlFor(plan.url, plan.scopeUrl, plan.useHttpPath)}.helper`;
      // 显式清空更宽作用域目标可能继承下来的 helper，隔离同主机多用户/多路径目标
      gitConfigArgs.push("-c", `${targetKey}=`);
      const decodedPath = plan.useHttpPath ? decodeCredPath(plan.url.pathname) || undefined : undefined;
      for (const act of plan.actions) {
        if (act.kind === "store-line") {
          scoped ??= createScopedSecretDir("pa-git-http-cred-", rawEnv);
          const slotFile = path.join(scoped.dir, `${act.prefix}-${fileSeq++}.creds`);
          fs.writeFileSync(slotFile, `${act.line}\n`, { mode: 0o600 });
          gitConfigArgs.push("-c", `${targetKey}=store --file=${slotFile}`);
          wroteAnyStagedFile = true;
        } else if (act.kind === "static-responder") {
          scoped ??= createScopedSecretDir("pa-git-http-cred-", rawEnv);
          const helperCmd = writeScopedStaticCredentialHelper(
            scoped.dir,
            fileSeq++,
            {
              protocol: plan.url.protocol.slice(0, -1),
              hostname: plan.url.hostname,
              port: plan.url.port,
              useHttpPath: plan.useHttpPath,
              decodedPath,
              expectedUsername: plan.initialUser || undefined,
              rejectNonEmptyUser: act.rejectNonEmptyUser,
            },
            act.responseLines,
          );
          gitConfigArgs.push("-c", `${targetKey}=${helperCmd}`);
          wroteAnyStagedFile = true;
        } else {
          gitConfigArgs.push("-c", `${targetKey}=${act.value}`);
        }
      }
    }

    gitConfigArgs.push(...extraUsernameArgs);

    if (!wroteAnyStagedFile && localKeysToClear.size === 0 && extraUsernameArgs.length === 0) {
      scoped?.cleanup();
      return undefined;
    }

    return {
      ...(scoped ? { credDir: scoped.dir } : {}),
      gitConfigArgs,
      cleanup: () => scoped?.cleanup(),
    };
  } catch (err) {
    scoped?.cleanup();
    throw err;
  }
}

export async function tryGit(cwd: string, args: string[], opts?: GitRunOpts): Promise<ProcResult> {
  const isRemote = REMOTE_GIT_SUBCMDS.has(args[0] ?? "");
  // 仅纯只读配置/URL 探测需要读取宿主机完整全局 Git 配置（尊重 GIT_CONFIG_GLOBAL）；
  // 所有其他本地操作（add/commit/checkout/worktree 等）与远程操作均使用脱敏后的全局配置，防止 clean/smudge 过滤器读取无关域的 http.extraHeader。
  const isConfigLookup = args[0] === "config" || (args[0] === "remote" && args[1] === "get-url");
  const shouldSanitizeGitCfg = !isConfigLookup;
  const effectiveRawEnv: NodeJS.ProcessEnv = opts?.extraEnv
    ? { ...process.env, ...opts.extraEnv }
    : process.env;
  const resolvedUrls = isRemote ? await resolveEffectiveRemoteUrls(cwd, args, opts) : [];
  const sshUrls = resolvedUrls.filter((u) => classifyGitRemoteTransport(cwd, u) === "ssh");
  const httpUrls = resolvedUrls.filter((u) => classifyGitRemoteTransport(cwd, u) === "http");
  const usesSsh = sshUrls.length > 0;
  const sshSock = usesSsh
    ? resolveAuthorizedSshAuthSock(args, effectiveRawEnv, opts?.cfg?.dataDir)
    : opts?.allowCommitSigningSshSock
      ? resolveValidatedSshAuthSock(effectiveRawEnv, opts?.cfg?.dataDir)
      : undefined;
  const baseEnv = prepareHarnessEnv(process.env, { preserveSshAgent: !!sshSock });
  let scopedHttpCreds: ScopedGitHttpCreds | undefined;
  let stagedGitCfg: StagedSanitizedGitConfig | undefined;
  try {
    const sshTargets: SshRemoteTarget[] = [];
    const seenSshTarget = new Set<string>();
    for (const u of sshUrls) {
      const t = extractSshTarget(u, cwd);
      if (!t) continue;
      const key = `${t.user ?? ""}@${t.host}:${t.port ?? ""}`;
      if (seenSshTarget.has(key)) continue;
      seenSshTarget.add(key);
      sshTargets.push(t);
    }
    const sshMounts = usesSsh
      ? collectScopedSshMounts(sshTargets, effectiveRawEnv, opts?.cfg?.dataDir, sshSock ?? false)
      : undefined;
    const baseIsoPlan = buildGitIsolation(
      cwd,
      opts,
      baseEnv.env.CREDENTIALS_DIRECTORY,
      sshSock,
      sshMounts,
      effectiveRawEnv,
      shouldSanitizeGitCfg,
    );
    const willIsolate = willIsolateCommand(effectiveRawEnv, baseIsoPlan);
    const remoteSpec = isRemote ? extractRemoteTargetSpec(args) : undefined;
    const allowedRemoteNames =
      remoteSpec?.target &&
      !remoteSpec.target.includes("://") &&
      !/^[./~]/.test(remoteSpec.target) &&
      !parseScpGitUrl(remoteSpec.target, cwd) &&
      !fs.existsSync(path.resolve(cwd, remoteSpec.target))
        ? [remoteSpec.target]
        : [];
    if (willIsolate && shouldSanitizeGitCfg) {
      stagedGitCfg = stageSanitizedGitConfig(effectiveRawEnv, opts?.cfg?.dataDir, {
        cwd,
        ...(isRemote ? { allowedRemoteUrls: resolvedUrls, allowedRemoteNames } : {}),
      });
    }
    // 仅在启用文件系统隔离且目标为 HTTP(S) 传输时投影目标域凭据，非隔离运行保持宿主机 credential.helper 链原样
    if (willIsolate && httpUrls.length > 0) {
      scopedHttpCreds = await prepareScopedGitHttpCredentials(cwd, httpUrls, effectiveRawEnv, opts);
    }
    const safeSubArgs = args[0] === "diff" ? ["diff", "--no-ext-diff", ...args.slice(1)] : args;
    const childEnv: NodeJS.ProcessEnv = {
      ...baseEnv.env,
      ...(opts?.extraEnv ?? {}),
      GIT_TERMINAL_PROMPT: "0",
      ...(sshSock ? { SSH_AUTH_SOCK: sshSock } : {}),
    };
    delete childEnv.GIT_EXTERNAL_DIFF;
    if (shouldSanitizeGitCfg) {
      applySanitizedGitConfigEnv(childEnv, stagedGitCfg, willIsolate);
    }
    const extraRo = [
      ...(opts?.extraReadOnlyPaths ?? []),
      ...(scopedHttpCreds?.credDir ? [scopedHttpCreds.credDir] : []),
      ...(stagedGitCfg ? [stagedGitCfg.dir, ...stagedGitCfg.extraReadOnlyPaths] : []),
    ];
    const extraSymlinks = [
      ...(opts?.extraSymlinks ?? []),
      ...(stagedGitCfg ? stagedGitCfg.symlinks : []),
    ];
    const effectiveOpts: GitRunOpts | undefined =
      scopedHttpCreds || stagedGitCfg
        ? {
            ...opts,
            extraReadOnlyPaths: extraRo,
            ...(extraSymlinks.length ? { extraSymlinks } : {}),
          }
        : opts;
    const wrapped = wrapCredentialIsolatedCommand(
      "git",
      [
        "-C",
        cwd,
        ...GIT_SAFE_ARGS,
        ...(opts?.extraGitConfigArgs ?? []),
        ...(scopedHttpCreds?.gitConfigArgs ?? []),
        ...safeSubArgs,
      ],
      effectiveRawEnv,
      buildGitIsolation(
        cwd,
        effectiveOpts,
        baseEnv.env.CREDENTIALS_DIRECTORY,
        sshSock,
        sshMounts,
        effectiveRawEnv,
        shouldSanitizeGitCfg,
        stagedGitCfg?.bindMounts,
      ),
    );
    return await runProcess(wrapped.cmd, wrapped.args, {
      env: childEnv,
      input: opts?.input,
      timeoutMs: opts?.timeoutMs ?? 300_000,
      group: true,
    });
  } finally {
    stagedGitCfg?.cleanup();
    scopedHttpCreds?.cleanup();
    baseEnv.cleanup();
  }
}

export async function git(cwd: string, args: string[], opts?: GitRunOpts): Promise<string> {
  const r = await tryGit(cwd, args, opts);
  if (r.code !== 0) throw new Error(`git ${args.join(" ")} 失败：${(r.stderr || r.stdout).trim()}`);
  return r.stdout;
}

/**
 * 仅在宿主机确认目标工作树缺失或尚未完成检出（不含 `.git`）且未被 `git worktree lock` 锁定时，
 * 定向清理该单一目标路径对应的失效 `.git/worktrees/<name>` 管理记录；
 * 绝不调用全局 `git worktree prune`，避免在隔离沙箱看不到同级派单目录时误删其他在途工作树的有效注册记录。
 */
export async function removeStaleWorktreeAdminRecord(
  repoPath: string,
  targetWtDir: string,
  gitOpts: Pick<GitRunOpts, "cfg" | "trustedRepoRoot">,
): Promise<{ removed: boolean; locked: boolean }> {
  if (fs.existsSync(path.join(targetWtDir, ".git"))) {
    return { removed: false, locked: false };
  }
  const commonRes = await tryGit(repoPath, ["rev-parse", "--path-format=absolute", "--git-common-dir"], {
    ...gitOpts,
    readOnly: true,
  });
  let commonGitDir = commonRes.code === 0 ? commonRes.stdout.trim() : "";
  if (!commonGitDir) {
    const fallbackRes = await tryGit(repoPath, ["rev-parse", "--git-common-dir"], { ...gitOpts, readOnly: true });
    if (fallbackRes.code !== 0 || !fallbackRes.stdout.trim()) return { removed: false, locked: false };
    commonGitDir = path.resolve(repoPath, fallbackRes.stdout.trim());
  }
  const wtAdminRoot = path.join(commonGitDir, "worktrees");
  if (!fs.existsSync(wtAdminRoot)) return { removed: false, locked: false };

  const normalizePath = (p: string): string => {
    const abs = path.resolve(p);
    if (fs.existsSync(abs)) {
      try {
        return fs.realpathSync(abs);
      } catch {
        return abs;
      }
    }
    const parent = path.dirname(abs);
    if (parent !== abs && fs.existsSync(parent)) {
      try {
        return path.join(fs.realpathSync(parent), path.basename(abs));
      } catch {
        return abs;
      }
    }
    return abs;
  };

  const targetPaths = new Set([path.resolve(targetWtDir), normalizePath(targetWtDir)]);
  let removedAny = false;
  let lockedAny = false;
  for (const ent of fs.readdirSync(wtAdminRoot, { withFileTypes: true })) {
    if (!ent.isDirectory() || ent.isSymbolicLink()) continue;
    const entryDir = path.join(wtAdminRoot, ent.name);
    const gitdirFile = path.join(entryDir, "gitdir");
    if (!fs.existsSync(gitdirFile)) continue;
    try {
      const raw = fs.readFileSync(gitdirFile, "utf8").trim();
      if (!raw) continue;
      const resolvedGitFile = path.resolve(entryDir, raw);
      const wtDir = path.dirname(resolvedGitFile);
      if (targetPaths.has(path.resolve(wtDir)) || targetPaths.has(normalizePath(wtDir))) {
        if (fs.existsSync(path.join(entryDir, "locked"))) {
          lockedAny = true;
          continue;
        }
        fs.rmSync(entryDir, { recursive: true, force: true });
        removedAny = true;
      }
    } catch {
      // 忽略无法读取的无关记录
    }
  }
  return { removed: removedAny, locked: lockedAny };
}

function isSshPrivateKeyEncrypted(filePath: string): boolean {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    if (raw.includes("ENCRYPTED")) return true;
    const m = raw.match(/-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----/);
    if (!m) return false;
    const buf = Buffer.from(m[1].replace(/\s+/g, ""), "base64");
    const magic = Buffer.from("openssh-key-v1\0", "ascii");
    if (buf.length < magic.length + 4 || !buf.subarray(0, magic.length).equals(magic)) return true;
    const cipherLen = buf.readUInt32BE(magic.length);
    if (cipherLen === 0 || magic.length + 4 + cipherLen > buf.length) return true;
    const cipher = buf.subarray(magic.length + 4, magic.length + 4 + cipherLen).toString("ascii");
    return cipher !== "none";
  } catch {
    return true;
  }
}

/**
 * 按 Git 官方 `--type=bool` 布尔语义解析仓库/工作树作用域（`local` 与 `worktree`，完整展开仓库内 `[include]`/`[includeIf]`）的生效 `commit.gpgSign` 策略：
 *   - 正确区分显式置空 `commit.gpgSign =`（`false`）与无值声明 `commit.gpgSign`（`true`）；
 *   - 刻意忽略宿主机 `global` / `system` 作用域，避免用户个人全局签名默认值阻断隔离代理提交。
 */
async function resolveRepoOrWorktreeGpgSign(cwd: string, roOpts: GitRunOpts): Promise<boolean> {
  const res = await tryGit(
    cwd,
    ["config", "--includes", "--type=bool", "--show-scope", "--null", "--get-all", "commit.gpgSign"],
    roOpts,
  );
  if (res.code === 0 && res.stdout) {
    const tokens = res.stdout.split("\0");
    let effective: boolean | undefined;
    for (let i = 0; i + 1 < tokens.length; i += 2) {
      const scope = tokens[i];
      const val = tokens[i + 1].trim().toLowerCase();
      if (scope !== "local" && scope !== "worktree") continue;
      if (val === "true") effective = true;
      else if (val === "false") effective = false;
    }
    return effective === true;
  }
  // 若配置文件中存在非法布尔值导致 `--type=bool` 返回非 0（如 exit 128），仅当仓库自身 local/worktree 作用域存在该键时 fail-closed 交由 git commit 报错
  if (res.code !== 1) {
    const rawRes = await tryGit(cwd, ["config", "--includes", "--show-scope", "--null", "--get-all", "commit.gpgSign"], roOpts);
    if (rawRes.code === 0 && rawRes.stdout) {
      const tokens = rawRes.stdout.split("\0");
      let effective: boolean | undefined;
      for (let i = 0; i + 1 < tokens.length; i += 2) {
        const scope = tokens[i];
        const val = tokens[i + 1].trim().toLowerCase();
        if (scope !== "local" && scope !== "worktree") continue;
        if (val === "true" || val === "yes" || val === "on") effective = true;
        else if (val === "" || val === "false" || val === "no" || val === "off") effective = false;
        else if (/^[+-]?\d+$/.test(val)) effective = Number(val) !== 0;
        else effective = true;
      }
      return effective === true;
    }
  }
  return false;
}

/**
 * 有改动就提交（含新文件）；没有改动什么都不做。返回是否提交了。
 *   - 暂存（`git add -A`）时同步挂载受信任本地配置指定的外部 `lfs.storage` 缓存目录，确保修改 LFS 文件时 clean filter 可写入共享缓存；
 *   - 仅当仓库本地 `.git/config`、其 `[include]`/`[includeIf]` 或工作树配置 `config.worktree` 显式要求 `commit.gpgSign=true` 时才保留提交签名策略（支持窄范围 SSH 签名密钥挂载；非 SSH 路径同样显式传递 `-c commit.gpgSign=true` 杜绝外部 include 不可见时静默产出未签名提交）；
 *   - 其余场景（例如宿主机全局 `~/.gitconfig` 设置了个人 `commit.gpgSign=true`）显式使用 `--no-gpg-sign` 执行无签名代理提交，
 *     与 `personal-agent` 提交身份及 `--no-verify` 保持一致，避免沙箱隐藏宿主机签名代理导致自动提交失败。
 */
/**
 * 解析仓库受信任本地配置指定的外部 `lfs.storage` 共享缓存目录，并在存在外部缓存时返回附带可写挂载与 `-c lfs.storage=...` 的 `GitRunOpts`：
 * 供 `commitAll`（clean filter）、`mergeLocal`（快进合并 smudge）、`Dispatcher.execute`（`reset --hard` 恢复检查点 smudge）共享。
 */
export async function resolveExternalLfsStorageGitOpts(
  cwd: string,
  opts?: GitRunOpts,
): Promise<GitRunOpts | undefined> {
  const roOpts: GitRunOpts = { ...opts, readOnly: true };
  const commonRes = await tryGit(cwd, ["rev-parse", "--path-format=absolute", "--git-common-dir"], roOpts);
  let commonGitDir = commonRes.code === 0 ? commonRes.stdout.trim() : "";
  if (!commonGitDir) {
    const fb = await tryGit(cwd, ["rev-parse", "--git-common-dir"], roOpts);
    if (fb.code === 0 && fb.stdout.trim()) commonGitDir = path.resolve(cwd, fb.stdout.trim());
  }
  if (!commonGitDir) return opts;
  const lfsStorage = await resolveEffectiveLfsStorageDir(cwd, commonGitDir, roOpts);
  if (!lfsStorage.isExternal) return opts;
  fs.mkdirSync(lfsStorage.storageDir, { recursive: true });
  return {
    ...opts,
    extraWritablePaths: [...new Set([...(opts?.extraWritablePaths ?? []), lfsStorage.storageDir])],
    extraGitConfigArgs: [...(opts?.extraGitConfigArgs ?? []), "-c", `lfs.storage=${lfsStorage.storageDir}`],
  };
}

export async function commitAll(cwd: string, message: string, opts?: GitRunOpts): Promise<boolean> {
  const roOpts: GitRunOpts = { ...opts, readOnly: true };
  const addOpts = await resolveExternalLfsStorageGitOpts(cwd, opts);
  await git(cwd, ["add", "-A"], addOpts);
  const dirty = (await tryGit(cwd, ["diff", "--cached", "--quiet"], roOpts)).code !== 0;
  if (!dirty) return false;

  const repoRequiresSigning = await resolveRepoOrWorktreeGpgSign(cwd, roOpts);
  if (!repoRequiresSigning) {
    await git(cwd, ["commit", "-q", "--no-verify", "--no-gpg-sign", "-m", message], opts);
    return true;
  }

  const fmtRes = await tryGit(cwd, ["config", "--includes", "--get", "gpg.format"], roOpts);
  const gpgFormat = fmtRes.code === 0 ? fmtRes.stdout.trim().toLowerCase() : "";
  const keyRes = await tryGit(cwd, ["config", "--includes", "--get", "user.signingkey"], roOpts);
  const signingKey = keyRes.code === 0 ? keyRes.stdout.trim() : "";

  if (gpgFormat === "ssh" && signingKey) {
    const effectiveRawEnv: NodeJS.ProcessEnv = opts?.extraEnv ? { ...process.env, ...opts.extraEnv } : process.env;
    const hostHome = effectiveRawEnv.HOME?.trim() || os.homedir();
    const dataDir = opts?.cfg?.dataDir;
    const realData = dataDir && fs.existsSync(dataDir) ? fs.realpathSync(dataDir) : "";
    const isOutsideData = (p: string): boolean => {
      if (!realData) return true;
      try {
        const real = fs.realpathSync(p);
        const rel = path.relative(realData, real);
        return rel !== "" && (rel.startsWith("..") || path.isAbsolute(rel));
      } catch {
        return false;
      }
    };
    const signingRo: string[] = [];
    const signingSymlinks: { dest: string; target: string }[] = [];
    const addKeyFile = (logicalPath: string) => {
      try {
        const lst = fs.lstatSync(logicalPath);
        const st = fs.statSync(logicalPath);
        if (!st.isFile() || st.size > 256 * 1024) return;
        const real = fs.realpathSync(logicalPath);
        if (!isOutsideData(real)) return;
        signingRo.push(real);
        if (lst.isSymbolicLink()) {
          const logicalDest = path.join(fs.realpathSync(path.dirname(logicalPath)), path.basename(logicalPath));
          if (logicalDest !== real) signingSymlinks.push({ dest: logicalDest, target: real });
        }
      } catch {
        // ignore missing/unreadable file
      }
    };

    const extraCfgArgs = ["-c", "commit.gpgSign=true", "-c", "gpg.format=ssh", "-c", `user.signingkey=${signingKey}`];
    const sshProgRes = await tryGit(cwd, ["config", "--includes", "--get", "gpg.ssh.program"], roOpts);
    const sshProg = sshProgRes.code === 0 ? sshProgRes.stdout.trim() : "";
    if (sshProg) extraCfgArgs.push("-c", `gpg.ssh.program=${sshProg}`);
    const allowedSignersRes = await tryGit(cwd, ["config", "--includes", "--get", "gpg.ssh.allowedSignersFile"], roOpts);
    const allowedSigners = allowedSignersRes.code === 0 ? allowedSignersRes.stdout.trim() : "";
    if (allowedSigners) {
      const resolvedAllowed = allowedSigners.startsWith("~/") && hostHome
        ? path.join(hostHome, allowedSigners.slice(2))
        : path.resolve(cwd, allowedSigners);
      addKeyFile(resolvedAllowed);
      extraCfgArgs.push("-c", `gpg.ssh.allowedSignersFile=${allowedSigners}`);
    }

    let needsAgent = false;
    if (signingKey.startsWith("key::")) {
      needsAgent = true;
    } else {
      const logicalKey = signingKey.startsWith("~/") && hostHome
        ? path.join(hostHome, signingKey.slice(2))
        : path.resolve(cwd, signingKey);
      addKeyFile(logicalKey);
      if (!logicalKey.endsWith(".pub")) addKeyFile(`${logicalKey}.pub`);
      needsAgent = logicalKey.endsWith(".pub") || isSshPrivateKeyEncrypted(logicalKey);
    }

    await git(cwd, ["commit", "-q", "--no-verify", "-m", message], {
      ...opts,
      extraGitConfigArgs: [...(opts?.extraGitConfigArgs ?? []), ...extraCfgArgs],
      extraReadOnlyPaths: [...(opts?.extraReadOnlyPaths ?? []), ...signingRo],
      extraSymlinks: [...(opts?.extraSymlinks ?? []), ...signingSymlinks],
      extraCmdPaths: [...(opts?.extraCmdPaths ?? []), sshProg || "ssh-keygen"],
      allowCommitSigningSshSock: needsAgent,
    });
    return true;
  }

  // 非 SSH 签名路径（如 OpenPGP）：显式把已核验的 commit.gpgSign=true（及 gpg.format / user.signingkey）带入提交命令，
  // 防止 commit.gpgSign 来自沙箱不可见的外部 [include] 时 git commit 静默生成未签名提交
  const nonSshSignCfg = [
    "-c",
    "commit.gpgSign=true",
    ...(gpgFormat ? ["-c", `gpg.format=${gpgFormat}`] : []),
    ...(signingKey ? ["-c", `user.signingkey=${signingKey}`] : []),
  ];
  try {
    await git(cwd, ["commit", "-q", "--no-verify", "-m", message], {
      ...opts,
      extraGitConfigArgs: [...(opts?.extraGitConfigArgs ?? []), ...nonSshSignCfg],
    });
    return true;
  } catch (err) {
    throw new Error(
      `仓库本地配置了 commit.gpgSign=true（gpg.format=${gpgFormat || "openpgp"}），隔离沙箱已屏蔽宿主机 GPG 代理；请改用 gpg.format=ssh 配置受限签名密钥，或在代理工作树仓库关闭本地 commit.gpgSign：${errMsg(err)}`,
    );
  }
}

/** 当前检出的分支名；游离 HEAD 返回 ""。 */
export async function currentBranch(repo: string, opts?: GitRunOpts): Promise<string> {
  const r = await tryGit(repo, ["symbolic-ref", "--quiet", "--short", "HEAD"], { ...opts, readOnly: true });
  return r.code === 0 ? r.stdout.trim() : "";
}

export async function branchExists(repo: string, branch: string, opts?: GitRunOpts): Promise<boolean> {
  return (await tryGit(repo, ["rev-parse", "--verify", "--quiet", `refs/heads/${branch}`], { ...opts, readOnly: true })).code === 0;
}

export async function revParse(repo: string, ref: string, opts?: GitRunOpts): Promise<string> {
  return (await git(repo, ["rev-parse", ref], { ...opts, readOnly: true })).trim();
}

/** a 是否是 b 的祖先，即能否把 a 快进到 b。 */
export async function isAncestor(repo: string, a: string, b: string, opts?: GitRunOpts): Promise<boolean> {
  const r = await tryGit(repo, ["merge-base", "--is-ancestor", a, b], { ...opts, readOnly: true });
  if (r.code === 0) return true;
  if (r.code === 1) return false;
  throw new Error(`git merge-base 失败：${r.stderr.trim()}`);
}

/** 已跟踪文件没有未提交的改动（未跟踪文件不算；真冲突时 git merge 自己会拒绝）。 */
export async function isClean(repo: string, opts?: GitRunOpts): Promise<boolean> {
  return (await git(repo, ["status", "--porcelain", "--untracked-files=no"], { ...opts, readOnly: true })).trim() === "";
}

/** 配置里 remote 的原始 URL（不展开 insteadOf，用来识别平台和仓库路径）。 */
export async function remoteUrl(cwd: string, remote: string, opts?: GitRunOpts): Promise<string> {
  const r = await tryGit(cwd, ["config", "--get", `remote.${remote}.url`], { ...opts, readOnly: true });
  if (r.code !== 0 || !r.stdout.trim()) throw new Error(`仓库没有名为 ${remote} 的 remote`);
  return r.stdout.trim();
}

/** 远端默认分支（ls-remote --symref HEAD）；解析并只读挂载本地镜像及其逻辑符号链接（如 url.*.insteadOf 或符号链接镜像路径），查不到返回 ""。 */
export async function remoteDefaultBranch(cwd: string, remote: string, opts?: GitRunOpts): Promise<string> {
  const urlRes = await tryGit(cwd, ["remote", "get-url", "--all", remote], { ...opts, readOnly: true });
  const urls =
    urlRes.code === 0
      ? urlRes.stdout.split("\n").map((s) => s.trim()).filter(Boolean)
      : [remote];
  const localDirs: string[] = [];
  const localSymlinks: { dest: string; target: string }[] = [];
  for (const u of urls) {
    const m = resolveLocalGitRemoteMount(cwd, u);
    if (!m) continue;
    localDirs.push(m.realDir);
    localSymlinks.push(...m.symlinks);
  }
  const r = await tryGit(cwd, ["ls-remote", "--symref", remote, "HEAD"], {
    ...opts,
    readOnly: true,
    extraReadOnlyPaths: [...(opts?.extraReadOnlyPaths ?? []), ...new Set(localDirs)],
    ...(localSymlinks.length ? { extraSymlinks: [...(opts?.extraSymlinks ?? []), ...localSymlinks] } : {}),
  });
  if (r.code !== 0) return "";
  return r.stdout.match(/^ref:\s+refs\/heads\/(\S+)\s+HEAD/m)?.[1] ?? "";
}

export async function diffStat(cwd: string, base: string, opts?: GitRunOpts): Promise<string> {
  if (!base) return "";
  const r = await tryGit(cwd, ["diff", "--stat", base, "HEAD"], { ...opts, readOnly: true });
  return r.code === 0 ? r.stdout.trim() : "";
}

export interface RemoteRef {
  host: string;
  /** 仓库路径，如 owner/repo、group/sub/repo（去掉 .git 后缀） */
  path: string;
}

/**
 * 解析 remote URL：https://host/owner/repo(.git)、ssh://git@host[:port]/owner/repo.git、git@host:owner/repo.git。
 * 本地路径等无法识别的形式返回 undefined。
 */
export function parseRemote(url: string): RemoteRef | undefined {
  const u = url.trim();
  const clean = (p: string) => p.replace(/^\/+/, "").replace(/\/+$/, "").replace(/\.git$/, "");
  const m = u.match(/^(?:https?|ssh|git):\/\/(?:[^@/]+@)?([^/:]+)(?::\d+)?\/(.+)$/i);
  if (m) {
    const path = clean(m[2]);
    return path.includes("/") ? { host: m[1].toLowerCase(), path } : undefined;
  }
  const scp = parseScpGitUrl(u);
  if (scp) {
    const path = clean(scp.path);
    return path.includes("/") ? { host: scp.host, path } : undefined;
  }
  return undefined;
}

const ZERO_OID = "0000000000000000000000000000000000000000";
// 与 Git LFS 官方 v1Aliases（git-lfs/lfs/pointer.go）完全一致：支持 spec/v1、hawser spec/v1 与 git-media.io/v/2
const LFS_SPEC_HEADERS = [
  "version https://git-lfs.github.com/spec/v1",
  "version https://hawser.github.com/spec/v1",
  "version http://git-media.io/v/2",
] as const;
const LFS_SPEC_HEADER_BUFS = LFS_SPEC_HEADERS.map((h) => Buffer.from(h, "utf8"));
const LFS_POINTER_MIN_BYTES = 80;
const LFS_POINTER_MAX_BYTES = 1024;
const LFS_MAX_INT64 = 9223372036854775807n;
// 保留 UTF-8 BOM（ignoreBOM: true），避免 BOM 字节序列被静默剥离而与 git-lfs（bytes.TrimSpace 不去 BOM）产生分歧
const UTF8_FATAL = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
// 精确对齐 Go unicode.IsSpace（含 U+0085 NEL、U+00A0 NBSP 及 Unicode Zs 空白，但绝不包含 U+FEFF BOM）
const GO_UNICODE_SPACE_TRIM =
  /^[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/g;
const LFS_META_CHUNK_SIZE = 1024;
const LFS_BATCH_CHUNK_SIZE = 256;

async function tryGitBuffer(
  cwd: string,
  args: string[],
  opts?: GitRunOpts,
): Promise<{ code: number; stdout: Buffer; stderr: string }> {
  const effectiveRawEnv: NodeJS.ProcessEnv = opts?.extraEnv
    ? { ...process.env, ...opts.extraEnv }
    : process.env;
  const baseEnv = prepareHarnessEnv(process.env);
  let stagedGitCfg: StagedSanitizedGitConfig | undefined;
  try {
    const roDefaultOpts: GitRunOpts = { ...opts, readOnly: opts?.readOnly ?? true };
    const baseIso = buildGitIsolation(
      cwd,
      roDefaultOpts,
      baseEnv.env.CREDENTIALS_DIRECTORY,
      undefined,
      undefined,
      effectiveRawEnv,
      true,
    );
    const willIsolate = willIsolateCommand(effectiveRawEnv, baseIso);
    if (willIsolate) {
      stagedGitCfg = stageSanitizedGitConfig(effectiveRawEnv, opts?.cfg?.dataDir, { cwd });
    }
    const childEnv: NodeJS.ProcessEnv = {
      ...baseEnv.env,
      ...(opts?.extraEnv ?? {}),
      GIT_TERMINAL_PROMPT: "0",
    };
    delete childEnv.GIT_EXTERNAL_DIFF;
    applySanitizedGitConfigEnv(childEnv, stagedGitCfg, willIsolate);
    const effectiveOpts: GitRunOpts = stagedGitCfg
      ? {
          ...roDefaultOpts,
          extraReadOnlyPaths: [...(roDefaultOpts.extraReadOnlyPaths ?? []), stagedGitCfg.dir, ...stagedGitCfg.extraReadOnlyPaths],
          ...(stagedGitCfg.symlinks.length
            ? { extraSymlinks: [...(roDefaultOpts.extraSymlinks ?? []), ...stagedGitCfg.symlinks] }
            : {}),
        }
      : roDefaultOpts;
    const wrapped = wrapCredentialIsolatedCommand(
      "git",
      ["-C", cwd, ...GIT_SAFE_ARGS, ...(opts?.extraGitConfigArgs ?? []), ...args],
      effectiveRawEnv,
      buildGitIsolation(cwd, effectiveOpts, baseEnv.env.CREDENTIALS_DIRECTORY, undefined, undefined, effectiveRawEnv, true),
    );
    return await new Promise((resolve) => {
      const child = spawn(wrapped.cmd, wrapped.args, {
        env: childEnv,
        stdio: ["pipe", "pipe", "pipe"],
        detached: true,
      });
      const outChunks: Buffer[] = [];
      let errStr = "";
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        killChildGroup(child);
      }, opts?.timeoutMs ?? 300_000);
      timer.unref?.();
      // 与 runProcess 一致：忽略子进程提前退出引发的 stdin EPIPE，避免未捕获错误导致常驻进程崩溃
      child.stdin.on("error", () => undefined);
      child.stdout.on("data", (d: Buffer) => outChunks.push(d));
      child.stderr.on("data", (d: Buffer) => {
        errStr += d.toString("utf8");
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        resolve({ code: 127, stdout: Buffer.alloc(0), stderr: err.message });
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        resolve({
          code: timedOut ? 124 : (code ?? 1),
          stdout: Buffer.concat(outChunks),
          stderr: timedOut ? `${errStr}\n(timeout)`.trim() : errStr,
        });
      });
      if (opts?.input !== undefined) child.stdin.end(opts.input);
      else child.stdin.end();
    });
  } finally {
    stagedGitCfg?.cleanup();
    baseEnv.cleanup();
  }
}

/**
 * 严格按 Git LFS 官方指针语法（git-lfs/lfs/pointer.go `DecodeKV`）校验指针文件并提取 sha256 OID：
 *   - 支持标准 spec/v1 与历史 hawser spec/v1；
 *   - 拒绝空字节、非法 UTF-8、UTF-8 BOM、超过 1024 字节、未知键值行（如 `not a pointer`）、重复 `oid`/`version`、
 *     冲突的 `ext-<idx>-<name>`、非 `int64` 范围 `size` 或 `size` 未位于最后一行。
 */
export function extractGitLfsPointerOid(content: string | Buffer): string | undefined {
  let text: string;
  if (Buffer.isBuffer(content)) {
    if (content.length === 0 || content.length > LFS_POINTER_MAX_BYTES || content.includes(0)) return undefined;
    try {
      text = UTF8_FATAL.decode(content);
    } catch {
      return undefined;
    }
  } else {
    if (!content || Buffer.byteLength(content, "utf8") > LFS_POINTER_MAX_BYTES || content.includes("\0")) return undefined;
    text = content;
  }
  // 精确对齐 Go bytes.TrimSpace（剥离首尾 Go unicode.IsSpace 空白，保留 \ufeff BOM 以拒绝带 BOM 的非法指针）
  const trimmed = text.replace(GO_UNICODE_SPACE_TRIM, "");
  if (!trimmed) return undefined;
  const lines = trimmed
    .split("\n")
    .map((l) => (l.endsWith("\r") ? l.slice(0, -1) : l))
    .filter((l) => l.length > 0);
  if (lines.length < 3) return undefined;
  if (!LFS_SPEC_HEADERS.includes(lines[0] as (typeof LFS_SPEC_HEADERS)[number])) return undefined;

  const lastLine = lines[lines.length - 1];
  const sizeMatch = lastLine.match(/^size \+?(\d+)$/);
  if (!sizeMatch) return undefined;
  try {
    const sizeVal = BigInt(sizeMatch[1]);
    if (sizeVal < 0n || sizeVal > LFS_MAX_INT64) return undefined;
  } catch {
    return undefined;
  }

  let oid: string | undefined;
  const extByIdx = new Map<number, string>();
  for (let i = 1; i < lines.length - 1; i++) {
    const line = lines[i];
    const parts = line.split(" ");
    if (parts.length !== 2) return undefined;
    const [key, val] = parts;
    if (!key || !val || /\s/.test(key) || /\s/.test(val)) return undefined;
    if (key === "oid") {
      if (oid !== undefined) return undefined;
      const oidMatch = val.match(/^sha256:([0-9a-f]{64})$/);
      if (!oidMatch) return undefined;
      oid = oidMatch[1];
    } else if (key.startsWith("ext-")) {
      // 对齐官方 git-lfs pointer 语法：扩展优先级严格为单个 ASCII 数字 0-9（ext-[0-9]-<name>）
      const extMatch = key.match(/^ext-([0-9])-(.+)$/);
      if (!extMatch) return undefined;
      const idx = Number(extMatch[1]);
      const name = extMatch[2];
      if (!name) return undefined;
      if (!/^sha256:[0-9a-f]{64}$/.test(val)) return undefined;
      const prevName = extByIdx.get(idx);
      if (prevName !== undefined && prevName !== name) return undefined;
      extByIdx.set(idx, name);
    } else {
      return undefined;
    }
  }
  return oid;
}

/** 严格校验一段文本或二进制块是否是合规的 Git LFS 指针文件（与 `git lfs pointer --check --stdin` 语法一致）。 */
export function isGitLfsPointerBlob(content: string | Buffer): boolean {
  return extractGitLfsPointerOid(content) !== undefined;
}

function collectBatchBufferLfsOids(
  buf: Buffer,
  out: Set<string>,
  stopOnFirst: boolean,
  bySha?: Map<string, string>,
): boolean {
  let offset = 0;
  let found = false;
  while (offset < buf.length) {
    const nl = buf.indexOf(0x0a, offset);
    if (nl === -1) break;
    const header = buf.subarray(offset, nl).toString("utf8").trim();
    offset = nl + 1;
    const parts = header.split(" ");
    if (parts.length < 3 || parts[1] === "missing") continue;
    const objSha = parts[0];
    const size = Number(parts[2]);
    if (!Number.isFinite(size) || size < 0 || offset + size > buf.length) {
      throw new Error("git cat-file --batch 输出帧长度异常，无法安全确认 LFS 指针");
    }
    const blobBuf = buf.subarray(offset, offset + size);
    offset += size + 1; // 跳过对象后的 '\n'
    if (LFS_SPEC_HEADER_BUFS.some((h) => blobBuf.includes(h))) {
      const oid = extractGitLfsPointerOid(blobBuf);
      if (oid) {
        out.add(oid);
        if (bySha && objSha) bySha.set(objSha, oid);
        found = true;
        if (stopOnFirst) return true;
      }
    }
  }
  return found;
}

export interface LocalGitRemoteMount {
  realDir: string;
  symlinks: { dest: string; target: string }[];
}

/**
 * 将本地远端路径（含 `file://` URL 与相对 `cwd` 的路径）解析为真实宿主机路径及逻辑路径上的符号链接映射，
 * 使隔离沙箱既挂载真实仓库目录又保留原始符号链接路径供 Git 直接按 `.git/config` URL 打开；非本地远端返回 undefined。
 */
export function resolveLocalGitRemoteMount(cwd: string, rawUrl: string): LocalGitRemoteMount | undefined {
  const u = rawUrl.trim();
  if (!u) return undefined;
  let candidate: string | undefined;
  if (/^file:\/\//i.test(u)) {
    try {
      candidate = fileURLToPath(u);
    } catch {
      return undefined;
    }
  } else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) {
    return undefined;
  } else if (parseScpGitUrl(u, cwd)) {
    return undefined;
  } else {
    candidate = path.resolve(cwd, u);
  }
  if (!candidate) return undefined;
  try {
    if (!fs.existsSync(candidate)) return undefined;
    const realDir = fs.realpathSync(candidate);
    const symlinks: { dest: string; target: string }[] = [];
    const seenDest = new Set<string>();
    const abs = path.resolve(candidate);
    const parts = abs.split(path.sep).filter(Boolean);
    let cur: string = path.sep;
    for (let i = 0; i < parts.length; i++) {
      const next = path.join(cur, parts[i]);
      try {
        const lst = fs.lstatSync(next);
        if (lst.isSymbolicLink()) {
          const parentReal = fs.realpathSync(path.dirname(next));
          const dest = path.join(parentReal, path.basename(next));
          const target = fs.realpathSync(next);
          if (dest !== target && !seenDest.has(dest)) {
            seenDest.add(dest);
            symlinks.push({ dest, target });
          }
          cur = target;
          continue;
        }
      } catch {
        break;
      }
      cur = next;
    }
    return { realDir, symlinks };
  } catch {
    return undefined;
  }
}

/** 将本地远端路径（含 `file://` URL 与相对 `cwd` 的路径）解析为真实宿主机路径，供沙箱显式挂载；非本地远端返回 undefined。 */
export function resolveLocalGitRemoteDir(cwd: string, rawUrl: string): string | undefined {
  return resolveLocalGitRemoteMount(cwd, rawUrl)?.realDir;
}

async function preparePinnedCheckAttr(
  cwd: string,
  targetRev: string,
  roOpts: GitRunOpts,
): Promise<{
  checkAttrArgs: string[];
  attrExtraEnv?: Record<string, string>;
  attrExtraRo: string[];
  cleanup: () => void;
}> {
  let checkAttrArgs: string[] = ["check-attr", `--source=${targetRev}`, "--stdin", "-z", "filter"];
  let attrTmpDir: string | undefined;
  let attrExtraEnv: Record<string, string> | undefined;
  let attrExtraRo: string[] = [];

  // 强制在 C locale 下探测 --source 支持情况，避免在 zh_CN 等本地化环境下被翻译为“未知选项”而误判失败
  const probe = await tryGit(cwd, checkAttrArgs, {
    ...roOpts,
    input: "",
    extraEnv: { ...(roOpts.extraEnv ?? {}), LC_ALL: "C", LC_MESSAGES: "C", LANG: "C", LANGUAGE: "C" },
  });
  if (probe.code !== 0) {
    if (probe.code === 129 && /unknown option.*source/i.test(`${probe.stderr}\n${probe.stdout}`)) {
      attrTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-git-attr-"));
      try {
        const pinnedIndex = path.join(attrTmpDir, "index");
        const rt = await tryGit(cwd, ["read-tree", targetRev], {
          ...roOpts,
          extraWritablePaths: [...(roOpts.extraWritablePaths ?? []), attrTmpDir],
          extraEnv: { ...(roOpts.extraEnv ?? {}), GIT_INDEX_FILE: pinnedIndex },
        });
        if (rt.code !== 0) {
          throw new Error(`git read-tree 加载目标提交 ${targetRev} 临时索引失败：${(rt.stderr || rt.stdout).trim()}`);
        }
        checkAttrArgs = ["check-attr", "--cached", "--stdin", "-z", "filter"];
        attrExtraEnv = { GIT_INDEX_FILE: pinnedIndex };
        attrExtraRo = [attrTmpDir];
      } catch (err) {
        fs.rmSync(attrTmpDir, { recursive: true, force: true });
        throw err;
      }
    } else {
      throw new Error(`git check-attr 检查提交 ${targetRev} 失败：${(probe.stderr || probe.stdout).trim()}`);
    }
  }
  return {
    checkAttrArgs,
    attrExtraEnv,
    attrExtraRo,
    cleanup: () => {
      if (attrTmpDir) fs.rmSync(attrTmpDir, { recursive: true, force: true });
    },
  };
}

const NUL_BYTE_BUF = Buffer.from([0]);
const FILTER_ATTR_BUF = Buffer.from("filter", "ascii");
const LFS_VAL_BUF = Buffer.from("lfs", "ascii");

function splitBufferByByte(buf: Buffer, delim: number): Buffer[] {
  const parts: Buffer[] = [];
  let start = 0;
  let idx = buf.indexOf(delim, start);
  while (idx !== -1) {
    parts.push(buf.subarray(start, idx));
    start = idx + 1;
    idx = buf.indexOf(delim, start);
  }
  if (start < buf.length) parts.push(buf.subarray(start));
  return parts;
}

/**
 * 仅筛出目标不可变提交 `targetRev` 中 `filter=lfs` 生效的原始字节路径集合（键为无损 latin1 字节映射）：
 * 全程保留 Unix 原始路径字节，不对非 UTF-8 路径做 U+FFFD 替换；支持跨有界批次复用已准备好的 `pinned` 索引。
 */
async function filterPathsWithLfsAttrBytes(
  cwd: string,
  targetRev: string,
  pathBufs: Buffer[],
  roOpts: GitRunOpts,
  existingPinned?: Awaited<ReturnType<typeof preparePinnedCheckAttr>>,
): Promise<Set<string>> {
  const out = new Set<string>();
  if (pathBufs.length === 0) return out;
  const pinned = existingPinned ?? (await preparePinnedCheckAttr(cwd, targetRev, roOpts));
  try {
    const CHUNK = 2000;
    for (let i = 0; i < pathBufs.length; i += CHUNK) {
      const slice = pathBufs.slice(i, i + CHUNK);
      const chunks: Buffer[] = [];
      for (const p of slice) {
        chunks.push(p, NUL_BYTE_BUF);
      }
      const res = await tryGitBuffer(cwd, pinned.checkAttrArgs, {
        ...roOpts,
        input: Buffer.concat(chunks),
        extraReadOnlyPaths: [...(roOpts.extraReadOnlyPaths ?? []), ...pinned.attrExtraRo],
        ...(pinned.attrExtraEnv ? { extraEnv: { ...(roOpts.extraEnv ?? {}), ...pinned.attrExtraEnv } } : {}),
      });
      if (res.code !== 0) {
        throw new Error(`git check-attr 过滤目标提交 ${targetRev} LFS 路径失败：${res.stderr.trim()}`);
      }
      const tokens = splitBufferByByte(res.stdout, 0x00);
      for (let j = 0; j + 2 < tokens.length; j += 3) {
        const filePathBuf = tokens[j];
        const attrBuf = tokens[j + 1];
        const valBuf = tokens[j + 2];
        if (filePathBuf.length > 0 && attrBuf.equals(FILTER_ATTR_BUF) && valBuf.equals(LFS_VAL_BUF)) {
          out.add(filePathBuf.toString("latin1"));
        }
      }
    }
  } finally {
    if (!existingPinned) pinned.cleanup();
  }
  return out;
}

/**
 * 流式检测目标不可变提交 `targetRev` 的任意树内路径是否命中 `filter=lfs`：
 *   - 优先使用 Git >= 2.40 的 `git check-attr --source=<targetRev>`；
 *   - 旧版 Git（如 2.39）不支持 `--source` 时，改用临时独立 `GIT_INDEX_FILE` 执行 `git read-tree <targetRev>` 后跑 `git check-attr --cached`，
 *     严格读取目标提交的 `.gitattributes`，绝不静默回退读取可能变动的工作区 `.gitattributes`；
 *   - `ls-tree` 与 `check-attr` 共享同一份脱敏全局 Git 配置（保留 `safe.directory` 与 `core.attributesFile`）；
 *   - 以背压管道流式连接 `git ls-tree -r --name-only -z` 与 `git check-attr --stdin -z filter`，保持 O(1) 内存并在命中首个 `filter=lfs` 时立即早停。
 */
async function targetRevHasLfsAttr(cwd: string, targetRev: string, roOpts: GitRunOpts): Promise<boolean> {
  const pinned = await preparePinnedCheckAttr(cwd, targetRev, roOpts);
  const { checkAttrArgs, attrExtraEnv, attrExtraRo } = pinned;

  try {
    const effectiveRawEnv: NodeJS.ProcessEnv = roOpts.extraEnv
      ? { ...process.env, ...roOpts.extraEnv }
      : process.env;
    const streamEnv = prepareHarnessEnv(process.env);
    let stagedGitCfg: StagedSanitizedGitConfig | undefined;
    try {
      const lsEnv: NodeJS.ProcessEnv = { ...streamEnv.env, ...(roOpts.extraEnv ?? {}), GIT_TERMINAL_PROMPT: "0" };
      delete lsEnv.GIT_EXTERNAL_DIFF;
      const caEnv: NodeJS.ProcessEnv = { ...lsEnv, ...(attrExtraEnv ?? {}) };
      const baseCaOpts: GitRunOpts = {
        ...roOpts,
        extraReadOnlyPaths: [...(roOpts.extraReadOnlyPaths ?? []), ...attrExtraRo],
      };
      const baseIso = buildGitIsolation(
        cwd,
        roOpts,
        streamEnv.env.CREDENTIALS_DIRECTORY,
        undefined,
        undefined,
        effectiveRawEnv,
        true,
      );
      const willIsolate = willIsolateCommand(effectiveRawEnv, baseIso);
      if (willIsolate) {
        stagedGitCfg = stageSanitizedGitConfig(effectiveRawEnv, roOpts.cfg?.dataDir, { cwd });
      }
      // ls-tree 与 check-attr 复用同一份脱敏全局配置（保留 safe.directory 与 core.attributesFile），避免异属主仓库或全局属性文件误判
      applySanitizedGitConfigEnv(lsEnv, stagedGitCfg, willIsolate);
      applySanitizedGitConfigEnv(caEnv, stagedGitCfg, willIsolate);
      const withStagedCfg = (base: GitRunOpts): GitRunOpts =>
        stagedGitCfg
          ? {
              ...base,
              extraReadOnlyPaths: [...(base.extraReadOnlyPaths ?? []), stagedGitCfg.dir, ...stagedGitCfg.extraReadOnlyPaths],
              ...(stagedGitCfg.symlinks.length
                ? { extraSymlinks: [...(base.extraSymlinks ?? []), ...stagedGitCfg.symlinks] }
                : {}),
            }
          : base;
      const lsOpts = withStagedCfg(roOpts);
      const caOpts = withStagedCfg(baseCaOpts);
      const lsWrapped = wrapCredentialIsolatedCommand(
        "git",
        ["-C", cwd, ...GIT_SAFE_ARGS, ...(roOpts.extraGitConfigArgs ?? []), "ls-tree", "-r", "--name-only", "-z", targetRev],
        effectiveRawEnv,
        buildGitIsolation(cwd, lsOpts, streamEnv.env.CREDENTIALS_DIRECTORY, undefined, undefined, effectiveRawEnv, true),
      );
      const caWrapped = wrapCredentialIsolatedCommand(
        "git",
        ["-C", cwd, ...GIT_SAFE_ARGS, ...(roOpts.extraGitConfigArgs ?? []), ...checkAttrArgs],
        effectiveRawEnv,
        buildGitIsolation(cwd, caOpts, streamEnv.env.CREDENTIALS_DIRECTORY, undefined, undefined, effectiveRawEnv, true),
      );

      const lsChild = spawn(lsWrapped.cmd, lsWrapped.args, { env: lsEnv, stdio: ["ignore", "pipe", "pipe"], detached: true });
      const caChild = spawn(caWrapped.cmd, caWrapped.args, { env: caEnv, stdio: ["pipe", "pipe", "pipe"], detached: true });

      let lsErr = "";
      let caErr = "";
      let timedOut = false;
      let stoppedEarly = false;
      let hasLfsAttr = false;
      const timeoutMs = roOpts.timeoutMs ?? 300_000;
      const timer = setTimeout(() => {
        timedOut = true;
        killChildGroup(lsChild);
        killChildGroup(caChild);
      }, timeoutMs);
      timer.unref?.();

      caChild.stdin.on("error", () => undefined);
      lsChild.stderr.on("data", (d: Buffer) => {
        if (lsErr.length < 16_384) lsErr += d.toString("utf8");
      });
      caChild.stderr.on("data", (d: Buffer) => {
        if (caErr.length < 16_384) caErr += d.toString("utf8");
      });

      const lsExitP = new Promise<{ code: number; spawnErr?: Error }>((resolve) => {
        lsChild.on("error", (err) => resolve({ code: 127, spawnErr: err }));
        lsChild.on("close", (code) => resolve({ code: timedOut ? 124 : (code ?? 1) }));
      });
      const caExitP = new Promise<{ code: number; spawnErr?: Error }>((resolve) => {
        caChild.on("error", (err) => resolve({ code: 127, spawnErr: err }));
        caChild.on("close", (code) => resolve({ code: timedOut ? 124 : (code ?? 1) }));
      });

      const pumpP = (async () => {
        try {
          for await (const chunk of lsChild.stdout as AsyncIterable<Buffer>) {
            if (stoppedEarly || caChild.stdin.destroyed) break;
            if (!caChild.stdin.write(chunk)) {
              await new Promise<void>((resolve) => {
                const onDone = () => {
                  caChild.stdin.off("drain", onDone);
                  caChild.stdin.off("close", onDone);
                  caChild.stdin.off("error", onDone);
                  resolve();
                };
                caChild.stdin.once("drain", onDone);
                caChild.stdin.once("close", onDone);
                caChild.stdin.once("error", onDone);
              });
            }
          }
        } catch {
          // 早停或子进程退出引起的管道中断由退出码阶段统一裁决
        } finally {
          if (!caChild.stdin.destroyed) caChild.stdin.end();
        }
      })();

      let carry = "";
      let fieldMod = 0; // 0 = path, 1 = attr, 2 = val
      let curAttr = "";
      try {
        for await (const raw of caChild.stdout as AsyncIterable<Buffer>) {
          carry += raw.toString("utf8");
          let nul = carry.indexOf("\0");
          while (nul !== -1) {
            const field = carry.slice(0, nul);
            carry = carry.slice(nul + 1);
            if (fieldMod === 1) {
              curAttr = field;
            } else if (fieldMod === 2) {
              if (curAttr === "filter" && field === "lfs") {
                hasLfsAttr = true;
                stoppedEarly = true;
                killChildGroup(lsChild);
                killChildGroup(caChild);
                break;
              }
            }
            fieldMod = (fieldMod + 1) % 3;
            nul = carry.indexOf("\0");
          }
          if (stoppedEarly) break;
        }
      } catch (err) {
        killChildGroup(lsChild);
        killChildGroup(caChild);
        await Promise.all([pumpP, lsExitP, caExitP]);
        throw err;
      } finally {
        clearTimeout(timer);
      }

      await pumpP;
      const [lsExit, caExit] = await Promise.all([lsExitP, caExitP]);
      if (!stoppedEarly) {
        if (lsExit.spawnErr) throw new Error(`git ls-tree 启动失败：${lsExit.spawnErr.message}`);
        if (caExit.spawnErr) throw new Error(`git check-attr 启动失败：${caExit.spawnErr.message}`);
        if (lsExit.code !== 0) {
          throw new Error(`git ls-tree 检查提交 ${targetRev} 失败：${(timedOut ? `${lsErr}\n(timeout)` : lsErr).trim()}`);
        }
        if (caExit.code !== 0) {
          throw new Error(`git check-attr 检查提交 ${targetRev} 失败：${(timedOut ? `${caErr}\n(timeout)` : caErr).trim()}`);
        }
      }
      return hasLfsAttr;
    } finally {
      stagedGitCfg?.cleanup();
      streamEnv.cleanup();
    }
  } finally {
    pinned.cleanup();
  }
}

async function scanOutgoingGitLfs(
  cwd: string,
  branchOrCommit: string,
  remoteSha: string | undefined,
  knownRemoteShas: string[] | undefined,
  opts: GitRunOpts | undefined,
  stopOnFirst: boolean,
  precomputedHasLfsAttr?: boolean,
): Promise<{ hasLfsAttr: boolean; oids: string[] }> {
  const roOpts: GitRunOpts = { ...opts, readOnly: true };
  const targetRev = /^[0-9a-f]{40,64}$/i.test(branchOrCommit) || branchOrCommit.startsWith("refs/")
    ? branchOrCommit
    : `refs/heads/${branchOrCommit}`;
  const hasLfsAttr =
    precomputedHasLfsAttr !== undefined ? precomputedHasLfsAttr : await targetRevHasLfsAttr(cwd, targetRev, roOpts);
  if (hasLfsAttr && stopOnFirst) {
    return { hasLfsAttr: true, oids: [] };
  }

  // 仅排除远端已拥有且本地可解析为 commit 的基线提交，避免扫描整仓无关历史
  const rawExcludes = [...new Set([remoteSha, ...(knownRemoteShas ?? [])].filter((s): s is string => !!s && s !== ZERO_OID && /^[0-9a-f]{40,64}$/i.test(s)))];
  const validRemoteCommits: string[] = [];
  if (rawExcludes.length > 0) {
    const chk = await tryGit(cwd, ["cat-file", "--batch-check=%(objecttype) %(objectname)"], {
      ...roOpts,
      input: rawExcludes.join("\n") + "\n",
    });
    if (chk.code !== 0) {
      throw new Error(`git cat-file 校验远端基线提交失败：${(chk.stderr || chk.stdout).trim()}`);
    }
    for (const line of chk.stdout.split("\n")) {
      const [type, sha] = line.trim().split(" ");
      if (type === "commit" && sha) validRemoteCommits.push(sha);
    }
  }

  const revInput = [targetRev, ...validRemoteCommits.map((sha) => `^${sha}`)].join("\n") + "\n";
  const oids = new Set<string>();

  interface OutgoingBlobCandidate {
    commitSha: string;
    sha: string;
    pathBuf: Buffer;
  }

  // 按有界批次过滤待推送提交中新增/修改的 blob：先筛体积、再验指针语法、仅对真正呈指针形态的 blob 在其所属提交上核验 filter=lfs 属性，
  // 从而排除普通仓库中的指针格式测试样本，同时完整覆盖历史中先添加后删除的真实 LFS 文件并保持 O(1) 内存。
  const processCandidateChunk = async (candidates: OutgoingBlobCandidate[]): Promise<boolean> => {
    const uniqueShas = [...new Set(candidates.map((c) => c.sha))];
    if (uniqueShas.length === 0) return false;
    const metaCheck = await tryGit(cwd, ["cat-file", "--batch-check=%(objecttype) %(objectsize) %(objectname)"], {
      ...roOpts,
      input: uniqueShas.join("\n") + "\n",
    });
    if (metaCheck.code !== 0) {
      throw new Error(`git cat-file --batch-check 检查待推送对象元信息失败：${(metaCheck.stderr || metaCheck.stdout).trim()}`);
    }
    const smallShaSet = new Set<string>();
    for (const line of metaCheck.stdout.split("\n")) {
      const parts = line.trim().split(" ");
      if (parts.length < 3) continue;
      const [type, sizeStr, sha] = parts;
      const size = Number(sizeStr);
      if (type === "blob" && Number.isFinite(size) && size >= LFS_POINTER_MIN_BYTES && size <= LFS_POINTER_MAX_BYTES) {
        smallShaSet.add(sha);
      }
    }
    if (smallShaSet.size === 0) return false;

    const smallShas = [...smallShaSet];
    const pointerOidBySha = new Map<string, string>();
    const scratchOids = new Set<string>();
    for (let j = 0; j < smallShas.length; j += LFS_BATCH_CHUNK_SIZE) {
      const blobChunk = smallShas.slice(j, j + LFS_BATCH_CHUNK_SIZE);
      const batchRes = await tryGitBuffer(cwd, ["cat-file", "--batch"], {
        ...roOpts,
        input: blobChunk.join("\n") + "\n",
      });
      if (batchRes.code !== 0) {
        throw new Error(`git cat-file --batch 读取候选 blob 失败：${batchRes.stderr.trim()}`);
      }
      collectBatchBufferLfsOids(batchRes.stdout, scratchOids, false, pointerOidBySha);
    }
    if (pointerOidBySha.size === 0) return false;

    const byCommit = new Map<string, { pathBuf: Buffer; oid: string }[]>();
    for (const cand of candidates) {
      const oid = pointerOidBySha.get(cand.sha);
      if (!oid) continue;
      const list = byCommit.get(cand.commitSha) ?? [];
      list.push({ pathBuf: cand.pathBuf, oid });
      byCommit.set(cand.commitSha, list);
    }

    for (const [commitSha, entries] of byCommit) {
      const lfsKeys = await filterPathsWithLfsAttrBytes(
        cwd,
        commitSha,
        entries.map((e) => e.pathBuf),
        roOpts,
      );
      for (const e of entries) {
        if (lfsKeys.has(e.pathBuf.toString("latin1"))) {
          oids.add(e.oid);
          if (stopOnFirst) return true;
        }
      }
    }
    return false;
  };

  // 流式串联 `git rev-list --stdin` -> `git diff-tree --stdin -r -m --root --no-abbrev --no-renames -z`，
  // 复用脱敏全局配置以保留 `safe.directory`，并保留原始非 UTF-8 路径字节与有界内存
  const effectiveRawEnv: NodeJS.ProcessEnv = roOpts.extraEnv
    ? { ...process.env, ...roOpts.extraEnv }
    : process.env;
  const revEnv = prepareHarnessEnv(process.env);
  let stagedGitCfg: StagedSanitizedGitConfig | undefined;
  try {
    const childEnv: NodeJS.ProcessEnv = { ...revEnv.env, ...(roOpts.extraEnv ?? {}), GIT_TERMINAL_PROMPT: "0" };
    delete childEnv.GIT_EXTERNAL_DIFF;
    const baseIso = buildGitIsolation(cwd, roOpts, revEnv.env.CREDENTIALS_DIRECTORY, undefined, undefined, effectiveRawEnv, true);
    const willIsolate = willIsolateCommand(effectiveRawEnv, baseIso);
    if (willIsolate) {
      stagedGitCfg = stageSanitizedGitConfig(effectiveRawEnv, roOpts.cfg?.dataDir, { cwd });
    }
    applySanitizedGitConfigEnv(childEnv, stagedGitCfg, willIsolate);
    const streamOpts: GitRunOpts = stagedGitCfg
      ? {
          ...roOpts,
          extraReadOnlyPaths: [...(roOpts.extraReadOnlyPaths ?? []), stagedGitCfg.dir, ...stagedGitCfg.extraReadOnlyPaths],
          ...(stagedGitCfg.symlinks.length
            ? { extraSymlinks: [...(roOpts.extraSymlinks ?? []), ...stagedGitCfg.symlinks] }
            : {}),
        }
      : roOpts;
    const revWrapped = wrapCredentialIsolatedCommand(
      "git",
      ["-C", cwd, ...GIT_SAFE_ARGS, ...(roOpts.extraGitConfigArgs ?? []), "rev-list", "--stdin"],
      effectiveRawEnv,
      buildGitIsolation(cwd, streamOpts, revEnv.env.CREDENTIALS_DIRECTORY, undefined, undefined, effectiveRawEnv, true),
    );
    const dtWrapped = wrapCredentialIsolatedCommand(
      "git",
      ["-C", cwd, ...GIT_SAFE_ARGS, ...(roOpts.extraGitConfigArgs ?? []), "diff-tree", "--stdin", "-r", "-m", "--root", "--no-abbrev", "--no-renames", "-z"],
      effectiveRawEnv,
      buildGitIsolation(cwd, streamOpts, revEnv.env.CREDENTIALS_DIRECTORY, undefined, undefined, effectiveRawEnv, true),
    );
    const revChild = spawn(revWrapped.cmd, revWrapped.args, {
      env: childEnv,
      stdio: ["pipe", "pipe", "pipe"],
      detached: true,
    });
    const dtChild = spawn(dtWrapped.cmd, dtWrapped.args, {
      env: childEnv,
      stdio: ["pipe", "pipe", "pipe"],
      detached: true,
    });
    let revErr = "";
    let dtErr = "";
    let timedOut = false;
    let stoppedEarly = false;
    const timer = setTimeout(() => {
      timedOut = true;
      killChildGroup(revChild);
      killChildGroup(dtChild);
    }, roOpts.timeoutMs ?? 300_000);
    timer.unref?.();
    revChild.stdin.on("error", () => undefined);
    dtChild.stdin.on("error", () => undefined);
    revChild.stderr.on("data", (d: Buffer) => {
      if (revErr.length < 16_384) revErr += d.toString("utf8");
    });
    dtChild.stderr.on("data", (d: Buffer) => {
      if (dtErr.length < 16_384) dtErr += d.toString("utf8");
    });
    const revExitP = new Promise<{ code: number; spawnErr?: Error }>((resolve) => {
      revChild.on("error", (err) => resolve({ code: 127, spawnErr: err }));
      revChild.on("close", (code) => resolve({ code: timedOut ? 124 : (code ?? 1) }));
    });
    const dtExitP = new Promise<{ code: number; spawnErr?: Error }>((resolve) => {
      dtChild.on("error", (err) => resolve({ code: 127, spawnErr: err }));
      dtChild.on("close", (code) => resolve({ code: timedOut ? 124 : (code ?? 1) }));
    });
    revChild.stdin.end(revInput);

    const pumpP = (async () => {
      try {
        for await (const chunkBuf of revChild.stdout as AsyncIterable<Buffer>) {
          if (stoppedEarly || dtChild.stdin.destroyed) break;
          if (!dtChild.stdin.write(chunkBuf)) {
            await new Promise<void>((resolve) => {
              const onDone = () => {
                dtChild.stdin.off("drain", onDone);
                dtChild.stdin.off("close", onDone);
                dtChild.stdin.off("error", onDone);
                resolve();
              };
              dtChild.stdin.once("drain", onDone);
              dtChild.stdin.once("close", onDone);
              dtChild.stdin.once("error", onDone);
            });
          }
        }
      } catch {
        // 早停或子进程退出引起的管道中断由退出码阶段统一裁决
      } finally {
        if (!dtChild.stdin.destroyed) dtChild.stdin.end();
      }
    })();

    let carry: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let currentCommitSha = "";
    let pendingEntry: { commitSha: string; newMode: string; blobSha: string } | undefined;
    let chunk: OutgoingBlobCandidate[] = [];
    const seenCommitBlobPath = new Set<string>();
    const flushChunk = async (): Promise<boolean> => {
      if (chunk.length === 0) return false;
      const batch = chunk;
      chunk = [];
      return processCandidateChunk(batch);
    };

    try {
      for await (const raw of dtChild.stdout as AsyncIterable<Buffer>) {
        carry = carry.length > 0 ? Buffer.concat([carry, raw]) : raw;
        let start = 0;
        let nul = carry.indexOf(0x00, start);
        while (nul !== -1) {
          const token = carry.subarray(start, nul);
          start = nul + 1;
          if (pendingEntry) {
            const ent = pendingEntry;
            pendingEntry = undefined;
            if (
              token.length > 0 &&
              ent.commitSha &&
              ent.blobSha &&
              ent.blobSha !== ZERO_OID &&
              (ent.newMode === "100644" || ent.newMode === "100755")
            ) {
              const pathBuf = Buffer.from(token);
              const dedupeKey = `${ent.commitSha}\0${ent.blobSha}\0${pathBuf.toString("latin1")}`;
              if (!seenCommitBlobPath.has(dedupeKey)) {
                seenCommitBlobPath.add(dedupeKey);
                chunk.push({ commitSha: ent.commitSha, sha: ent.blobSha, pathBuf });
                if (chunk.length >= LFS_META_CHUNK_SIZE) {
                  if (await flushChunk()) {
                    stoppedEarly = true;
                    killChildGroup(revChild);
                    killChildGroup(dtChild);
                    break;
                  }
                }
              }
            }
          } else if (token.length > 0 && token[0] === 0x3a) {
            const parts = token.subarray(1).toString("ascii").trim().split(/\s+/);
            pendingEntry = {
              commitSha: currentCommitSha,
              newMode: parts[1] ?? "",
              blobSha: parts[3] ?? "",
            };
          } else if (token.length > 0) {
            const firstTok = token.toString("ascii").trim().split(/\s+/)[0] ?? "";
            if (/^[0-9a-f]{40,64}$/i.test(firstTok)) {
              currentCommitSha = firstTok;
              // 切换提交时清理仅用于同提交 merge -m 去重的集合，防止多提交历史增长占用内存
              seenCommitBlobPath.clear();
            }
          }
          nul = carry.indexOf(0x00, start);
        }
        carry = start > 0 ? Buffer.from(carry.subarray(start)) : carry;
        if (stoppedEarly) break;
      }
      if (!stoppedEarly && (await flushChunk())) {
        stoppedEarly = true;
      }
    } catch (err) {
      killChildGroup(revChild);
      killChildGroup(dtChild);
      await Promise.all([pumpP, revExitP, dtExitP]);
      throw err;
    } finally {
      clearTimeout(timer);
    }
    await pumpP;
    const [revExit, dtExit] = await Promise.all([revExitP, dtExitP]);
    if (!stoppedEarly) {
      if (revExit.spawnErr) throw new Error(`git rev-list 启动失败：${revExit.spawnErr.message}`);
      if (dtExit.spawnErr) throw new Error(`git diff-tree 启动失败：${dtExit.spawnErr.message}`);
      if (revExit.code !== 0) {
        const detail = (timedOut ? `${revErr}\n(timeout)` : revErr).trim();
        throw new Error(`git rev-list 扫描提交 ${branchOrCommit} 待推送对象失败：${detail}`);
      }
      if (dtExit.code !== 0) {
        const detail = (timedOut ? `${dtErr}\n(timeout)` : dtErr).trim();
        throw new Error(`git diff-tree 扫描提交 ${branchOrCommit} 待推送路径失败：${detail}`);
      }
    }
  } finally {
    stagedGitCfg?.cleanup();
    revEnv.cleanup();
  }
  return { hasLfsAttr, oids: [...oids] };
}

/**
 * 检测指定分支或不可变提交（含当前树及远端尚未拥有的待推送历史对象，包括先添加后删除的 LFS 文件）是否涉及 Git LFS 对象：
 *   - 仅使用只读内置 git 命令（禁用仓库 hooks），不依赖本机是否安装 git-lfs；
 *   - 既检查目标提交 `.gitattributes` 的 `filter=lfs`，也按有界分块扫描远端缺少的对象（`rev-list --objects`）并严格校验小 blob 是否为合法 Git LFS 指针（含历史 hawser spec/v1），命中首条即短路返回；
 *   - 任一检查命令失败/超时时显式抛错（fail-closed），绝不把扫描失败当成“无 LFS 对象”。
 */
export async function branchUsesGitLfs(
  cwd: string,
  branchOrCommit: string,
  remoteSha?: string,
  knownRemoteShas?: string[],
  opts?: GitRunOpts,
): Promise<boolean> {
  const res = await scanOutgoingGitLfs(cwd, branchOrCommit, remoteSha, knownRemoteShas, opts, true);
  return res.hasLfsAttr || res.oids.length > 0;
}

const LFS_UPLOAD_OID_CHUNK = 200;

function isTruthyLfsEnv(val: string | undefined): boolean {
  const s = (val ?? "").trim().toLowerCase();
  return s === "1" || s === "true" || s === "yes" || s === "on";
}

/** 检测当前检出是否处于 skip-smudge / 无 smudge 过滤器模式（`GIT_LFS_SKIP_SMUDGE=1` 或 `git lfs install --skip-smudge`）。 */
async function isGitLfsSmudgeDisabled(repoPath: string, roOpts: GitRunOpts): Promise<boolean> {
  const effectiveRawEnv: NodeJS.ProcessEnv = roOpts.extraEnv ? { ...process.env, ...roOpts.extraEnv } : process.env;
  if (isTruthyLfsEnv(effectiveRawEnv.GIT_LFS_SKIP_SMUDGE)) return true;
  const procRes = await tryGit(repoPath, ["config", "--includes", "--get", "filter.lfs.process"], roOpts);
  const procCmd = procRes.code === 0 ? procRes.stdout.trim() : "";
  if (procCmd) {
    return /(?:^|\s)--skip(?:\s|$)/.test(procCmd);
  }
  const smudgeRes = await tryGit(repoPath, ["config", "--includes", "--get", "filter.lfs.smudge"], roOpts);
  const smudgeCmd = smudgeRes.code === 0 ? smudgeRes.stdout.trim() : "";
  if (!smudgeCmd) return true;
  return /(?:^|\s)--skip(?:\s|$)/.test(smudgeCmd);
}

/**
 * 仅从受信任本地 Git 配置解析生效的 Git LFS 存储目录（`lfs.storage`，相对路径基于仓库 `commonGitDir`，默认为 `<commonGitDir>/lfs`）；
 * 严禁采信受版本控制的 `.lfsconfig` 中的 `lfs.storage`（与 `git-lfs` 自身安全策略一致，防止恶意仓库指定宿主机任意可写目录），
 * 同时拒绝与 `dataDir` 重叠，并返回该目录是否位于仓库 `commonGitDir` 外部以供隔离挂载。
 */
async function resolveEffectiveLfsStorageDir(
  repoPath: string,
  commonGitDir: string,
  roOpts: GitRunOpts,
): Promise<{ storageDir: string; isExternal: boolean }> {
  const defaultDir = path.join(commonGitDir, "lfs");
  const cfgRes = await tryGit(repoPath, ["config", "--includes", "--get", "lfs.storage"], roOpts);
  const rawStorage = cfgRes.code === 0 ? cfgRes.stdout.trim() : "";
  if (!rawStorage) {
    return { storageDir: defaultDir, isExternal: false };
  }
  const effectiveRawEnv: NodeJS.ProcessEnv = roOpts.extraEnv ? { ...process.env, ...roOpts.extraEnv } : process.env;
  const hostHome = effectiveRawEnv.HOME?.trim() || os.homedir();
  const expanded =
    rawStorage === "~"
      ? hostHome || rawStorage
      : rawStorage.startsWith("~/") && hostHome
        ? path.join(hostHome, rawStorage.slice(2))
        : rawStorage;
  const resolved = path.isAbsolute(expanded) ? path.resolve(expanded) : path.resolve(commonGitDir, expanded);
  const realResolved = fs.existsSync(resolved) ? fs.realpathSync(resolved) : resolved;
  const dataDir = roOpts.cfg?.dataDir;
  if (dataDir) {
    const realData = fs.existsSync(dataDir) ? fs.realpathSync(dataDir) : path.resolve(dataDir);
    const relA = path.relative(realData, realResolved);
    const relB = path.relative(realResolved, realData);
    if (
      relA === "" ||
      (!relA.startsWith("..") && !path.isAbsolute(relA)) ||
      relB === "" ||
      (!relB.startsWith("..") && !path.isAbsolute(relB))
    ) {
      throw new Error(`lfs.storage (${rawStorage}) 与常驻数据目录重叠，已按安全策略拒绝使用`);
    }
  }
  const realCommon = fs.existsSync(commonGitDir) ? fs.realpathSync(commonGitDir) : path.resolve(commonGitDir);
  const relCommon = path.relative(realCommon, realResolved);
  const isInsideCommon = relCommon === "" || (!relCommon.startsWith("..") && !path.isAbsolute(relCommon));
  return { storageDir: realResolved, isExternal: !isInsideCommon };
}

/**
 * 在隔离 `git worktree add` 检出前，检查目标提交树是否引用了本地 LFS 存储目录中缺失的 Git LFS 对象：
 *   - 尊重 `GIT_LFS_SKIP_SMUDGE=1` 与 `git lfs install --skip-smudge`（关闭 smudge 时直接跳过预拉取）；
 *   - 尊重 `lfs.storage` 自定义共享缓存路径（返回给调用方供隔离 fetch 与 worktree checkout 共同挂载使用）；
 *   - 若有缺失，通过单独授权的远程 `git lfs fetch <remote> <sha>` 提前拉入 LFS 缓存，使随后的本地 `git worktree add` 无需远端凭据即可 smudge。
 */
export async function ensureGitLfsObjectsForCheckout(
  repoPath: string,
  targetRev: string,
  opts?: GitRunOpts & { branchHint?: string },
): Promise<{
  fetched: boolean;
  missingCount: number;
  skippedSmudge?: boolean;
  remote?: string;
  lfsStorageDir?: string;
  lfsStorageExternal?: boolean;
}> {
  const roOpts: GitRunOpts = { ...opts, readOnly: true };
  const hasLfsAttr = await targetRevHasLfsAttr(repoPath, targetRev, roOpts);
  if (!hasLfsAttr) return { fetched: false, missingCount: 0 };

  if (await isGitLfsSmudgeDisabled(repoPath, roOpts)) {
    return { fetched: false, missingCount: 0, skippedSmudge: true };
  }

  const shaRes = await tryGit(repoPath, ["rev-parse", "--verify", `${targetRev}^{commit}`], roOpts);
  if (shaRes.code !== 0 || !shaRes.stdout.trim()) return { fetched: false, missingCount: 0 };
  const targetSha = shaRes.stdout.trim();

  let commonGitDir = "";
  const commonRes = await tryGit(repoPath, ["rev-parse", "--path-format=absolute", "--git-common-dir"], roOpts);
  if (commonRes.code === 0 && commonRes.stdout.trim()) {
    commonGitDir = commonRes.stdout.trim();
  } else {
    const fallback = await tryGit(repoPath, ["rev-parse", "--git-common-dir"], roOpts);
    if (fallback.code === 0 && fallback.stdout.trim()) {
      commonGitDir = path.resolve(repoPath, fallback.stdout.trim());
    }
  }
  if (!commonGitDir) return { fetched: false, missingCount: 0 };

  const lfsStorage = await resolveEffectiveLfsStorageDir(repoPath, commonGitDir, roOpts);
  const storageMeta = {
    lfsStorageDir: lfsStorage.storageDir,
    lfsStorageExternal: lfsStorage.isExternal,
  };

  // 流式消费 `git ls-tree -r -l -z <targetSha>`，按原始字节保留非 UTF-8 路径，分有界批次做 filter=lfs 核验与 cat-file --batch 指针解析，
  // 避免大仓库仅含少量 LFS 文件时把整棵目录树缓冲进内存导致 OOM，同时复用脱敏全局配置保留 safe.directory
  const requiredOids = new Set<string>();
  const checkedLfsBlobShas = new Set<string>();
  const pinnedAttr = await preparePinnedCheckAttr(repoPath, targetSha, roOpts);
  const effectiveRawEnv: NodeJS.ProcessEnv = roOpts.extraEnv
    ? { ...process.env, ...roOpts.extraEnv }
    : process.env;
  const streamEnv = prepareHarnessEnv(process.env);
  let stagedGitCfg: StagedSanitizedGitConfig | undefined;
  try {
    const lsEnv: NodeJS.ProcessEnv = { ...streamEnv.env, ...(roOpts.extraEnv ?? {}), GIT_TERMINAL_PROMPT: "0" };
    delete lsEnv.GIT_EXTERNAL_DIFF;
    const baseIso = buildGitIsolation(
      repoPath,
      roOpts,
      streamEnv.env.CREDENTIALS_DIRECTORY,
      undefined,
      undefined,
      effectiveRawEnv,
      true,
    );
    const willIsolate = willIsolateCommand(effectiveRawEnv, baseIso);
    if (willIsolate) {
      stagedGitCfg = stageSanitizedGitConfig(effectiveRawEnv, roOpts.cfg?.dataDir, { cwd: repoPath });
    }
    applySanitizedGitConfigEnv(lsEnv, stagedGitCfg, willIsolate);
    const lsOpts: GitRunOpts = stagedGitCfg
      ? {
          ...roOpts,
          extraReadOnlyPaths: [...(roOpts.extraReadOnlyPaths ?? []), stagedGitCfg.dir, ...stagedGitCfg.extraReadOnlyPaths],
          ...(stagedGitCfg.symlinks.length
            ? { extraSymlinks: [...(roOpts.extraSymlinks ?? []), ...stagedGitCfg.symlinks] }
            : {}),
        }
      : roOpts;
    const lsWrapped = wrapCredentialIsolatedCommand(
      "git",
      ["-C", repoPath, ...GIT_SAFE_ARGS, ...(roOpts.extraGitConfigArgs ?? []), "ls-tree", "-r", "-l", "-z", targetSha],
      effectiveRawEnv,
      buildGitIsolation(repoPath, lsOpts, streamEnv.env.CREDENTIALS_DIRECTORY, undefined, undefined, effectiveRawEnv, true),
    );
    const lsChild = spawn(lsWrapped.cmd, lsWrapped.args, {
      env: lsEnv,
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    let lsErr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      killChildGroup(lsChild);
    }, roOpts.timeoutMs ?? 300_000);
    timer.unref?.();
    lsChild.stderr.on("data", (d: Buffer) => {
      if (lsErr.length < 16_384) lsErr += d.toString("utf8");
    });
    const lsExitP = new Promise<{ code: number; spawnErr?: Error }>((resolve) => {
      lsChild.on("error", (err) => resolve({ code: 127, spawnErr: err }));
      lsChild.on("close", (code) => resolve({ code: timedOut ? 124 : (code ?? 1) }));
    });

    let smallBatch: { sha: string; pathBuf: Buffer }[] = [];
    const flushSmallBatch = async (): Promise<void> => {
      if (smallBatch.length === 0) return;
      const batch = smallBatch;
      smallBatch = [];
      const lfsKeys = await filterPathsWithLfsAttrBytes(
        repoPath,
        targetSha,
        batch.map((b) => b.pathBuf),
        roOpts,
        pinnedAttr,
      );
      const toRead: string[] = [];
      for (const b of batch) {
        if (!lfsKeys.has(b.pathBuf.toString("latin1"))) continue;
        if (checkedLfsBlobShas.has(b.sha)) continue;
        checkedLfsBlobShas.add(b.sha);
        toRead.push(b.sha);
      }
      if (toRead.length === 0) return;
      const batchRes = await tryGitBuffer(repoPath, ["cat-file", "--batch"], {
        ...roOpts,
        input: toRead.join("\n") + "\n",
      });
      if (batchRes.code !== 0) {
        throw new Error(`git cat-file --batch 读取检出目标 ${targetRev} LFS 指针失败：${batchRes.stderr.trim()}`);
      }
      collectBatchBufferLfsOids(batchRes.stdout, requiredOids, false);
    };

    let carry: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    try {
      for await (const raw of lsChild.stdout as AsyncIterable<Buffer>) {
        carry = carry.length > 0 ? Buffer.concat([carry, raw]) : raw;
        let start = 0;
        let nul = carry.indexOf(0x00, start);
        while (nul !== -1) {
          const rec = carry.subarray(start, nul);
          start = nul + 1;
          if (rec.length > 0) {
            const tab = rec.indexOf(0x09);
            if (tab > 0 && tab + 1 < rec.length) {
              const header = rec.subarray(0, tab).toString("ascii").trim().split(/\s+/);
              if (header.length >= 4) {
                const [, objType, objSha, sizeStr] = header;
                const size = Number(sizeStr);
                if (
                  objType === "blob" &&
                  objSha &&
                  Number.isFinite(size) &&
                  size >= LFS_POINTER_MIN_BYTES &&
                  size <= LFS_POINTER_MAX_BYTES
                ) {
                  smallBatch.push({ sha: objSha, pathBuf: Buffer.from(rec.subarray(tab + 1)) });
                  if (smallBatch.length >= LFS_BATCH_CHUNK_SIZE) {
                    await flushSmallBatch();
                  }
                }
              }
            }
          }
          nul = carry.indexOf(0x00, start);
        }
        carry = start > 0 ? Buffer.from(carry.subarray(start)) : carry;
      }
      await flushSmallBatch();
    } catch (err) {
      killChildGroup(lsChild);
      await lsExitP;
      throw err;
    } finally {
      clearTimeout(timer);
    }
    const lsExit = await lsExitP;
    if (lsExit.spawnErr) {
      throw new Error(`git ls-tree 启动失败：${lsExit.spawnErr.message}`);
    }
    if (lsExit.code !== 0) {
      const detail = (timedOut ? `${lsErr}\n(timeout)` : lsErr).trim();
      throw new Error(`git ls-tree 检查检出目标 ${targetRev} LFS 对象失败：${detail}`);
    }
  } finally {
    stagedGitCfg?.cleanup();
    streamEnv.cleanup();
    pinnedAttr.cleanup();
  }
  if (requiredOids.size === 0) return { fetched: false, missingCount: 0, ...storageMeta };

  const missingOids: string[] = [];
  for (const oid of requiredOids) {
    const objPath = path.join(lfsStorage.storageDir, "objects", oid.slice(0, 2), oid.slice(2, 4), oid);
    if (!fs.existsSync(objPath)) missingOids.push(oid);
  }
  if (missingOids.length === 0) return { fetched: false, missingCount: 0, ...storageMeta };

  // 选择拉取远端：优先目标分支（含 branchHint）或当前分支配置的 upstream remote，其次 origin，再其次仓库首个 remote
  let remote = "";
  const tryBranchRemote = async (branchName: string): Promise<string> => {
    if (!branchName || /^[0-9a-f]{40,64}$/i.test(branchName) || branchName === "HEAD") return "";
    const shortName = branchName.startsWith("refs/heads/") ? branchName.slice("refs/heads/".length) : branchName;
    const r = await tryGit(repoPath, ["config", "--get", `branch.${shortName}.remote`], roOpts);
    const v = r.code === 0 ? r.stdout.trim() : "";
    return v && v !== "." ? v : "";
  };
  remote = await tryBranchRemote(opts?.branchHint || targetRev);
  if (!remote) {
    const cur = await currentBranch(repoPath, roOpts);
    if (cur) remote = await tryBranchRemote(cur);
  }
  if (!remote) {
    const remotesRes = await tryGit(repoPath, ["remote"], roOpts);
    const remotes = remotesRes.code === 0
      ? remotesRes.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean)
      : [];
    if (remotes.includes("origin")) remote = "origin";
    else if (remotes.length > 0) remote = remotes[0];
  }
  if (!remote) return { fetched: false, missingCount: missingOids.length, ...storageMeta };

  const remoteUrlRes = await tryGit(repoPath, ["remote", "get-url", "--all", remote], roOpts);
  const fetchUrls = remoteUrlRes.code === 0
    ? [...new Set(remoteUrlRes.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean))]
    : [];
  const effectiveLfsUrls = await resolveEffectiveLfsUrls(repoPath, { mode: "fetch", target: remote }, fetchUrls, roOpts);
  const mountUrls = effectiveLfsUrls.length > 0 ? effectiveLfsUrls : fetchUrls;
  const localRoDirs: string[] = [];
  const localSyms: { dest: string; target: string }[] = [];
  for (const u of mountUrls) {
    const m = resolveLocalGitRemoteMount(repoPath, u);
    if (!m) continue;
    localRoDirs.push(m.realDir);
    localSyms.push(...m.symlinks);
  }
  if (lfsStorage.isExternal) {
    fs.mkdirSync(lfsStorage.storageDir, { recursive: true });
  }

  const fetchRes = await tryGit(repoPath, ["lfs", "fetch", remote, targetSha], {
    ...opts,
    extraWritablePaths: [
      ...new Set([...(opts?.extraWritablePaths ?? []), ...(lfsStorage.isExternal ? [lfsStorage.storageDir] : [])]),
    ],
    extraReadOnlyPaths: [...new Set([...(opts?.extraReadOnlyPaths ?? []), ...localRoDirs])],
    ...(localSyms.length ? { extraSymlinks: [...(opts?.extraSymlinks ?? []), ...localSyms] } : {}),
    ...(lfsStorage.isExternal
      ? { extraGitConfigArgs: [...(opts?.extraGitConfigArgs ?? []), "-c", `lfs.storage=${lfsStorage.storageDir}`] }
      : {}),
  });
  if (fetchRes.code !== 0) {
    const out = `${fetchRes.stdout}\n${fetchRes.stderr}`.trim();
    throw new Error(
      `检出隔离工作树前预拉取 ${missingOids.length} 个缺失 Git LFS 对象失败（remote=${remote}, rev=${targetRev}）：${out.slice(-600)}`,
    );
  }
  return { fetched: true, missingCount: missingOids.length, remote, ...storageMeta };
}

/**
 * 保持禁用仓库自定义 hooks（core.hooksPath=/dev/null）；
 * 针对每个实际生效的推送目标（`git remote get-url --push --all` 解析出的 pushurl / pushInsteadOf）：
 *   - 锁定同一不可变提交 `localSha` 执行 LFS 历史扫描、按实际缺失 OID 显式上传（`git lfs push --object-id`，
 *     不受 fetch 远端 `refs/remotes/<remote>/*` 缓存误排除影响）与最终 `git push <localSha>:<localRef>`；
 *   - 扫描或上传失败均立即中止推送并返回明确错误，防止远端只收到悬空 LFS 指针。
 * 被拒绝（远端有本地没有的提交）是永久错误；网络等其他失败可重试。
 */
export async function pushBranch(
  cwd: string,
  remote: string,
  branch: string,
  opts?: GitRunOpts,
): Promise<{ ok: true } | { ok: false; rejected: boolean; message: string }> {
  const localRef = `refs/heads/${branch}`;
  const localShaRes = await tryGit(cwd, ["rev-parse", localRef], { ...opts, readOnly: true });
  if (localShaRes.code !== 0 || !localShaRes.stdout.trim()) {
    return { ok: false, rejected: false, message: `无法解析本地分支 ${branch}：${(localShaRes.stderr || localShaRes.stdout).trim()}` };
  }
  const localSha = localShaRes.stdout.trim();

  // 解析所有生效的推送目标 URL（尊重 remote.<name>.pushurl 与 url.<base>.pushInsteadOf），绝不用 fetch URL 替代 push 目标
  const pushUrlRes = await tryGit(cwd, ["remote", "get-url", "--push", "--all", remote], { ...opts, readOnly: true });
  const pushUrls = pushUrlRes.code === 0
    ? [...new Set(pushUrlRes.stdout.split("\n").map((s) => s.trim()).filter(Boolean))]
    : [];
  const effectivePushUrls = pushUrls.length > 0 ? pushUrls : [remote];
  const localMountByUrl = new Map<string, LocalGitRemoteMount>();
  for (const u of effectivePushUrls) {
    const resolved = resolveLocalGitRemoteMount(cwd, u);
    if (resolved) localMountByUrl.set(u, resolved);
  }
  const localRemoteDirs = [...new Set([...localMountByUrl.values()].map((m) => m.realDir))];
  const localRemoteSymlinks = [...localMountByUrl.values()].flatMap((m) => m.symlinks);

  // 仅在至少存在一个需要更新的目标远端时按需执行一次 .gitattributes 流式扫描（避免已发布相同提交触发无谓扫描与 git-lfs 预检）
  let precomputedHasLfsAttr: boolean | undefined;
  let namedRemoteLfsOverrides: string[] | undefined;
  let configuredPushLfsUrls: string[] = [];
  let extraLfsLocalDirs: string[] = [];
  let extraLfsLocalSyms: { dest: string; target: string }[] = [];
  let externalLfsStorageDir: string | undefined;
  const uploadedNamedRemoteLfsOids = new Set<string>();

  for (const pushUrl of effectivePushUrls) {
    const localMount = localMountByUrl.get(pushUrl);
    const localDir = localMount?.realDir;
    const localSyms = localMount?.symlinks ?? [];
    // 尽量用 ls-remote 缩小扫描范围；若远端是仅允许 receive-pack（禁止 upload-pack）的 push-only 端点，
    // 不在此处中止，而是保守按远端无已知引用扫描全量待推对象（非 LFS 仓库可直接进入 git push）。
    const lsRemote = await tryGit(cwd, ["ls-remote", pushUrl], {
      ...opts,
      readOnly: true,
      extraReadOnlyPaths: [...(opts?.extraReadOnlyPaths ?? []), ...(localDir ? [localDir] : [])],
      ...(localSyms.length ? { extraSymlinks: [...(opts?.extraSymlinks ?? []), ...localSyms] } : {}),
    });
    let remoteSha = ZERO_OID;
    const knownRemoteShas: string[] = [];
    if (lsRemote.code === 0) {
      for (const line of lsRemote.stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        const [sha, ref] = trimmed.split(/\s+/);
        if (!sha || !ref) continue;
        if (ref === localRef) remoteSha = sha;
        if (!ref.endsWith("^{}")) knownRemoteShas.push(sha);
      }
    }
    // 目标远端分支已精确指向 localSha（无任何待推送新提交）：跳过 LFS 树扫描与 git lfs pre-push，避免无 git-lfs 宿主机重试 PR 失败
    if (lsRemote.code === 0 && remoteSha === localSha) {
      continue;
    }

    if (precomputedHasLfsAttr === undefined) {
      try {
        precomputedHasLfsAttr = await targetRevHasLfsAttr(cwd, localSha, { ...opts, readOnly: true });
      } catch (err) {
        return {
          ok: false,
          rejected: false,
          message: `检测分支 ${branch}（提交 ${localSha.slice(0, 12)}）的 Git LFS 属性失败，已中止推送：${errMsg(err)}`,
        };
      }
    }

    let scan: { hasLfsAttr: boolean; oids: string[] };
    try {
      scan = await scanOutgoingGitLfs(cwd, localSha, remoteSha, knownRemoteShas, opts, false, precomputedHasLfsAttr);
    } catch (err) {
      return {
        ok: false,
        rejected: false,
        message: `检测分支 ${branch}（提交 ${localSha.slice(0, 12)}）是否包含 Git LFS 对象失败，已中止推送以避免遗漏历史 LFS 对象：${errMsg(err)}`,
      };
    }

    if (scan.hasLfsAttr || scan.oids.length > 0) {
      if (namedRemoteLfsOverrides === undefined) {
        const roOpts = { ...opts, readOnly: true };
        namedRemoteLfsOverrides = await resolveNamedRemoteLfsOverrides(cwd, remote, "push", roOpts);
        configuredPushLfsUrls = await resolveEffectiveLfsUrls(cwd, { mode: "push", target: remote }, effectivePushUrls, roOpts);
        const dirs = new Set<string>();
        const syms: { dest: string; target: string }[] = [];
        for (const u of configuredPushLfsUrls) {
          const m = resolveLocalGitRemoteMount(cwd, u);
          if (!m) continue;
          dirs.add(m.realDir);
          syms.push(...m.symlinks);
        }
        const commonRes = await tryGit(cwd, ["rev-parse", "--path-format=absolute", "--git-common-dir"], roOpts);
        const commonGitDir = commonRes.code === 0 ? commonRes.stdout.trim() : "";
        if (commonGitDir) {
          const lfsStorage = await resolveEffectiveLfsStorageDir(cwd, commonGitDir, roOpts);
          if (lfsStorage.isExternal) {
            externalLfsStorageDir = lfsStorage.storageDir;
            dirs.add(lfsStorage.storageDir);
          }
        }
        extraLfsLocalDirs = [...dirs];
        extraLfsLocalSyms = syms;
      }
      // 当显式 LFS 上传端点覆盖生效时，仅挂载被选中的上传端点及受信任外部 lfs.storage，绝不把被覆盖的 Git 远端或下载镜像目录挂载为可写
      const includeGitLocalDirForLfs = configuredPushLfsUrls.length === 0 && !!localDir;
      const lfsWritePaths = [
        ...new Set([...(opts?.extraWritablePaths ?? []), ...(includeGitLocalDirForLfs ? [localDir!] : []), ...extraLfsLocalDirs]),
      ];
      const lfsSyms = [...(opts?.extraSymlinks ?? []), ...(includeGitLocalDirForLfs ? localSyms : []), ...extraLfsLocalSyms];
      const lfsExtraCfg = externalLfsStorageDir
        ? [...(opts?.extraGitConfigArgs ?? []), "-c", `lfs.storage=${externalLfsStorageDir}`]
        : opts?.extraGitConfigArgs;
      // 1) 始终先运行受信任、感知路径的 `git lfs pre-push`，保留客户端 LFS 文件锁校验（lfs.locksverify）
      const prePush = await tryGit(cwd, ["lfs", "pre-push", remote, pushUrl], {
        ...opts,
        input: `${localRef} ${localSha} ${localRef} ${remoteSha}\n`,
        extraWritablePaths: lfsWritePaths,
        ...(lfsSyms.length ? { extraSymlinks: lfsSyms } : {}),
        ...(lfsExtraCfg ? { extraGitConfigArgs: lfsExtraCfg } : {}),
      });
      if (prePush.code !== 0) {
        const lfsOut = `${prePush.stdout}\n${prePush.stderr}`.trim();
        const missingLfs = /not a git command|git-lfs.*not found|No such file/i.test(lfsOut);
        const lockRejected = /locked|lock verification/i.test(lfsOut);
        return {
          ok: false,
          rejected: missingLfs || lockRejected,
          message: `检测到分支 ${branch}（含待推送提交历史）涉及 Git LFS 对象，但 LFS 预推校验/上传到 ${pushUrl} 失败（已禁用仓库 hooks 以保障安全；请确认本机已安装 git-lfs、未命中他人文件锁且具备远端推送权限）：${lfsOut.slice(-600)}`,
        };
      }

      // 2) 当待推送提交含 LFS 指针时，继续按精确缺失 OID 显式上传（解决 split-pushurl 下 pre-push 误按 fetch 缓存跳过对象的问题）。
      // 若命名远端配置了显式 `remote.<remote>.lfspushurl`/`lfsurl`（或仅有单一 pushUrl），必须保留命名远端作为上传目标，
      // 避免切换为裸 Git URL 后丢失命名远端的独立 LFS 端点覆盖与对应凭据授权。
      if (scan.oids.length > 0) {
        const useNamedRemoteLfs = effectivePushUrls.length === 1 || namedRemoteLfsOverrides.length > 0;
        const lfsTarget = useNamedRemoteLfs ? remote : localDir ? pathToFileURL(localDir).href : pushUrl;
        const oidsToUpload = useNamedRemoteLfs
          ? scan.oids.filter((oid) => !uploadedNamedRemoteLfsOids.has(oid))
          : scan.oids;
        for (let i = 0; i < oidsToUpload.length; i += LFS_UPLOAD_OID_CHUNK) {
          const oidChunk = oidsToUpload.slice(i, i + LFS_UPLOAD_OID_CHUNK);
          const lfs = await tryGit(cwd, ["lfs", "push", "--object-id", lfsTarget, ...oidChunk], {
            ...opts,
            extraWritablePaths: lfsWritePaths,
            ...(lfsSyms.length ? { extraSymlinks: lfsSyms } : {}),
            ...(lfsExtraCfg ? { extraGitConfigArgs: lfsExtraCfg } : {}),
          });
          if (lfs.code !== 0) {
            const lfsOut = `${lfs.stdout}\n${lfs.stderr}`.trim();
            const missingLfs = /not a git command|git-lfs.*not found|No such file/i.test(lfsOut);
            return {
              ok: false,
              rejected: missingLfs,
              message: `检测到分支 ${branch}（含待推送提交历史）涉及 Git LFS 对象，但上传 LFS 对象到 ${useNamedRemoteLfs ? remote : pushUrl} 失败（已禁用仓库 hooks 以保障安全；请确认本机已安装 git-lfs 并具备远端推送权限）：${lfsOut.slice(-600)}`,
            };
          }
          if (useNamedRemoteLfs) {
            for (const oid of oidChunk) uploadedNamedRemoteLfsOids.add(oid);
          }
        }
      }
    }
  }

  const force = branch.startsWith("pa/") ? ["--force-with-lease"] : [];
  // 推送通过预检的精确不可变提交 localSha，防止分支在预检期间推进导致未经扫描的新提交绕过 LFS 预检
  const r = await tryGit(cwd, ["push", "--porcelain", ...force, remote, `${localSha}:${localRef}`], {
    ...opts,
    extraWritablePaths: [...(opts?.extraWritablePaths ?? []), ...localRemoteDirs],
    ...(localRemoteSymlinks.length ? { extraSymlinks: [...(opts?.extraSymlinks ?? []), ...localRemoteSymlinks] } : {}),
  });
  if (r.code === 0) return { ok: true };
  const out = `${r.stdout}\n${r.stderr}`.trim();
  return { ok: false, rejected: /rejected|stale info|non-fast-forward/i.test(out), message: out.slice(-800) };
}
