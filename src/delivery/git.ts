import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import type { Config } from "../config.ts";
import {
  buildWorkspaceIsolation,
  collectSafeGitConfigMounts,
  createScopedSecretDir,
  detectGitWorktreeDirs,
  prepareHarnessEnv,
  resolveTrustedSystemBin,
  willIsolateCommand,
  workspaceRequiresIsolation,
  wrapCredentialIsolatedCommand,
  type IsolationOptions,
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
  input?: string;
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
  extraEnv?: Record<string, string>;
}

/** 仅对授权的远程 Git 传输子命令解析并校验单个 SSH 代理 Unix 套接字路径（绝不开放给普通 worker 或本地 git 命令） */
export function resolveAuthorizedSshAuthSock(
  args: string[],
  rawEnv: NodeJS.ProcessEnv = process.env,
  dataDir?: string,
): string | undefined {
  if (!REMOTE_GIT_SUBCMDS.has(args[0] ?? "")) return undefined;
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
  if (opts?.cfg) {
    const plan = buildWorkspaceIsolation(
      opts.cfg,
      {
        mode: opts.readOnly ? "git-ro" : "git-rw",
        cwd,
        trustedRepoRoot: opts.trustedRepoRoot,
        disableGitWorktreeMounts: opts.disableGitWorktreeMounts,
        extraWritablePaths: extraRw,
        extraReadOnlyPaths: extraRo,
        extraSymlinks,
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
  const gitCfg = isoActive ? collectSafeGitConfigMounts(rawEnv, undefined, { cwd }) : { readOnlyPaths: [], symlinks: [] };
  const combinedRo = [...gitCfg.readOnlyPaths, ...extraRo];
  const combinedSymlinks = [...gitCfg.symlinks, ...extraSymlinks];
  return {
    cwd,
    requireIsolation: isoActive,
    writablePaths: opts?.readOnly ? extraRw : [cwd, ...wtTargets, ...extraRw],
    readOnlyPaths: opts?.readOnly ? [cwd, ...wtTargets, ...combinedRo] : combinedRo,
    ...(combinedSymlinks.length ? { extraSymlinks: combinedSymlinks } : {}),
  };
}

interface ScopedGitHttpCreds {
  credDir: string;
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

function decodeUrlUser(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/** 按 git-credential-store 匹配语义判断单行凭据是否适用于指定目标 HTTP(S) URL（兼容 URL 内嵌或 `credential.<url>.username` 指定的用户名） */
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
  const entryPath = normalizeCredPath(entry.pathname);
  const targetPath = normalizeCredPath(target.pathname);
  if (useHttpPath || entryPath) {
    if (!entryPath) {
      // 未限定路径的通配条目在 useHttpPath=true 时仍可匹配同主机目标（与 git credential-store 一致）
      return true;
    }
    return targetPath === entryPath || targetPath.startsWith(`${entryPath}/`);
  }
  return true;
}

function parseStoreHelperFile(helperValue: string, hostHome: string): { isStore: boolean; explicitFile?: string } {
  const v = helperValue.trim();
  if (!v) return { isStore: false };
  if (!/^(?:(?:\/[^\s]*\/)?git-credential-)?store(?:\s|$)/.test(v)) return { isStore: false };
  const eqMatch = v.match(/(?:^|\s)--file=(?:"([^"]+)"|'([^']+)'|(\S+))/);
  const spMatch = v.match(/(?:^|\s)--file\s+(?:"([^"]+)"|'([^']+)'|(\S+))/);
  const rawFile = eqMatch?.[1] ?? eqMatch?.[2] ?? eqMatch?.[3] ?? spMatch?.[1] ?? spMatch?.[2] ?? spMatch?.[3];
  if (!rawFile) return { isStore: true };
  const expanded = rawFile.startsWith("~/") && hostHome ? path.join(hostHome, rawFile.slice(2)) : rawFile;
  return { isStore: true, explicitFile: path.resolve(expanded) };
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

function gitCredentialSectionMatchesUrl(sectionUrl: string, target: URL): boolean {
  const parsed = parseHttpUrlSafe(sectionUrl);
  if (!parsed) return false;
  if (parsed.protocol !== target.protocol) return false;
  if (parsed.hostname.toLowerCase() !== target.hostname.toLowerCase()) return false;
  const targetPort = target.port || defaultPortForProtocol(target.protocol);
  const secPort = parsed.port || defaultPortForProtocol(parsed.protocol);
  if (targetPort !== secPort) return false;
  if (parsed.username && target.username && parsed.username !== target.username) return false;
  const secPath = normalizeCredPath(parsed.pathname);
  if (secPath) {
    const targetPath = normalizeCredPath(target.pathname);
    return targetPath === secPath || targetPath.startsWith(`${secPath}/`);
  }
  return true;
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
 * 解析 `git lfs` 实际生效的 LFS 服务端点 URL（按 `git-lfs` 优先级检查 `remote.<target>.lfsurl`、`lfs.pushurl`、`lfs.url`，
 * 同时覆盖 Git 配置（含 `--includes`）与仓库根目录 `.lfsconfig`），避免 SSH origin 搭配独立 HTTPS `lfs.url`/`lfs.pushurl` 时漏授 HTTPS 凭据。
 */
async function resolveEffectiveLfsUrls(
  cwd: string,
  spec: { mode: "push" | "fetch"; target?: string },
  baseUrls: Iterable<string>,
  opts?: GitRunOpts,
): Promise<string[]> {
  const keys: string[] = [];
  const targetLooksLikeName =
    !!spec.target &&
    spec.target !== "." &&
    spec.target !== ".." &&
    !/^[a-z][a-z0-9+.-]*:\/\//i.test(spec.target) &&
    !spec.target.startsWith("/") &&
    !spec.target.startsWith("./") &&
    !spec.target.startsWith("../") &&
    !parseScpGitUrl(spec.target, cwd);
  if (targetLooksLikeName) {
    if (spec.mode === "push") keys.push(`remote.${spec.target}.lfspushurl`);
    keys.push(`remote.${spec.target}.lfsurl`);
  }
  if (spec.mode === "push") {
    keys.push("lfs.pushurl");
  }
  keys.push("lfs.url");

  const rawCandidates = new Set<string>();
  const readKey = async (extraCfgArgs: string[], key: string) => {
    const r = await tryGit(cwd, ["config", ...extraCfgArgs, "--get-all", key], { ...opts, readOnly: true });
    if (r.code !== 0 || !r.stdout) return;
    for (const line of r.stdout.split(/\r?\n/)) {
      const v = line.trim();
      if (v) rawCandidates.add(v);
    }
  };

  for (const key of keys) {
    await readKey(["--includes"], key);
  }
  const lfsConfigPath = path.join(cwd, ".lfsconfig");
  try {
    const st = fs.statSync(lfsConfigPath);
    if (st.isFile() && st.size <= 256 * 1024) {
      for (const key of keys) {
        await readKey(["--file", lfsConfigPath], key);
      }
    }
  } catch {
    // no .lfsconfig
  }

  const baseHttpUrl = [...baseUrls].find((u) => /^https?:\/\//i.test(u.trim()));
  const out = new Set<string>();
  for (const cand of rawCandidates) {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(cand) || cand.startsWith("/") || cand.startsWith("./") || cand.startsWith("../") || parseScpGitUrl(cand, cwd)) {
      out.add(cand);
    } else if (baseHttpUrl) {
      try {
        out.add(new URL(cand, baseHttpUrl.endsWith("/") ? baseHttpUrl : `${baseHttpUrl}/`).href);
      } catch {
        // ignore invalid relative LFS URL
      }
    }
  }
  return [...out];
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
    for (const lfsUrl of await resolveEffectiveLfsUrls(cwd, spec, rawUrls, opts)) {
      rawUrls.add(lfsUrl);
    }
  }
  return [...rawUrls];
}

/**
 * 在受信任宿主机上下文中调用单个 global/system 配置的非 store helper（例如 `gh auth setup-git`、`git credential-cache`），
 * 严格隔离仓库级 `.git/config` 与个人 Web 凭据，仅解析目标 URL 的单次用户名与密码（携带 URL 内嵌或 `credential.<url>.username` 生效用户名）。
 */
async function resolveHostCredentialViaHelper(
  helperValue: string,
  target: URL,
  useHttpPath: boolean,
  rawEnv: NodeJS.ProcessEnv,
  effectiveUsername?: string,
): Promise<string | undefined> {
  const hostPrep = prepareHarnessEnv(rawEnv, { preserveDbusSession: true });
  try {
    const hostEnv: NodeJS.ProcessEnv = {
      ...hostPrep.env,
      GIT_TERMINAL_PROMPT: "0",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
    };
    const proto = target.protocol.slice(0, -1); // "http" | "https"
    const cleanPath = target.pathname.replace(/^\/+/, "");
    const lines = [`protocol=${proto}`, `host=${target.host}`];
    if (useHttpPath && cleanPath) lines.push(`path=${cleanPath}`);
    const queryUser = effectiveUsername || (target.username ? decodeUrlUser(target.username) : "");
    if (queryUser) {
      lines.push(`username=${queryUser}`);
    }
    const input = `${lines.join("\n")}\n\n`;
    const r = await runProcess(
      "git",
      [
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "credential.helper=",
        "-c",
        `credential.helper=${helperValue}`,
        "-c",
        `credential.useHttpPath=${useHttpPath ? "true" : "false"}`,
        "credential",
        "fill",
      ],
      {
        cwd: os.tmpdir(),
        env: hostEnv,
        input,
        timeoutMs: 10_000,
        group: true,
      },
    );
    if (r.code !== 0 || r.timedOut) return undefined;
    const kv = new Map<string, string>();
    for (const rawLine of r.stdout.split(/\r?\n/)) {
      if (!rawLine) break;
      const eq = rawLine.indexOf("=");
      if (eq <= 0) continue;
      kv.set(rawLine.slice(0, eq).trim(), rawLine.slice(eq + 1));
    }
    const username = kv.get("username") ?? queryUser;
    const password = kv.get("password");
    if (username === undefined || password === undefined || (!username && !password)) return undefined;
    const outProto = (kv.get("protocol") || proto).trim();
    const outHost = (kv.get("host") || target.host).trim();
    const outPath = useHttpPath ? (kv.get("path") ?? cleanPath).replace(/^\/+/, "") : "";
    const pathSuffix = outPath ? `/${outPath}` : "";
    return `${outProto}://${encodeURIComponent(username)}:${encodeURIComponent(password)}@${outHost}${pathSuffix}`;
  } finally {
    hostPrep.cleanup();
  }
}

/**
 * 仅为处于沙箱隔离下的受信任远程 Git HTTP(S) 操作投影目标域作用域内的凭据：
 *   - 每个 `store` 槽位独立过滤并写入各自 `0600` 临时文件（绝不将多个 store 合并到首个槽位，严格保持 `store A -> 中间 helper -> store B` 优先级）；
 *   - 对宿主机 global/system 作用域配置的非 store helper（如 `gh auth setup-git`、`git credential-cache`），在宿主机按槽位预解析目标 URL 凭据并原位替换为单目标临时 store 文件，
 *     绝不把 `~/.config/gh` 或宿主机 cache 套接字暴露进沙箱，也不在宿主机执行仓库级 local helper。
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

  // 读取宿主机/仓库生效的 credential.helper 与按 URL 限定的 credential.<url>.helper（含 --includes 与作用域）
  const helperCfg = await tryGit(
    cwd,
    ["config", "--includes", "--show-scope", "--null", "--get-regexp", "^credential(\\..+)?\\.helper$"],
    { ...opts, readOnly: true },
  );
  if (helperCfg.code !== 0 || !helperCfg.stdout) return undefined;

  interface ScopedHelperEntry {
    value: string;
    scope: string;
  }
  const activeScopedByKey = new Map<string, ScopedHelperEntry[]>();
  const tokens = helperCfg.stdout.split("\0");
  for (let i = 0; i + 1 < tokens.length; i += 2) {
    const scope = tokens[i].trim();
    const rec = tokens[i + 1];
    if (!rec) continue;
    const nl = rec.indexOf("\n");
    const rawKey = nl === -1 ? rec : rec.slice(0, nl);
    const val = nl === -1 ? "" : rec.slice(nl + 1).trim();
    let normKey: string;
    if (/^credential\.helper$/i.test(rawKey)) {
      normKey = "credential.helper";
    } else {
      const subMatch = rawKey.match(/^credential\.(.+)\.helper$/i);
      if (!subMatch) continue;
      normKey = `credential.${subMatch[1]}.helper`;
    }
    if (!val) {
      activeScopedByKey.set(normKey, []);
    } else {
      const list = activeScopedByKey.get(normKey) ?? [];
      list.push({ value: val, scope });
      activeScopedByKey.set(normKey, list);
    }
  }

  const matchingKeys = new Map<string, URL[]>();
  for (const [key, helpers] of activeScopedByKey) {
    if (helpers.length === 0) continue;
    if (key === "credential.helper") {
      matchingKeys.set(key, targetUrls);
    } else if (key.startsWith("credential.") && key.endsWith(".helper")) {
      const pattern = key.slice("credential.".length, -".helper".length);
      const matchedTargets = targetUrls.filter((t) => gitCredentialSectionMatchesUrl(pattern, t));
      if (matchedTargets.length > 0) matchingKeys.set(key, matchedTargets);
    }
  }
  if (matchingKeys.size === 0) return undefined;

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

  let scoped: { dir: string; cleanup: () => void } | undefined;
  let fileSeq = 0;
  let wroteAnyCreds = false;
  const rewrittenKeys = new Set<string>();
  const slotMappings = new Map<string, (string | null | undefined)[]>();

  try {
    for (const [key, keyTargets] of matchingKeys) {
      const helpers = activeScopedByKey.get(key) ?? [];
      const mappedSlots: (string | null | undefined)[] = [];
      let keyRewritten = false;

      for (const entry of helpers) {
        const parsed = parseStoreHelperFile(entry.value, hostHome);
        if (parsed.isStore) {
          keyRewritten = true;
          const filesForSlot = parsed.explicitFile ? [parsed.explicitFile] : defaultStoreFiles;
          const slotLines = new Set<string>();
          for (const file of filesForSlot) {
            if (!file || !fs.existsSync(file) || !isOutsideDataDir(file)) continue;
            try {
              const st = fs.statSync(file);
              if (!st.isFile() || st.size > 4 * 1024 * 1024) continue;
              const text = fs.readFileSync(file, "utf8");
              for (const rawLine of text.split(/\r?\n/)) {
                const line = rawLine.trim();
                if (!line || line.startsWith("#")) continue;
                const matches = keyTargets.some((t) =>
                  gitCredentialLineMatchesTarget(
                    line,
                    t,
                    useHttpPathByTarget.get(t) === true,
                    effectiveUsernameByTarget.get(t),
                  ),
                );
                if (matches) slotLines.add(line);
              }
            } catch {
              // ignore unreadable credential file
            }
          }
          if (slotLines.size > 0) {
            scoped ??= createScopedSecretDir("pa-git-http-cred-", rawEnv);
            const slotFile = path.join(scoped.dir, `store-${fileSeq++}.creds`);
            fs.writeFileSync(slotFile, `${[...slotLines].join("\n")}\n`, { mode: 0o600 });
            mappedSlots.push(`store --file=${slotFile}`);
            wroteAnyCreds = true;
          } else {
            // 该 store 槽位对目标 URL 无命中：原位省略以便 Git 顺序进入下一个 helper（绝不把后续 store 凭据提前到本槽位）
            mappedSlots.push(null);
          }
        } else if (entry.scope === "global" || entry.scope === "system") {
          // 仅对宿主机 global/system 作用域的非 store helper（如 gh / credential-cache）在受信任宿主机预解析目标凭据
          keyRewritten = true;
          const slotLines = new Set<string>();
          for (const t of keyTargets) {
            const line = await resolveHostCredentialViaHelper(
              entry.value,
              t,
              useHttpPathByTarget.get(t) === true,
              rawEnv,
              effectiveUsernameByTarget.get(t),
            );
            if (line) slotLines.add(line);
          }
          if (slotLines.size > 0) {
            scoped ??= createScopedSecretDir("pa-git-http-cred-", rawEnv);
            const slotFile = path.join(scoped.dir, `helper-${fileSeq++}.creds`);
            fs.writeFileSync(slotFile, `${[...slotLines].join("\n")}\n`, { mode: 0o600 });
            mappedSlots.push(`store --file=${slotFile}`);
            wroteAnyCreds = true;
          } else {
            mappedSlots.push(null);
          }
        } else {
          // 仓库 local 作用域的自定义 helper 不在宿主机执行，原位保留在沙箱内按原顺序执行
          mappedSlots.push(undefined);
        }
      }

      if (keyRewritten) {
        rewrittenKeys.add(key);
        slotMappings.set(key, mappedSlots);
      }
    }

    if (!scoped || !wroteAnyCreds || rewrittenKeys.size === 0) {
      scoped?.cleanup();
      return undefined;
    }

    const activeValuesByKey = new Map<string, string[]>();
    for (const [k, list] of activeScopedByKey) {
      activeValuesByKey.set(k, list.map((x) => x.value));
    }
    const gitConfigArgs = rewriteGitCredentialHelperChain(
      activeValuesByKey,
      rewrittenKeys,
      (key, _hv, idx) => slotMappings.get(key)?.[idx],
      hostHome,
    );
    return {
      credDir: scoped.dir,
      gitConfigArgs,
      cleanup: scoped.cleanup,
    };
  } catch (err) {
    scoped?.cleanup();
    throw err;
  }
}

export async function tryGit(cwd: string, args: string[], opts?: GitRunOpts): Promise<ProcResult> {
  const isRemote = REMOTE_GIT_SUBCMDS.has(args[0] ?? "");
  const effectiveRawEnv: NodeJS.ProcessEnv = opts?.extraEnv
    ? { ...process.env, ...opts.extraEnv }
    : process.env;
  const resolvedUrls = isRemote ? await resolveEffectiveRemoteUrls(cwd, args, opts) : [];
  const sshUrls = resolvedUrls.filter((u) => classifyGitRemoteTransport(cwd, u) === "ssh");
  const httpUrls = resolvedUrls.filter((u) => classifyGitRemoteTransport(cwd, u) === "http");
  const usesSsh = sshUrls.length > 0;
  const sshSock = usesSsh ? resolveAuthorizedSshAuthSock(args, effectiveRawEnv, opts?.cfg?.dataDir) : undefined;
  const baseEnv = prepareHarnessEnv(process.env, { preserveSshAgent: !!sshSock });
  let scopedHttpCreds: ScopedGitHttpCreds | undefined;
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
    const baseIsoPlan = buildGitIsolation(cwd, opts, baseEnv.env.CREDENTIALS_DIRECTORY, sshSock, sshMounts, effectiveRawEnv);
    const willIsolate = willIsolateCommand(effectiveRawEnv, baseIsoPlan);
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
    const effectiveOpts: GitRunOpts | undefined = scopedHttpCreds
      ? {
          ...opts,
          extraReadOnlyPaths: [...(opts?.extraReadOnlyPaths ?? []), scopedHttpCreds.credDir],
        }
      : opts;
    const wrapped = wrapCredentialIsolatedCommand(
      "git",
      ["-C", cwd, ...GIT_SAFE_ARGS, ...(scopedHttpCreds?.gitConfigArgs ?? []), ...safeSubArgs],
      effectiveRawEnv,
      buildGitIsolation(cwd, effectiveOpts, baseEnv.env.CREDENTIALS_DIRECTORY, sshSock, sshMounts, effectiveRawEnv),
    );
    return await runProcess(wrapped.cmd, wrapped.args, {
      env: childEnv,
      input: opts?.input,
      timeoutMs: opts?.timeoutMs ?? 300_000,
      group: true,
    });
  } finally {
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

/** 有改动就提交（含新文件）；没有改动什么都不做。返回是否提交了。 */
export async function commitAll(cwd: string, message: string, opts?: GitRunOpts): Promise<boolean> {
  await git(cwd, ["add", "-A"], opts);
  const dirty = (await tryGit(cwd, ["diff", "--cached", "--quiet"], { ...opts, readOnly: true })).code !== 0;
  if (dirty) await git(cwd, ["commit", "-q", "--no-verify", "-m", message], opts);
  return dirty;
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
  const baseEnv = prepareHarnessEnv();
  try {
    const childEnv: NodeJS.ProcessEnv = { ...baseEnv.env, GIT_TERMINAL_PROMPT: "0" };
    delete childEnv.GIT_EXTERNAL_DIFF;
    const wrapped = wrapCredentialIsolatedCommand(
      "git",
      ["-C", cwd, ...GIT_SAFE_ARGS, ...args],
      process.env,
      buildGitIsolation(cwd, { ...opts, readOnly: opts?.readOnly ?? true }, baseEnv.env.CREDENTIALS_DIRECTORY),
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

function collectBatchBufferLfsOids(buf: Buffer, out: Set<string>, stopOnFirst: boolean): boolean {
  let offset = 0;
  let found = false;
  while (offset < buf.length) {
    const nl = buf.indexOf(0x0a, offset);
    if (nl === -1) break;
    const header = buf.subarray(offset, nl).toString("utf8").trim();
    offset = nl + 1;
    const parts = header.split(" ");
    if (parts.length < 3 || parts[1] === "missing") continue;
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

/**
 * 流式检测目标不可变提交 `targetRev` 的任意树内路径是否命中 `filter=lfs`：
 *   - 优先使用 Git >= 2.40 的 `git check-attr --source=<targetRev>`；
 *   - 旧版 Git（如 2.39）不支持 `--source` 时，改用临时独立 `GIT_INDEX_FILE` 执行 `git read-tree <targetRev>` 后跑 `git check-attr --cached`，
 *     严格读取目标提交的 `.gitattributes`，绝不静默回退读取可能变动的工作区 `.gitattributes`；
 *   - 以背压管道流式连接 `git ls-tree -r --name-only -z` 与 `git check-attr --stdin -z filter`，保持 O(1) 内存并在命中首个 `filter=lfs` 时立即早停。
 */
async function targetRevHasLfsAttr(cwd: string, targetRev: string, roOpts: GitRunOpts): Promise<boolean> {
  let checkAttrArgs: string[] = ["check-attr", `--source=${targetRev}`, "--stdin", "-z", "filter"];
  let attrTmpDir: string | undefined;
  let attrExtraEnv: Record<string, string> | undefined;
  let attrExtraRo: string[] = [];

  try {
    // 强制在 C locale 下探测 --source 支持情况，避免在 zh_CN 等本地化环境下被翻译为“未知选项”而误判失败
    const probe = await tryGit(cwd, checkAttrArgs, {
      ...roOpts,
      input: "",
      extraEnv: { ...(roOpts.extraEnv ?? {}), LC_ALL: "C", LC_MESSAGES: "C", LANG: "C", LANGUAGE: "C" },
    });
    if (probe.code !== 0) {
      if (probe.code === 129 && /unknown option.*source/i.test(`${probe.stderr}\n${probe.stdout}`)) {
        attrTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-git-attr-"));
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
      } else {
        throw new Error(`git check-attr 检查提交 ${targetRev} 失败：${(probe.stderr || probe.stdout).trim()}`);
      }
    }

    const streamEnv = prepareHarnessEnv();
    try {
      const lsEnv: NodeJS.ProcessEnv = { ...streamEnv.env, ...(roOpts.extraEnv ?? {}), GIT_TERMINAL_PROMPT: "0" };
      delete lsEnv.GIT_EXTERNAL_DIFF;
      const caEnv: NodeJS.ProcessEnv = { ...lsEnv, ...(attrExtraEnv ?? {}) };
      const lsWrapped = wrapCredentialIsolatedCommand(
        "git",
        ["-C", cwd, ...GIT_SAFE_ARGS, "ls-tree", "-r", "--name-only", "-z", targetRev],
        process.env,
        buildGitIsolation(cwd, roOpts, streamEnv.env.CREDENTIALS_DIRECTORY),
      );
      const caOpts: GitRunOpts = {
        ...roOpts,
        extraReadOnlyPaths: [...(roOpts.extraReadOnlyPaths ?? []), ...attrExtraRo],
      };
      const caWrapped = wrapCredentialIsolatedCommand(
        "git",
        ["-C", cwd, ...GIT_SAFE_ARGS, ...checkAttrArgs],
        process.env,
        buildGitIsolation(cwd, caOpts, streamEnv.env.CREDENTIALS_DIRECTORY),
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
      streamEnv.cleanup();
    }
  } finally {
    if (attrTmpDir) fs.rmSync(attrTmpDir, { recursive: true, force: true });
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

  // 将待检查的 1024 条对象分批送入 cat-file --batch-check 与 ≤256 条 cat-file --batch，保持 O(1) 峰值内存
  const processMetaChunk = async (metaChunk: string[]): Promise<boolean> => {
    const metaCheck = await tryGit(cwd, ["cat-file", "--batch-check=%(objecttype) %(objectsize) %(objectname)"], {
      ...roOpts,
      input: metaChunk.join("\n") + "\n",
    });
    if (metaCheck.code !== 0) {
      throw new Error(`git cat-file --batch-check 检查待推送对象元信息失败：${(metaCheck.stderr || metaCheck.stdout).trim()}`);
    }
    const smallBlobs: string[] = [];
    for (const line of metaCheck.stdout.split("\n")) {
      const parts = line.trim().split(" ");
      if (parts.length < 3) continue;
      const [type, sizeStr, sha] = parts;
      const size = Number(sizeStr);
      if (type === "blob" && Number.isFinite(size) && size >= LFS_POINTER_MIN_BYTES && size <= LFS_POINTER_MAX_BYTES) {
        smallBlobs.push(sha);
      }
    }
    for (let j = 0; j < smallBlobs.length; j += LFS_BATCH_CHUNK_SIZE) {
      const blobChunk = smallBlobs.slice(j, j + LFS_BATCH_CHUNK_SIZE);
      const batchRes = await tryGitBuffer(cwd, ["cat-file", "--batch"], {
        ...roOpts,
        input: blobChunk.join("\n") + "\n",
      });
      if (batchRes.code !== 0) {
        throw new Error(`git cat-file --batch 读取候选 blob 失败：${batchRes.stderr.trim()}`);
      }
      if (collectBatchBufferLfsOids(batchRes.stdout, oids, stopOnFirst) && stopOnFirst) {
        return true;
      }
    }
    return false;
  };

  // 流式消费 `git rev-list --objects --stdin`（配合 async iterator 背压），避免首推或 push-only 远端将整仓历史读入内存
  const revEnv = prepareHarnessEnv();
  try {
    const childEnv: NodeJS.ProcessEnv = { ...revEnv.env, GIT_TERMINAL_PROMPT: "0" };
    delete childEnv.GIT_EXTERNAL_DIFF;
    const wrapped = wrapCredentialIsolatedCommand(
      "git",
      ["-C", cwd, ...GIT_SAFE_ARGS, "rev-list", "--objects", "--stdin"],
      process.env,
      buildGitIsolation(cwd, roOpts, revEnv.env.CREDENTIALS_DIRECTORY),
    );
    const child = spawn(wrapped.cmd, wrapped.args, {
      env: childEnv,
      stdio: ["pipe", "pipe", "pipe"],
      detached: true,
    });
    let errStr = "";
    let timedOut = false;
    let stoppedEarly = false;
    const timer = setTimeout(() => {
      timedOut = true;
      killChildGroup(child);
    }, roOpts.timeoutMs ?? 300_000);
    timer.unref?.();
    child.stdin.on("error", () => undefined);
    child.stderr.on("data", (d: Buffer) => {
      if (errStr.length < 16_384) errStr += d.toString("utf8");
    });
    const exitPromise = new Promise<{ code: number; spawnErr?: Error }>((resolve) => {
      child.on("error", (err) => resolve({ code: 127, spawnErr: err }));
      child.on("close", (code) => resolve({ code: timedOut ? 124 : (code ?? 1) }));
    });
    child.stdin.end(revInput);

    let carry = "";
    let chunk: string[] = [];
    try {
      for await (const raw of child.stdout as AsyncIterable<Buffer>) {
        carry += raw.toString("utf8");
        let nl = carry.indexOf("\n");
        while (nl !== -1) {
          const line = carry.slice(0, nl).trim();
          carry = carry.slice(nl + 1);
          const sha = line.split(/\s+/)[0];
          if (sha) {
            chunk.push(sha);
            if (chunk.length >= LFS_META_CHUNK_SIZE) {
              const batch = chunk;
              chunk = [];
              if (await processMetaChunk(batch)) {
                stoppedEarly = true;
                killChildGroup(child);
                break;
              }
            }
          }
          nl = carry.indexOf("\n");
        }
        if (stoppedEarly) break;
      }
      if (!stoppedEarly) {
        const lastSha = carry.trim().split(/\s+/)[0];
        if (lastSha) chunk.push(lastSha);
        if (chunk.length > 0 && (await processMetaChunk(chunk))) {
          stoppedEarly = true;
        }
      }
    } catch (err) {
      killChildGroup(child);
      await exitPromise;
      throw err;
    } finally {
      clearTimeout(timer);
    }
    const exitRes = await exitPromise;
    if (!stoppedEarly) {
      if (exitRes.spawnErr) {
        throw new Error(`git rev-list 启动失败：${exitRes.spawnErr.message}`);
      }
      if (exitRes.code !== 0) {
        const detail = (timedOut ? `${errStr}\n(timeout)` : errStr).trim();
        throw new Error(`git rev-list 扫描提交 ${branchOrCommit} 待推送对象失败：${detail}`);
      }
    }
  } finally {
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

/**
 * 推送 pa/ 分支。只对我们自己的 pa/ 分支使用 --force-with-lease（返工后历史可能被改写），其他分支普通推送。
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
      const lfsWritePaths = [...(opts?.extraWritablePaths ?? []), ...(localDir ? [localDir] : [])];
      const lfsSyms = localSyms.length ? [...(opts?.extraSymlinks ?? []), ...localSyms] : opts?.extraSymlinks;
      // 1) 始终先运行受信任、感知路径的 `git lfs pre-push`，保留客户端 LFS 文件锁校验（lfs.locksverify）
      const prePush = await tryGit(cwd, ["lfs", "pre-push", remote, pushUrl], {
        ...opts,
        input: `${localRef} ${localSha} ${localRef} ${remoteSha}\n`,
        extraWritablePaths: lfsWritePaths,
        ...(lfsSyms?.length ? { extraSymlinks: lfsSyms } : {}),
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

      // 2) 当待推送提交含 LFS 指针时，继续按精确缺失 OID 显式上传（解决 split-pushurl 下 pre-push 误按 fetch 缓存跳过对象的问题）
      if (scan.oids.length > 0) {
        const lfsTarget =
          effectivePushUrls.length === 1 ? remote : localDir ? pathToFileURL(localDir).href : pushUrl;
        for (let i = 0; i < scan.oids.length; i += LFS_UPLOAD_OID_CHUNK) {
          const oidChunk = scan.oids.slice(i, i + LFS_UPLOAD_OID_CHUNK);
          const lfs = await tryGit(cwd, ["lfs", "push", "--object-id", lfsTarget, ...oidChunk], {
            ...opts,
            extraWritablePaths: lfsWritePaths,
            ...(lfsSyms?.length ? { extraSymlinks: lfsSyms } : {}),
          });
          if (lfs.code !== 0) {
            const lfsOut = `${lfs.stdout}\n${lfs.stderr}`.trim();
            const missingLfs = /not a git command|git-lfs.*not found|No such file/i.test(lfsOut);
            return {
              ok: false,
              rejected: missingLfs,
              message: `检测到分支 ${branch}（含待推送提交历史）涉及 Git LFS 对象，但上传 LFS 对象到 ${pushUrl} 失败（已禁用仓库 hooks 以保障安全；请确认本机已安装 git-lfs 并具备远端推送权限）：${lfsOut.slice(-600)}`,
            };
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
