import { prepareHarnessEnv } from "../harness.ts";
import { runProcess, type ProcResult } from "../util.ts";

/** 交付用到的 git 操作。所有命令都显式指定 -C 目录，不依赖进程当前目录；不弹交互式认证提示，并剥离个人 Web 凭据环境。 */

const GIT_ID = ["-c", "user.name=personal-agent", "-c", "user.email=personal-agent@localhost"];

export async function tryGit(cwd: string, args: string[]): Promise<ProcResult> {
  const baseEnv = prepareHarnessEnv();
  try {
    return await runProcess("git", ["-C", cwd, ...GIT_ID, ...args], {
      env: { ...baseEnv.env, GIT_TERMINAL_PROMPT: "0" },
      timeoutMs: 300_000,
    });
  } finally {
    baseEnv.cleanup();
  }
}

export async function git(cwd: string, args: string[]): Promise<string> {
  const r = await tryGit(cwd, args);
  if (r.code !== 0) throw new Error(`git ${args.join(" ")} 失败：${(r.stderr || r.stdout).trim()}`);
  return r.stdout;
}

/** 有改动就提交（含新文件）；没有改动什么都不做。返回是否提交了。 */
export async function commitAll(cwd: string, message: string): Promise<boolean> {
  await git(cwd, ["add", "-A"]);
  const dirty = (await tryGit(cwd, ["diff", "--cached", "--quiet"])).code !== 0;
  if (dirty) await git(cwd, ["commit", "-q", "--no-verify", "-m", message]);
  return dirty;
}

/** 当前检出的分支名；游离 HEAD 返回 ""。 */
export async function currentBranch(repo: string): Promise<string> {
  const r = await tryGit(repo, ["symbolic-ref", "--quiet", "--short", "HEAD"]);
  return r.code === 0 ? r.stdout.trim() : "";
}

export async function branchExists(repo: string, branch: string): Promise<boolean> {
  return (await tryGit(repo, ["rev-parse", "--verify", "--quiet", `refs/heads/${branch}`])).code === 0;
}

export async function revParse(repo: string, ref: string): Promise<string> {
  return (await git(repo, ["rev-parse", ref])).trim();
}

/** a 是否是 b 的祖先，即能否把 a 快进到 b。 */
export async function isAncestor(repo: string, a: string, b: string): Promise<boolean> {
  const r = await tryGit(repo, ["merge-base", "--is-ancestor", a, b]);
  if (r.code === 0) return true;
  if (r.code === 1) return false;
  throw new Error(`git merge-base 失败：${r.stderr.trim()}`);
}

/** 已跟踪文件没有未提交的改动（未跟踪文件不算；真冲突时 git merge 自己会拒绝）。 */
export async function isClean(repo: string): Promise<boolean> {
  return (await git(repo, ["status", "--porcelain", "--untracked-files=no"])).trim() === "";
}

/** 配置里 remote 的原始 URL（不展开 insteadOf，用来识别平台和仓库路径）。 */
export async function remoteUrl(cwd: string, remote: string): Promise<string> {
  const r = await tryGit(cwd, ["config", "--get", `remote.${remote}.url`]);
  if (r.code !== 0 || !r.stdout.trim()) throw new Error(`仓库没有名为 ${remote} 的 remote`);
  return r.stdout.trim();
}

/** 远端默认分支（ls-remote --symref HEAD）；查不到返回 ""。 */
export async function remoteDefaultBranch(cwd: string, remote: string): Promise<string> {
  const r = await tryGit(cwd, ["ls-remote", "--symref", remote, "HEAD"]);
  if (r.code !== 0) return "";
  return r.stdout.match(/^ref:\s+refs\/heads\/(\S+)\s+HEAD/m)?.[1] ?? "";
}

export async function diffStat(cwd: string, base: string): Promise<string> {
  if (!base) return "";
  const r = await tryGit(cwd, ["diff", "--stat", base, "HEAD"]);
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
  const scp = u.match(/^(?:[^@/]+@)?([^/:]+):(?!\/)(.+)$/);
  if (scp && !/^[a-z]:\\/i.test(u)) {
    const path = clean(scp[2]);
    return path.includes("/") ? { host: scp[1].toLowerCase(), path } : undefined;
  }
  return undefined;
}

/**
 * 推送 pa/ 分支。只对我们自己的 pa/ 分支使用 --force-with-lease（返工后历史可能被改写），其他分支普通推送。
 * 被拒绝（远端有本地没有的提交）是永久错误；网络等其他失败可重试。
 */
export async function pushBranch(cwd: string, remote: string, branch: string): Promise<{ ok: true } | { ok: false; rejected: boolean; message: string }> {
  const force = branch.startsWith("pa/") ? ["--force-with-lease"] : [];
  const r = await tryGit(cwd, ["push", "--porcelain", ...force, remote, `refs/heads/${branch}:refs/heads/${branch}`]);
  if (r.code === 0) return { ok: true };
  const out = `${r.stdout}\n${r.stderr}`.trim();
  return { ok: false, rejected: /rejected|stale info|non-fast-forward/i.test(out), message: out.slice(-800) };
}
