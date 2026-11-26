import { spawn } from "node:child_process";
import { prepareHarnessEnv, wrapCredentialIsolatedCommand } from "../harness.ts";
import { errMsg, runProcess, type ProcResult } from "../util.ts";

/**
 * 交付用到的 git 操作：
 *   - 显式指定 -C 目录，不依赖进程当前目录；
 *   - 关闭交互认证、禁用仓库级 hooks / fsmonitor / external diff（防不可信仓库配置执行任意代码）；
 *   - 剥离个人 Web 凭据环境，并在存在 systemd feishu-web-key 时通过内核挂载命名空间遮罩该密钥文件。
 */

const GIT_SAFE_ARGS = [
  "-c", "user.name=personal-agent",
  "-c", "user.email=personal-agent@localhost",
  "-c", "core.hooksPath=/dev/null",
  "-c", "core.fsmonitor=false",
  "-c", "core.pager=cat",
];

export async function tryGit(cwd: string, args: string[], opts?: { input?: string }): Promise<ProcResult> {
  const baseEnv = prepareHarnessEnv();
  try {
    const safeSubArgs = args[0] === "diff" ? ["diff", "--no-ext-diff", ...args.slice(1)] : args;
    const childEnv: NodeJS.ProcessEnv = { ...baseEnv.env, GIT_TERMINAL_PROMPT: "0" };
    delete childEnv.GIT_EXTERNAL_DIFF;
    const wrapped = wrapCredentialIsolatedCommand("git", ["-C", cwd, ...GIT_SAFE_ARGS, ...safeSubArgs]);
    return await runProcess(wrapped.cmd, wrapped.args, {
      env: childEnv,
      input: opts?.input,
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

const ZERO_OID = "0000000000000000000000000000000000000000";
const LFS_SPEC_HEADER = "version https://git-lfs.github.com/spec/v1";
const LFS_SPEC_HEADER_BUF = Buffer.from(LFS_SPEC_HEADER, "utf8");
const LFS_POINTER_MIN_BYTES = 80;
const LFS_POINTER_MAX_BYTES = 1024;

async function tryGitBuffer(
  cwd: string,
  args: string[],
  opts?: { input?: string; timeoutMs?: number },
): Promise<{ code: number; stdout: Buffer; stderr: string }> {
  const baseEnv = prepareHarnessEnv();
  try {
    const childEnv: NodeJS.ProcessEnv = { ...baseEnv.env, GIT_TERMINAL_PROMPT: "0" };
    delete childEnv.GIT_EXTERNAL_DIFF;
    const wrapped = wrapCredentialIsolatedCommand("git", ["-C", cwd, ...GIT_SAFE_ARGS, ...args]);
    return await new Promise((resolve) => {
      const child = spawn(wrapped.cmd, wrapped.args, {
        env: childEnv,
        stdio: ["pipe", "pipe", "pipe"],
      });
      const outChunks: Buffer[] = [];
      let errStr = "";
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, opts?.timeoutMs ?? 300_000);
      timer.unref?.();
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

/** 严格校验一段文本是否是合规的 Git LFS 指针文件（防止源代码里出现 spec URL 字面量造成误判）。 */
export function isGitLfsPointerBlob(content: string): boolean {
  if (!content || Buffer.byteLength(content, "utf8") > LFS_POINTER_MAX_BYTES) return false;
  const lines = content.replace(/\r\n/g, "\n").split("\n").filter((l) => l.length > 0);
  if (lines.length < 3) return false;
  if (lines[0] !== LFS_SPEC_HEADER) return false;
  let hasOid = false;
  let hasSize = false;
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (/^oid sha256:[0-9a-f]{64}$/.test(line)) hasOid = true;
    else if (/^size \d+$/.test(line)) hasSize = true;
    else if (!/^[a-z0-9._-]+ \S/.test(line)) return false;
  }
  return hasOid && hasSize;
}

/**
 * 检测分支（含当前树及远端尚未拥有的待推送历史对象，包括先添加后删除的 LFS 文件）是否涉及 Git LFS 对象：
 *   - 仅使用只读内置 git 命令（禁用仓库 hooks），不依赖本机是否安装 git-lfs；
 *   - 既检查分支顶端 `.gitattributes` 的 `filter=lfs`，也仅扫描远端缺少的对象（`rev-list --objects`）并严格校验小 blob 是否为合法 Git LFS 指针；
 *   - 任一检查命令失败/超时时显式抛错（fail-closed），绝不把扫描失败当成“无 LFS 对象”。
 */
export async function branchUsesGitLfs(
  cwd: string,
  branch: string,
  remoteSha?: string,
  knownRemoteShas?: string[],
): Promise<boolean> {
  const localRef = `refs/heads/${branch}`;
  const tree = await tryGit(cwd, ["ls-tree", "-r", "--name-only", "-z", localRef]);
  if (tree.code !== 0) {
    throw new Error(`git ls-tree 检查分支 ${branch} 失败：${(tree.stderr || tree.stdout).trim()}`);
  }
  if (tree.stdout) {
    const attrs = await tryGit(cwd, ["check-attr", "--stdin", "-z", "filter"], { input: tree.stdout });
    if (attrs.code !== 0) {
      throw new Error(`git check-attr 检查分支 ${branch} 失败：${(attrs.stderr || attrs.stdout).trim()}`);
    }
    if (attrs.stdout) {
      const fields = attrs.stdout.split("\0");
      for (let i = 0; i + 2 < fields.length; i += 3) {
        if (fields[i + 1] === "filter" && fields[i + 2] === "lfs") return true;
      }
    }
  }

  // 仅排除远端已拥有且本地可解析为 commit 的基线提交，避免扫描整仓无关历史
  const rawExcludes = [...new Set([remoteSha, ...(knownRemoteShas ?? [])].filter((s): s is string => !!s && s !== ZERO_OID && /^[0-9a-f]{40,64}$/i.test(s)))];
  const validRemoteCommits: string[] = [];
  if (rawExcludes.length > 0) {
    const chk = await tryGit(cwd, ["cat-file", "--batch-check=%(objecttype) %(objectname)"], {
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

  const revArgs = ["rev-list", "--objects", localRef, ...(validRemoteCommits.length ? ["--not", ...validRemoteCommits] : [])];
  const revList = await tryGit(cwd, revArgs);
  if (revList.code !== 0) {
    throw new Error(`git rev-list 扫描分支 ${branch} 待推送对象失败：${(revList.stderr || revList.stdout).trim()}`);
  }
  const objShas: string[] = [];
  const seen = new Set<string>();
  for (const line of revList.stdout.split("\n")) {
    const sha = line.trim().split(/\s+/)[0];
    if (sha && !seen.has(sha)) {
      seen.add(sha);
      objShas.push(sha);
    }
  }
  if (objShas.length === 0) return false;

  const metaCheck = await tryGit(cwd, ["cat-file", "--batch-check=%(objecttype) %(objectsize) %(objectname)"], {
    input: objShas.join("\n") + "\n",
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
  if (smallBlobs.length === 0) return false;

  // 以原始 Buffer 偏移解析 git cat-file --batch，避免二进制小文件触发 UTF-8 截断/错位
  const batchRes = await tryGitBuffer(cwd, ["cat-file", "--batch"], { input: smallBlobs.join("\n") + "\n" });
  if (batchRes.code !== 0) {
    throw new Error(`git cat-file --batch 读取候选 blob 失败：${batchRes.stderr.trim()}`);
  }
  const buf = batchRes.stdout;
  let offset = 0;
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
    if (blobBuf.includes(LFS_SPEC_HEADER_BUF) && isGitLfsPointerBlob(blobBuf.toString("utf8"))) {
      return true;
    }
  }
  return false;
}

/**
 * 推送 pa/ 分支。只对我们自己的 pa/ 分支使用 --force-with-lease（返工后历史可能被改写），其他分支普通推送。
 * 保持禁用仓库自定义 hooks（core.hooksPath=/dev/null）；若分支或待推送历史涉及 Git LFS 对象，
 * 推送前通过 Git LFS 官方的 `git lfs pre-push` 按实际推送引用范围上传所有历史与当前引用的 LFS 对象，
 * 扫描或上传失败均立即中止推送并返回明确错误，防止远端只收到悬空 LFS 指针。
 * 被拒绝（远端有本地没有的提交）是永久错误；网络等其他失败可重试。
 */
export async function pushBranch(cwd: string, remote: string, branch: string): Promise<{ ok: true } | { ok: false; rejected: boolean; message: string }> {
  const localRef = `refs/heads/${branch}`;
  const localShaRes = await tryGit(cwd, ["rev-parse", localRef]);
  if (localShaRes.code !== 0 || !localShaRes.stdout.trim()) {
    return { ok: false, rejected: false, message: `无法解析本地分支 ${branch}：${(localShaRes.stderr || localShaRes.stdout).trim()}` };
  }
  const localSha = localShaRes.stdout.trim();
  const lsRemote = await tryGit(cwd, ["ls-remote", remote]);
  if (lsRemote.code !== 0) {
    return { ok: false, rejected: false, message: `无法读取远端 ${remote} 引用列表：${(lsRemote.stderr || lsRemote.stdout).trim()}` };
  }
  let remoteSha = ZERO_OID;
  const knownRemoteShas: string[] = [];
  for (const line of lsRemote.stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const [sha, ref] = trimmed.split(/\s+/);
    if (!sha || !ref) continue;
    if (ref === localRef) remoteSha = sha;
    if (!ref.endsWith("^{}")) knownRemoteShas.push(sha);
  }

  let usesLfs = false;
  try {
    usesLfs = await branchUsesGitLfs(cwd, branch, remoteSha, knownRemoteShas);
  } catch (err) {
    return {
      ok: false,
      rejected: false,
      message: `检测分支 ${branch} 是否包含 Git LFS 对象失败，已中止推送以避免遗漏历史 LFS 对象：${errMsg(err)}`,
    };
  }

  if (usesLfs) {
    const urlRes = await tryGit(cwd, ["config", "--get", `remote.${remote}.url`]);
    const rUrl = urlRes.code === 0 ? urlRes.stdout.trim() : "";
    const lfsArgs = ["lfs", "pre-push", remote, ...(rUrl ? [rUrl] : [])];
    const stdinLine = `${localRef} ${localSha} ${localRef} ${remoteSha}\n`;
    const lfs = await tryGit(cwd, lfsArgs, { input: stdinLine });
    if (lfs.code !== 0) {
      const lfsOut = `${lfs.stdout}\n${lfs.stderr}`.trim();
      const missingLfs = /not a git command|git-lfs.*not found|No such file/i.test(lfsOut);
      return {
        ok: false,
        rejected: missingLfs,
        message: `检测到分支 ${branch}（含待推送提交历史）涉及 Git LFS 对象，但上传 LFS 对象失败（已禁用仓库 hooks 以保障安全；请确认本机已安装 git-lfs 并具备远端推送权限）：${lfsOut.slice(-600)}`,
      };
    }
  }
  const force = branch.startsWith("pa/") ? ["--force-with-lease"] : [];
  const r = await tryGit(cwd, ["push", "--porcelain", ...force, remote, `${localRef}:${localRef}`]);
  if (r.code === 0) return { ok: true };
  const out = `${r.stdout}\n${r.stderr}`.trim();
  return { ok: false, rejected: /rejected|stale info|non-fast-forward/i.test(out), message: out.slice(-800) };
}
