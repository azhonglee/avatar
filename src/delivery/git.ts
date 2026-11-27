import { spawn } from "node:child_process";
import fs from "node:fs";
import type { Config } from "../config.ts";
import {
  buildWorkspaceIsolation,
  detectGitWorktreeDirs,
  prepareHarnessEnv,
  wrapCredentialIsolatedCommand,
  type IsolationOptions,
} from "../harness.ts";
import { errMsg, runProcess, type ProcResult } from "../util.ts";

/**
 * 交付用到的 git 操作：
 *   - 显式指定 -C 目录，不依赖进程当前目录；
 *   - 关闭交互认证、禁用仓库级 hooks / fsmonitor / external diff（防不可信仓库配置执行任意代码）；
 *   - 剥离个人 Web 凭据环境，并在需要隔离的工作区或持钥环境下通过内核 PID + 只读根挂载命名空间隐藏 dataDir 与密钥文件。
 */

const GIT_SAFE_ARGS = [
  "-c", "user.name=personal-agent",
  "-c", "user.email=personal-agent@localhost",
  "-c", "core.hooksPath=/dev/null",
  "-c", "core.fsmonitor=false",
  "-c", "core.pager=cat",
];

export interface GitRunOpts {
  input?: string;
  timeoutMs?: number;
  cfg?: Pick<Config, "dataDir" | "context">;
  readOnly?: boolean;
  extraWritablePaths?: string[];
  extraReadOnlyPaths?: string[];
}

function buildGitIsolation(cwd: string, opts: GitRunOpts | undefined, filteredCredDir?: string): IsolationOptions {
  const extraRo = [
    ...(opts?.extraReadOnlyPaths ?? []),
    ...(filteredCredDir ? [filteredCredDir] : []),
  ];
  if (opts?.cfg) {
    return buildWorkspaceIsolation(opts.cfg, {
      mode: opts.readOnly ? "git-ro" : "git-rw",
      cwd,
      extraWritablePaths: opts.extraWritablePaths,
      extraReadOnlyPaths: extraRo,
    });
  }
  const wt = detectGitWorktreeDirs(cwd);
  const wtTargets = [wt.commonDir, wt.gitDir].filter((p): p is string => !!p);
  return {
    cwd,
    writablePaths: opts?.readOnly ? [] : [cwd, ...wtTargets, ...(opts?.extraWritablePaths ?? [])],
    readOnlyPaths: opts?.readOnly ? [cwd, ...wtTargets, ...extraRo] : extraRo,
  };
}

export async function tryGit(cwd: string, args: string[], opts?: GitRunOpts): Promise<ProcResult> {
  const baseEnv = prepareHarnessEnv();
  try {
    const safeSubArgs = args[0] === "diff" ? ["diff", "--no-ext-diff", ...args.slice(1)] : args;
    const childEnv: NodeJS.ProcessEnv = { ...baseEnv.env, GIT_TERMINAL_PROMPT: "0" };
    delete childEnv.GIT_EXTERNAL_DIFF;
    const wrapped = wrapCredentialIsolatedCommand(
      "git",
      ["-C", cwd, ...GIT_SAFE_ARGS, ...safeSubArgs],
      process.env,
      buildGitIsolation(cwd, opts, baseEnv.env.CREDENTIALS_DIRECTORY),
    );
    return await runProcess(wrapped.cmd, wrapped.args, {
      env: childEnv,
      input: opts?.input,
      timeoutMs: opts?.timeoutMs ?? 300_000,
    });
  } finally {
    baseEnv.cleanup();
  }
}

export async function git(cwd: string, args: string[], opts?: GitRunOpts): Promise<string> {
  const r = await tryGit(cwd, args, opts);
  if (r.code !== 0) throw new Error(`git ${args.join(" ")} 失败：${(r.stderr || r.stdout).trim()}`);
  return r.stdout;
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

/** 远端默认分支（ls-remote --symref HEAD）；查不到返回 ""。 */
export async function remoteDefaultBranch(cwd: string, remote: string, opts?: GitRunOpts): Promise<string> {
  const r = await tryGit(cwd, ["ls-remote", "--symref", remote, "HEAD"], { ...opts, readOnly: true });
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
  const scp = u.match(/^(?:[^@/]+@)?([^/:]+):(?!\/)(.+)$/);
  if (scp && !/^[a-z]:\\/i.test(u)) {
    const path = clean(scp[2]);
    return path.includes("/") ? { host: scp[1].toLowerCase(), path } : undefined;
  }
  return undefined;
}

const ZERO_OID = "0000000000000000000000000000000000000000";
// 与 Git LFS 官方 v1Aliases（git-lfs/lfs/pointer.go）完全一致：支持当前 spec/v1 与历史 hawser spec/v1
const LFS_SPEC_HEADERS = [
  "version https://git-lfs.github.com/spec/v1",
  "version https://hawser.github.com/spec/v1",
] as const;
const LFS_SPEC_HEADER_BUFS = LFS_SPEC_HEADERS.map((h) => Buffer.from(h, "utf8"));
const LFS_POINTER_MIN_BYTES = 80;
const LFS_POINTER_MAX_BYTES = 1024;
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
      });
      const outChunks: Buffer[] = [];
      let errStr = "";
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
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

/** 从合规的 Git LFS 指针文本中提取 sha256 OID（支持标准 spec/v1 与历史 hawser spec/v1；非法文本返回 undefined）。 */
export function extractGitLfsPointerOid(content: string): string | undefined {
  if (!content || Buffer.byteLength(content, "utf8") > LFS_POINTER_MAX_BYTES) return undefined;
  const lines = content.replace(/\r\n/g, "\n").split("\n").filter((l) => l.length > 0);
  if (lines.length < 3) return undefined;
  if (!LFS_SPEC_HEADERS.includes(lines[0] as (typeof LFS_SPEC_HEADERS)[number])) return undefined;
  let oid: string | undefined;
  let hasSize = false;
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    const oidMatch = line.match(/^oid sha256:([0-9a-f]{64})$/);
    if (oidMatch) oid = oidMatch[1];
    else if (/^size \d+$/.test(line)) hasSize = true;
    else if (!/^[a-z0-9._-]+ \S/.test(line)) return undefined;
  }
  return oid && hasSize ? oid : undefined;
}

/** 严格校验一段文本是否是合规的 Git LFS 指针文件（支持标准 spec/v1 与历史 hawser spec/v1，防止源代码字面量误判）。 */
export function isGitLfsPointerBlob(content: string): boolean {
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
      const oid = extractGitLfsPointerOid(blobBuf.toString("utf8"));
      if (oid) {
        out.add(oid);
        found = true;
        if (stopOnFirst) return true;
      }
    }
  }
  return found;
}

async function scanOutgoingGitLfs(
  cwd: string,
  branchOrCommit: string,
  remoteSha: string | undefined,
  knownRemoteShas: string[] | undefined,
  opts: GitRunOpts | undefined,
  stopOnFirst: boolean,
): Promise<{ hasLfsAttr: boolean; oids: string[] }> {
  const roOpts: GitRunOpts = { ...opts, readOnly: true };
  const targetRev = /^[0-9a-f]{40,64}$/i.test(branchOrCommit) || branchOrCommit.startsWith("refs/")
    ? branchOrCommit
    : `refs/heads/${branchOrCommit}`;
  let hasLfsAttr = false;
  const tree = await tryGit(cwd, ["ls-tree", "-r", "--name-only", "-z", targetRev], roOpts);
  if (tree.code !== 0) {
    throw new Error(`git ls-tree 检查提交 ${branchOrCommit} 失败：${(tree.stderr || tree.stdout).trim()}`);
  }
  if (tree.stdout) {
    // Git >= 2.40 支持 --source=<rev> 精确读取目标提交的 .gitattributes；旧版 Git 自动回退标准 check-attr
    let attrs = await tryGit(cwd, ["check-attr", `--source=${targetRev}`, "--stdin", "-z", "filter"], {
      ...roOpts,
      input: tree.stdout,
    });
    if (attrs.code !== 0 && /unknown option.*source/i.test(`${attrs.stderr}\n${attrs.stdout}`)) {
      attrs = await tryGit(cwd, ["check-attr", "--stdin", "-z", "filter"], {
        ...roOpts,
        input: tree.stdout,
      });
    }
    if (attrs.code !== 0) {
      throw new Error(`git check-attr 检查提交 ${branchOrCommit} 失败：${(attrs.stderr || attrs.stdout).trim()}`);
    }
    if (attrs.stdout) {
      const fields = attrs.stdout.split("\0");
      for (let i = 0; i + 2 < fields.length; i += 3) {
        if (fields[i + 1] === "filter" && fields[i + 2] === "lfs") {
          hasLfsAttr = true;
          if (stopOnFirst) return { hasLfsAttr: true, oids: [] };
          break;
        }
      }
    }
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

  const revArgs = ["rev-list", "--objects", targetRev, ...(validRemoteCommits.length ? ["--not", ...validRemoteCommits] : [])];
  const revList = await tryGit(cwd, revArgs, roOpts);
  if (revList.code !== 0) {
    throw new Error(`git rev-list 扫描提交 ${branchOrCommit} 待推送对象失败：${(revList.stderr || revList.stdout).trim()}`);
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
  const oids = new Set<string>();
  if (objShas.length === 0) return { hasLfsAttr, oids: [] };

  // 有界分块扫描（每批至多 256 个 ≤1KiB 候选 blob，峰值内存 <256KiB），stopOnFirst=true 时命中首条即短路返回
  for (let i = 0; i < objShas.length; i += LFS_META_CHUNK_SIZE) {
    const metaChunk = objShas.slice(i, i + LFS_META_CHUNK_SIZE);
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
        return { hasLfsAttr, oids: [...oids] };
      }
    }
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
  const localRemoteDirs = effectivePushUrls.filter((u) => {
    try {
      return !/^[a-z][a-z0-9+.-]*:\/\//i.test(u) && fs.existsSync(u);
    } catch {
      return false;
    }
  });

  for (const pushUrl of effectivePushUrls) {
    const isLocalDir = localRemoteDirs.includes(pushUrl);
    const lsRemote = await tryGit(cwd, ["ls-remote", pushUrl], {
      ...opts,
      readOnly: true,
      extraReadOnlyPaths: [...(opts?.extraReadOnlyPaths ?? []), ...(isLocalDir ? [pushUrl] : [])],
    });
    if (lsRemote.code !== 0) {
      return { ok: false, rejected: false, message: `无法读取推送目标 ${pushUrl} 引用列表：${(lsRemote.stderr || lsRemote.stdout).trim()}` };
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

    let scan: { hasLfsAttr: boolean; oids: string[] };
    try {
      scan = await scanOutgoingGitLfs(cwd, localSha, remoteSha, knownRemoteShas, opts, false);
    } catch (err) {
      return {
        ok: false,
        rejected: false,
        message: `检测分支 ${branch}（提交 ${localSha.slice(0, 12)}）是否包含 Git LFS 对象失败，已中止推送以避免遗漏历史 LFS 对象：${errMsg(err)}`,
      };
    }

    if (scan.oids.length > 0) {
      // 单推送目标时传 remote 名（自动遵从 remote.<name>.pushurl 与 lfsurl）；多推送目标时直接传规范化 pushUrl（本地路径转 file://）
      const lfsTarget =
        effectivePushUrls.length === 1 ? remote : isLocalDir ? `file://${pushUrl.startsWith("/") ? pushUrl : `${cwd}/${pushUrl}`}` : pushUrl;
      for (let i = 0; i < scan.oids.length; i += LFS_UPLOAD_OID_CHUNK) {
        const oidChunk = scan.oids.slice(i, i + LFS_UPLOAD_OID_CHUNK);
        const lfs = await tryGit(cwd, ["lfs", "push", "--object-id", lfsTarget, ...oidChunk], {
          ...opts,
          extraWritablePaths: [...(opts?.extraWritablePaths ?? []), ...(isLocalDir ? [pushUrl] : [])],
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
    } else if (scan.hasLfsAttr) {
      const lfsArgs = ["lfs", "pre-push", remote, pushUrl];
      const stdinLine = `${localRef} ${localSha} ${localRef} ${remoteSha}\n`;
      const lfs = await tryGit(cwd, lfsArgs, {
        ...opts,
        input: stdinLine,
        extraWritablePaths: [...(opts?.extraWritablePaths ?? []), ...(isLocalDir ? [pushUrl] : [])],
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

  const force = branch.startsWith("pa/") ? ["--force-with-lease"] : [];
  // 推送通过预检的精确不可变提交 localSha，防止分支在预检期间推进导致未经扫描的新提交绕过 LFS 预检
  const r = await tryGit(cwd, ["push", "--porcelain", ...force, remote, `${localSha}:${localRef}`], {
    ...opts,
    extraWritablePaths: [...(opts?.extraWritablePaths ?? []), ...localRemoteDirs],
  });
  if (r.code === 0) return { ok: true };
  const out = `${r.stdout}\n${r.stderr}`.trim();
  return { ok: false, rejected: /rejected|stale info|non-fast-forward/i.test(out), message: out.slice(-800) };
}
