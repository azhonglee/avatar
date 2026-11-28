import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import YAML from "yaml";
import { createApp } from "../src/app.ts";
import { loadConfig } from "../src/config.ts";
import { ContextStore } from "../src/context/store.ts";
import {
  PersonalWebBridge,
  gatewayEnvFilePath,
  parseGatewayEnvText,
  readGatewayEnvFile,
  resolveGatewayClientConfig,
  writeGatewayEnvFile,
} from "../src/context/personal-web.ts";
import { runPersonalWebSetup } from "../src/context/personal-web-setup.ts";
import { runDoctor } from "../src/doctor.ts";
import { loadGatewayConfig } from "../src/gateway/config.ts";
import { GATEWAY_USER_SENDER_TYPE } from "../src/gateway/protocol.ts";
import { startGatewayServer } from "../src/gateway/server.ts";
import { FeishuGatewayService } from "../src/gateway/service.ts";
import { GatewayStore } from "../src/gateway/store.ts";

const execFileAsync = promisify(execFile);

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STUBS = path.join(ROOT, "test", "stubs");

function makeTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeCommentedAvatarConfig(
  dir: string,
  opts: {
    dataDir?: string;
    personalWeb?: { enabled?: boolean; gateway_socket?: string; gateway_url?: string; send_replies?: boolean };
  } = {},
): string {
  const cfgFile = path.join(dir, "config.yaml");
  const dataDir = opts.dataDir ?? path.join(dir, "avatar-data");
  const pw = opts.personalWeb ?? {};
  fs.writeFileSync(
    cfgFile,
    `# 顶部注释必须保留
owner:
  open_id: ou_owner
  timezone: Asia/Shanghai
data_dir: ${dataDir}
bins:
  lark: ${path.join(STUBS, "lark-cli")}
  acpx: ${path.join(STUBS, "acpx")}
harnesses:
  brain:
    agent: claude
roles:
  brain: brain
context:
  enabled: true # 保留工作上下文注释
  personal_web:
    enabled: ${pw.enabled ?? false} # 保留开关注释
    gateway_socket: "${pw.gateway_socket ?? ""}" # 保留地址注释
    gateway_url: "${pw.gateway_url ?? ""}"
    read_token_env: FEISHU_GW_READ_TOKEN
    reply_token_env: FEISHU_GW_REPLY_TOKEN
    send_replies: ${pw.send_replies ?? false}
`,
    "utf8",
  );
  return cfgFile;
}

async function startLocalGateway(dir: string, opts: { allowReply?: boolean; loggedIn?: boolean } = {}) {
  const gwDataDir = path.join(dir, "gw-data");
  const sockPath = path.join(dir, "gw-run", "gateway.sock");
  const gwCfgFile = path.join(dir, "gateway.yaml");
  fs.writeFileSync(
    gwCfgFile,
    YAML.stringify({
      data_dir: gwDataDir,
      listen: { socket: sockPath, socket_mode: "0660" },
      allow_reply: opts.allowReply ?? false,
    }),
    "utf8",
  );
  const gwCfg = loadGatewayConfig(gwCfgFile);
  const gwStore = new GatewayStore(gwCfg.dataDir);
  const gwService = new FeishuGatewayService(gwCfg, gwStore);
  if (opts.loggedIn !== false) {
    const prevKey = process.env.FEISHU_GW_KEY;
    process.env.FEISHU_GW_KEY = "test-setup-gw-key-32bytes-000001";
    gwService.loginStore.save({
      owner_id: "1001",
      owner_name: "测试主人",
      cookies: [{ name: "session", value: "s1", domain: "feishu.cn", path: "/" }],
    });
    if (prevKey === undefined) delete process.env.FEISHU_GW_KEY;
    else process.env.FEISHU_GW_KEY = prevKey;
  }
  const tokens = gwStore.resolveTokens();
  const gwServer = await startGatewayServer(gwCfg, gwService, tokens);
  return {
    gwCfgFile,
    gwDataDir,
    sockPath,
    gwCfg,
    gwStore,
    gwService,
    gwServer,
    tokens,
    async close() {
      await gwServer.stop();
      gwStore.close();
    },
  };
}

describe("gateway.env 凭据自动加载、pa context web-setup 与 pa init 只读检测", () => {
  it("gateway.env 原子 0600 读写、严格权限/符号链接拒绝与加载优先级（env > credential > gateway.env）", () => {
    const dir = makeTmp("pa-gw-env-");
    const dataDir = path.join(dir, "data");
    const credDir = path.join(dir, "creds");
    fs.mkdirSync(credDir, { recursive: true, mode: 0o700 });
    try {
      // 1) 写入与解析 roundtrip（含单引号、双引号、$、反引号与反斜杠）
      const envFile = writeGatewayEnvFile(dataDir, {
        FEISHU_GW_READ_TOKEN: "read-tok-abc_123",
        CUSTOM_QUOTE_TOKEN: "has'quote\"and$dollar`backtick`\\slash",
      });
      assert.equal(envFile, gatewayEnvFilePath(dataDir));
      const mode = fs.statSync(envFile).mode & 0o777;
      assert.equal(mode, 0o600, "gateway.env 必须固定为 0600 权限");
      assert.match(fs.readFileSync(envFile, "utf8"), /\\`backtick\\`/, "双引号值必须转义反引号");

      const parsed = readGatewayEnvFile(dataDir);
      assert.equal(parsed.status, "ok");
      assert.equal(parsed.values.FEISHU_GW_READ_TOKEN, "read-tok-abc_123");
      assert.equal(parsed.values.CUSTOM_QUOTE_TOKEN, "has'quote\"and$dollar`backtick`\\slash");

      // parseGatewayEnvText 也支持 export 前缀与注释
      const manualParsed = parseGatewayEnvText("# comment\nexport FEISHU_GW_READ_TOKEN='tok-exp'\nBAD LINE\nFEISHU_GW_REPLY_TOKEN=plain-val\n");
      assert.equal(manualParsed.FEISHU_GW_READ_TOKEN, "tok-exp");
      assert.equal(manualParsed.FEISHU_GW_REPLY_TOKEN, "plain-val");

      const pwCfg = loadConfig(writeCommentedAvatarConfig(dir, { dataDir, personalWeb: { enabled: true, gateway_socket: path.join(dir, "s.sock") } })).context.personal_web;

      // 2) 仅 gateway.env -> source=env_file
      const rFile = resolveGatewayClientConfig(pwCfg, {}, { dataDir });
      assert.equal(rFile.readToken, "read-tok-abc_123");
      assert.equal(rFile.readTokenSource, "env_file");
      assert.equal(rFile.replyToken, "");
      assert.equal(rFile.replyTokenSource, "none");

      // 3) systemd LoadCredential 优先于 gateway.env
      fs.writeFileSync(path.join(credDir, "read-token"), "cred-read-tok\n", { mode: 0o600 });
      const rCred = resolveGatewayClientConfig(pwCfg, { CREDENTIALS_DIRECTORY: credDir }, { dataDir });
      assert.equal(rCred.readToken, "cred-read-tok");
      assert.equal(rCred.readTokenSource, "credential");

      // 4) 显式环境变量优先于 LoadCredential 和 gateway.env
      const rEnv = resolveGatewayClientConfig(
        pwCfg,
        { FEISHU_GW_READ_TOKEN: "env-read-tok", CREDENTIALS_DIRECTORY: credDir },
        { dataDir },
      );
      assert.equal(rEnv.readToken, "env-read-tok");
      assert.equal(rEnv.readTokenSource, "env");

      // 5) 宽松权限（0644）必须拒绝加载
      fs.chmodSync(envFile, 0o644);
      const rUnsafe = resolveGatewayClientConfig(pwCfg, {}, { dataDir });
      assert.equal(rUnsafe.readToken, "");
      assert.equal(rUnsafe.readTokenSource, "none");
      assert.match(rUnsafe.envFileError ?? "", /权限过于宽松|0600/);

      // 6) 符号链接必须拒绝加载且拒绝覆盖写入
      const realTarget = path.join(dir, "real.env");
      fs.writeFileSync(realTarget, "FEISHU_GW_READ_TOKEN='sym-tok'\n", { mode: 0o600 });
      fs.rmSync(envFile);
      fs.symlinkSync(realTarget, envFile);
      const rSym = readGatewayEnvFile(dataDir);
      assert.equal(rSym.status, "unsafe");
      assert.match(rSym.error ?? "", /符号链接/);
      assert.throws(() => writeGatewayEnvFile(dataDir, { FEISHU_GW_READ_TOKEN: "x" }), /符号链接/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("runPersonalWebSetup 自动配置 config.yaml（保注释）、写入 0600 gateway.env（仅 read_token）、轮换更新、--with-reply/--no-reply 与 fail-fast 保护", async () => {
    const dir = makeTmp("pa-web-setup-");
    const prevKey = process.env.FEISHU_GW_KEY;
    process.env.FEISHU_GW_KEY = "test-setup-gw-key-32bytes-000001";
    const gw = await startLocalGateway(dir, { allowReply: false, loggedIn: true });
    const cfgFile = writeCommentedAvatarConfig(dir, { personalWeb: { enabled: false, gateway_socket: "" } });
    const app = createApp(loadConfig(cfgFile));

    try {
      // 1) 一键接入：从 gateway.yaml + tokens.json 自动配置并校验通过
      const res1 = await runPersonalWebSetup(app, { gatewayConfig: gw.gwCfgFile, env: {} });
      assert.equal(res1.configChanged, true);
      assert.equal(res1.reachable, true);
      assert.equal(res1.sendReplies, false);
      assert.equal(res1.readTokenOrigin, "gateway_tokens");
      assert.equal(res1.replyTokenStored, false);
      assert.equal(res1.gatewayStatus?.owner_id, "1001");

      // 验证 config.yaml 保留注释且不含明文 token
      const updatedYaml = fs.readFileSync(cfgFile, "utf8");
      assert.match(updatedYaml, /# 顶部注释必须保留/);
      assert.match(updatedYaml, /# 保留开关注释/);
      assert.match(updatedYaml, /# 保留地址注释/);
      assert.ok(!updatedYaml.includes(gw.tokens.readToken), "config.yaml 绝不能写入明文 read_token");
      assert.ok(!updatedYaml.includes(gw.tokens.replyToken), "config.yaml 绝不能写入明文 reply_token");
      const reloaded = loadConfig(cfgFile);
      assert.equal(reloaded.context.personal_web.enabled, true);
      assert.equal(reloaded.context.personal_web.gateway_socket, gw.sockPath);
      assert.equal(reloaded.context.personal_web.send_replies, false);

      // 验证 gateway.env 为 0600，仅含 read_token，不含 reply_token
      const envRead1 = readGatewayEnvFile(app.cfg.dataDir);
      assert.equal(envRead1.status, "ok");
      assert.equal(envRead1.values.FEISHU_GW_READ_TOKEN, gw.tokens.readToken);
      assert.equal(envRead1.values.FEISHU_GW_REPLY_TOKEN, undefined);

      // 2) doctor 在无任何环境变量下仅凭 gateway.env 全部通过
      const doc1 = await runDoctor(app, { env: {} });
      assert.equal(doc1.checks.find((c) => c.id === "personal_web")?.status, "ok");
      assert.match(doc1.checks.find((c) => c.id === "personal_web")?.detail ?? "", /gateway\.env/);
      assert.equal(doc1.checks.find((c) => c.id === "personal_web_boundary")?.status, "ok");

      // 3) 401 鉴权失败（传错令牌）必须 fail-fast，绝不覆盖 config.yaml 和 gateway.env
      const beforeEnvText = fs.readFileSync(res1.envFile, "utf8");
      await assert.rejects(
        runPersonalWebSetup(app, { gatewayConfig: gw.gwCfgFile, readToken: "wrong-token-should-fail-401", env: {} }),
        /鉴权失败.*未修改配置文件/,
      );
      assert.equal(fs.readFileSync(res1.envFile, "utf8"), beforeEnvText);

      // 4) 工作区账号绑定冲突必须 fail-fast，不覆盖文件
      app.store.set("ctx.personal_web.bound_owner_id", "9999-other-owner");
      await assert.rejects(
        runPersonalWebSetup(app, { gatewayConfig: gw.gwCfgFile, env: {} }),
        /web-unbind/,
      );
      app.store.db.prepare("DELETE FROM kv WHERE k = ?").run("ctx.personal_web.bound_owner_id");

      // 5) 网关轮换 read_token 并重启后，重新执行 web-setup 自动更新 gateway.env 且不重写未变的 config.yaml
      const rotated = gw.gwStore.resolveTokens({ rotateRead: true });
      assert.notEqual(rotated.readToken, gw.tokens.readToken);
      await gw.gwServer.stop();
      const gwServer2 = await startGatewayServer(gw.gwCfg, gw.gwService, rotated);
      try {
        const resRotate = await runPersonalWebSetup(app, { gatewayConfig: gw.gwCfgFile, env: {} });
        assert.equal(resRotate.configChanged, false, "config.yaml 无变化时不应重写");
        assert.equal(resRotate.reachable, true);
        assert.equal(readGatewayEnvFile(app.cfg.dataDir).values.FEISHU_GW_READ_TOKEN, rotated.readToken);

        // 6) --with-reply 同步 reply_token 并提示网关 allow_reply=false；随后 --no-reply 清理 reply_token
        const resReply = await runPersonalWebSetup(app, { gatewayConfig: gw.gwCfgFile, withReply: true, env: {} });
        assert.equal(resReply.sendReplies, true);
        assert.equal(resReply.replyTokenStored, true);
        assert.ok(resReply.warnings.some((w) => w.includes("allow_reply 为 false")));
        assert.equal(readGatewayEnvFile(app.cfg.dataDir).values.FEISHU_GW_REPLY_TOKEN, rotated.replyToken);

        // 再次不带 --with-reply/--no-reply 同步只读令牌时，应保留已有 reply_token
        const resKeepReply = await runPersonalWebSetup(app, { gatewayConfig: gw.gwCfgFile, env: {} });
        assert.equal(resKeepReply.sendReplies, true);
        assert.equal(resKeepReply.replyTokenStored, true);
        assert.equal(readGatewayEnvFile(app.cfg.dataDir).values.FEISHU_GW_REPLY_TOKEN, rotated.replyToken);

        // --no-reply 关闭回复并清除 gateway.env 中的 reply_token
        const resNoReply = await runPersonalWebSetup(app, { gatewayConfig: gw.gwCfgFile, noReply: true, env: {} });
        assert.equal(resNoReply.sendReplies, false);
        assert.equal(resNoReply.replyTokenStored, false);
        assert.equal(resNoReply.removedReplyTokenFromEnvFile, true);
        assert.equal(readGatewayEnvFile(app.cfg.dataDir).values.FEISHU_GW_REPLY_TOKEN, undefined);

        // 7) --read-token-file 模式（模拟跨用户部署）
        const secretFile = path.join(dir, "read-token.secret");
        fs.writeFileSync(secretFile, `${rotated.readToken}\n`, { mode: 0o600 });
        const resFile = await runPersonalWebSetup(app, {
          socket: gw.sockPath,
          readTokenFile: secretFile,
          env: {},
        });
        assert.equal(resFile.readTokenOrigin, "file");
        assert.equal(resFile.reachable, true);

        // 8) doctor 对 0644 宽松权限 gateway.env 报错，以及对 gateway.env 残留 reply_token 告警
        writeGatewayEnvFile(app.cfg.dataDir, {
          FEISHU_GW_READ_TOKEN: rotated.readToken,
          FEISHU_GW_REPLY_TOKEN: rotated.replyToken,
        });
        const docResidual = await runDoctor(app, { env: {} });
        const bWarn = docResidual.checks.find((c) => c.id === "personal_web_boundary");
        assert.equal(bWarn?.status, "warn");
        assert.match(bWarn?.detail ?? "", /仍存在 reply_token/);
        assert.match(bWarn?.fix ?? "", /web-setup --no-reply/);

        fs.chmodSync(gatewayEnvFilePath(app.cfg.dataDir), 0o644);
        const docLoose = await runDoctor(app, { env: {} });
        const pwLoose = docLoose.checks.find((c) => c.id === "personal_web");
        assert.equal(pwLoose?.status, "fail");
        assert.match(pwLoose?.detail ?? "", /权限过于宽松|0600/);
        assert.match(pwLoose?.fix ?? "", /chmod 600/);

        // 9) 切换到回环 --url 时自动清空 gateway_socket；网关未监听时保留配置并提示
        const resUrl = await runPersonalWebSetup(app, {
          url: "http://127.0.0.1:19999",
          readToken: rotated.readToken,
          env: {},
        });
        assert.equal(resUrl.reachable, false);
        assert.equal(resUrl.gatewaySocket, "");
        assert.equal(resUrl.gatewayUrl, "http://127.0.0.1:19999");
        assert.ok(resUrl.warnings.some((w) => w.includes("无法连接到网关")));
        const reloadedUrl = loadConfig(cfgFile);
        assert.equal(reloadedUrl.context.personal_web.gateway_socket, "");
        assert.equal(reloadedUrl.context.personal_web.gateway_url, "http://127.0.0.1:19999");

        // 非回环 URL 拒绝
        await assert.rejects(
          runPersonalWebSetup(app, { url: "http://192.168.1.2:7879", readToken: rotated.readToken, noVerify: true, env: {} }),
          /回环地址/,
        );
      } finally {
        await gwServer2.stop();
      }
    } finally {
      app.store.db.close();
      await gw.close();
      if (prevKey === undefined) delete process.env.FEISHU_GW_KEY;
      else process.env.FEISHU_GW_KEY = prevKey;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("CLI 端到端：bin/pa context web-setup / web-status（无环境变量纯靠 gateway.env）与 bin/pa init 末尾只读检测", async () => {
    const dir = makeTmp("pa-cli-web-setup-");
    const prevKey = process.env.FEISHU_GW_KEY;
    process.env.FEISHU_GW_KEY = "test-setup-gw-key-32bytes-000001";
    const gw = await startLocalGateway(dir, { allowReply: false, loggedIn: true });
    const cfgFile = writeCommentedAvatarConfig(dir, { personalWeb: { enabled: false, gateway_socket: "" } });
    const stubState = path.join(dir, "stub-state.json");
    const cleanEnv: NodeJS.ProcessEnv = { ...process.env, PA_CONFIG: cfgFile, STUB_STATE: stubState };
    delete cleanEnv.FEISHU_GW_READ_TOKEN;
    delete cleanEnv.FEISHU_GW_REPLY_TOKEN;
    delete cleanEnv.CREDENTIALS_DIRECTORY;
    delete cleanEnv.FEISHU_GW_CONFIG;

    try {
      const paBin = path.join(ROOT, "bin", "pa");

      // 1) 未启用时 pa init 正常完成并显示未启用提示
      const { stdout: initDisabledOut } = await execFileAsync(paBin, ["init"], { env: cleanEnv, encoding: "utf8", cwd: dir });
      assert.match(initDisabledOut, /✅ 初始化完成/);
      assert.match(initDisabledOut, /个人 Web 网关：未启用/);

      // 2) 运行 pa context web-setup（完全不设置 FEISHU_GW_READ_TOKEN）
      const { stdout: setupOut } = await execFileAsync(paBin, ["context", "web-setup", "--gateway-config", gw.gwCfgFile], {
        env: cleanEnv,
        encoding: "utf8",
        cwd: dir,
      });
      assert.match(setupOut, /✅ 个人 Web 网关配置已完成/);
      assert.match(setupOut, /权限 0600/);
      assert.match(setupOut, /测试主人/);
      assert.ok(!setupOut.includes(gw.tokens.readToken), "CLI 输出绝不能泄露明文 read_token");
      assert.ok(!setupOut.includes(gw.tokens.replyToken), "CLI 输出绝不能泄露明文 reply_token");

      // 3) 运行 pa context web-status（无环境变量，自动从 gateway.env 加载）
      const { stdout: statusOut } = await execFileAsync(paBin, ["context", "web-status"], { env: cleanEnv, encoding: "utf8", cwd: dir });
      assert.match(statusOut, /只读令牌：已配置（gateway\.env）/);
      assert.match(statusOut, /网关账号：测试主人/);

      // 4) 已启用 + 有效 gateway.env 时 pa init 末尾输出 ✅
      const { stdout: initOkOut } = await execFileAsync(paBin, ["init"], { env: cleanEnv, encoding: "utf8", cwd: dir });
      assert.match(initOkOut, /✅ 初始化完成/);
      assert.match(initOkOut, /个人 Web 网关：✅ 测试主人/);
      assert.match(initOkOut, /gateway\.env/);

      // 5) 删除 gateway.env 后 pa init 仍成功完成飞书初始化，并在末尾输出 ❌ 与修复指引
      fs.rmSync(gatewayEnvFilePath(path.join(dir, "avatar-data")));
      const { stdout: initMissingOut } = await execFileAsync(paBin, ["init"], { env: cleanEnv, encoding: "utf8", cwd: dir });
      assert.match(initMissingOut, /✅ 初始化完成/);
      assert.match(initMissingOut, /个人 Web 网关：❌ 缺少网关只读令牌/);
      assert.match(initMissingOut, /pa context web-setup/);
    } finally {
      await gw.close();
      if (prevKey === undefined) delete process.env.FEISHU_GW_KEY;
      else process.env.FEISHU_GW_KEY = prevKey;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("安全与边界回归：显式 --socket/--url 隔离默认 tokens.json、read_token_env 空值写回、.bak 0600 权限、403/404/409 fail-fast、gateway.yaml 形态与 PersonalWebBridge 纯 gateway.env 运行", async () => {
    const dir = makeTmp("pa-web-setup-edge-");
    const prevKey = process.env.FEISHU_GW_KEY;
    process.env.FEISHU_GW_KEY = "test-setup-gw-key-32bytes-000001";
    const gw = await startLocalGateway(dir, { allowReply: false, loggedIn: true });

    // 启动一个可编程 mock HTTP 服务：用于测试非网关 404、--verify 返回 409 account_mismatch 与 503
    let mockMode: "not_found" | "verify_409" | "verify_503" = "not_found";
    const mockSrv = http.createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://127.0.0.1");
      if (mockMode === "not_found") {
        res.writeHead(404, { "content-type": "text/plain" });
        res.end("not a gateway");
        return;
      }
      if (u.pathname === "/v1/status" && u.searchParams.get("verify") === "1") {
        if (mockMode === "verify_409") {
          res.writeHead(409, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: false, code: "account_mismatch", error: "网关已绑定旧账号，请 --force-switch-account" }));
          return;
        }
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, code: "verify_failed", error: "上游飞书暂不可达" }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          state: "listening",
          logged_in: true,
          credential_status: "ok",
          owner_id: "1001",
          owner_name: "Mock主人",
          allow_reply: false,
          cached_events: 0,
          min_seq: 0,
          latest_seq: 0,
          db_epoch: "ep-mock",
        }),
      );
    });
    await new Promise<void>((resolve) => mockSrv.listen(0, "127.0.0.1", resolve));
    const mockPort = (mockSrv.address() as { port: number }).port;
    const mockUrl = `http://127.0.0.1:${mockPort}`;

    try {
      // 1) 显式 --socket 时不读取默认 gateway.yaml / tokens.json，直接采用环境变量令牌；且 .bak 保持 0600 权限
      const cfgFile = path.join(dir, "config-0600.yaml");
      fs.writeFileSync(
        cfgFile,
        `owner: { open_id: ou_owner }
data_dir: ${path.join(dir, "d1")}
harnesses: { brain: { agent: claude } }
roles: { brain: brain }
context:
  enabled: false
  personal_web:
    enabled: false
    read_token_env: ""
    reply_token_env: ""
`,
        { mode: 0o600 },
      );
      fs.chmodSync(cfgFile, 0o600);
      // 预置一个宽松权限的旧 .bak，验证写入后收紧回 0600
      fs.writeFileSync(`${cfgFile}.bak`, "stale-backup", { mode: 0o644 });
      fs.chmodSync(`${cfgFile}.bak`, 0o644);

      const app1 = createApp(loadConfig(cfgFile));
      try {
        // 空参数拒绝
        await assert.rejects(runPersonalWebSetup(app1, { socket: "   ", env: {} }), /--socket 不能为空/);
        await assert.rejects(runPersonalWebSetup(app1, { readToken: "", env: {} }), /--read-token 不能为空/);
        // 互斥参数与相同令牌拒绝
        await assert.rejects(runPersonalWebSetup(app1, { socket: gw.sockPath, url: mockUrl, env: {} }), /只能二选一/);
        await assert.rejects(runPersonalWebSetup(app1, { withReply: true, noReply: true, env: {} }), /不能同时指定/);
        await assert.rejects(runPersonalWebSetup(app1, { verify: true, noVerify: true, env: {} }), /不能同时指定/);
        await assert.rejects(runPersonalWebSetup(app1, { replyToken: "r", env: {} }), /必须同时指定 --with-reply/);
        await assert.rejects(
          runPersonalWebSetup(app1, {
            socket: gw.sockPath,
            readToken: gw.tokens.readToken,
            withReply: true,
            replyToken: gw.tokens.readToken,
            noVerify: true,
            env: {},
          }),
          /不能相同/,
        );

        // 403 insufficient_scope（误传 reply_token 给 --read-token）必须保留原消息并 fail-fast
        await assert.rejects(
          runPersonalWebSetup(app1, { socket: gw.sockPath, readToken: gw.tokens.replyToken, env: {} }),
          /insufficient_scope.*reply_token/,
        );

        // 显式 --socket + env 传入正确 token，即使 FEISHU_GW_CONFIG 指向坏配置也不会越界读取
        const res1 = await runPersonalWebSetup(app1, {
          socket: gw.sockPath,
          env: { FEISHU_GW_READ_TOKEN: gw.tokens.readToken, FEISHU_GW_CONFIG: path.join(dir, "non-existent.yaml") },
        });
        assert.equal(res1.readTokenOrigin, "env");
        assert.equal(res1.reachable, true);
        // context.enabled: false 应给出明确提醒
        assert.ok(res1.warnings.some((w) => w.includes("context.enabled 为 false")));
        // 原来为空的 read_token_env 必须已写回 config.yaml，重启后凭 gateway.env 可直接解析
        const reloaded1 = loadConfig(cfgFile);
        assert.equal(reloaded1.context.personal_web.read_token_env, "FEISHU_GW_READ_TOKEN");
        assert.equal(resolveGatewayClientConfig(reloaded1.context.personal_web, {}, { dataDir: reloaded1.dataDir }).readToken, gw.tokens.readToken);
        // .bak 权限必须严格保持 0600
        assert.equal(fs.statSync(`${cfgFile}.bak`).mode & 0o777, 0o600, "config.yaml.bak 必须保持 0600 权限");

        // .bak 若为符号链接必须拒绝覆盖，且不产生 gateway.env 半写状态（reply_token 仍不应写入）
        const decoy = path.join(dir, "decoy.txt");
        fs.writeFileSync(decoy, "do-not-touch");
        fs.rmSync(`${cfgFile}.bak`);
        fs.symlinkSync(decoy, `${cfgFile}.bak`);
        await assert.rejects(
          runPersonalWebSetup(app1, { socket: gw.sockPath, readToken: gw.tokens.readToken, withReply: true, replyToken: gw.tokens.replyToken, noVerify: true, env: {} }),
          /符号链接/,
        );
        assert.equal(fs.readFileSync(decoy, "utf8"), "do-not-touch");
        assert.equal(readGatewayEnvFile(app1.cfg.dataDir).values.FEISHU_GW_REPLY_TOKEN, undefined, ".bak 拒绝覆盖时不得半写 gateway.env");
        fs.rmSync(`${cfgFile}.bak`);

        // --no-reply 在存在其他地址的 gateway.yaml 时，必须保留已有自定义地址，且绝不从无关 gateway.yaml 的 tokens.json 覆盖已有令牌
        const customUrl = "http://127.0.0.1:19888";
        const customReadTok = "custom-endpoint-read-tok-999";
        const customReplyTok = "custom-endpoint-reply-tok-999";
        await runPersonalWebSetup(app1, { url: customUrl, readToken: customReadTok, withReply: true, replyToken: customReplyTok, noVerify: true, env: {} });
        const resNoReplyKeepAddr = await runPersonalWebSetup(app1, {
          noReply: true,
          noVerify: true,
          env: { FEISHU_GW_CONFIG: gw.gwCfgFile },
        });
        assert.equal(resNoReplyKeepAddr.gatewayUrl, customUrl, "--no-reply 不得覆盖已有自定义网关地址");
        assert.equal(resNoReplyKeepAddr.gatewaySocket, "");
        assert.equal(resNoReplyKeepAddr.readTokenOrigin, "env_file", "自定义端点不应读取无关 gateway.yaml 的 tokens.json");
        assert.equal(readGatewayEnvFile(app1.cfg.dataDir).values.FEISHU_GW_READ_TOKEN, customReadTok);
        assert.equal(readGatewayEnvFile(app1.cfg.dataDir).values.FEISHU_GW_REPLY_TOKEN, undefined);

        // 2) 非网关 404 fail-fast（不修改配置文件）
        const beforeNonGw = fs.readFileSync(cfgFile, "utf8");
        mockMode = "not_found";
        await assert.rejects(
          runPersonalWebSetup(app1, { url: mockUrl, readToken: "any-tok-1234567890", env: {} }),
          /非网关协议响应.*404/,
        );
        assert.equal(fs.readFileSync(cfgFile, "utf8"), beforeNonGw);

        // 3) --verify 返回 409 account_mismatch 必须 fail-fast（不修改配置文件）
        mockMode = "verify_409";
        await assert.rejects(
          runPersonalWebSetup(app1, { url: mockUrl, readToken: "any-tok-1234567890", verify: true, env: {} }),
          /account_mismatch/,
        );
        assert.equal(fs.readFileSync(cfgFile, "utf8"), beforeNonGw);

        // 4) --verify 返回 503 时保持 reachable=true 且仅告警，不误报无法连接网关
        mockMode = "verify_503";
        const res503 = await runPersonalWebSetup(app1, { url: mockUrl, readToken: "any-tok-1234567890", verify: true, env: {} });
        assert.equal(res503.reachable, true);
        assert.equal(res503.verifiedOnline, false);
        assert.ok(res503.warnings.some((w) => w.includes("飞书在线会话核验失败")));
        assert.ok(!res503.warnings.some((w) => w.includes("当前无法连接到网关")));
      } finally {
        app1.store.db.close();
      }

      // 5) gateway.yaml 多种形态：IPv6 TCP、socket 与 host/port 冲突、离线 allow_reply=false 提醒、以及最小无 context 节点 config.yaml
      const minCfgFile = path.join(dir, "minimal-config.yaml");
      fs.writeFileSync(
        minCfgFile,
        `owner: { open_id: ou_owner }
data_dir: ${path.join(dir, "d2")}
harnesses: { brain: { agent: claude } }
roles: { brain: brain }
`,
      );
      const app2 = createApp(loadConfig(minCfgFile));
      try {
        // 冲突 gateway.yaml（同时有默认 socket 和 host/port）报错
        const badGwYaml = path.join(dir, "bad-gw.yaml");
        fs.writeFileSync(badGwYaml, YAML.stringify({ listen: { host: "127.0.0.1", port: 7879 } }));
        await assert.rejects(runPersonalWebSetup(app2, { gatewayConfig: badGwYaml, noVerify: true, env: {} }), /二选一/);

        // FEISHU_GW_CONFIG 指向不存在文件报错
        await assert.rejects(
          runPersonalWebSetup(app2, { noVerify: true, env: { FEISHU_GW_CONFIG: path.join(dir, "missing-gw.yaml") } }),
          /无法读取网关配置文件/,
        );

        // IPv6 TCP 回环 + allow_reply: false 离线 --with-reply 提醒 + shell env 覆盖提醒
        const v6GwYaml = path.join(dir, "v6-gw.yaml");
        fs.writeFileSync(
          v6GwYaml,
          YAML.stringify({ data_dir: path.join(dir, "v6-data"), listen: { socket: "", host: "::1", port: 19789 }, allow_reply: false }),
        );
        const resV6 = await runPersonalWebSetup(app2, {
          gatewayConfig: v6GwYaml,
          readToken: "tok-read-v6-123456",
          withReply: true,
          replyToken: "tok-reply-v6-123456",
          noVerify: true,
          env: { FEISHU_GW_READ_TOKEN: "stale-env-token-old" },
        });
        assert.equal(resV6.gatewayUrl, "http://[::1]:19789");
        assert.equal(resV6.gatewaySocket, "");
        assert.ok(resV6.warnings.some((w) => w.includes("allow_reply 为 false")));
        assert.ok(resV6.warnings.some((w) => w.includes("环境变量优先级更高")));
        const reloadedMin = loadConfig(minCfgFile);
        assert.equal(reloadedMin.context.personal_web.enabled, true);
        assert.equal(reloadedMin.context.personal_web.gateway_url, "http://[::1]:19789");
      } finally {
        app2.store.db.close();
      }

      // 6) PersonalWebBridge 运行时纯靠 gateway.env（完全无环境变量）自动订阅 SSE 并落库观测
      const prevEnvRead = process.env.FEISHU_GW_READ_TOKEN;
      const prevEnvReply = process.env.FEISHU_GW_REPLY_TOKEN;
      const prevCred = process.env.CREDENTIALS_DIRECTORY;
      delete process.env.FEISHU_GW_READ_TOKEN;
      delete process.env.FEISHU_GW_REPLY_TOKEN;
      delete process.env.CREDENTIALS_DIRECTORY;
      const bridgeCfgFile = writeCommentedAvatarConfig(dir, {
        dataDir: path.join(dir, "bridge-data"),
        personalWeb: { enabled: true, gateway_socket: gw.sockPath, send_replies: false },
      });
      const bridgeApp = createApp(loadConfig(bridgeCfgFile));
      try {
        writeGatewayEnvFile(bridgeApp.cfg.dataDir, { FEISHU_GW_READ_TOKEN: gw.tokens.readToken });
        const ctxStore = new ContextStore(bridgeApp.store.db);
        const bridge = new PersonalWebBridge(bridgeApp, ctxStore, {
          onFastTrigger: () => undefined,
          onReconnect: () => undefined,
          onNeedsLogin: () => undefined,
          watchIntervalMs: 50,
        });
        // 预先在网关写入一条私聊消息事件
        gw.gwStore.appendMessage({
          id: "99001",
          conversationId: "dm-env-file-test",
          conversationKind: "dm",
          chatName: "张三",
          chatNameResolved: true,
          actorId: "actor-zs",
          senderType: GATEWAY_USER_SENDER_TYPE,
          text: "验证纯 gateway.env 启动 SSE 消费",
          createdAtMs: Date.now(),
          rootId: "",
          parentId: "",
          threadId: "",
          position: 1,
          mentions: [],
          resources: [],
          ownerId: "1001",
          ownerName: "测试主人",
        });
        const handle = bridge.start();
        try {
          const deadline = Date.now() + 5_000;
          while (Date.now() < deadline && !ctxStore.obs("pw:99001")) {
            await new Promise((r) => setTimeout(r, 40));
          }
          const obs = ctxStore.obs("pw:99001");
          assert.ok(obs, "PersonalWebBridge 应仅凭 gateway.env 连通 SSE 并消费事件");
          assert.match(obs.text, /纯 gateway\.env/);
        } finally {
          handle.stop();
        }
      } finally {
        bridgeApp.store.db.close();
        if (prevEnvRead === undefined) delete process.env.FEISHU_GW_READ_TOKEN;
        else process.env.FEISHU_GW_READ_TOKEN = prevEnvRead;
        if (prevEnvReply === undefined) delete process.env.FEISHU_GW_REPLY_TOKEN;
        else process.env.FEISHU_GW_REPLY_TOKEN = prevEnvReply;
        if (prevCred === undefined) delete process.env.CREDENTIALS_DIRECTORY;
        else process.env.CREDENTIALS_DIRECTORY = prevCred;
      }
    } finally {
      await new Promise<void>((resolve) => mockSrv.close(() => resolve()));
      await gw.close();
      if (prevKey === undefined) delete process.env.FEISHU_GW_KEY;
      else process.env.FEISHU_GW_KEY = prevKey;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
