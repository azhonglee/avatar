import fs from "node:fs";
import { parseArgs } from "node:util";
import { defaultGatewayConfigPath, loadGatewayConfig } from "./config.ts";
import { beginLogin, pollLogin, renderQrSvg, renderQrTerminal, WebLoginStore } from "./feishu-web/index.ts";
import { startGatewayServer } from "./server.ts";
import { commitGatewayLogin, FeishuGatewayService } from "./service.ts";
import { GatewayStore } from "./store.ts";

const USAGE = `用法：feishu-gateway <命令> [选项]

  run [--config <gateway.yaml>]                     常驻运行独立飞书个人 Web 网关服务
  login [--config <file>] [--out qr.svg] [--force-switch-account]
                                                    扫码登录并保存 AES-256-GCM 加密凭据（需配置 FEISHU_GW_KEY 或 PA_FEISHU_WEB_KEY）
  status [--config <file>] [--verify]               查看网关凭据、缓存与连接状态（--verify 在线核验飞书会话）
  logout [--config <file>]                          清除网关本地加密凭据（运行中的网关将在数秒内自动断开）
  tokens [--config <file>] [--rotate-read] [--rotate-reply] [--force-file]
                                                    查看或轮换读写分离双令牌（read_token / reply_token）
`;

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
    process.stdout.write(USAGE);
    return;
  }

  const { values } = parseArgs({
    args: rest,
    options: {
      config: { type: "string" },
      out: { type: "string" },
      verify: { type: "boolean" },
      "force-switch-account": { type: "boolean" },
      "rotate-read": { type: "boolean" },
      "rotate-reply": { type: "boolean" },
      "force-file": { type: "boolean" },
    },
    allowPositionals: true,
  });

  const explicitCfg = values.config?.trim() || process.env.FEISHU_GW_CONFIG?.trim();
  const cfgPath = explicitCfg || defaultGatewayConfigPath();
  const cfg = loadGatewayConfig(cfgPath, { required: !!explicitCfg });
  const store = new GatewayStore(cfg.dataDir);

  try {
    switch (cmd) {
      case "run": {
        const tokens = store.resolveTokens();
        store.recordTokenSources(tokens);
        const service = new FeishuGatewayService(cfg, store);
        const server = await startGatewayServer(cfg, service, tokens);
        service.start();
        const st = service.status();
        console.log(`✅ 飞书个人 Web 网关已启动`);
        console.log(`监听地址：${server.address}${server.socketPath ? `（mode ${cfg.listen.socket_mode}）` : ""}`);
        console.log(`数据目录：${cfg.dataDir}`);
        console.log(`回复总闸门（allow_reply）：${cfg.allow_reply ? "已开启" : "已关闭（默认安全模式）"}`);
        console.log(`强制排除规则（deny_chats）：${cfg.deny_chats.length} 条`);
        console.log(`令牌来源：read=${tokens.readSource}，reply=${tokens.replySource}`);
        console.log(`登录状态：${st.logged_in ? `${st.owner_name || st.owner_id}` : `${st.credential_status}（运行 feishu-gateway login 扫码）`}`);

        await new Promise<void>((resolve) => {
          const shutdown = () => resolve();
          process.once("SIGINT", shutdown);
          process.once("SIGTERM", shutdown);
        });
        console.log("正在停止飞书个人 Web 网关…");
        await service.stop();
        await server.stop();
        return;
      }

      case "login": {
        if (!WebLoginStore.hasEncryptionKey()) {
          throw new Error(
            "执行 feishu-gateway login 前必须配置加密密钥（例如 export FEISHU_GW_KEY=$(openssl rand -hex 32) 或 systemd LoadCredential=feishu-gw-key:...），拒绝明文写入会话 Cookie",
          );
        }
        console.log("正在向飞书申请个人 Web 登录二维码…");
        const challenge = await beginLogin();
        console.log("\n" + renderQrTerminal(challenge.qrCode) + "\n");
        if (values.out) {
          fs.writeFileSync(values.out, renderQrSvg(challenge.qrCode), "utf8");
          console.log(`已将二维码写入：${values.out}`);
        }
        const deadline = new Date(challenge.expiresAtMs).toLocaleTimeString("zh-CN", { timeZone: cfg.timezone, hour12: false });
        console.log(`请用本人飞书 App 扫码确认（有效期至 ${deadline}，按 Ctrl+C 取消）…`);
        const ctrl = new AbortController();
        const onSig = () => ctrl.abort();
        process.once("SIGINT", onSig);
        process.once("SIGTERM", onSig);
        try {
          const login = await pollLogin(challenge, {
            signal: ctrl.signal,
            onProgress: (st) => {
              if (st === "scanned") console.log("📱 已扫码，请在手机飞书上点击「确认登录」…");
              if (st === "approved") console.log("✅ 已确认，正在验证账号并保存加密凭据…");
            },
          });
          const loginStore = new WebLoginStore(cfg.dataDir);
          const { saved, switched, previousOwnerId, dbEpoch } = commitGatewayLogin(store, loginStore, login, {
            forceSwitch: !!values["force-switch-account"],
          });
          console.log(`✅ 网关个人 Web 登录成功：${saved.owner_name || "(无昵称)"}（ID: ${saved.owner_id}）`);
          if (switched) {
            console.log(`⚠️ 已强制切换绑定账号（${previousOwnerId} -> ${saved.owner_id}）：已清空旧账号的事件日志、会话缓存与投递账本，并轮换 db_epoch=${dbEpoch}。`);
            console.log("提示：如 Avatar 工作区此前绑定了旧账号，请在 Avatar 侧执行 `pa context web-unbind` 解除绑定后再重新同步。");
          }
          console.log(`加密凭据（AES-256-GCM, 0600）已保存到：${loginStore.file}`);
          console.log("提示：若 `feishu-gateway run` 正在运行，将在数秒内自动加载新凭据并建立长连接。");
        } finally {
          process.off("SIGINT", onSig);
          process.off("SIGTERM", onSig);
        }
        return;
      }

      case "logout": {
        const loginStore = new WebLoginStore(cfg.dataDir);
        loginStore.clear();
        store.deleteKv("state");
        console.log(`已清除网关个人 Web 登录凭据（${loginStore.file}）。若 feishu-gateway run 正在运行，将在数秒内自动断开。`);
        return;
      }

      case "status": {
        const service = new FeishuGatewayService(cfg, store);
        const st = service.status();
        const listenDesc = cfg.socketPath ? `unix://${cfg.socketPath} (mode ${cfg.listen.socket_mode})` : `http://${cfg.listen.host}:${cfg.listen.port}`;
        console.log(`配置文件：${cfg.file}`);
        console.log(`数据目录：${cfg.dataDir}`);
        console.log(`监听目标：${listenDesc}`);
        console.log(`回复开关：allow_reply=${cfg.allow_reply}，网关排除规则=${cfg.deny_chats.length} 条`);
        console.log(`凭据状态：${st.credential_status}${st.logged_in ? `（${st.owner_name || st.owner_id}）` : ""}`);
        console.log(`运行状态：${st.state}，缓存事件 ${st.cached_events} 条（seq ${st.min_seq}..${st.latest_seq}）`);
        if (st.last_message_at) {
          console.log(`最近消息：${new Date(st.last_message_at).toLocaleString("zh-CN", { timeZone: cfg.timezone, hour12: false })}`);
        }
        if (st.last_error) console.log(`最近错误：${st.last_error}`);
        if (values.verify) {
          const verified = await service.verifyStatus();
          console.log(`✅ 在线核验通过：${verified.owner_name || verified.owner_id}（ID: ${verified.owner_id}）`);
        }
        return;
      }

      case "tokens": {
        const tokens = store.resolveTokens({
          rotateRead: !!values["rotate-read"],
          rotateReply: !!values["rotate-reply"],
          rejectConflictingFileGeneration: !values["force-file"],
        });
        if (tokens.readSource === "file" || tokens.replySource === "file") {
          console.log(`令牌文件：${tokens.file}`);
        } else {
          console.log("令牌来源：外部注入（环境变量 / systemd LoadCredential，未使用本地 tokens.json）");
        }
        console.log(`read_token  (${tokens.readSource}): ${tokens.readToken}`);
        console.log(`reply_token (${tokens.replySource}): ${tokens.replyToken}`);
        console.log("\nAvatar 客户端环境变量示例（仅只读消费时无需提供 REPLY 令牌）：");
        console.log(`  export FEISHU_GW_READ_TOKEN='${tokens.readToken}'`);
        if (cfg.allow_reply) {
          console.log(`  export FEISHU_GW_REPLY_TOKEN='${tokens.replyToken}'`);
        } else {
          console.log("  # 当前 gateway.yaml 的 allow_reply 为 false，未开启回复能力");
        }
        if (values["rotate-read"] || values["rotate-reply"]) {
          console.log("\n⚠️ 令牌已轮换：请重启 `feishu-gateway run` 并更新客户端环境变量。");
        }
        return;
      }

      default:
        process.stdout.write(USAGE);
        process.exitCode = 2;
    }
  } finally {
    store.close();
  }
}

main().catch((e) => {
  console.error(`错误：${errMsg(e)}`);
  process.exit(1);
});
