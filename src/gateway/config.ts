import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";
import { z } from "zod";
import { isLoopbackHostname, isValidOctalSocketMode, parseSocketMode } from "./protocol.ts";

/** 仓库根目录（用于默认查找 gateway.yaml）。 */
const GATEWAY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

export function expandHomePath(p: string): string {
  return p.startsWith("~/") ? path.join(os.homedir(), p.slice(2)) : p;
}

const GatewaySchema = z.object({
  /** 网关独占的数据目录（建议 0700，存放加密凭据、SQLite 缓存与 tokens.json） */
  data_dir: z.string().default("~/.feishu-gateway"),
  listen: z
    .object({
      /** Unix Domain Socket 路径（推荐：与独立 OS 用户 / 属组 0660 配合形成内核级隔离）；与 host/port 二选一 */
      socket: z.string().default("~/.feishu-gateway/run/gateway.sock"),
      /** Socket 文件权限（八进制，禁止 world 权限，默认 0660 允许同组客户端连接） */
      socket_mode: z.string().default("0660"),
      /** 可选回环 TCP 地址（仅允许 127.0.0.1 / localhost / ::1；填写时需清空 socket） */
      host: z.string().default(""),
      /** 可选回环 TCP 端口（与 host 配合使用） */
      port: z.number().int().min(0).max(65535).default(0),
    })
    .prefault({}),
  /** 网关侧回复总闸门（默认关闭：即便客户端有 reply_token 也会拒绝发送，需显式开启） */
  allow_reply: z.boolean().default(false),
  /** 网关侧强制排除的会话（原生 chat_id、pw_chat:<id> 或群名/私聊名关键字；客户端无法通过 API 绕过） */
  deny_chats: z.array(z.string()).default([]),
  /** 本地消息事件缓存保留天数（撤回消息会立即清除正文） */
  retention_days: z.number().int().min(1).max(90).default(7),
  /** 已完成/终态发送幂等记录保留天数 */
  delivery_retention_days: z.number().int().min(1).max(365).default(30),
  /** 日志与 CLI 显示时区 */
  timezone: z.string().default("Asia/Shanghai"),
});

export type GatewayConfig = z.infer<typeof GatewaySchema> & {
  dataDir: string;
  file: string;
  socketPath: string;
  socketMode: number;
};

export const GatewayConfigSchema = GatewaySchema;

export function defaultGatewayConfigPath(): string {
  return process.env.FEISHU_GW_CONFIG?.trim() || path.join(GATEWAY_ROOT, "gateway.yaml");
}

export function loadGatewayConfig(file = defaultGatewayConfigPath()): GatewayConfig {
  let raw: unknown = {};
  if (fs.existsSync(file)) {
    raw = YAML.parse(fs.readFileSync(file, "utf8")) ?? {};
  } else if (process.env.FEISHU_GW_CONFIG?.trim()) {
    throw new Error(`找不到网关配置文件 ${file}`);
  }
  const parsed = GatewaySchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error(`网关配置文件 ${file} 有误：\n${z.prettifyError(parsed.error)}`);
  }
  const cfg = parsed.data;
  const socketRaw = cfg.listen.socket.trim();
  const host = cfg.listen.host.trim();
  const port = cfg.listen.port;
  const useTcp = host.length > 0 || port > 0;

  if (socketRaw && useTcp) {
    throw new Error("listen.socket 与 listen.host/port 只能二选一；如需使用 TCP 回环监听，请将 listen.socket 设为空字符串");
  }
  if (!socketRaw && !useTcp) {
    throw new Error("必须配置 listen.socket 或 listen.host + listen.port 之一");
  }
  if (useTcp) {
    if (!host || !isLoopbackHostname(host)) {
      throw new Error(`出于安全隔离要求，网关 TCP 监听仅允许回环地址（127.0.0.1 / localhost / ::1），拒绝：${host || "(空)"}`);
    }
    if (port < 1) {
      throw new Error("启用 TCP 监听时 listen.port 必须在 1..65535 之间");
    }
  }
  if (!isValidOctalSocketMode(cfg.listen.socket_mode)) {
    throw new Error(`listen.socket_mode「${cfg.listen.socket_mode}」不合法：仅允许属主可读写且不对 other 开放权限（如 0600 / 0660）`);
  }

  const dataDir = path.resolve(expandHomePath(cfg.data_dir));
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const socketPath = socketRaw ? path.resolve(expandHomePath(socketRaw)) : "";

  return {
    ...cfg,
    dataDir,
    file,
    socketPath,
    socketMode: parseSocketMode(cfg.listen.socket_mode),
  };
}
