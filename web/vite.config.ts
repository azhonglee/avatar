/// <reference types="vitest/config" />
import path from "node:path";
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const here = path.dirname(fileURLToPath(import.meta.url));
const backend = process.env.PA_CONSOLE_URL ?? "http://127.0.0.1:7878";

export default defineConfig({
  root: here,
  base: "/",
  plugins: [react()],
  build: {
    outDir: path.join(here, "dist"),
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 800,
  },
  server: {
    port: 5173,
    proxy: {
      // SSE 需要关闭缓冲；http-proxy 对 text/event-stream 默认就是流式转发
      "/api": { target: backend, changeOrigin: false },
      "/login": { target: backend, changeOrigin: false },
      "/logout": { target: backend, changeOrigin: false },
    },
  },
  test: {
    root: here,
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/test/setup.ts"],
    css: false,
  },
});
