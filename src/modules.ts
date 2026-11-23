import type { App } from "./app.ts";
import { registerDelivery } from "./delivery/index.ts";
import { registerPlatform } from "./platform.ts";

/**
 * 可选模块注册表。每个模块提供 register(app)：注册命令、填充 app.ext、订阅 app.bus、设置钩子。
 * 新模块在这里加一行即可；模块之间不直接互相引用，只通过 app.commands / app.ext / app.bus 交互。
 */
export function registerModules(app: App): void {
  registerDelivery(app);
  registerPlatform(app);
}
