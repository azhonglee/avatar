import type { App } from "./app.ts";
import { registerDoctor } from "./doctor.ts";
import { registerNotifyPrefs } from "./notify-prefs.ts";
import { registerSettings } from "./settings.ts";

/** 平台服务：设置、体检、通知偏好。 */
export function registerPlatform(app: App): void {
  registerSettings(app);
  registerDoctor(app);
  registerNotifyPrefs(app);
}
