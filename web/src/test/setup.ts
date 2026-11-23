import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

if (typeof Element !== "undefined" && !Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = () => undefined;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
