import { describe, expect, it } from "vitest";
import { parseDiff } from "./diff.ts";

describe("parseDiff", () => {
  it("parses modified, added, deleted, and binary diff sections", () => {
    const patch = [
      "diff --git a/src/a.ts b/src/a.ts",
      "index 111..222 100644",
      "--- a/src/a.ts",
      "+++ b/src/a.ts",
      "@@ -1,3 +1,4 @@",
      " const x = 1;",
      "-const y = 2;",
      "+const y = 3;",
      "+const z = 4;",
      "diff --git a/src/new.ts b/src/new.ts",
      "new file mode 100644",
      "--- /dev/null",
      "+++ b/src/new.ts",
      "@@ -0,0 +1 @@",
      "+export const ok = true;",
      "diff --git a/logo.png b/logo.png",
      "Binary files a/logo.png and b/logo.png differ",
      "",
    ].join("\n");

    const files = parseDiff(patch);
    expect(files).toHaveLength(3);
    expect(files[0]).toMatchObject({ path: "src/a.ts", status: "modified", adds: 2, dels: 1 });
    expect(files[0].lines.map((l) => l.kind)).toEqual(["hunk", "ctx", "del", "add", "add"]);
    expect(files[1]).toMatchObject({ path: "src/new.ts", status: "added", adds: 1, dels: 0 });
    expect(files[2]).toMatchObject({ path: "logo.png", status: "binary", adds: 0, dels: 0 });
  });

  it("returns empty array for blank patch", () => {
    expect(parseDiff("   \n")).toEqual([]);
  });
});
