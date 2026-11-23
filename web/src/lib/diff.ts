export interface DiffLine {
  kind: "add" | "del" | "ctx" | "hunk" | "meta";
  text: string;
  oldNo?: number;
  newNo?: number;
}

export interface DiffFile {
  path: string;
  oldPath: string;
  status: "modified" | "added" | "deleted" | "renamed" | "binary";
  adds: number;
  dels: number;
  lines: DiffLine[];
}

/** 解析 git unified diff（diff --git 分段）。 */
export function parseDiff(patch: string): DiffFile[] {
  if (!patch.trim()) return [];
  const files: DiffFile[] = [];
  const chunks = patch.replace(/\r\n/g, "\n").split(/^(?=diff --git )/m);
  for (const chunk of chunks) {
    if (!chunk.startsWith("diff --git ")) continue;
    const rows = chunk.split("\n");
    if (rows[rows.length - 1] === "") rows.pop();
    const head = rows[0].match(/^diff --git a\/(.+?) b\/(.+)$/);
    const f: DiffFile = { path: head?.[2] ?? rows[0].slice(11), oldPath: head?.[1] ?? "", status: "modified", adds: 0, dels: 0, lines: [] };
    let i = 1;
    for (; i < rows.length && !rows[i].startsWith("@@"); i++) {
      const r = rows[i];
      if (r.startsWith("new file mode")) f.status = "added";
      else if (r.startsWith("deleted file mode")) f.status = "deleted";
      else if (r.startsWith("rename to ")) {
        f.status = "renamed";
        f.path = r.slice(10);
      } else if (r.startsWith("rename from ")) f.oldPath = r.slice(12);
      else if (r.startsWith("Binary files") || r.startsWith("GIT binary patch")) f.status = "binary";
      else if (r.startsWith("+++ b/")) f.path = r.slice(6);
    }
    let oldNo = 0;
    let newNo = 0;
    for (; i < rows.length; i++) {
      const r = rows[i];
      if (r.startsWith("@@")) {
        const m = r.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
        oldNo = m ? Number(m[1]) : 0;
        newNo = m ? Number(m[2]) : 0;
        f.lines.push({ kind: "hunk", text: r });
      } else if (r.startsWith("+")) {
        f.adds++;
        f.lines.push({ kind: "add", text: r.slice(1), newNo: newNo++ });
      } else if (r.startsWith("-")) {
        f.dels++;
        f.lines.push({ kind: "del", text: r.slice(1), oldNo: oldNo++ });
      } else if (r.startsWith("\\")) {
        f.lines.push({ kind: "meta", text: r });
      } else {
        f.lines.push({ kind: "ctx", text: r.slice(1), oldNo: oldNo++, newNo: newNo++ });
      }
    }
    files.push(f);
  }
  return files;
}
