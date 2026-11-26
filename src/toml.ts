/**
 * 零外部依赖的 TOML 1.0 递归下降解析器（面向 Codex `config.toml` 与 `-c key=value` 严格解析）。
 * 完整支持：
 *   - 单行/多行基础字符串（"..." / """..."""，含完整转义与行尾反斜杠续行）
 *   - 单行/多行字面量字符串（'...' / '''...'''，字符串内部任意 `[xxx]` 绝不会误识别为表头）
 *   - 裸键 / 引号键 / 点分键路径（a.b."c.d"）
 *   - 标准表 `[a.b]`、表数组 `[[a.b]]`、内联表 `{ k = v }`、多行数组 `[ ... ]`
 *   - 布尔、整数/浮点（含下划线、进制前缀、inf/nan）与 RFC 3339 日期时间字面量
 * 遇到任何无法解析的非法/未闭合语法立即抛错（fail-closed），绝不静默跳过或误归表。
 */

export type TomlValue = string | number | boolean | TomlValue[] | TomlTable;
export interface TomlTable {
  [key: string]: TomlValue;
}

function emptyTable(): TomlTable {
  return Object.create(null) as TomlTable;
}

class TomlParser {
  private readonly src: string;
  private pos = 0;

  constructor(src: string) {
    // 统一换行符，简化多行字符串与换行判断
    this.src = src.replace(/\r\n/g, "\n");
  }

  private eof(): boolean {
    return this.pos >= this.src.length;
  }

  private peek(offset = 0): string {
    return this.src[this.pos + offset] ?? "";
  }

  private skipSpaces(): void {
    while (this.pos < this.src.length) {
      const ch = this.src[this.pos];
      if (ch === " " || ch === "\t") this.pos++;
      else break;
    }
  }

  private skipComment(): void {
    if (this.peek() === "#") {
      while (!this.eof() && this.peek() !== "\n") this.pos++;
    }
  }

  private skipWsAndComments(): void {
    while (!this.eof()) {
      const ch = this.peek();
      if (ch === " " || ch === "\t" || ch === "\n") {
        this.pos++;
      } else if (ch === "#") {
        this.skipComment();
      } else {
        break;
      }
    }
  }

  private expectLineEnd(): void {
    this.skipSpaces();
    this.skipComment();
    if (this.eof()) return;
    if (this.peek() === "\n") {
      this.pos++;
      return;
    }
    throw new Error(`TOML 语法错误：行尾存在多余字符 "${this.src.slice(this.pos, this.pos + 24)}"`);
  }

  parseDocument(): TomlTable {
    const root: TomlTable = emptyTable();
    let current: TomlTable = root;

    while (!this.eof()) {
      this.skipWsAndComments();
      if (this.eof()) break;

      if (this.peek() === "[") {
        const isArrayTable = this.peek(1) === "[";
        this.pos += isArrayTable ? 2 : 1;
        this.skipSpaces();
        const path = this.parseKeyPath();
        this.skipSpaces();
        if (isArrayTable) {
          if (this.peek() !== "]" || this.peek(1) !== "]") {
            throw new Error("TOML 语法错误：表数组头缺少闭合 ]]");
          }
          this.pos += 2;
          this.expectLineEnd();
          current = this.openArrayTable(root, path);
        } else {
          if (this.peek() !== "]") {
            throw new Error("TOML 语法错误：表头缺少闭合 ]");
          }
          this.pos += 1;
          this.expectLineEnd();
          current = this.openTable(root, path);
        }
        continue;
      }

      const path = this.parseKeyPath();
      this.skipSpaces();
      if (this.peek() !== "=") {
        throw new Error(`TOML 语法错误：键 "${path.join(".")}" 后缺少 '='`);
      }
      this.pos++;
      this.skipSpaces();
      const val = this.parseValue();
      this.expectLineEnd();
      this.assignKey(current, path, val);
    }

    return root;
  }

  parseStandaloneValue(): TomlValue {
    this.skipWsAndComments();
    const val = this.parseValue();
    this.skipWsAndComments();
    if (!this.eof()) {
      throw new Error(`TOML 值后存在多余字符 "${this.src.slice(this.pos, this.pos + 24)}"`);
    }
    return val;
  }

  parseStandaloneKeyPath(): string[] {
    this.skipSpaces();
    const path = this.parseKeyPath();
    this.skipSpaces();
    if (!this.eof()) {
      throw new Error(`TOML 键路径存在多余字符 "${this.src.slice(this.pos, this.pos + 24)}"`);
    }
    return path;
  }

  private openTable(root: TomlTable, path: string[]): TomlTable {
    let cur: TomlTable = root;
    for (const seg of path) {
      const existing = cur[seg];
      if (existing === undefined) {
        const next: TomlTable = emptyTable();
        cur[seg] = next;
        cur = next;
      } else if (Array.isArray(existing)) {
        const last = existing[existing.length - 1];
        if (!isPlainTable(last)) {
          throw new Error(`TOML 表路径冲突：${path.join(".")}`);
        }
        cur = last;
      } else if (isPlainTable(existing)) {
        cur = existing;
      } else {
        throw new Error(`TOML 表路径与标量键冲突：${path.join(".")}`);
      }
    }
    return cur;
  }

  private openArrayTable(root: TomlTable, path: string[]): TomlTable {
    let cur: TomlTable = root;
    for (let i = 0; i < path.length - 1; i++) {
      const seg = path[i];
      const existing = cur[seg];
      if (existing === undefined) {
        const next: TomlTable = emptyTable();
        cur[seg] = next;
        cur = next;
      } else if (Array.isArray(existing)) {
        const last = existing[existing.length - 1];
        if (!isPlainTable(last)) throw new Error(`TOML 表数组路径冲突：${path.join(".")}`);
        cur = last;
      } else if (isPlainTable(existing)) {
        cur = existing;
      } else {
        throw new Error(`TOML 表数组路径与标量冲突：${path.join(".")}`);
      }
    }
    const lastKey = path[path.length - 1];
    const existing = cur[lastKey];
    const entry: TomlTable = emptyTable();
    if (existing === undefined) {
      cur[lastKey] = [entry];
    } else if (Array.isArray(existing)) {
      existing.push(entry);
    } else {
      throw new Error(`TOML 表数组与已有非数组键冲突：${path.join(".")}`);
    }
    return entry;
  }

  private assignKey(target: TomlTable, path: string[], value: TomlValue): void {
    let cur = target;
    for (let i = 0; i < path.length - 1; i++) {
      const seg = path[i];
      const existing = cur[seg];
      if (existing === undefined) {
        const next: TomlTable = emptyTable();
        cur[seg] = next;
        cur = next;
      } else if (isPlainTable(existing)) {
        cur = existing;
      } else {
        throw new Error(`TOML 嵌套键路径冲突：${path.join(".")}`);
      }
    }
    cur[path[path.length - 1]] = value;
  }

  private parseKeyPath(): string[] {
    const parts: string[] = [];
    while (true) {
      this.skipSpaces();
      parts.push(this.parseKeySegment());
      this.skipSpaces();
      if (this.peek() === ".") {
        this.pos++;
        continue;
      }
      break;
    }
    return parts;
  }

  private parseKeySegment(): string {
    const ch = this.peek();
    if (ch === '"') return this.parseBasicString();
    if (ch === "'") return this.parseLiteralString();
    const start = this.pos;
    while (!this.eof() && /[A-Za-z0-9_-]/.test(this.peek())) this.pos++;
    if (this.pos === start) {
      throw new Error(`TOML 语法错误：非法键名 "${this.src.slice(this.pos, this.pos + 16)}"`);
    }
    return this.src.slice(start, this.pos);
  }

  private parseValue(): TomlValue {
    const ch = this.peek();
    if (!ch || ch === "\n" || ch === "#") {
      throw new Error("TOML 语法错误：缺少键值");
    }
    if (ch === '"') {
      if (this.src.startsWith('"""', this.pos)) return this.parseMultilineBasicString();
      return this.parseBasicString();
    }
    if (ch === "'") {
      if (this.src.startsWith("'''", this.pos)) return this.parseMultilineLiteralString();
      return this.parseLiteralString();
    }
    if (ch === "[") return this.parseArray();
    if (ch === "{") return this.parseInlineTable();
    return this.parseScalar();
  }

  private parseBasicString(): string {
    this.pos++; // skip opening "
    let out = "";
    while (!this.eof()) {
      const ch = this.src[this.pos++];
      if (ch === '"') return out;
      if (ch === "\n") throw new Error("TOML 语法错误：单行字符串中出现换行");
      if (ch === "\\") {
        out += this.parseEscapeSequence();
      } else {
        out += ch;
      }
    }
    throw new Error("TOML 语法错误：基础字符串未闭合");
  }

  private parseMultilineBasicString(): string {
    this.pos += 3; // skip """
    if (this.peek() === "\n") this.pos++; // 按 TOML 规范紧随开头 """ 的首个换行忽略
    let out = "";
    while (!this.eof()) {
      if (this.src.startsWith('"""', this.pos)) {
        // 允许闭合处最多连续 5 个引号（多出的 1~2 个属于内容末尾引号）
        let run = 0;
        while (this.peek(run) === '"') run++;
        if (run > 5) throw new Error("TOML 语法错误：多行字符串引号数量非法");
        if (run > 3) {
          out += '"'.repeat(run - 3);
        }
        this.pos += run;
        return out;
      }
      const ch = this.src[this.pos++];
      if (ch === "\\") {
        // 行尾反斜杠续行：跳过后续空白与换行
        let look = this.pos;
        while (look < this.src.length && (this.src[look] === " " || this.src[look] === "\t")) look++;
        if (this.src[look] === "\n") {
          this.pos = look + 1;
          while (!this.eof() && (this.peek() === " " || this.peek() === "\t" || this.peek() === "\n")) {
            this.pos++;
          }
          continue;
        }
        out += this.parseEscapeSequence();
      } else {
        out += ch;
      }
    }
    throw new Error("TOML 语法错误：多行基础字符串未闭合");
  }

  private parseEscapeSequence(): string {
    if (this.eof()) throw new Error("TOML 语法错误：转义序列不完整");
    const esc = this.src[this.pos++];
    switch (esc) {
      case "b":
        return "\b";
      case "t":
        return "\t";
      case "n":
        return "\n";
      case "f":
        return "\f";
      case "r":
        return "\r";
      case '"':
        return '"';
      case "\\":
        return "\\";
      case "u": {
        const hex = this.src.slice(this.pos, this.pos + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error(`TOML 非法 \\u 转义：${hex}`);
        this.pos += 4;
        return String.fromCodePoint(parseInt(hex, 16));
      }
      case "U": {
        const hex = this.src.slice(this.pos, this.pos + 8);
        if (!/^[0-9a-fA-F]{8}$/.test(hex)) throw new Error(`TOML 非法 \\U 转义：${hex}`);
        this.pos += 8;
        const cp = parseInt(hex, 16);
        if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) throw new Error(`TOML 非法 Unicode 码点：${hex}`);
        return String.fromCodePoint(cp);
      }
      default:
        throw new Error(`TOML 非法转义字符：\\${esc}`);
    }
  }

  private parseLiteralString(): string {
    this.pos++; // skip '
    const start = this.pos;
    while (!this.eof()) {
      const ch = this.src[this.pos++];
      if (ch === "'") return this.src.slice(start, this.pos - 1);
      if (ch === "\n") throw new Error("TOML 语法错误：单行字面量字符串中出现换行");
    }
    throw new Error("TOML 语法错误：字面量字符串未闭合");
  }

  private parseMultilineLiteralString(): string {
    this.pos += 3; // skip '''
    if (this.peek() === "\n") this.pos++;
    let out = "";
    while (!this.eof()) {
      if (this.src.startsWith("'''", this.pos)) {
        let run = 0;
        while (this.peek(run) === "'") run++;
        if (run > 5) throw new Error("TOML 语法错误：多行字面量字符串引号数量非法");
        if (run > 3) {
          out += "'".repeat(run - 3);
        }
        this.pos += run;
        return out;
      }
      out += this.src[this.pos++];
    }
    throw new Error("TOML 语法错误：多行字面量字符串未闭合");
  }

  private parseArray(): TomlValue[] {
    this.pos++; // skip [
    const out: TomlValue[] = [];
    while (true) {
      this.skipWsAndComments();
      if (this.eof()) throw new Error("TOML 语法错误：数组未闭合");
      if (this.peek() === "]") {
        this.pos++;
        return out;
      }
      out.push(this.parseValue());
      this.skipWsAndComments();
      if (this.peek() === ",") {
        this.pos++;
        continue;
      }
      if (this.peek() === "]") {
        this.pos++;
        return out;
      }
      throw new Error(`TOML 语法错误：数组元素间缺少 ',' 或 ']'`);
    }
  }

  private parseInlineTable(): TomlTable {
    this.pos++; // skip {
    const out: TomlTable = emptyTable();
    this.skipSpaces();
    if (this.peek() === "}") {
      this.pos++;
      return out;
    }
    while (true) {
      this.skipSpaces();
      if (this.eof() || this.peek() === "\n") {
        throw new Error("TOML 语法错误：内联表未闭合或非法换行");
      }
      const path = this.parseKeyPath();
      this.skipSpaces();
      if (this.peek() !== "=") {
        throw new Error(`TOML 语法错误：内联表键 "${path.join(".")}" 后缺少 '='`);
      }
      this.pos++;
      this.skipSpaces();
      const val = this.parseValue();
      this.assignKey(out, path, val);
      this.skipSpaces();
      if (this.peek() === ",") {
        this.pos++;
        continue;
      }
      if (this.peek() === "}") {
        this.pos++;
        return out;
      }
      throw new Error("TOML 语法错误：内联表缺少 ',' 或 '}'");
    }
  }

  private parseScalar(): TomlValue {
    const start = this.pos;
    // 日期时间可能含单个空格分隔日期与时间，其余标量遇空白/分隔符/注释结束
    while (!this.eof()) {
      const ch = this.peek();
      if (ch === "\n" || ch === "#" || ch === "," || ch === "]" || ch === "}") break;
      if (ch === " " || ch === "\t") {
        const prefix = this.src.slice(start, this.pos);
        if (/^\d{4}-\d{2}-\d{2}$/.test(prefix) && /^\s+\d{2}:\d{2}/.test(this.src.slice(this.pos))) {
          this.pos++;
          continue;
        }
        break;
      }
      this.pos++;
    }
    const raw = this.src.slice(start, this.pos).trim();
    if (!raw) throw new Error("TOML 语法错误：空标量");
    if (raw === "true") return true;
    if (raw === "false") return false;
    if (raw === "inf" || raw === "+inf") return Infinity;
    if (raw === "-inf") return -Infinity;
    if (raw === "nan" || raw === "+nan" || raw === "-nan") return Number.NaN;
    if (/^0x[0-9a-fA-F_]+$/.test(raw)) return parseInt(raw.slice(2).replace(/_/g, ""), 16);
    if (/^0o[0-7_]+$/.test(raw)) return parseInt(raw.slice(2).replace(/_/g, ""), 8);
    if (/^0b[01_]+$/.test(raw)) return parseInt(raw.slice(2).replace(/_/g, ""), 2);
    if (/^[+-]?\d[\d_]*(\.\d[\d_]*)?([eE][+-]?\d[\d_]*)?$/.test(raw)) {
      const cleaned = raw.replace(/_/g, "");
      const num = Number(cleaned);
      if (Number.isFinite(num)) return num;
    }
    // RFC 3339 date / time / datetime
    if (/^\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})?)?$/.test(raw) || /^\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(raw)) {
      return raw;
    }
    throw new Error(`TOML 语法错误：无法识别的标量 "${raw}"`);
  }
}

export function isPlainTable(v: unknown): v is TomlTable {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function parseToml(input: string): TomlTable {
  return new TomlParser(input).parseDocument();
}

export function parseTomlValue(input: string): TomlValue {
  return new TomlParser(input).parseStandaloneValue();
}

export function parseTomlKeyPath(input: string): string[] {
  return new TomlParser(input).parseStandaloneKeyPath();
}
