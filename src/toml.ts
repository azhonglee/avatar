/**
 * 零外部依赖的 TOML 1.0 递归下降解析器（面向 Codex `config.toml` 与 `-c key=value` 严格解析）。
 * 完整支持：
 *   - 单行/多行基础字符串（"..." / """..."""，含完整转义与行尾反斜杠续行）
 *   - 单行/多行字面量字符串（'...' / '''...'''，字符串内部任意 `[xxx]` 绝不会误识别为表头）
 *   - 裸键 / 引号键 / 点分键路径（a.b."c.d"）
 *   - 标准表 `[a.b]`、表数组 `[[a.b]]`、内联表 `{ k = v }`、多行数组 `[ ... ]`
 *   - 布尔、整数/浮点（含下划线、进制前缀、inf/nan）与 RFC 3339 日期时间字面量
 * 严格遵循 TOML 1.0 唯一性规则：拒绝重复键、重复表头、对内联表或已定义表的二次覆写。
 * 所有报错仅报告行列号与键路径，绝不回显原始配置值（防止未加引号的密钥泄漏到日志或错误状态）。
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
  /** 已通过显式 `[table]` 打开过的表（禁止再次通过 `[table]` 重复定义） */
  private readonly explicitTables = new WeakSet<TomlTable>();
  /** 内联表 `{ ... }`（按 TOML 1.0 规范不可变，禁止后续再向其追加键或重新打开） */
  private readonly sealedTables = new WeakSet<TomlTable>();
  /** 由点分键隐式生成的表（不能再被 `[table]` 重复定义为显式表） */
  private readonly dottedTables = new WeakSet<TomlTable>();
  /** 由 `[[array_table]]` 创建的表数组（区别于普通静态数组） */
  private readonly arrayTables = new WeakSet<TomlValue[]>();

  constructor(src: string) {
    this.src = src.replace(/\r\n/g, "\n");
  }

  private loc(at = this.pos): string {
    let line = 1;
    let col = 1;
    const limit = Math.min(at, this.src.length);
    for (let i = 0; i < limit; i++) {
      if (this.src[i] === "\n") {
        line++;
        col = 1;
      } else {
        col++;
      }
    }
    return `第 ${line} 行第 ${col} 列`;
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
    throw new Error(`TOML 语法错误（${this.loc()}）：行尾存在多余内容`);
  }

  parseDocument(): TomlTable {
    const root: TomlTable = emptyTable();
    let current: TomlTable = root;

    while (!this.eof()) {
      this.skipWsAndComments();
      if (this.eof()) break;

      if (this.peek() === "[") {
        const startPos = this.pos;
        const isArrayTable = this.peek(1) === "[";
        this.pos += isArrayTable ? 2 : 1;
        this.skipSpaces();
        const path = this.parseKeyPath();
        this.skipSpaces();
        if (isArrayTable) {
          if (this.peek() !== "]" || this.peek(1) !== "]") {
            throw new Error(`TOML 语法错误（${this.loc(startPos)}）：表数组头缺少闭合 ]]`);
          }
          this.pos += 2;
          this.expectLineEnd();
          current = this.openArrayTable(root, path, startPos);
        } else {
          if (this.peek() !== "]") {
            throw new Error(`TOML 语法错误（${this.loc(startPos)}）：表头缺少闭合 ]`);
          }
          this.pos += 1;
          this.expectLineEnd();
          current = this.openTable(root, path, startPos);
        }
        continue;
      }

      const keyPos = this.pos;
      const path = this.parseKeyPath();
      this.skipSpaces();
      if (this.peek() !== "=") {
        throw new Error(`TOML 语法错误（${this.loc(keyPos)}）：键 "${path.join(".")}" 后缺少 '='`);
      }
      this.pos++;
      this.skipSpaces();
      const val = this.parseValue();
      this.expectLineEnd();
      this.assignKey(current, path, val, keyPos);
    }

    return root;
  }

  parseStandaloneValue(): TomlValue {
    this.skipWsAndComments();
    const val = this.parseValue();
    this.skipWsAndComments();
    if (!this.eof()) {
      throw new Error(`TOML 值语法错误（${this.loc()}）：存在多余尾部字符`);
    }
    return val;
  }

  parseStandaloneKeyPath(): string[] {
    this.skipSpaces();
    const path = this.parseKeyPath();
    this.skipSpaces();
    if (!this.eof()) {
      throw new Error(`TOML 键路径语法错误（${this.loc()}）：存在多余尾部字符`);
    }
    return path;
  }

  private openTable(root: TomlTable, path: string[], startPos: number): TomlTable {
    let cur: TomlTable = root;
    for (let i = 0; i < path.length; i++) {
      const seg = path[i];
      const isLast = i === path.length - 1;
      const existing = cur[seg];
      if (existing === undefined) {
        const next: TomlTable = emptyTable();
        cur[seg] = next;
        cur = next;
      } else if (Array.isArray(existing)) {
        if (isLast || !this.arrayTables.has(existing)) {
          throw new Error(`TOML 表路径冲突（${this.loc(startPos)}）：${path.join(".")}`);
        }
        const last = existing[existing.length - 1];
        if (!isPlainTable(last)) {
          throw new Error(`TOML 表路径冲突（${this.loc(startPos)}）：${path.join(".")}`);
        }
        cur = last;
      } else if (isPlainTable(existing)) {
        if (this.sealedTables.has(existing)) {
          throw new Error(`TOML 语法错误（${this.loc(startPos)}）：不能向内联表 "${path.join(".")}" 追加或重开定义`);
        }
        if (isLast && (this.explicitTables.has(existing) || this.dottedTables.has(existing))) {
          throw new Error(`TOML 语法错误（${this.loc(startPos)}）：表 "${path.join(".")}" 重复定义`);
        }
        cur = existing;
      } else {
        throw new Error(`TOML 表路径与标量键冲突（${this.loc(startPos)}）：${path.join(".")}`);
      }
    }
    this.explicitTables.add(cur);
    return cur;
  }

  private openArrayTable(root: TomlTable, path: string[], startPos: number): TomlTable {
    let cur: TomlTable = root;
    for (let i = 0; i < path.length - 1; i++) {
      const seg = path[i];
      const existing = cur[seg];
      if (existing === undefined) {
        const next: TomlTable = emptyTable();
        cur[seg] = next;
        cur = next;
      } else if (Array.isArray(existing)) {
        if (!this.arrayTables.has(existing)) {
          throw new Error(`TOML 表数组路径冲突（${this.loc(startPos)}）：${path.join(".")}`);
        }
        const last = existing[existing.length - 1];
        if (!isPlainTable(last)) throw new Error(`TOML 表数组路径冲突（${this.loc(startPos)}）：${path.join(".")}`);
        cur = last;
      } else if (isPlainTable(existing)) {
        if (this.sealedTables.has(existing)) {
          throw new Error(`TOML 语法错误（${this.loc(startPos)}）：不能修改内联表 "${path.join(".")}"`);
        }
        cur = existing;
      } else {
        throw new Error(`TOML 表数组路径与标量冲突（${this.loc(startPos)}）：${path.join(".")}`);
      }
    }
    const lastKey = path[path.length - 1];
    const existing = cur[lastKey];
    const entry: TomlTable = emptyTable();
    if (existing === undefined) {
      const arr: TomlValue[] = [entry];
      this.arrayTables.add(arr);
      cur[lastKey] = arr;
    } else if (Array.isArray(existing) && this.arrayTables.has(existing)) {
      existing.push(entry);
    } else {
      throw new Error(`TOML 表数组与已有键冲突（${this.loc(startPos)}）：${path.join(".")}`);
    }
    return entry;
  }

  private assignKey(target: TomlTable, path: string[], value: TomlValue, startPos: number): void {
    let cur = target;
    for (let i = 0; i < path.length - 1; i++) {
      const seg = path[i];
      const existing = cur[seg];
      if (existing === undefined) {
        const next: TomlTable = emptyTable();
        this.dottedTables.add(next);
        cur[seg] = next;
        cur = next;
      } else if (isPlainTable(existing)) {
        if (this.sealedTables.has(existing) || this.explicitTables.has(existing)) {
          throw new Error(`TOML 语法错误（${this.loc(startPos)}）：不能通过点分键修改已定义的表 "${path.slice(0, i + 1).join(".")}"`);
        }
        cur = existing;
      } else {
        throw new Error(`TOML 嵌套键路径冲突（${this.loc(startPos)}）：${path.join(".")}`);
      }
    }
    const lastKey = path[path.length - 1];
    if (Object.prototype.hasOwnProperty.call(cur, lastKey)) {
      throw new Error(`TOML 语法错误（${this.loc(startPos)}）：键 "${path.join(".")}" 重复定义`);
    }
    cur[lastKey] = value;
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
    const startPos = this.pos;
    const ch = this.peek();
    if (ch === '"') return this.parseBasicString();
    if (ch === "'") return this.parseLiteralString();
    const start = this.pos;
    while (!this.eof() && /[A-Za-z0-9_-]/.test(this.peek())) this.pos++;
    if (this.pos === start) {
      throw new Error(`TOML 语法错误（${this.loc(startPos)}）：非法键名`);
    }
    return this.src.slice(start, this.pos);
  }

  private parseValue(): TomlValue {
    const startPos = this.pos;
    const ch = this.peek();
    if (!ch || ch === "\n" || ch === "#") {
      throw new Error(`TOML 语法错误（${this.loc(startPos)}）：缺少键值`);
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
    const startPos = this.pos;
    this.pos++;
    let out = "";
    while (!this.eof()) {
      const ch = this.src[this.pos++];
      if (ch === '"') return out;
      if (ch === "\n") throw new Error(`TOML 语法错误（${this.loc(startPos)}）：单行字符串中出现换行`);
      if (ch === "\\") {
        out += this.parseEscapeSequence();
      } else {
        out += ch;
      }
    }
    throw new Error(`TOML 语法错误（${this.loc(startPos)}）：基础字符串未闭合`);
  }

  private parseMultilineBasicString(): string {
    const startPos = this.pos;
    this.pos += 3;
    if (this.peek() === "\n") this.pos++;
    let out = "";
    while (!this.eof()) {
      if (this.src.startsWith('"""', this.pos)) {
        let run = 0;
        while (this.peek(run) === '"') run++;
        if (run > 5) throw new Error(`TOML 语法错误（${this.loc()}）：多行字符串引号数量非法`);
        if (run > 3) {
          out += '"'.repeat(run - 3);
        }
        this.pos += run;
        return out;
      }
      const ch = this.src[this.pos++];
      if (ch === "\\") {
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
    throw new Error(`TOML 语法错误（${this.loc(startPos)}）：多行基础字符串未闭合`);
  }

  private parseEscapeSequence(): string {
    const startPos = this.pos;
    if (this.eof()) throw new Error(`TOML 语法错误（${this.loc(startPos)}）：转义序列不完整`);
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
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error(`TOML 语法错误（${this.loc(startPos)}）：非法 \\u 转义`);
        this.pos += 4;
        return String.fromCodePoint(parseInt(hex, 16));
      }
      case "U": {
        const hex = this.src.slice(this.pos, this.pos + 8);
        if (!/^[0-9a-fA-F]{8}$/.test(hex)) throw new Error(`TOML 语法错误（${this.loc(startPos)}）：非法 \\U 转义`);
        this.pos += 8;
        const cp = parseInt(hex, 16);
        if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
          throw new Error(`TOML 语法错误（${this.loc(startPos)}）：非法 Unicode 码点`);
        }
        return String.fromCodePoint(cp);
      }
      default:
        throw new Error(`TOML 语法错误（${this.loc(startPos)}）：非法转义序列`);
    }
  }

  private parseLiteralString(): string {
    const startPos = this.pos;
    this.pos++;
    const start = this.pos;
    while (!this.eof()) {
      const ch = this.src[this.pos++];
      if (ch === "'") return this.src.slice(start, this.pos - 1);
      if (ch === "\n") throw new Error(`TOML 语法错误（${this.loc(startPos)}）：单行字面量字符串中出现换行`);
    }
    throw new Error(`TOML 语法错误（${this.loc(startPos)}）：字面量字符串未闭合`);
  }

  private parseMultilineLiteralString(): string {
    const startPos = this.pos;
    this.pos += 3;
    if (this.peek() === "\n") this.pos++;
    let out = "";
    while (!this.eof()) {
      if (this.src.startsWith("'''", this.pos)) {
        let run = 0;
        while (this.peek(run) === "'") run++;
        if (run > 5) throw new Error(`TOML 语法错误（${this.loc()}）：多行字面量字符串引号数量非法`);
        if (run > 3) {
          out += "'".repeat(run - 3);
        }
        this.pos += run;
        return out;
      }
      out += this.src[this.pos++];
    }
    throw new Error(`TOML 语法错误（${this.loc(startPos)}）：多行字面量字符串未闭合`);
  }

  private parseArray(): TomlValue[] {
    const startPos = this.pos;
    this.pos++;
    const out: TomlValue[] = [];
    while (true) {
      this.skipWsAndComments();
      if (this.eof()) throw new Error(`TOML 语法错误（${this.loc(startPos)}）：数组未闭合`);
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
      throw new Error(`TOML 语法错误（${this.loc()}）：数组元素间缺少 ',' 或 ']'`);
    }
  }

  private parseInlineTable(): TomlTable {
    const startPos = this.pos;
    this.pos++;
    const out: TomlTable = emptyTable();
    // 兼容 TOML 1.1（Codex CLI 使用的 Rust toml 语法）：允许内联表内换行、注释与末尾逗号
    this.skipWsAndComments();
    if (this.peek() === "}") {
      this.pos++;
      this.sealedTables.add(out);
      return out;
    }
    while (true) {
      this.skipWsAndComments();
      if (this.eof()) {
        throw new Error(`TOML 语法错误（${this.loc(startPos)}）：内联表未闭合`);
      }
      if (this.peek() === "}") {
        this.pos++;
        this.sealedTables.add(out);
        return out;
      }
      const keyPos = this.pos;
      const path = this.parseKeyPath();
      this.skipSpaces();
      if (this.peek() !== "=") {
        throw new Error(`TOML 语法错误（${this.loc(keyPos)}）：内联表键 "${path.join(".")}" 后缺少 '='`);
      }
      this.pos++;
      this.skipSpaces();
      const val = this.parseValue();
      this.assignKey(out, path, val, keyPos);
      this.skipWsAndComments();
      if (this.peek() === ",") {
        this.pos++;
        continue;
      }
      if (this.peek() === "}") {
        this.pos++;
        this.sealedTables.add(out);
        return out;
      }
      throw new Error(`TOML 语法错误（${this.loc()}）：内联表缺少 ',' 或 '}'`);
    }
  }

  private parseScalar(): TomlValue {
    const start = this.pos;
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
    if (!raw) throw new Error(`TOML 语法错误（${this.loc(start)}）：空标量`);
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
    if (/^\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})?)?$/.test(raw) || /^\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(raw)) {
      return raw;
    }
    // 绝不把原始标量值写进错误信息，防止未加引号的凭据泄漏到日志或状态字段
    throw new Error(`TOML 语法错误（${this.loc(start)}）：存在无法识别的标量字面量（请检查字符串是否缺少引号）`);
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
