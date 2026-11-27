import { Fragment, type ReactNode } from "react";

/**
 * 极小的 Markdown 渲染（体检修复指引、审查结论用）：标题、段落、列表、代码块、行内代码、粗体、链接。
 * 不使用 innerHTML，链接只允许 http(s)。
 */
export function Markdown({ text, className = "" }: { text: string; className?: string }) {
  return <div className={`md ${className}`}>{renderBlocks(text)}</div>;
}

function renderBlocks(src: string): ReactNode[] {
  const lines = src.replace(/\r\n/g, "\n").split("\n");
  const out: ReactNode[] = [];
  let i = 0;
  let key = 0;
  while (i < lines.length) {
    const line = lines[i];
    const fence = line.match(/^\s*```(\w*)/);
    if (fence) {
      const buf: string[] = [];
      i++;
      while (i < lines.length && !/^\s*```/.test(lines[i])) buf.push(lines[i++]);
      i++;
      out.push(
        <pre key={key++} className="pre md-code" tabIndex={0}>
          <code>{buf.join("\n")}</code>
        </pre>,
      );
      continue;
    }
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      const level = Math.min(6, h[1].length + 2);
      const Tag = `h${level}` as "h3";
      out.push(<Tag key={key++}>{inline(h[2])}</Tag>);
      i++;
      continue;
    }
    if (/^\s*([-*]|\d+[.)])\s+/.test(line)) {
      const ordered = /^\s*\d+[.)]\s+/.test(line);
      const items: string[] = [];
      while (i < lines.length && /^\s*([-*]|\d+[.)])\s+/.test(lines[i])) {
        let item = lines[i].replace(/^\s*([-*]|\d+[.)])\s+/, "");
        i++;
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !/^\s*([-*]|\d+[.)])\s+/.test(lines[i])) item += " " + lines[i++].trim();
        items.push(item);
      }
      const L = ordered ? "ol" : "ul";
      out.push(
        <L key={key++}>
          {items.map((it, j) => (
            <li key={j}>{inline(it)}</li>
          ))}
        </L>,
      );
      continue;
    }
    if (!line.trim()) {
      i++;
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() && !/^\s*```/.test(lines[i]) && !/^#{1,4}\s/.test(lines[i]) && !/^\s*([-*]|\d+[.)])\s+/.test(lines[i])) para.push(lines[i++]);
    out.push(
      <p key={key++}>
        {para.map((p, j) => (
          <Fragment key={j}>
            {j > 0 && <br />}
            {inline(p)}
          </Fragment>
        ))}
      </p>,
    );
  }
  return out;
}

const INLINE = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\[[^\]]+\]\((https?:\/\/[^)\s]+)\))|(https?:\/\/[^\s)]+)/g;

function inline(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  let k = 0;
  for (const m of text.matchAll(INLINE)) {
    if (m.index! > last) out.push(text.slice(last, m.index));
    if (m[1]) out.push(<code key={k++}>{m[1].slice(1, -1)}</code>);
    else if (m[2]) out.push(<strong key={k++}>{m[2].slice(2, -2)}</strong>);
    else if (m[3]) {
      const label = m[3].slice(1, m[3].indexOf("]"));
      out.push(
        <a key={k++} href={m[4]} target="_blank" rel="noreferrer noopener">
          {label}
        </a>,
      );
    } else if (m[5])
      out.push(
        <a key={k++} href={m[5]} target="_blank" rel="noreferrer noopener">
          {m[5]}
        </a>,
      );
    last = m.index! + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}
