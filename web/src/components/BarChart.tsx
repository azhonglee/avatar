import { useId } from "react";

export interface BarDatum {
  label: string;
  value: number;
  title: string;
}

/** 小型 SVG 柱状图：自适应宽度，柱子带悬浮提示；同时输出隐藏的表格供读屏使用。 */
export function BarChart({ data, format, label, height = 180 }: { data: BarDatum[]; format: (v: number) => string; label: string; height?: number }) {
  const id = useId();
  const max = Math.max(0, ...data.map((d) => d.value));
  const W = 640;
  const H = height;
  const padL = 8;
  const padB = 22;
  const padT = 16;
  const n = Math.max(1, data.length);
  const slot = (W - padL * 2) / n;
  const bw = Math.max(2, Math.min(28, slot * 0.7));
  const every = Math.ceil(n / 10);
  return (
    <figure className="chart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-labelledby={id} preserveAspectRatio="none" className="chart-svg">
        <title id={id}>{label}</title>
        {[0.25, 0.5, 0.75, 1].map((r) => (
          <line key={r} x1={padL} x2={W - padL} y1={padT + (H - padT - padB) * (1 - r)} y2={padT + (H - padT - padB) * (1 - r)} className="chart-grid" />
        ))}
        {data.map((d, i) => {
          const h = max > 0 ? ((H - padT - padB) * d.value) / max : 0;
          const x = padL + slot * i + (slot - bw) / 2;
          return (
            <g key={i}>
              <rect x={x} y={H - padB - h} width={bw} height={Math.max(h, d.value > 0 ? 1 : 0)} rx={3} className="chart-bar">
                <title>{d.title}</title>
              </rect>
              {i % every === 0 && (
                <text x={x + bw / 2} y={H - 6} textAnchor="middle" className="chart-label">
                  {d.label}
                </text>
              )}
            </g>
          );
        })}
        <text x={W - padL} y={12} textAnchor="end" className="chart-label">
          最高 {format(max)}
        </text>
      </svg>
      <table className="sr-only">
        <caption>{label}</caption>
        <tbody>
          {data.map((d, i) => (
            <tr key={i}>
              <th>{d.label}</th>
              <td>{format(d.value)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </figure>
  );
}
