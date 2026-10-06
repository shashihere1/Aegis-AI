import { useState } from "react";
import type { LucideIcon } from "lucide-react";

// Mark specs: bars <= 24px, 4px rounded data end / square baseline, 2px surface gap between stacked segments,
// hairline recessive gridlines, values and labels in text tokens (never in the series colour).

function niceTicks(max: number): number[] {
  if (max <= 0) return [0, 1];
  const steps = [1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000];
  const step = steps.find((s) => max / s <= 4) ?? Math.ceil(max / 4);
  const top = Math.ceil(max / step) * step;
  return Array.from({ length: top / step + 1 }, (_, i) => i * step);
}

function roundedTop(x: number, y: number, w: number, h: number, r: number): string {
  const rr = Math.min(r, h, w / 2);
  return `M${x},${y + h} L${x},${y + rr} Q${x},${y} ${x + rr},${y} L${x + w - rr},${y} Q${x + w},${y} ${x + w},${y + rr} L${x + w},${y + h} Z`;
}

export interface StackSeries {
  key: string;
  label: string;
  color: string;
  icon: LucideIcon;
}

export function Legend({ series }: { series: StackSeries[] }) {
  return (
    <div className="flex flex-wrap gap-4 text-sm text-muted">
      {series.map((s) => (
        <span key={s.key} className="inline-flex items-center gap-1.5">
          <span className="size-2.5 rounded-sm" style={{ background: s.color }} />
          <s.icon className="size-3.5" />
          {s.label}
        </span>
      ))}
    </div>
  );
}

export function StackedColumns<T extends Record<string, number | string>>({
  data,
  series,
  xLabel,
  height = 220,
}: {
  data: T[];
  series: StackSeries[];
  xLabel: (row: T) => string;
  height?: number;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const width = 900;
  const pad = { l: 36, r: 8, t: 10, b: 26 };
  const plotW = width - pad.l - pad.r;
  const plotH = height - pad.t - pad.b;
  const totals = data.map((row) => series.reduce((sum, s) => sum + Number(row[s.key] ?? 0), 0));
  const ticks = niceTicks(Math.max(...totals, 0));
  const top = ticks[ticks.length - 1];
  const slot = plotW / Math.max(data.length, 1);
  const barW = Math.min(24, slot * 0.62);
  const y = (v: number) => pad.t + plotH - (v / top) * plotH;

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full" role="img" aria-label="Decisions per minute by outcome">
        {ticks.map((t) => (
          <g key={t}>
            <line x1={pad.l} x2={width - pad.r} y1={y(t)} y2={y(t)} stroke="var(--line)" strokeWidth={1} />
            <text x={pad.l - 8} y={y(t) + 4} textAnchor="end" fontSize={11} fill="var(--faint)" className="tabular">
              {t}
            </text>
          </g>
        ))}
        {data.map((row, i) => {
          const x = pad.l + i * slot + (slot - barW) / 2;
          let base = 0;
          const present = series.filter((s) => Number(row[s.key] ?? 0) > 0);
          return (
            <g key={i}>
              {present.map((s, j) => {
                const v = Number(row[s.key]);
                const y0 = y(base);
                const y1 = y(base + v);
                base += v;
                const isTop = j === present.length - 1;
                const h = Math.max(y0 - y1 - (isTop ? 0 : 2), 1);
                return isTop ? (
                  <path key={s.key} d={roundedTop(x, y1, barW, h, 4)} fill={s.color} opacity={hover === null || hover === i ? 1 : 0.45} />
                ) : (
                  <rect key={s.key} x={x} y={y1 + 2} width={barW} height={h} fill={s.color} opacity={hover === null || hover === i ? 1 : 0.45} />
                );
              })}
              {/* hit target larger than the mark */}
              <rect x={pad.l + i * slot} y={pad.t} width={slot} height={plotH} fill="transparent" onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} />
            </g>
          );
        })}
        <line x1={pad.l} x2={width - pad.r} y1={y(0)} y2={y(0)} stroke="var(--line-strong)" strokeWidth={1} />
        {data.map((row, i) =>
          i % 5 === 0 || i === data.length - 1 ? (
            <text key={i} x={pad.l + i * slot + slot / 2} y={height - 6} textAnchor="middle" fontSize={11} fill="var(--faint)">
              {xLabel(row)}
            </text>
          ) : null,
        )}
      </svg>
      {hover !== null && (
        <div
          className="pointer-events-none absolute top-2 z-10 w-52 rounded-lg border border-line-strong bg-card p-3 text-sm shadow-xl"
          style={{ left: `min(calc(${((pad.l + hover * slot + slot) / width) * 100}% + 8px), calc(100% - 13rem))` }}
        >
          <div className="mb-1.5 font-medium">{xLabel(data[hover])}</div>
          {series.map((s) => (
            <div key={s.key} className="flex items-center gap-2 py-0.5">
              <span className="size-2.5 rounded-sm" style={{ background: s.color }} />
              <s.icon className="size-3.5 text-muted" />
              <span className="flex-1 text-muted">{s.label}</span>
              <span className="tabular font-medium">{Number(data[hover][s.key] ?? 0)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function HBars({ rows, unit, format = (v) => String(v) }: { rows: { label: string; value: number }[]; unit: string; format?: (v: number) => string }) {
  const [hover, setHover] = useState<number | null>(null);
  const max = Math.max(...rows.map((r) => r.value), 1);
  return (
    <div className="space-y-3" role="list">
      {rows.map((r, i) => (
        <div key={r.label} role="listitem" className="relative" onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
          <div className="mb-1 truncate text-sm">{r.label}</div>
          <div className="flex items-center gap-2">
            <div className="h-5 flex-1">
              <div className="h-5 rounded-r-[4px]" style={{ width: `${(r.value / max) * 100}%`, background: "var(--series)", opacity: hover === null || hover === i ? 1 : 0.5 }} />
            </div>
            <span className="tabular w-16 text-right text-sm font-medium">{format(r.value)}</span>
          </div>
          {hover === i && (
            <div className="pointer-events-none absolute right-20 -top-1 z-10 rounded-lg border border-line-strong bg-card px-3 py-2 text-sm shadow-xl">
              {r.label}: <span className="font-medium">{format(r.value)}</span> {unit}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
