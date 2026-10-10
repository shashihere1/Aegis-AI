import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { Link } from "react-router";
import type { LucideIcon } from "lucide-react";
import { cx, focusRing } from "./ui";

// Hand-built SVG charts following the house rules: thin marks (bars <= 24px, 4px rounded data end, square at
// the baseline), 2px surface gaps between stacked segments, hairline solid gridlines, muted axis text, values
// in text tokens (never the series colour), a tooltip on hover AND keyboard focus, and a table-view twin on
// the page. Only exceptions carry colour; routine volume uses the de-emphasis grey (--chart-muted).

function niceTicks(max: number, count = 4): number[] {
  if (max <= 0) return [0, 1];
  const raw = max / count;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? raw;
  const top = Math.ceil(max / step) * step;
  return Array.from({ length: Math.round(top / step) + 1 }, (_, i) => +(i * step).toFixed(6));
}

function roundedTop(x: number, y: number, w: number, h: number, r: number) {
  const rr = Math.min(r, w / 2, h);
  return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`;
}

/** Real pixel width of a container, so chart text never scales with a viewBox. */
export function useChartSize<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    setWidth(el.clientWidth);
    const ro = new ResizeObserver(([entry]) => setWidth(Math.round(entry.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, width] as const;
}

export interface StackSeries {
  key: string;
  label: string;
  color: string;
  icon?: LucideIcon;
}

export function Legend({ series, line }: { series: { key: string; label: string; color: string }[]; line?: boolean }) {
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1 text-caption text-muted" aria-label="Legend">
      {series.map((s) => (
        <li key={s.key} className="flex items-center gap-1.5">
          <span className={line ? "h-0.5 w-3 rounded-full" : "size-2.5 rounded-[3px]"} style={{ background: s.color }} aria-hidden />
          {s.label}
        </li>
      ))}
    </ul>
  );
}

function Tooltip({ left, title, rows }: { left: number; title: ReactNode; rows: { key: string; label: string; value: ReactNode; color: string }[] }) {
  return (
    <div
      className="pointer-events-none absolute top-2 z-10 w-52 rounded-lg border border-line bg-card p-3 text-caption shadow-overlay"
      style={{ left: `min(max(${left}px - 6.5rem, 0px), calc(100% - 13rem))` }}
      role="status"
    >
      <div className="mb-1.5 font-medium text-fg">{title}</div>
      <ul className="space-y-1">
        {rows.map((r) => (
          <li key={r.key} className="flex items-center gap-2">
            <span className="h-0.5 w-3 shrink-0 rounded-full" style={{ background: r.color }} aria-hidden />
            <span className="tabular font-semibold text-fg">{r.value}</span>
            <span className="truncate text-muted">{r.label}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Keyboard + pointer index tracking shared by the time-series charts. */
function useActiveIndex(count: number) {
  const [active, setActive] = useState<number | null>(null);
  const onKeyDown = (e: KeyboardEvent) => {
    if (!count) return;
    const step = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : e.key === "End" ? count : e.key === "Home" ? -count : 0;
    if (!step) return;
    e.preventDefault();
    setActive((i) => Math.max(0, Math.min(count - 1, (i ?? count - 1) + step)));
  };
  return { active, setActive, onKeyDown };
}

const M = { top: 8, right: 8, bottom: 24, left: 40 };

/** Stacked columns over time (e.g. decisions per minute by outcome). */
export function StackedBars<T extends Record<string, unknown>>({
  data,
  series,
  xLabel,
  height = 220,
  ariaLabel,
  dimmed,
}: {
  data: T[];
  series: StackSeries[];
  xLabel: (row: T) => string;
  height?: number;
  ariaLabel: string;
  /** Hold the previous frame at reduced opacity while refetching. */
  dimmed?: boolean;
}) {
  const [ref, width] = useChartSize<HTMLDivElement>();
  const { active, setActive, onKeyDown } = useActiveIndex(data.length);
  const value = (row: T, key: string) => Number(row[key] ?? 0);
  const totals = data.map((row) => series.reduce((sum, s) => sum + value(row, s.key), 0));
  const ticks = niceTicks(Math.max(1, ...totals));
  const top = ticks[ticks.length - 1];
  const plotW = Math.max(0, width - M.left - M.right);
  const plotH = height - M.top - M.bottom;
  const slot = data.length ? plotW / data.length : 0;
  const barW = Math.max(2, Math.min(24, slot * 0.62));
  const y = (v: number) => M.top + plotH - (v / top) * plotH;
  const labelEvery = Math.max(1, Math.ceil(data.length / Math.max(1, Math.floor(plotW / 64))));

  return (
    <div
      ref={ref}
      className={cx("relative rounded-lg", focusRing, dimmed && "opacity-60 transition-opacity")}
      tabIndex={0}
      role="img"
      aria-label={`${ariaLabel}. Use the arrow keys to read each column.`}
      onKeyDown={onKeyDown}
      onBlur={() => setActive(null)}
      onMouseLeave={() => setActive(null)}
    >
      {width > 0 && (
        <svg width={width} height={height} className="block">
          {ticks.map((t) => (
            <g key={t}>
              <line x1={M.left} x2={width - M.right} y1={y(t)} y2={y(t)} stroke="var(--line)" />
              <text x={M.left - 8} y={y(t)} dy="0.32em" textAnchor="end" className="tabular" fontSize={11} fill="var(--muted)">
                {t.toLocaleString()}
              </text>
            </g>
          ))}
          {data.map((row, i) => {
            const cx0 = M.left + i * slot + (slot - barW) / 2;
            let cursor = y(0);
            const parts = series.filter((s) => value(row, s.key) > 0);
            return (
              <g key={i} opacity={active === null || active === i ? 1 : 0.4}>
                {parts.map((s, k) => {
                  const h = (value(row, s.key) / top) * plotH;
                  const gap = k > 0 ? 2 : 0;
                  const yTop = cursor - h;
                  const segH = Math.max(1, h - gap);
                  cursor = yTop;
                  return k === parts.length - 1 ? (
                    <path key={s.key} d={roundedTop(cx0, yTop, barW, segH, 4)} fill={s.color} />
                  ) : (
                    <rect key={s.key} x={cx0} y={yTop} width={barW} height={segH} fill={s.color} />
                  );
                })}
                <rect x={M.left + i * slot} y={M.top} width={slot} height={plotH} fill="transparent" onMouseEnter={() => setActive(i)} />
              </g>
            );
          })}
          <line x1={M.left} x2={width - M.right} y1={y(0)} y2={y(0)} stroke="var(--line-strong)" />
          {data.map((row, i) =>
            i % labelEvery === 0 || i === data.length - 1 ? (
              <text key={i} x={M.left + i * slot + slot / 2} y={height - 6} textAnchor="middle" className="tabular" fontSize={11} fill="var(--muted)">
                {xLabel(row)}
              </text>
            ) : null,
          )}
        </svg>
      )}
      {active !== null && data[active] && (
        <Tooltip
          left={M.left + active * slot + slot / 2}
          title={xLabel(data[active])}
          rows={series.map((s) => ({ key: s.key, label: s.label, value: value(data[active], s.key).toLocaleString(), color: s.color }))}
        />
      )}
      {width === 0 && <div style={{ height }} />}
    </div>
  );
}

/** @deprecated alias kept for older imports. */
export const StackedColumns = StackedBars;

/** Line/area time series (1–3 series, not stacked), with a crosshair tooltip. */
export function AreaChart<T extends Record<string, unknown>>({
  data,
  series,
  xLabel,
  height = 200,
  ariaLabel,
}: {
  data: T[];
  series: { key: string; label: string; color: string }[];
  xLabel: (row: T) => string;
  height?: number;
  ariaLabel: string;
}) {
  const [ref, width] = useChartSize<HTMLDivElement>();
  const { active, setActive, onKeyDown } = useActiveIndex(data.length);
  const num = (row: T, key: string) => Number(row[key] ?? 0);
  const ticks = niceTicks(Math.max(1, ...data.flatMap((row) => series.map((s) => num(row, s.key)))));
  const top = ticks[ticks.length - 1];
  const plotW = Math.max(0, width - M.left - M.right);
  const plotH = height - M.top - M.bottom;
  const x = (i: number) => M.left + (data.length <= 1 ? plotW / 2 : (i / (data.length - 1)) * plotW);
  const y = (v: number) => M.top + plotH - (v / top) * plotH;
  const labelEvery = Math.max(1, Math.ceil(data.length / Math.max(1, Math.floor(plotW / 72))));

  const onMove = (clientX: number) => {
    const el = ref.current;
    if (!el || data.length === 0) return;
    const px = clientX - el.getBoundingClientRect().left - M.left;
    setActive(Math.max(0, Math.min(data.length - 1, Math.round((px / Math.max(1, plotW)) * (data.length - 1)))));
  };

  return (
    <div
      ref={ref}
      className={cx("relative rounded-lg", focusRing)}
      tabIndex={0}
      role="img"
      aria-label={`${ariaLabel}. Use the arrow keys to read each point.`}
      onKeyDown={onKeyDown}
      onBlur={() => setActive(null)}
      onMouseMove={(e) => onMove(e.clientX)}
      onMouseLeave={() => setActive(null)}
    >
      {width > 0 && (
        <svg width={width} height={height} className="block">
          {ticks.map((t) => (
            <g key={t}>
              <line x1={M.left} x2={width - M.right} y1={y(t)} y2={y(t)} stroke="var(--line)" />
              <text x={M.left - 8} y={y(t)} dy="0.32em" textAnchor="end" className="tabular" fontSize={11} fill="var(--muted)">
                {t.toLocaleString()}
              </text>
            </g>
          ))}
          {series.map((s) => {
            const line = data.map((row, i) => `${i ? "L" : "M"}${x(i)},${y(num(row, s.key))}`).join("");
            const area = data.length ? `${line}L${x(data.length - 1)},${y(0)}L${x(0)},${y(0)}Z` : "";
            return (
              <g key={s.key}>
                <path d={area} fill={s.color} opacity={0.1} />
                <path d={line} fill="none" stroke={s.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
              </g>
            );
          })}
          {active !== null && (
            <g>
              <line x1={x(active)} x2={x(active)} y1={M.top} y2={M.top + plotH} stroke="var(--line-strong)" />
              {series.map((s) => (
                <circle key={s.key} cx={x(active)} cy={y(num(data[active], s.key))} r={4} fill={s.color} stroke="var(--card)" strokeWidth={2} />
              ))}
            </g>
          )}
          {data.map((row, i) =>
            i % labelEvery === 0 || i === data.length - 1 ? (
              <text key={i} x={x(i)} y={height - 6} textAnchor="middle" className="tabular" fontSize={11} fill="var(--muted)">
                {xLabel(row)}
              </text>
            ) : null,
          )}
        </svg>
      )}
      {active !== null && data[active] && (
        <Tooltip
          left={x(active)}
          title={xLabel(data[active])}
          rows={series.map((s) => ({ key: s.key, label: s.label, value: num(data[active], s.key).toLocaleString(), color: s.color }))}
        />
      )}
      {width === 0 && <div style={{ height }} />}
    </div>
  );
}

/** Tiny trend line for a stat tile: de-emphasis grey body, latest point in the accent. */
export function Sparkline({ data, height = 32, label }: { data: number[]; height?: number; label: string }) {
  const [ref, width] = useChartSize<HTMLDivElement>();
  const max = Math.max(1, ...data);
  const x = (i: number) => (data.length <= 1 ? width / 2 : 2 + (i / (data.length - 1)) * (width - 6));
  const y = (v: number) => height - 3 - (v / max) * (height - 8);
  const line = data.map((v, i) => `${i ? "L" : "M"}${x(i)},${y(v)}`).join("");
  return (
    <div ref={ref} role="img" aria-label={label}>
      {width > 0 && data.length > 0 && (
        <svg width={width} height={height} className="block overflow-visible">
          <path d={`${line}L${x(data.length - 1)},${height}L${x(0)},${height}Z`} fill="var(--chart-muted)" opacity={0.25} />
          <path d={line} fill="none" stroke="var(--chart-muted)" strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
          <circle cx={x(data.length - 1)} cy={y(data[data.length - 1])} r={3} fill="var(--accent)" stroke="var(--card)" strokeWidth={1.5} />
        </svg>
      )}
    </div>
  );
}

/** Ranked horizontal bars: label inside a light wash bar, value at the tip. Values are always visible. */
export function BarList({
  items,
  format = (v: number) => v.toLocaleString(),
  ariaLabel,
}: {
  items: { key: string; label: string; value: number; to?: string }[];
  format?: (v: number) => string;
  ariaLabel: string;
}) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <ul className="space-y-1.5" aria-label={ariaLabel}>
      {items.map((item) => {
        const bar = (
          <>
            <span className="relative flex h-8 min-w-0 flex-1 items-center overflow-hidden rounded-md">
              <span className="absolute inset-y-0 left-0 rounded-md" style={{ width: `${(item.value / max) * 100}%`, background: "color-mix(in srgb, var(--series) 14%, transparent)" }} aria-hidden />
              <span className="relative truncate px-2.5 text-sm text-fg">{item.label}</span>
            </span>
            <span className="tabular w-16 shrink-0 text-right text-sm font-medium text-fg">{format(item.value)}</span>
          </>
        );
        return (
          <li key={item.key}>
            {item.to ? (
              <Link to={item.to} className={cx("flex items-center gap-3 rounded-md hover:bg-hover", focusRing)}>
                {bar}
              </Link>
            ) : (
              <div className="flex items-center gap-3">{bar}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/** @deprecated kept for older pages: a BarList. */
export function HBars({ rows, unit, format = String }: { rows: { label: string; value: number }[]; unit: string; format?: (v: number) => string }) {
  return <BarList items={rows.map((r) => ({ key: r.label, label: r.label, value: r.value }))} format={format} ariaLabel={unit} />;
}

/** One thin stacked bar showing composition, with a legend of counts and shares. */
export function CategoryBar({ segments, ariaLabel }: { segments: { key: string; label: string; value: number; color: string; to?: string }[]; ariaLabel: string }) {
  const total = segments.reduce((s, x) => s + x.value, 0);
  const visible = segments.filter((s) => s.value > 0);
  return (
    <div>
      <div className="flex h-2 gap-0.5 overflow-hidden rounded-full bg-inset" role="img" aria-label={`${ariaLabel}: ${visible.map((s) => `${s.label} ${s.value}`).join(", ") || "none"}`}>
        {visible.map((s) => (
          <span key={s.key} className="h-full first:rounded-l-full last:rounded-r-full" style={{ width: `${(s.value / total) * 100}%`, background: s.color }} />
        ))}
      </div>
      <ul className="mt-3 space-y-1.5">
        {segments.map((s) => {
          const row = (
            <>
              <span className="size-2 shrink-0 rounded-full" style={{ background: s.color }} aria-hidden />
              <span className="flex-1 truncate text-muted">{s.label}</span>
              <span className="tabular font-medium text-fg">{s.value.toLocaleString()}</span>
              <span className="tabular w-10 text-right text-muted">{total ? Math.round((s.value / total) * 100) : 0}%</span>
            </>
          );
          return (
            <li key={s.key}>
              {s.to ? (
                <Link to={s.to} className={cx("flex items-center gap-2 rounded-md px-1 py-0.5 text-sm hover:bg-hover", focusRing)}>
                  {row}
                </Link>
              ) : (
                <div className="flex items-center gap-2 px-1 py-0.5 text-sm">{row}</div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** Re-render on an interval (used to keep "updated Xs ago" honest). */
export function useTicker(ms = 5000) {
  const [, set] = useState(0);
  useEffect(() => {
    const t = setInterval(() => set((n) => n + 1), ms);
    return () => clearInterval(t);
  }, [ms]);
}
