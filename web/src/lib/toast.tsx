import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { CheckCircle2, OctagonAlert, X } from "lucide-react";

type Tone = "success" | "error";
interface ToastItem {
  id: number;
  tone: Tone;
  title: string;
  detail?: string;
}

const ToastContext = createContext<(tone: Tone, title: string, detail?: string) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const push = useCallback((tone: Tone, title: string, detail?: string) => {
    const id = Date.now() + Math.random();
    setItems((list) => [...list, { id, tone, title, detail }]);
    setTimeout(() => setItems((list) => list.filter((t) => t.id !== id)), tone === "error" ? 7000 : 4000);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      {/* Above dialogs (z-40) and menus (z-50); clickable even while a dialog locks pointer events. */}
      <div className="pointer-events-none fixed right-4 bottom-20 z-[60] flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2" aria-live="polite">
        {items.map((t) => (
          <div
            key={t.id}
            data-toast
            className="pointer-events-auto flex gap-3 rounded-xl border border-line bg-card p-3.5 shadow-overlay"
            role={t.tone === "error" ? "alert" : "status"}
          >
            {t.tone === "success" ? <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-good-ink" /> : <OctagonAlert className="mt-0.5 size-4 shrink-0 text-critical-ink" />}
            <div className="min-w-0 flex-1">
              <div className="text-sm font-medium text-fg">{t.title}</div>
              {t.detail && <div className="mt-0.5 text-sm break-words text-muted">{t.detail}</div>}
            </div>
            <button
              type="button"
              className="grid size-6 shrink-0 place-items-center rounded-md text-muted hover:bg-hover hover:text-fg focus-visible:outline-2 focus-visible:outline-solid focus-visible:outline-offset-2 focus-visible:outline-accent"
              onClick={() => setItems((list) => list.filter((x) => x.id !== t.id))}
              aria-label="Dismiss"
            >
              <X className="size-4" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);
