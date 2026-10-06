import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { CheckCircle2, ShieldAlert, X } from "lucide-react";

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
      <div className="fixed right-5 bottom-24 z-50 flex w-96 flex-col gap-2" aria-live="polite">
        {items.map((t) => (
          <div
            key={t.id}
            className="flex gap-3 rounded-xl border border-line-strong bg-card p-3.5 shadow-2xl shadow-black/30"
            role={t.tone === "error" ? "alert" : "status"}
          >
            {t.tone === "success" ? (
              <CheckCircle2 className="mt-0.5 size-5 shrink-0 text-good-ink" />
            ) : (
              <ShieldAlert className="mt-0.5 size-5 shrink-0 text-critical-ink" />
            )}
            <div className="min-w-0 flex-1">
              <div className="text-sm font-semibold">{t.title}</div>
              {t.detail && <div className="mt-0.5 text-sm break-words text-muted">{t.detail}</div>}
            </div>
            <button
              className="text-faint hover:text-fg"
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
