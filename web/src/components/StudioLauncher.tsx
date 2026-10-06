import { useState } from "react";
import { useNavigate } from "react-router";
import { Play, RotateCcw, Sparkles, X } from "lucide-react";
import { SCENES, useResetDemo, useRunScene } from "../lib/scenes";
import { Spinner } from "./ui";

/** The floating button from the prototype: a quick launcher for the demo scenes. */
export function StudioLauncher() {
  const [open, setOpen] = useState(false);
  const run = useRunScene();
  const reset = useResetDemo();
  const navigate = useNavigate();
  return (
    <>
      {open && (
        <div className="fixed right-6 bottom-24 z-40 w-96 rounded-2xl border border-line-strong bg-card p-2 shadow-2xl">
          <div className="flex items-center justify-between px-3 py-2">
            <div>
              <div className="text-sm font-semibold">Run a demo scene</div>
              <div className="text-xs text-muted">Calls the real APIs; results appear across the console.</div>
            </div>
            <button onClick={() => setOpen(false)} className="text-faint hover:text-fg" aria-label="Close">
              <X className="size-4" />
            </button>
          </div>
          {SCENES.map((scene) => (
            <button
              key={scene.key}
              disabled={run.isPending}
              onClick={() => run.mutate(scene)}
              className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left hover:bg-hover disabled:opacity-50"
            >
              <span className="grid size-8 place-items-center rounded-lg bg-accent-soft text-accent">
                <scene.icon className="size-4" />
              </span>
              <span className="flex-1">
                <span className="block text-sm font-medium">
                  {scene.code} · {scene.title}
                </span>
              </span>
              {run.isPending && run.variables?.key === scene.key ? <Spinner /> : <Play className="size-4 text-faint" />}
            </button>
          ))}
          <div className="mt-1 flex gap-2 border-t border-line p-2">
            <button onClick={() => (setOpen(false), navigate("/studio"))} className="flex-1 rounded-lg px-3 py-2 text-sm text-accent hover:bg-hover">
              Open Demo Studio
            </button>
            <button onClick={() => reset.mutate()} className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm text-muted hover:bg-hover">
              <RotateCcw className="size-4" /> Reset
            </button>
          </div>
        </div>
      )}
      <button
        onClick={() => setOpen((v) => !v)}
        className="fixed right-6 bottom-6 z-40 grid size-14 place-items-center rounded-2xl bg-accent-strong text-white shadow-xl shadow-black/40 hover:bg-accent"
        aria-label="Demo scenes"
      >
        <Sparkles className="size-6" />
      </button>
    </>
  );
}
