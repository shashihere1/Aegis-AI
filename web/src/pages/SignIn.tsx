import { useState } from "react";
import { KeyRound, ShieldCheck, TriangleAlert } from "lucide-react";
import { useSession } from "../lib/session";
import { Button, Card } from "../components/ui";

/** Shown when development login is off, or when someone chooses to sign in with their own account. */
export function SignIn({ problem }: { problem?: string }) {
  const { config, signIn } = useSession();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const sso = config?.oidc;
  const shown = problem ?? error ?? config?.oidc_error;

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      await signIn("/");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not start sign-in.");
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-screen place-items-center bg-page px-4">
      <Card className="w-full max-w-md p-8">
        <div className="mb-6 flex items-center gap-3">
          <div className="grid size-12 place-items-center rounded-xl bg-accent-strong text-white">
            <ShieldCheck className="size-7" />
          </div>
          <div>
            <div className="text-lg font-semibold">Aegis AI</div>
            <div className="text-sm text-accent">Agent governance console</div>
          </div>
        </div>
        <h1 className="text-xl font-semibold">Sign in</h1>
        <p className="mt-1 mb-6 text-sm text-muted">
          Use your organisation account. The console never sees your password: you sign in at the identity provider.
        </p>
        {shown && (
          <div className="mb-4 flex gap-2 rounded-lg border border-critical/40 bg-critical/12 p-3 text-sm text-critical-ink" role="alert">
            <TriangleAlert className="mt-0.5 size-4 shrink-0" />
            <span>{shown}</span>
          </div>
        )}
        {sso ? (
          <>
            <Button variant="primary" icon={KeyRound} loading={busy} onClick={start} className="h-11 w-full text-base">
              {sso.builtin ? "Sign in with the demo SSO provider" : "Sign in with SSO"}
            </Button>
            <p className="mt-4 text-xs text-faint">
              Provider: <span className="font-mono">{sso.issuer}</span>
              {sso.builtin && " (built-in development provider)"}
            </p>
          </>
        ) : (
          !shown && <p className="text-sm text-muted">Single sign-on is not configured on this server.</p>
        )}
      </Card>
    </div>
  );
}
