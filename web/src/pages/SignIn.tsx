import { useMemo, useRef, useState, type FormEvent } from "react";
import { useLocation, useNavigate } from "react-router";
import { ChevronDown, Eye, EyeOff, Moon, ShieldCheck, Sun, Users, Zap } from "lucide-react";
import { useSession } from "../lib/session";
import { useTheme } from "../lib/theme";
import { Avatar, Button, Callout, Field, IconButton, TextInput, cx, focusRing } from "../components/ui";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "../components/shadcn/dropdown-menu";

interface Account {
  /** The identity provider login name. */
  login: string;
  name: string;
  role: string;
}

/**
 * The only screen anyone sees before signing in: the console, its navigation and its data stay hidden until a
 * sign-in succeeds. People type a username and password, which the identity provider (Keycloak) checks. The
 * corner menu picks a role to fill in, or, when development login is on, signs in as a demo persona instantly.
 */
export function SignIn({ problem }: { problem?: string }) {
  const { config, personas, signInWithPassword, switchTo } = useSession();
  const navigate = useNavigate();
  const location = useLocation();
  const [theme, toggleTheme] = useTheme();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [reveal, setReveal] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const passwordRef = useRef<HTMLInputElement>(null);
  const usernameRef = useRef<HTMLInputElement>(null);

  const idp = config?.oidc;
  const instant = config?.dev_login ? personas.filter((p) => p.status === "active") : [];
  const shown = error ?? problem ?? config?.oidc_error;

  // One identity-provider account per Aegis role: the first role keeps the person's username, further roles are
  // "<username>.<role>" (mirrors the realm built by keycloak_setup). Customers have no staff account.
  const accounts = useMemo<Account[]>(
    () =>
      personas
        .filter((p) => !p.roles.includes("customer"))
        .flatMap((p) => p.roles.map((role, i) => ({ login: i === 0 ? p.username : `${p.username}.${role}`, name: p.name, role }))),
    [personas],
  );

  const done = () => {
    // Signed in from the SSO callback screen: there is no console route under it, so go to the app.
    if (location.pathname.endsWith("/auth/callback")) navigate("/", { replace: true });
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError(!username.trim() ? "Enter your username." : "Enter your password.");
      (!username.trim() ? usernameRef : passwordRef).current?.focus();
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await signInWithPassword(username, password);
      done();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not sign in.");
      setPassword("");
      setBusy(false);
      passwordRef.current?.focus();
    }
  };

  const pickAccount = (a: Account) => {
    setUsername(a.login);
    setPassword("");
    setError(null);
    setTimeout(() => passwordRef.current?.focus(), 0);
  };

  const enterInstantly = async (login: string) => {
    setBusy(true);
    setError(null);
    try {
      await switchTo(login);
      done();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not sign in as that user.");
      setBusy(false);
    }
  };

  const hasMenu = accounts.length > 0 || instant.length > 0;

  return (
    <div className="relative flex min-h-screen flex-col items-center bg-page px-4 py-12 sm:py-16">
      {/* Top-right corner: switch role, theme */}
      <div className="absolute top-4 right-4 flex items-center gap-1">
        {hasMenu && (
          <DropdownMenu>
            <DropdownMenuTrigger
              disabled={busy}
              className={cx(
                "flex h-9 items-center gap-2 rounded-lg border border-line-strong bg-card px-3 text-sm font-medium text-fg shadow-card transition-colors hover:bg-hover disabled:opacity-50",
                focusRing,
              )}
            >
              <Users className="size-4 text-muted" />
              Switch role
              <ChevronDown className="size-4 text-faint" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-80 max-w-[calc(100vw-1.5rem)]">
              {accounts.length > 0 && idp && (
                <>
                  <DropdownMenuLabel>Fill in a role account</DropdownMenuLabel>
                  {accounts.map((a) => (
                    <DropdownMenuItem key={a.login} onSelect={() => pickAccount(a)}>
                      <Avatar name={a.name} size="sm" />
                      <span className="min-w-0 flex-1">
                        <span className="block text-sm font-medium text-fg">{a.name}</span>
                        <span className="block truncate text-xs text-muted">
                          {a.role} · <span className="font-mono">{a.login}</span>
                        </span>
                      </span>
                    </DropdownMenuItem>
                  ))}
                </>
              )}
              {instant.length > 0 && (
                <>
                  {accounts.length > 0 && idp && <DropdownMenuSeparator />}
                  <DropdownMenuLabel className="flex items-center gap-1.5">
                    <Zap className="size-3.5" /> Instant demo sign-in, no password
                  </DropdownMenuLabel>
                  {instant.map((p) => (
                    <DropdownMenuItem key={p.username} onSelect={() => void enterInstantly(p.username)}>
                      <Avatar name={p.name} size="sm" />
                      <span className="min-w-0 flex-1">
                        <span className="block text-sm font-medium text-fg">{p.name}</span>
                        <span className="block truncate text-xs text-muted">{p.roles.join(", ")}</span>
                      </span>
                    </DropdownMenuItem>
                  ))}
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
        <IconButton label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"} icon={theme === "dark" ? Sun : Moon} onClick={toggleTheme} />
      </div>

      <main className="w-full max-w-[400px]">
        <div className="mb-8 flex flex-col items-center text-center">
          <span className="grid size-11 place-items-center rounded-xl bg-fg text-page shadow-card">
            <ShieldCheck className="size-6" />
          </span>
          <h1 className="mt-5 text-2xl font-semibold tracking-[-0.02em] text-fg">Sign in to Aegis</h1>
          <p className="mt-1.5 text-sm text-muted">The governance console for every AI agent at ABN AMRO.</p>
        </div>

        <form onSubmit={submit} noValidate className="space-y-4 rounded-xl border border-line bg-card p-6 shadow-card">
          {shown && (
            <Callout tone="critical" title="Could not sign in">
              {shown}
            </Callout>
          )}

          {!idp && (
            <Callout tone="warning" title="The identity provider is not available">
              {instant.length
                ? "Password sign-in needs the identity provider (Keycloak). Use the Switch role menu in the top-right corner to sign in as a demo user."
                : "Password sign-in needs the identity provider (Keycloak), which this server has not been configured to use."}
            </Callout>
          )}

          <Field label="Username">
            <TextInput
              ref={usernameRef}
              name="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              autoFocus
              disabled={busy || !idp}
              placeholder="e.g. mark.jansen"
            />
          </Field>

          <Field label="Password">
            <div className="relative">
              <TextInput
                ref={passwordRef}
                name="password"
                type={reveal ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                disabled={busy || !idp}
                className="pr-10"
              />
              <button
                type="button"
                onClick={() => setReveal((v) => !v)}
                disabled={!idp}
                className={cx("absolute top-1/2 right-2 grid size-7 -translate-y-1/2 place-items-center rounded-md text-muted hover:bg-hover hover:text-fg", focusRing)}
                aria-label={reveal ? "Hide password" : "Show password"}
                aria-pressed={reveal}
              >
                {reveal ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
              </button>
            </div>
          </Field>

          <Button type="submit" variant="primary" loading={busy} disabled={!idp} className="h-10 w-full">
            Sign in
          </Button>
        </form>

        <p className="mt-6 text-center text-caption text-muted">
          {idp && (
            <>
              Checked by <span className="font-mono">{idp.issuer.replace(/^https?:\/\//, "").split("/")[0]}</span> · Aegis never stores your password ·{" "}
            </>
          )}
          Synthetic demo environment
        </p>
      </main>
    </div>
  );
}
