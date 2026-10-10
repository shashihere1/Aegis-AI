import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, setRelogin, setToken } from "./api";
import {
  clearSsoToken,
  completeSignIn,
  hasStoredSession,
  localSignOut,
  passwordSignIn,
  refreshSession,
  signOut as endSession,
  signedInWithPassword,
  startSignIn,
  storedSsoToken,
  takePendingSignIn,
  type AuthConfig,
} from "./auth";
import type { Persona } from "./types";

// Two ways in, both on the sign-in page. Real SSO (any OpenID Connect provider) shows who you really are. The
// development login signs in as a demo persona with no password, so segregation of duties can be shown by signing
// in as a different role. Nothing is shown until one of them succeeds.
const STORAGE_KEY = "aegis.persona";

interface Session {
  personas: Persona[];
  persona: Persona | null;
  source: "sso" | "dev" | null;
  config: AuthConfig | null;
  ready: boolean;
  needsSignIn: boolean;
  switchTo: (username: string) => Promise<void>;
  signIn: (returnTo?: string) => Promise<void>;
  /** Username + password, checked by the identity provider. Throws a readable message when refused. */
  signInWithPassword: (username: string, password: string) => Promise<void>;
  signOut: () => void;
  completeSso: (search: string) => Promise<string>;
  can: (...roles: string[]) => boolean;
}

const SessionContext = createContext<Session | null>(null);

// sessionStorage: a reload keeps you signed in, closing the tab signs you out.
function remembered(): string | null {
  try {
    return sessionStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function remember(username: string | null) {
  try {
    if (username) sessionStorage.setItem(STORAGE_KEY, username);
    else sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    /* storage unavailable: a reload will return to the sign-in page */
  }
}

async function login(username: string): Promise<string> {
  const { access_token } = await api<{ access_token: string }>("/idp/login", { method: "POST", body: { username } });
  return access_token;
}

// Staff personas, plus the synthetic customer Jan for the Bank Assistant demo (other customers are not offered).
const selectable = (p: Persona) => !p.roles.includes("customer") || p.username === "jan.devries";

const onCallback = () => window.location.pathname.endsWith("/auth/callback");

export function SessionProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const configRef = useRef<AuthConfig | null>(null); // lets the callbacks below stay stable once config loads
  const ssoUserRef = useRef<Persona | null>(null);
  const [personas, setPersonas] = useState<Persona[]>([]);
  const [username, setUsername] = useState<string>("");
  const [ssoUser, setSsoUserState] = useState<Persona | null>(null);
  const setSsoUser = useCallback((user: Persona | null) => {
    ssoUserRef.current = user;
    setSsoUserState(user);
  }, []);
  const [ready, setReady] = useState(false);
  const [needsSignIn, setNeedsSignIn] = useState(false);

  // A person choosing "Sign in with SSO" or "Switch account" wants to pick the account, so the provider's own login
  // session is ended first; otherwise it would silently sign them straight back in as the previous account.
  const signIn = useCallback(async (returnTo = "/") => {
    if (!configRef.current?.oidc) return;
    setSsoUser(null);
    setToken(null);
    endSession(configRef.current.oidc, { returnTo });
  }, []);

  // After an SSO token is rejected (expired, provider keys rotated) the way forward is a silent re-sign-in: the
  // provider session, if it is still alive, renews the token without asking again.
  const resignIn = useCallback(async () => {
    // A session with a refresh token renews silently; only when that fails does the person have to sign in again.
    const oidc = configRef.current?.oidc;
    const renewed = oidc ? await refreshSession(oidc) : null;
    if (renewed) {
      setToken(renewed);
      return renewed;
    }
    if (signedInWithPassword()) {
      clearSsoToken();
      ssoUserRef.current = null;
      setSsoUserState(null);
      setToken(null);
      setNeedsSignIn(true);
      return new Promise<string>(() => {}); // the sign-in page replaces the console
    }
    clearSsoToken();
    const here = window.location.pathname.replace(import.meta.env.BASE_URL.replace(/\/$/, ""), "") || "/";
    if (configRef.current?.oidc) void startSignIn(configRef.current.oidc, here);
    return new Promise<string>(() => {}); // the page is navigating away
  }, []);

  const adoptSsoToken = useCallback(
    /** Resolves to null when the server accepts the token, otherwise to the server's reason for refusing it. */
    async (accessToken: string): Promise<string | null> => {
      setToken(accessToken);
      try {
        const me = await api<Omit<Persona, "status">>("/v1/auth/me");
        setSsoUser({ ...me, status: "active" });
        setRelogin(resignIn);
        return null;
      } catch (error) {
        setToken(null);
        clearSsoToken();
        const reason = error instanceof Error ? error.message : "";
        return reason.replace(/^invalid token: /, "") || "The server did not accept the new token.";
      }
    },
    [resignIn],
  );

  const switchTo = useCallback(
    async (next: string) => {
      if (ssoUserRef.current && configRef.current?.oidc) {
        // Leaving an SSO identity: remember the persona, then end the provider session so a later "Sign in with SSO"
        // does not silently log back in as the account being left. The page reloads as the chosen persona.
        remember(next);
        setSsoUser(null);
        setToken(null);
        endSession(configRef.current.oidc);
        return;
      }
      clearSsoToken();
      setSsoUser(null);
      await queryClient.cancelQueries();
      queryClient.clear(); // Never display the previous persona's cached customer records.
      setToken(await login(next));
      setRelogin(() => login(next).then((t) => (setToken(t), t)));
      setUsername(next);
      remember(next);
      setNeedsSignIn(false);
      setReady(true);
      await queryClient.invalidateQueries();
    },
    [queryClient],
  );

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const found = await api<AuthConfig>("/v1/auth/config").catch(() => ({ dev_login: true, oidc: null, oidc_error: null }));
      if (cancelled) return;
      configRef.current = found;
      setConfig(found);
      if (onCallback()) return; // the callback page finishes the sign-in itself
      const again = takePendingSignIn();
      if (again !== null && found.oidc) {
        await startSignIn(found.oidc, again); // the provider session has ended: this shows a fresh login form
        return;
      }
      // An access token that expired while the tab was closed can often be renewed with the refresh token.
      let token = storedSsoToken();
      if (!token && found.oidc && hasStoredSession()) {
        await refreshSession(found.oidc);
        token = storedSsoToken();
      }
      if (token && (await adoptSsoToken(token.access_token)) === null) {
        setReady(true);
        return;
      }
      // No one is signed in yet. Load the demo personas so the sign-in page can offer them, and resume this tab's
      // earlier dev session if there was one. Otherwise show the sign-in page and nothing else.
      let staff: Persona[] = [];
      if (found.dev_login) {
        try {
          staff = (await api<Persona[]>("/idp/personas")).filter(selectable);
          setPersonas(staff);
        } catch {
          /* the sign-in page shows its own message */
        }
      }
      const resume = staff.find((p) => p.username === remembered() && p.status === "active");
      if (resume) {
        try {
          await switchTo(resume.username);
          return;
        } catch {
          remember(null);
        }
      }
      setNeedsSignIn(true);
      setReady(true);
    })();
    return () => {
      cancelled = true;
    };
  }, [switchTo, adoptSsoToken]);

  // The dev persona list is only needed when development login is on (it is refused otherwise).
  useEffect(() => {
    if (ssoUser && config?.dev_login && personas.length === 0) {
      api<Persona[]>("/idp/personas")
        .then((list) => setPersonas(list.filter(selectable)))
        .catch(() => undefined);
    }
  }, [ssoUser, config, personas.length]);

  const completeSso = useCallback(
    async (search: string) => {
      if (!config?.oidc) throw new Error("SSO is not configured on this server.");
      const returnTo = await completeSignIn(config.oidc, search);
      const token = storedSsoToken();
      const problem = token ? await adoptSsoToken(token.access_token) : "The sign-in did not return a token.";
      if (problem) throw new Error(problem);
      setNeedsSignIn(false);
      setReady(true);
      await queryClient.cancelQueries();
      queryClient.clear();
      return returnTo;
    },
    [config, queryClient, adoptSsoToken],
  );

  const signInWithPassword = useCallback(
    async (user: string, password: string) => {
      const oidc = configRef.current?.oidc;
      if (!oidc) throw new Error("Password sign-in needs the identity provider, which is not configured on this server.");
      await passwordSignIn(oidc, user.trim(), password);
      const token = storedSsoToken();
      const problem = token ? await adoptSsoToken(token.access_token) : "The sign-in did not return a token.";
      if (problem) throw new Error(problem);
      remember(null);
      setUsername("");
      setNeedsSignIn(false);
      setReady(true);
      await queryClient.cancelQueries();
      queryClient.clear(); // never show the previous person's cached records
    },
    [queryClient, adoptSsoToken],
  );

  const signOut = useCallback(() => {
    remember(null);
    if (ssoUserRef.current && signedInWithPassword()) {
      // No provider browser session exists for a password sign-in, so there is nothing to redirect through.
      localSignOut(configRef.current?.oidc ?? null);
      setSsoUser(null);
      setToken(null);
      setRelogin(null);
      queryClient.cancelQueries();
      queryClient.clear();
      setNeedsSignIn(true);
      return;
    }
    if (ssoUserRef.current) {
      // End the provider's session too; the page reloads on the sign-in page.
      setSsoUser(null);
      setToken(null);
      endSession(config?.oidc ?? null);
      return;
    }
    setToken(null);
    setRelogin(null);
    setUsername("");
    queryClient.cancelQueries();
    queryClient.clear(); // The next person must never see this one's cached records.
    setNeedsSignIn(true);
  }, [config, queryClient]);

  const devPersona = personas.find((p) => p.username === username) ?? null;
  const persona = ssoUser ?? devPersona;
  const source: Session["source"] = ssoUser ? "sso" : devPersona ? "dev" : null;
  const can = useCallback((...roles: string[]) => !!persona && roles.some((r) => persona.roles.includes(r)), [persona]);
  const value = useMemo(
    () => ({ personas, persona, source, config, ready, needsSignIn, switchTo, signIn, signInWithPassword, signOut, completeSso, can }),
    [personas, persona, source, config, ready, needsSignIn, switchTo, signIn, signInWithPassword, signOut, completeSso, can],
  );
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): Session {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession outside SessionProvider");
  return ctx;
}
