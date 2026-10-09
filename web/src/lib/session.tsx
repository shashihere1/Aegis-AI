import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, setRelogin, setToken } from "./api";
import { clearSsoToken, completeSignIn, signOut as endSession, startSignIn, storedSsoToken, type AuthConfig } from "./auth";
import type { Persona } from "./types";

// Two ways in. Real SSO (any OpenID Connect provider) shows who you really are. The development persona switcher
// logs in as demo users with no password, so segregation of duties can be shown by changing role.
const STORAGE_KEY = "aegis.persona";
const DEFAULT_PERSONA = "mark.jansen";

interface Session {
  personas: Persona[];
  persona: Persona | null;
  source: "sso" | "dev" | null;
  config: AuthConfig | null;
  ready: boolean;
  needsSignIn: boolean;
  switchTo: (username: string) => Promise<void>;
  signIn: (returnTo?: string) => Promise<void>;
  signOut: () => void;
  completeSso: (search: string) => Promise<string>;
  can: (...roles: string[]) => boolean;
}

const SessionContext = createContext<Session | null>(null);

function stored(): string {
  try {
    return localStorage.getItem(STORAGE_KEY) || DEFAULT_PERSONA;
  } catch {
    return DEFAULT_PERSONA;
  }
}

async function login(username: string): Promise<string> {
  const { access_token } = await api<{ access_token: string }>("/idp/login", { method: "POST", body: { username } });
  return access_token;
}

const onCallback = () => window.location.pathname.endsWith("/auth/callback");

export function SessionProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const configRef = useRef<AuthConfig | null>(null); // lets the callbacks below stay stable once config loads
  const [personas, setPersonas] = useState<Persona[]>([]);
  const [username, setUsername] = useState<string>(stored());
  const [ssoUser, setSsoUser] = useState<Persona | null>(null);
  const [ready, setReady] = useState(false);
  const [needsSignIn, setNeedsSignIn] = useState(false);

  const signIn = useCallback(
    async (returnTo = "/") => {
      if (configRef.current?.oidc) await startSignIn(configRef.current.oidc, returnTo);
    },
    [],
  );

  // After an SSO token is rejected (expired, provider keys rotated) the only way forward is to sign in again.
  const resignIn = useCallback(() => {
    clearSsoToken();
    void signIn(window.location.pathname.replace(import.meta.env.BASE_URL.replace(/\/$/, ""), "") || "/");
    return new Promise<string>(() => {}); // the page is navigating away
  }, [signIn]);

  const adoptSsoToken = useCallback(
    async (accessToken: string): Promise<boolean> => {
      setToken(accessToken);
      try {
        const me = await api<Omit<Persona, "status">>("/v1/auth/me");
        setSsoUser({ ...me, status: "active" });
        setRelogin(resignIn);
        return true;
      } catch {
        setToken(null);
        clearSsoToken();
        return false;
      }
    },
    [resignIn],
  );

  const switchTo = useCallback(
    async (next: string) => {
      clearSsoToken();
      setSsoUser(null);
      setToken(await login(next));
      setRelogin(() => login(next).then((t) => (setToken(t), t)));
      setUsername(next);
      try {
        localStorage.setItem(STORAGE_KEY, next);
      } catch {
        /* storage unavailable: the choice just won't persist */
      }
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
      const token = storedSsoToken();
      if (token && (await adoptSsoToken(token.access_token))) {
        setReady(true);
        return;
      }
      if (found.dev_login) {
        try {
          const list = await api<Persona[]>("/idp/personas");
          const staff = list.filter((p) => !p.roles.includes("customer"));
          setPersonas(staff);
          const initial = staff.find((p) => p.username === stored() && p.status === "active") ?? staff[0];
          await switchTo(initial.username);
        } catch {
          setReady(true);
        }
      } else {
        setNeedsSignIn(true);
        setReady(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [switchTo, adoptSsoToken]);

  // The dev persona list is only needed when development login is on (it is refused otherwise).
  useEffect(() => {
    if (ssoUser && config?.dev_login && personas.length === 0) {
      api<Persona[]>("/idp/personas")
        .then((list) => setPersonas(list.filter((p) => !p.roles.includes("customer"))))
        .catch(() => undefined);
    }
  }, [ssoUser, config, personas.length]);

  const completeSso = useCallback(
    async (search: string) => {
      if (!config?.oidc) throw new Error("SSO is not configured on this server.");
      const returnTo = await completeSignIn(config.oidc, search);
      const token = storedSsoToken();
      if (!token || !(await adoptSsoToken(token.access_token))) throw new Error("The server did not accept the new token.");
      setNeedsSignIn(false);
      setReady(true);
      await queryClient.invalidateQueries();
      return returnTo;
    },
    [config, queryClient, adoptSsoToken],
  );

  const signOut = useCallback(() => {
    setSsoUser(null);
    setToken(null);
    endSession(config?.oidc ?? null);
  }, [config]);

  const devPersona = personas.find((p) => p.username === username) ?? null;
  const persona = ssoUser ?? devPersona;
  const source: Session["source"] = ssoUser ? "sso" : devPersona ? "dev" : null;
  const can = useCallback((...roles: string[]) => !!persona && roles.some((r) => persona.roles.includes(r)), [persona]);
  const value = useMemo(
    () => ({ personas, persona, source, config, ready, needsSignIn, switchTo, signIn, signOut, completeSso, can }),
    [personas, persona, source, config, ready, needsSignIn, switchTo, signIn, signOut, completeSso, can],
  );
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): Session {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession outside SessionProvider");
  return ctx;
}
