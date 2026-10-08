import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, setRelogin, setToken } from "./api";
import type { Persona } from "./types";

// Demo personas from the dev IdP. Each has different roles, so switching shows segregation of duties.
const STORAGE_KEY = "aegis.persona";
const DEFAULT_PERSONA = "mark.jansen";

interface Session {
  personas: Persona[];
  persona: Persona | null;
  ready: boolean;
  switchTo: (username: string) => Promise<void>;
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

export function SessionProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [personas, setPersonas] = useState<Persona[]>([]);
  const [username, setUsername] = useState<string>(stored());
  const [ready, setReady] = useState(false);

  const switchTo = useCallback(
    async (next: string) => {
      await queryClient.cancelQueries();
      queryClient.clear(); // Never display the previous persona's cached customer records.
      setToken(await login(next));
      setRelogin(() => login(next).then((t) => (setToken(t), t)));
      setUsername(next);
      try {
        localStorage.setItem(STORAGE_KEY, next);
      } catch {
        /* storage unavailable: the choice just won't persist */
      }
      setReady(true);
      await queryClient.invalidateQueries();
    },
    [queryClient],
  );

  useEffect(() => {
    api<Persona[]>("/idp/personas")
      .then((list) => {
        const staff = list.filter((p) => !p.roles.includes("customer") || p.username === "jan.devries");
        setPersonas(staff);
        const initial = staff.find((p) => p.username === stored() && p.status === "active") ?? staff[0];
        return switchTo(initial.username);
      })
      .catch(() => setReady(true));
  }, [switchTo]);

  const persona = personas.find((p) => p.username === username) ?? null;
  const can = useCallback((...roles: string[]) => !!persona && roles.some((r) => persona.roles.includes(r)), [persona]);
  const value = useMemo(() => ({ personas, persona, ready, switchTo, can }), [personas, persona, ready, switchTo, can]);
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): Session {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession outside SessionProvider");
  return ctx;
}
