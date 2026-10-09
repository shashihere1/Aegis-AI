// OpenID Connect sign-in for the console: authorization code + PKCE (RFC 7636), a public client with no secret.
// The provider is Keycloak, Microsoft Entra ID, any OIDC provider, or the demo server's built-in one. The console
// never sees a password: it is sent to the provider, and comes back with a code it exchanges for an access token.

export interface SsoConfig {
  issuer: string;
  client_id: string;
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint: string | null;
  scopes: string;
  builtin: boolean;
}

export interface AuthConfig {
  dev_login: boolean;
  oidc: SsoConfig | null;
  oidc_error: string | null;
}

interface StoredToken {
  access_token: string;
  id_token?: string;
  expires_at: number; // epoch ms
}

interface Pending {
  verifier: string;
  state: string;
  nonce: string;
  return_to: string;
}

const TOKEN_KEY = "aegis.sso.token";
const PENDING_KEY = "aegis.sso.pending";

// sessionStorage: the token disappears when the tab closes, and is not shared with other tabs.
function read<T>(key: string): T | null {
  try {
    const raw = sessionStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    return null;
  }
}

function write(key: string, value: unknown | null) {
  try {
    if (value === null) sessionStorage.removeItem(key);
    else sessionStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* storage unavailable: sign-in just will not survive a reload */
  }
}

const base64url = (bytes: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const randomString = (bytes = 32) => base64url(crypto.getRandomValues(new Uint8Array(bytes)));

export const redirectUri = () => `${window.location.origin}${import.meta.env.BASE_URL}auth/callback`;

export function storedSsoToken(): StoredToken | null {
  const token = read<StoredToken>(TOKEN_KEY);
  return token && token.expires_at - 30_000 > Date.now() ? token : null;
}

export const clearSsoToken = () => write(TOKEN_KEY, null);

export async function startSignIn(config: SsoConfig, returnTo = "/"): Promise<void> {
  if (!crypto.subtle) throw new Error("Sign-in needs a secure context: open the console on localhost or over HTTPS.");
  const pending: Pending = { verifier: randomString(48), state: randomString(), nonce: randomString(), return_to: returnTo };
  write(PENDING_KEY, pending);
  const challenge = base64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pending.verifier)));
  const url = new URL(config.authorization_endpoint);
  url.search = new URLSearchParams({
    client_id: config.client_id,
    redirect_uri: redirectUri(),
    response_type: "code",
    scope: config.scopes,
    state: pending.state,
    nonce: pending.nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();
  window.location.assign(url.toString());
}

function claims(jwt: string): Record<string, unknown> {
  try {
    return JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
  } catch {
    return {};
  }
}

const inFlight = new Map<string, Promise<string>>();

/** Finish the redirect: check state, trade the code for tokens, remember them. Resolves to the page to return to. */
export function completeSignIn(config: SsoConfig, search: string): Promise<string> {
  // React StrictMode runs effects twice in development; an authorization code can be used only once.
  const running = inFlight.get(search) ?? exchange(config, search);
  inFlight.set(search, running);
  return running;
}

async function exchange(config: SsoConfig, search: string): Promise<string> {
  const query = new URLSearchParams(search);
  const pending = read<Pending>(PENDING_KEY);
  write(PENDING_KEY, null);
  if (query.get("error")) throw new Error(`The provider refused the sign-in: ${query.get("error_description") ?? query.get("error")}`);
  if (!pending || !query.get("code") || query.get("state") !== pending.state) {
    throw new Error("This sign-in did not start in this browser tab. Please try again.");
  }
  const issuer = query.get("iss");
  if (issuer && issuer !== config.issuer) throw new Error("The response came from an unexpected provider.");

  const response = await fetch(config.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: query.get("code")!,
      redirect_uri: redirectUri(),
      client_id: config.client_id,
      code_verifier: pending.verifier,
    }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || !body.access_token) throw new Error(body.error_description ?? "The provider did not issue a token.");
  if (body.id_token && claims(body.id_token).nonce !== pending.nonce) throw new Error("The sign-in response was not for this request.");
  write(TOKEN_KEY, {
    access_token: body.access_token,
    id_token: body.id_token,
    expires_at: Date.now() + (body.expires_in ?? 3600) * 1000,
  } satisfies StoredToken);
  return pending.return_to;
}

/** Forget the token and, when the provider supports it, end its session too. */
export function signOut(config: SsoConfig | null) {
  const idToken = read<StoredToken>(TOKEN_KEY)?.id_token;
  clearSsoToken();
  const home = `${window.location.origin}${import.meta.env.BASE_URL}`;
  if (config?.end_session_endpoint) {
    const url = new URL(config.end_session_endpoint);
    url.searchParams.set("post_logout_redirect_uri", home);
    if (idToken) url.searchParams.set("id_token_hint", idToken);
    window.location.assign(url.toString());
  } else {
    window.location.assign(home);
  }
}
