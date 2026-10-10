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
  refresh_token?: string;
  expires_at: number; // epoch ms
  /** Signed in with the console's own username + password form (no provider browser session to end). */
  via?: "password";
}

interface Pending {
  verifier: string;
  state: string;
  nonce: string;
  return_to: string;
}

const TOKEN_KEY = "aegis.sso.token";
const PENDING_KEY = "aegis.sso.pending";
const THEN_KEY = "aegis.sso.then"; // "sign in again right after the provider session has ended"

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

/** True when the stored session came from the username + password form. */
export const signedInWithPassword = () => read<StoredToken>(TOKEN_KEY)?.via === "password";

/** The stored session even if its access token has expired (a refresh token may still renew it). */
export const hasStoredSession = () => !!read<StoredToken>(TOKEN_KEY)?.refresh_token;

interface TokenBody {
  access_token?: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  error?: string;
  error_description?: string;
}

async function tokenRequest(config: SsoConfig, form: Record<string, string>): Promise<{ ok: boolean; body: TokenBody }> {
  let response: Response;
  try {
    response = await fetch(config.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: config.client_id, ...form }),
    });
  } catch {
    throw new Error(`Could not reach the identity provider at ${new URL(config.token_endpoint).host}. Is Keycloak running?`);
  }
  return { ok: response.ok, body: (await response.json().catch(() => ({}))) as TokenBody };
}

/** A readable reason for a refused password sign-in. */
function passwordProblem(body: TokenBody): string {
  const detail = (body.error_description ?? "").toLowerCase();
  if (body.error === "invalid_grant") {
    if (detail.includes("disabled")) return "This account is disabled.";
    if (detail.includes("not fully set up")) return "This account still needs setup in the identity provider before it can sign in.";
    return "Incorrect username or password.";
  }
  if (body.error === "unauthorized_client") return "Password sign-in is not enabled on the identity provider. An administrator can turn it on with: python -m aegis_demo.keycloak_setup enable-password-login";
  return body.error_description || "The identity provider refused the sign-in.";
}

/**
 * Sign in with a username and password typed into the console. The password goes straight to the identity
 * provider's token endpoint (never to the Aegis API) and the console keeps only the resulting tokens.
 */
export async function passwordSignIn(config: SsoConfig, username: string, password: string): Promise<void> {
  const { ok, body } = await tokenRequest(config, { grant_type: "password", username, password, scope: config.scopes });
  if (!ok || !body.access_token) throw new Error(passwordProblem(body));
  write(TOKEN_KEY, {
    access_token: body.access_token,
    id_token: body.id_token,
    refresh_token: body.refresh_token,
    expires_at: Date.now() + (body.expires_in ?? 300) * 1000,
    via: "password",
  } satisfies StoredToken);
}

/** Trade the stored refresh token for a fresh access token. Resolves to it, or null when the session is over. */
export async function refreshSession(config: SsoConfig): Promise<string | null> {
  const stored = read<StoredToken>(TOKEN_KEY);
  if (!stored?.refresh_token) return null;
  try {
    const { ok, body } = await tokenRequest(config, { grant_type: "refresh_token", refresh_token: stored.refresh_token });
    if (!ok || !body.access_token) return null;
    write(TOKEN_KEY, {
      ...stored,
      access_token: body.access_token,
      id_token: body.id_token ?? stored.id_token,
      refresh_token: body.refresh_token ?? stored.refresh_token,
      expires_at: Date.now() + (body.expires_in ?? 300) * 1000,
    } satisfies StoredToken);
    return body.access_token;
  } catch {
    return null;
  }
}

/** Sign out of a password session: end it at the provider in the background, then forget the tokens. No redirect. */
export function localSignOut(config: SsoConfig | null) {
  const stored = read<StoredToken>(TOKEN_KEY);
  clearSsoToken();
  if (config?.end_session_endpoint && stored?.refresh_token) {
    void fetch(config.end_session_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: config.client_id, refresh_token: stored.refresh_token }),
    }).catch(() => undefined); // best effort: the tokens are gone from this tab either way
  }
}

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

/** Where to land after the provider has ended its session (must be a registered post-logout URI). */
const homeUrl = () => `${window.location.origin}${import.meta.env.BASE_URL}`;

/**
 * Forget the token and end the provider's own session too. Without that the provider keeps its login cookie and
 * would silently sign the next "Sign in" straight back in as the same account, so you could never change role.
 *
 * With `signInAfter`, the console signs in again as soon as the provider has sent the browser back (see
 * takePendingSignIn), which is how "Switch account" works.
 */
export function signOut(config: SsoConfig | null, signInAfter?: { returnTo: string }) {
  const stored = read<StoredToken>(TOKEN_KEY);
  clearSsoToken();
  if (signInAfter) write(THEN_KEY, { return_to: signInAfter.returnTo });
  if (!config?.end_session_endpoint) {
    // A provider without logout support: the best we can do is to sign in again (or just go home).
    if (signInAfter && config) void startSignIn(config, signInAfter.returnTo);
    else window.location.assign(homeUrl());
    return;
  }
  const url = new URL(config.end_session_endpoint);
  url.searchParams.set("client_id", config.client_id);
  url.searchParams.set("post_logout_redirect_uri", homeUrl());
  // Only a still-valid ID token is offered as a hint; with none, the provider asks the person to confirm the logout.
  if (stored?.id_token && stored.expires_at > Date.now()) url.searchParams.set("id_token_hint", stored.id_token);
  window.location.assign(url.toString());
}

/** After the provider's logout redirect: was a fresh sign-in requested? Returns the page to go back to, once. */
export function takePendingSignIn(): string | null {
  const pending = read<{ return_to: string }>(THEN_KEY);
  write(THEN_KEY, null);
  return pending ? pending.return_to : null;
}
