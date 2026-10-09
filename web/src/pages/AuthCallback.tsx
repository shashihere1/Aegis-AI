import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { useSession } from "../lib/session";
import { Loading } from "../components/ui";
import { SignIn } from "./SignIn";

/** The provider sends the browser back here with a one-time code; this page finishes the sign-in. */
export function AuthCallback() {
  const { config, completeSso } = useSession();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!config) return; // wait until the server has told us where the provider is
    completeSso(window.location.search)
      .then((returnTo) => navigate(returnTo || "/", { replace: true }))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "Sign-in failed."));
  }, [config, completeSso, navigate]);

  return error ? <SignIn problem={error} /> : <Loading />;
}
