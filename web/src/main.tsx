import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createBrowserRouter, Navigate, RouterProvider, useRouteError } from "react-router";
import { RefreshCw, TriangleAlert } from "lucide-react";
import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "./index.css";
import { Layout } from "./components/Layout";
import { SessionProvider, useSession } from "./lib/session";
import { ToastProvider } from "./lib/toast";
import { ApiError } from "./lib/api";
import { Button, Loading } from "./components/ui";
import { TooltipProvider } from "./components/shadcn/tooltip";
import { Registry } from "./pages/Registry";
import { AgentDetail } from "./pages/AgentDetail";
import { ShadowAgents } from "./pages/ShadowAgents";
import { Attestation } from "./pages/Attestation";
import { ActivityFeed } from "./pages/Activity";
import { Overview } from "./pages/Overview";
import { Alerts } from "./pages/Alerts";
import { LineagePage } from "./pages/Lineage";
import { PromptInjection } from "./pages/PromptInjection";
import { UsagePage } from "./pages/Usage";
import { AccessControl } from "./pages/AccessControl";
import { Approvals } from "./pages/Approvals";
import { Tools } from "./pages/Tools";
import { PoliciesPage } from "./pages/Policies";
import { Evidence } from "./pages/Evidence";
import { SignIn } from "./pages/SignIn";
import { AuthCallback } from "./pages/AuthCallback";
import { BankAssistant } from "./pages/BankAssistant";
import { Copilot } from "./pages/Copilot";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // A 401/403/404 won't fix itself on retry; everything else gets one more try.
      retry: (count, error) => !(error instanceof ApiError && [401, 403, 404].includes(error.status)) && count < 1,
      refetchOnWindowFocus: false,
      staleTime: 1000,
    },
  },
});

function Gate() {
  const { ready, needsSignIn } = useSession();
  if (!ready) return <Loading />;
  return needsSignIn ? <SignIn /> : <Layout />;
}

/** Staff land on the Overview; customers only ever see the Bank Assistant. */
function Home() {
  const { can } = useSession();
  return <Navigate to={can("customer") ? "/assistant" : "/overview"} replace />;
}

/** Catches render/loader errors anywhere under the root route so the app never blanks out. */
function RouteError() {
  const error = useRouteError();
  const message = error instanceof Error ? error.message : typeof error === "string" ? error : "An unexpected error occurred.";
  return (
    <div className="grid min-h-screen place-items-center bg-page p-6">
      <div className="w-full max-w-md rounded-xl border border-line bg-card p-8 text-center shadow-card">
        <div className="mx-auto mb-4 grid size-10 place-items-center rounded-full bg-critical/10 text-critical-ink">
          <TriangleAlert className="size-5" />
        </div>
        <h1 className="text-base font-semibold text-fg">Something went wrong</h1>
        <p className="mt-1.5 text-sm break-words text-muted">{message}</p>
        <Button variant="primary" icon={RefreshCw} className="mt-5" onClick={() => window.location.assign("/ui/")}>
          Reload console
        </Button>
      </div>
    </div>
  );
}

const router = createBrowserRouter(
  [
    { path: "auth/callback", element: <AuthCallback /> },
    {
      path: "/",
      element: <Gate />,
      errorElement: <RouteError />,
      children: [
        { index: true, element: <Home /> },
        { path: "overview", element: <Overview /> },
        { path: "agents", element: <Registry /> },
        { path: "agents/:id", element: <AgentDetail /> },
        { path: "shadow", element: <ShadowAgents /> },
        { path: "attestation", element: <Attestation /> },
        { path: "activity", element: <ActivityFeed /> },
        { path: "soc", element: <Navigate to="/overview" replace /> },
        { path: "alerts", element: <Alerts /> },
        { path: "lineage", element: <LineagePage /> },
        { path: "lineage/:rootId", element: <LineagePage /> },
        { path: "injection", element: <PromptInjection /> },
        { path: "usage", element: <UsagePage /> },
        { path: "access", element: <AccessControl /> },
        { path: "approvals", element: <Approvals /> },
        { path: "tools", element: <Tools /> },
        { path: "policies", element: <PoliciesPage /> },
        { path: "evidence", element: <Evidence /> },
        { path: "assistant", element: <BankAssistant /> },
        { path: "studio", element: <Navigate to="/assistant" replace /> },
        { path: "copilot", element: <Copilot /> },
        { path: "*", element: <Home /> },
      ],
    },
  ],
  { basename: "/ui" },
);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <SessionProvider>
          <TooltipProvider>
            <RouterProvider router={router} />
          </TooltipProvider>
        </SessionProvider>
      </ToastProvider>
    </QueryClientProvider>
  </StrictMode>,
);
