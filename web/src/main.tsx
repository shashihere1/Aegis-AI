import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createBrowserRouter, Navigate, RouterProvider } from "react-router";
import "./index.css";
import { Layout } from "./components/Layout";
import { SessionProvider, useSession } from "./lib/session";
import { ToastProvider } from "./lib/toast";
import { Loading } from "./components/ui";
import { Registry } from "./pages/Registry";
import { AgentDetail } from "./pages/AgentDetail";
import { ShadowAgents } from "./pages/ShadowAgents";
import { Attestation } from "./pages/Attestation";
import { ActivityFeed } from "./pages/Activity";
import { SocDashboard } from "./pages/SocDashboard";
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
  defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 1000 } },
});

function Gate() {
  const { ready, needsSignIn } = useSession();
  if (!ready) return <Loading />;
  return needsSignIn ? <SignIn /> : <Layout />;
}

const router = createBrowserRouter(
  [
    { path: "auth/callback", element: <AuthCallback /> },
    {
      path: "/",
      element: <Gate />,
      children: [
        { index: true, element: <Navigate to="/agents" replace /> },
        { path: "agents", element: <Registry /> },
        { path: "agents/:id", element: <AgentDetail /> },
        { path: "shadow", element: <ShadowAgents /> },
        { path: "attestation", element: <Attestation /> },
        { path: "activity", element: <ActivityFeed /> },
        { path: "soc", element: <SocDashboard /> },
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
        { path: "*", element: <Navigate to="/agents" replace /> },
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
          <RouterProvider router={router} />
        </SessionProvider>
      </ToastProvider>
    </QueryClientProvider>
  </StrictMode>,
);
