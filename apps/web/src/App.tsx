import { BrowserRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Layout } from "./components/Layout";
import { DashboardPage } from "./pages/DashboardPage";
import { CloudEnvironmentPage } from "./pages/CloudEnvironmentPage";
import { LoginPage } from "./pages/LoginPage";
import { ConnectionsPage } from "./pages/ConnectionsPage";
import { AssetsPage } from "./pages/AssetsPage";
import { FindingsPage } from "./pages/FindingsPage";
import { FindingDetailPage } from "./pages/FindingDetailPage";
import { IdentityPage } from "./pages/IdentityPage";
import { DetectionsPage } from "./pages/DetectionsPage";
import { CompliancePage } from "./pages/CompliancePage";
import { AssessmentsPage } from "./pages/AssessmentsPage";
import { RemediationPage } from "./pages/RemediationPage";
import { ReportsPage } from "./pages/ReportsPage";
import { AuditLogsPage, SettingsPage } from "./pages/AuditAndSettingsPages";
import { SystemStatusPage } from "./pages/SystemStatusPage";

export function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        refetchOnWindowFocus: false,
      },
    },
  });
}

export function AppRoutes() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/connections" element={<ConnectionsPage />} />
        <Route path="/aws" element={<CloudEnvironmentPage provider="aws" />} />
        <Route path="/azure" element={<CloudEnvironmentPage provider="azure" />} />
        <Route path="/assets" element={<AssetsPage />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/findings/:id" element={<FindingDetailPage />} />
        <Route path="/identity" element={<IdentityPage />} />
        <Route path="/detections" element={<DetectionsPage />} />
        <Route path="/compliance" element={<CompliancePage />} />
        <Route path="/assessments" element={<AssessmentsPage />} />
        <Route path="/remediations" element={<RemediationPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/audit" element={<AuditLogsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/system" element={<SystemStatusPage />} />
      </Routes>
    </Layout>
  );
}

const defaultQueryClient = createQueryClient();

export function App() {
  return (
    <QueryClientProvider client={defaultQueryClient}>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
