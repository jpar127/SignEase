import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useAuth } from "@/hooks/useAuth";
import Dashboard from "@/pages/dashboard";
import DocumentViewer from "@/pages/document-viewer";
import AuditLogs from "@/pages/audit-logs";
import ComplianceDashboard from "@/pages/compliance-dashboard";
import Login from "@/pages/login";
import Register from "@/pages/register";
import NotFound from "@/pages/not-found";

function Router() {
  const { isAuthenticated, isLoading, user } = useAuth();

  // Show loading while authentication state is being determined
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  // Debug logging for auth state
  console.log('Auth state:', { isAuthenticated, user: user ? 'present' : 'null', isLoading });

  // If authenticated, redirect from login/register pages
  if (isAuthenticated) {
    return (
      <Switch>
        <Route path="/login"><Dashboard /></Route>
        <Route path="/register"><Dashboard /></Route>
        <Route path="/document/:id"><DocumentViewer /></Route>
        <Route path="/audit-logs"><AuditLogs /></Route>
        <Route path="/compliance"><ComplianceDashboard /></Route>
        <Route path="/"><Dashboard /></Route>
        <Route><NotFound /></Route>
      </Switch>
    );
  }

  // If not authenticated, show login for all protected routes
  return (
    <Switch>
      <Route path="/login"><Login /></Route>
      <Route path="/register"><Register /></Route>
      <Route><Login /></Route>
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Router />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
