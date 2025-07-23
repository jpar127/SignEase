import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Shield, 
  Activity, 
  FileText, 
  User, 
  Calendar,
  Search,
  Download,
  AlertTriangle,
  Clock,
  CheckCircle,
  XCircle
} from "lucide-react";
import { useAuth } from "@/hooks/useAuth";

interface AuditLogEntry {
  id: number;
  action: string;
  timestamp: string;
  userId?: number;
  entityType?: string;
  entityId?: number;
  ipAddress: string;
  userAgent?: string;
  success: boolean;
  errorMessage?: string;
  details?: any;
}

interface SecurityAuditEntry {
  id: number;
  action: string;
  risk_level: string;
  timestamp: string;
  userId?: number;
  ipAddress: string;
  resolved: boolean;
  resolvedBy?: number;
  resolvedAt?: string;
  details?: any;
}

export default function AuditLogs() {
  const { user } = useAuth();
  const [searchTerm, setSearchTerm] = useState("");
  const [actionFilter, setActionFilter] = useState("all");
  const [dateRange, setDateRange] = useState("7d");

  // Activity logs query
  const { data: activityLogs = [], isLoading: activityLoading } = useQuery<AuditLogEntry[]>({
    queryKey: ['/api/audit/activity', dateRange, actionFilter],
  });

  // Security audit logs query (admin only)
  const { data: securityLogs = [], isLoading: securityLoading } = useQuery<SecurityAuditEntry[]>({
    queryKey: ['/api/audit/security'],
    enabled: user?.role === 'admin',
  });

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'login':
      case 'logout':
      case 'register':
        return <User className="w-4 h-4 text-blue-600" />;
      case 'file_upload':
      case 'file_download':
      case 'file_view':
        return <FileText className="w-4 h-4 text-green-600" />;
      case 'document_created':
      case 'document_signed':
        return <FileText className="w-4 h-4 text-purple-600" />;
      case 'failed_login':
      case 'unauthorized_access':
        return <AlertTriangle className="w-4 h-4 text-red-600" />;
      default:
        return <Activity className="w-4 h-4 text-gray-600" />;
    }
  };

  const getRiskBadge = (riskLevel: string) => {
    switch (riskLevel) {
      case 'critical':
        return <Badge variant="destructive">Critical</Badge>;
      case 'high':
        return <Badge className="bg-orange-500">High</Badge>;
      case 'medium':
        return <Badge className="bg-yellow-500">Medium</Badge>;
      case 'low':
        return <Badge variant="secondary">Low</Badge>;
      default:
        return <Badge variant="outline">{riskLevel}</Badge>;
    }
  };

  const getSuccessBadge = (success: boolean) => {
    return success ? (
      <CheckCircle className="w-4 h-4 text-green-600" />
    ) : (
      <XCircle className="w-4 h-4 text-red-600" />
    );
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const filteredActivityLogs = activityLogs.filter(log => {
    const matchesSearch = searchTerm === "" || 
      log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.ipAddress.includes(searchTerm) ||
      (log.details && JSON.stringify(log.details).toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesAction = actionFilter === "all" || log.action === actionFilter;
    
    return matchesSearch && matchesAction;
  });

  const uniqueActions = [...new Set(activityLogs.map(log => log.action))];

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Audit Logs</h1>
          <p className="text-gray-600">Comprehensive system activity and security monitoring</p>
        </div>

        {/* Filters */}
        <Card className="mb-6">
          <CardContent className="p-6">
            <div className="flex flex-wrap gap-4 items-center">
              <div className="flex-1 min-w-64">
                <div className="relative">
                  <Search className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                  <Input
                    placeholder="Search logs..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10"
                  />
                </div>
              </div>
              
              <Select value={actionFilter} onValueChange={setActionFilter}>
                <SelectTrigger className="w-48">
                  <SelectValue placeholder="Filter by action" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All actions</SelectItem>
                  {uniqueActions.map(action => (
                    <SelectItem key={action} value={action}>{action}</SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select value={dateRange} onValueChange={setDateRange}>
                <SelectTrigger className="w-40">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1d">Last 24 hours</SelectItem>
                  <SelectItem value="7d">Last 7 days</SelectItem>
                  <SelectItem value="30d">Last 30 days</SelectItem>
                  <SelectItem value="90d">Last 90 days</SelectItem>
                </SelectContent>
              </Select>

              <Button variant="outline">
                <Download className="w-4 h-4 mr-2" />
                Export
              </Button>
            </div>
          </CardContent>
        </Card>

        <Tabs defaultValue="activity" className="space-y-6">
          <TabsList className="grid w-full max-w-md grid-cols-2">
            <TabsTrigger value="activity">Activity Logs</TabsTrigger>
            <TabsTrigger value="security" disabled={user?.role !== 'admin'}>
              Security Audit
            </TabsTrigger>
          </TabsList>

          {/* Activity Logs Tab */}
          <TabsContent value="activity">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Activity className="w-5 h-5" />
                  <span>System Activity</span>
                  <Badge variant="secondary">{filteredActivityLogs.length} entries</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {activityLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                  </div>
                ) : filteredActivityLogs.length === 0 ? (
                  <div className="text-center py-8 text-gray-500">
                    No activity logs found for the selected criteria.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {filteredActivityLogs.map((log) => (
                      <div key={log.id} className="border rounded-lg p-4 hover:bg-gray-50">
                        <div className="flex items-start justify-between">
                          <div className="flex items-start space-x-3">
                            {getActionIcon(log.action)}
                            <div className="flex-1">
                              <div className="flex items-center space-x-2">
                                <span className="font-medium text-gray-900">
                                  {log.action.replace(/_/g, ' ').toUpperCase()}
                                </span>
                                {getSuccessBadge(log.success)}
                                {log.errorMessage && (
                                  <span className="text-sm text-red-600">
                                    ({log.errorMessage})
                                  </span>
                                )}
                              </div>
                              <div className="text-sm text-gray-600 mt-1">
                                <div className="flex items-center space-x-4">
                                  <span className="flex items-center space-x-1">
                                    <Clock className="w-3 h-3" />
                                    <span>{formatTimestamp(log.timestamp)}</span>
                                  </span>
                                  <span>IP: {log.ipAddress}</span>
                                  {log.userId && <span>User ID: {log.userId}</span>}
                                </div>
                              </div>
                              {log.details && (
                                <details className="mt-2">
                                  <summary className="text-sm text-gray-500 cursor-pointer hover:text-gray-700">
                                    View details
                                  </summary>
                                  <pre className="text-xs bg-gray-100 p-2 rounded mt-1 overflow-auto">
                                    {JSON.stringify(log.details, null, 2)}
                                  </pre>
                                </details>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Security Audit Tab */}
          <TabsContent value="security">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Shield className="w-5 h-5" />
                  <span>Security Audit</span>
                  <Badge variant="secondary">{securityLogs.length} entries</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {securityLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                  </div>
                ) : securityLogs.length === 0 ? (
                  <div className="text-center py-8 text-gray-500">
                    No security events found.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {securityLogs.map((log) => (
                      <div key={log.id} className="border rounded-lg p-4 hover:bg-gray-50">
                        <div className="flex items-start justify-between">
                          <div className="flex items-start space-x-3">
                            <AlertTriangle className="w-4 h-4 text-red-600" />
                            <div className="flex-1">
                              <div className="flex items-center space-x-2">
                                <span className="font-medium text-gray-900">
                                  {log.action.replace(/_/g, ' ').toUpperCase()}
                                </span>
                                {getRiskBadge(log.risk_level)}
                                {log.resolved ? (
                                  <Badge className="bg-green-500">Resolved</Badge>
                                ) : (
                                  <Badge variant="destructive">Open</Badge>
                                )}
                              </div>
                              <div className="text-sm text-gray-600 mt-1">
                                <div className="flex items-center space-x-4">
                                  <span className="flex items-center space-x-1">
                                    <Clock className="w-3 h-3" />
                                    <span>{formatTimestamp(log.timestamp)}</span>
                                  </span>
                                  <span>IP: {log.ipAddress}</span>
                                  {log.userId && <span>User ID: {log.userId}</span>}
                                </div>
                                {log.resolved && log.resolvedAt && (
                                  <div className="text-green-600 mt-1">
                                    Resolved on {formatTimestamp(log.resolvedAt)}
                                  </div>
                                )}
                              </div>
                              {log.details && (
                                <details className="mt-2">
                                  <summary className="text-sm text-gray-500 cursor-pointer hover:text-gray-700">
                                    View details
                                  </summary>
                                  <pre className="text-xs bg-gray-100 p-2 rounded mt-1 overflow-auto">
                                    {JSON.stringify(log.details, null, 2)}
                                  </pre>
                                </details>
                              )}
                            </div>
                          </div>
                          {!log.resolved && (
                            <Button size="sm" variant="outline">
                              Mark Resolved
                            </Button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}