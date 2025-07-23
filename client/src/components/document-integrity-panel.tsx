import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { 
  Shield, 
  ShieldCheck, 
  ShieldAlert, 
  ChevronDown, 
  Clock,
  FileText,
  User,
  Hash,
  Calendar
} from "lucide-react";

interface DocumentIntegrityPanelProps {
  documentId: number;
}

interface IntegrityResult {
  isValid: boolean;
  errors: string[];
}

interface AuditLogEntry {
  id: number;
  action: string;
  userId?: number;
  documentHash: string;
  timestamp: string;
  ipAddress?: string;
  details?: any;
}

export function DocumentIntegrityPanel({ documentId }: DocumentIntegrityPanelProps) {
  const [showAuditLog, setShowAuditLog] = useState(false);

  const { data: integrityResult, isLoading: integrityLoading, refetch: refetchIntegrity } = useQuery<IntegrityResult>({
    queryKey: [`/api/documents/${documentId}/integrity`],
    refetchInterval: 30000, // Check every 30 seconds
  });

  const { data: auditLog = [], isLoading: auditLoading } = useQuery<AuditLogEntry[]>({
    queryKey: [`/api/documents/${documentId}/audit`],
    enabled: showAuditLog,
  });

  const handleVerifyIntegrity = () => {
    refetchIntegrity();
  };

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'created':
        return <FileText className="w-4 h-4 text-blue-600" />;
      case 'signed':
        return <User className="w-4 h-4 text-green-600" />;
      case 'completed':
        return <ShieldCheck className="w-4 h-4 text-purple-600" />;
      case 'hash_verified':
        return <Hash className="w-4 h-4 text-gray-600" />;
      default:
        return <Clock className="w-4 h-4 text-gray-400" />;
    }
  };

  const formatActionName = (action: string) => {
    switch (action) {
      case 'created':
        return 'Document Created';
      case 'signed':
        return 'Document Signed';
      case 'completed':
        return 'Document Completed';
      case 'hash_verified':
        return 'Integrity Verified';
      default:
        return action.charAt(0).toUpperCase() + action.slice(1);
    }
  };

  if (integrityLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Shield className="w-5 h-5" />
            <span>Document Integrity</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2">
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
            <span className="text-sm text-gray-600">Verifying integrity...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Shield className="w-5 h-5" />
            <span>Document Integrity</span>
          </div>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={handleVerifyIntegrity}
          >
            Verify Now
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Integrity Status */}
        <div className="flex items-center space-x-3">
          {integrityResult?.isValid ? (
            <>
              <ShieldCheck className="w-6 h-6 text-green-600" />
              <div>
                <Badge className="bg-green-100 text-green-800">
                  Verified
                </Badge>
                <p className="text-sm text-gray-600 mt-1">
                  Document integrity verified. No tampering detected.
                </p>
              </div>
            </>
          ) : (
            <>
              <ShieldAlert className="w-6 h-6 text-red-600" />
              <div>
                <Badge variant="destructive">
                  Integrity Issues
                </Badge>
                <p className="text-sm text-gray-600 mt-1">
                  {integrityResult?.errors.length || 0} integrity issue(s) detected.
                </p>
              </div>
            </>
          )}
        </div>

        {/* Error Details */}
        {integrityResult && !integrityResult.isValid && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-3">
            <h4 className="text-sm font-medium text-red-800 mb-2">Integrity Issues:</h4>
            <ul className="text-sm text-red-700 space-y-1">
              {integrityResult.errors.map((error, index) => (
                <li key={index} className="flex items-start space-x-2">
                  <span className="text-red-400">•</span>
                  <span>{error}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Audit Trail */}
        <Collapsible open={showAuditLog} onOpenChange={setShowAuditLog}>
          <CollapsibleTrigger asChild>
            <Button variant="outline" className="w-full justify-between">
              <span className="flex items-center space-x-2">
                <Calendar className="w-4 h-4" />
                <span>View Audit Trail</span>
              </span>
              <ChevronDown className={`w-4 h-4 transition-transform ${showAuditLog ? 'rotate-180' : ''}`} />
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="space-y-2 mt-3">
            {auditLoading ? (
              <div className="flex items-center space-x-2 p-3">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
                <span className="text-sm text-gray-600">Loading audit trail...</span>
              </div>
            ) : auditLog.length === 0 ? (
              <p className="text-sm text-gray-500 p-3">No audit entries found.</p>
            ) : (
              <div className="space-y-2">
                {auditLog.map((entry) => (
                  <div key={entry.id} className="border rounded-lg p-3 bg-gray-50">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center space-x-3">
                        {getActionIcon(entry.action)}
                        <div>
                          <p className="text-sm font-medium text-gray-900">
                            {formatActionName(entry.action)}
                          </p>
                          <p className="text-xs text-gray-500">
                            {new Date(entry.timestamp).toLocaleString()}
                          </p>
                        </div>
                      </div>
                      <div className="text-right">
                        {entry.ipAddress && (
                          <p className="text-xs text-gray-500">
                            IP: {entry.ipAddress}
                          </p>
                        )}
                      </div>
                    </div>
                    
                    {entry.details && (
                      <div className="mt-2 pt-2 border-t border-gray-200">
                        <p className="text-xs text-gray-600">
                          Hash: <code className="bg-gray-200 px-1 rounded text-xs">
                            {entry.documentHash.substring(0, 16)}...
                          </code>
                        </p>
                        {entry.details.fileName && (
                          <p className="text-xs text-gray-600">
                            File: {entry.details.fileName}
                          </p>
                        )}
                        {entry.details.signatureType && (
                          <p className="text-xs text-gray-600">
                            Signature: {entry.details.signatureType}
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CollapsibleContent>
        </Collapsible>

        {/* Security Info */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
          <div className="flex items-start space-x-2">
            <Shield className="w-4 h-4 text-blue-600 mt-0.5" />
            <div className="text-sm text-blue-800">
              <p className="font-medium">Cryptographic Protection</p>
              <p className="text-blue-700 mt-1">
                This document is protected with SHA-256 hashing and maintains 
                a complete audit trail of all changes and signatures.
              </p>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}