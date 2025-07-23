import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { 
  Shield, 
  CheckCircle, 
  XCircle, 
  AlertTriangle, 
  Download,
  FileCheck,
  Gavel,
  Clock,
  MapPin
} from "lucide-react";

interface CompliancePanelProps {
  documentId: number;
}

interface ComplianceValidation {
  ready: boolean;
  issues: string[];
  recommendations: string[];
}

interface ComplianceCertificate {
  certificateId: string;
  documentName: string;
  jurisdiction: string;
  issuedAt: string;
  complianceStatus: string;
  legalAssurance: {
    enforceability: string;
    admissibility: string;
    integrityVerified: boolean;
  };
  validUntil: string;
}

export function CompliancePanel({ documentId }: CompliancePanelProps) {
  const [selectedJurisdiction, setSelectedJurisdiction] = useState<'NZ' | 'US' | 'BOTH'>('BOTH');

  // Validate document compliance readiness
  const { data: validation, isLoading: validationLoading } = useQuery<ComplianceValidation>({
    queryKey: [`/api/compliance/validate/${documentId}`, selectedJurisdiction],
    queryFn: () => fetch(`/api/compliance/validate/${documentId}?jurisdiction=${selectedJurisdiction}`, {
      credentials: 'include'
    }).then(res => res.json())
  });

  // Get compliance certificate if document is completed
  const { data: certificate, isLoading: certificateLoading } = useQuery<ComplianceCertificate>({
    queryKey: [`/api/compliance/certificate/${documentId}`, selectedJurisdiction],
    queryFn: () => fetch(`/api/compliance/certificate/${documentId}?jurisdiction=${selectedJurisdiction}`, {
      credentials: 'include'
    }).then(res => res.json()),
    enabled: validation?.ready || false
  });

  const getJurisdictionInfo = (jurisdiction: string) => {
    switch (jurisdiction) {
      case 'NZ':
        return {
          name: 'New Zealand',
          law: 'Electronic Transactions Act 2002',
          icon: <MapPin className="w-4 h-4" />
        };
      case 'US':
        return {
          name: 'United States',
          law: 'UETA/ESIGN Act',
          icon: <MapPin className="w-4 h-4" />
        };
      case 'BOTH':
        return {
          name: 'NZ & US',
          law: 'ETA 2002 & UETA/ESIGN',
          icon: <MapPin className="w-4 h-4" />
        };
      default:
        return { name: jurisdiction, law: 'Unknown', icon: <MapPin className="w-4 h-4" /> };
    }
  };

  const getComplianceStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLIANT':
        return <Badge className="bg-green-500"><CheckCircle className="w-3 h-3 mr-1" />Compliant</Badge>;
      case 'non_compliant':
        return <Badge variant="destructive"><XCircle className="w-3 h-3 mr-1" />Non-Compliant</Badge>;
      case 'pending_verification':
        return <Badge className="bg-yellow-500"><AlertTriangle className="w-3 h-3 mr-1" />Pending</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  const downloadCertificate = () => {
    if (!certificate) return;
    
    const blob = new Blob([JSON.stringify(certificate, null, 2)], {
      type: 'application/json'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `compliance-certificate-${certificate.certificateId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Shield className="w-5 h-5" />
            <span>Legal Compliance</span>
          </CardTitle>
          <p className="text-sm text-gray-600">
            Ensure electronic signatures meet legal requirements for enforceability
          </p>
        </CardHeader>
      </Card>

      {/* Jurisdiction Selection */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Jurisdiction</CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs value={selectedJurisdiction} onValueChange={(value) => setSelectedJurisdiction(value as 'NZ' | 'US' | 'BOTH')}>
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="NZ">New Zealand</TabsTrigger>
              <TabsTrigger value="US">United States</TabsTrigger>
              <TabsTrigger value="BOTH">Both</TabsTrigger>
            </TabsList>
            
            <TabsContent value="NZ" className="mt-4">
              <Alert>
                <Gavel className="w-4 h-4" />
                <AlertDescription>
                  <strong>Electronic Transactions Act 2002 (NZ)</strong><br />
                  Ensures electronic signatures are reliable and legally valid under New Zealand law.
                </AlertDescription>
              </Alert>
            </TabsContent>
            
            <TabsContent value="US" className="mt-4">
              <Alert>
                <Gavel className="w-4 h-4" />
                <AlertDescription>
                  <strong>UETA/ESIGN Act (US)</strong><br />
                  Complies with Uniform Electronic Transactions Act and Electronic Signatures in Global and National Commerce Act.
                </AlertDescription>
              </Alert>
            </TabsContent>
            
            <TabsContent value="BOTH" className="mt-4">
              <Alert>
                <Gavel className="w-4 h-4" />
                <AlertDescription>
                  <strong>Dual Jurisdiction Compliance</strong><br />
                  Meets both New Zealand ETA 2002 and US UETA/ESIGN requirements for maximum legal protection.
                </AlertDescription>
              </Alert>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Compliance Validation */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <FileCheck className="w-5 h-5" />
            <span>Compliance Validation</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {validationLoading ? (
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
          ) : validation ? (
            <div className="space-y-4">
              <div className="flex items-center space-x-2">
                {validation.ready ? (
                  <CheckCircle className="w-5 h-5 text-green-600" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-600" />
                )}
                <span className="font-medium">
                  {validation.ready ? 'Ready for Compliant Signing' : 'Issues Found'}
                </span>
              </div>

              {validation.issues.length > 0 && (
                <Alert variant="destructive">
                  <AlertTriangle className="w-4 h-4" />
                  <AlertDescription>
                    <strong>Issues to resolve:</strong>
                    <ul className="mt-2 list-disc list-inside">
                      {validation.issues.map((issue, index) => (
                        <li key={index}>{issue}</li>
                      ))}
                    </ul>
                  </AlertDescription>
                </Alert>
              )}

              {validation.recommendations.length > 0 && (
                <Alert>
                  <AlertTriangle className="w-4 h-4" />
                  <AlertDescription>
                    <strong>Recommendations:</strong>
                    <ul className="mt-2 list-disc list-inside">
                      {validation.recommendations.map((rec, index) => (
                        <li key={index}>{rec}</li>
                      ))}
                    </ul>
                  </AlertDescription>
                </Alert>
              )}
            </div>
          ) : (
            <p className="text-gray-500">No validation data available</p>
          )}
        </CardContent>
      </Card>

      {/* Compliance Certificate */}
      {certificate && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Shield className="w-5 h-5" />
              <span>Compliance Certificate</span>
              {getComplianceStatusBadge(certificate.complianceStatus)}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-gray-600">Certificate ID</label>
                <p className="text-sm font-mono">{certificate.certificateId}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-600">Jurisdiction</label>
                <p className="text-sm">{getJurisdictionInfo(certificate.jurisdiction).name}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-600">Issued At</label>
                <p className="text-sm flex items-center">
                  <Clock className="w-3 h-3 mr-1" />
                  {new Date(certificate.issuedAt).toLocaleString()}
                </p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-600">Valid Until</label>
                <p className="text-sm flex items-center">
                  <Clock className="w-3 h-3 mr-1" />
                  {new Date(certificate.validUntil).toLocaleDateString()}
                </p>
              </div>
            </div>

            <div className="border-t pt-4">
              <label className="text-sm font-medium text-gray-600">Legal Assurance</label>
              <div className="mt-2 grid grid-cols-1 md:grid-cols-3 gap-2">
                <div className="flex items-center space-x-2">
                  <CheckCircle className="w-4 h-4 text-green-600" />
                  <span className="text-sm">Enforceability: {certificate.legalAssurance.enforceability}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <CheckCircle className="w-4 h-4 text-green-600" />
                  <span className="text-sm">Admissibility: {certificate.legalAssurance.admissibility}</span>
                </div>
                <div className="flex items-center space-x-2">
                  {certificate.legalAssurance.integrityVerified ? (
                    <CheckCircle className="w-4 h-4 text-green-600" />
                  ) : (
                    <XCircle className="w-4 h-4 text-red-600" />
                  )}
                  <span className="text-sm">Integrity Verified</span>
                </div>
              </div>
            </div>

            <div className="flex justify-end">
              <Button onClick={downloadCertificate} variant="outline">
                <Download className="w-4 h-4 mr-2" />
                Download Certificate
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Legal Information */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Legal Framework</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <Alert>
              <Gavel className="w-4 h-4" />
              <AlertDescription>
                <strong>Key Legal Requirements:</strong>
                <ul className="mt-2 list-disc list-inside space-y-1">
                  <li>Signer identity verification and authentication</li>
                  <li>Intent to sign must be clearly demonstrated</li>
                  <li>Document integrity must be maintained and verifiable</li>
                  <li>Comprehensive audit trail of all signing activities</li>
                  <li>Proper consent to use electronic signatures</li>
                  <li>Secure record retention for legal compliance periods</li>
                </ul>
              </AlertDescription>
            </Alert>
            
            <p className="text-xs text-gray-500">
              This compliance system ensures electronic signatures meet the legal standards of the selected 
              jurisdiction(s). It does not constitute legal advice. Consult with qualified legal counsel for 
              specific legal requirements in your situation.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}