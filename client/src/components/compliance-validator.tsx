import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { Shield, CheckCircle, XCircle, AlertTriangle, FileText, Globe } from "lucide-react";

interface ComplianceValidatorProps {
  documentId: number;
  documentName: string;
  onValidationComplete?: (result: any) => void;
}

interface ValidationResult {
  isCompliant: boolean;
  jurisdiction: string;
  requirements: Array<{
    requirement: string;
    status: 'met' | 'not_met' | 'partial';
    description: string;
    legalReference: string;
  }>;
  recommendations?: string[];
}

export default function ComplianceValidator({ 
  documentId, 
  documentName, 
  onValidationComplete 
}: ComplianceValidatorProps) {
  const { toast } = useToast();
  const [selectedJurisdiction, setSelectedJurisdiction] = useState<string>("");
  const [selectedDocumentType, setSelectedDocumentType] = useState<string>("");
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null);

  const validateMutation = useMutation({
    mutationFn: async ({ jurisdiction, documentType }: { jurisdiction: string; documentType: string }) =>
      apiRequest(`/api/documents/${documentId}/compliance/validate`, "POST", {
        jurisdiction,
        documentType
      }),
    onSuccess: (result) => {
      setValidationResult(result);
      onValidationComplete?.(result);
      
      toast({
        title: result.isCompliant ? "Compliance Validated" : "Compliance Issues Found",
        description: result.isCompliant 
          ? "Document meets all compliance requirements"
          : "Document has compliance issues that need attention",
        variant: result.isCompliant ? "default" : "destructive",
      });
    },
    onError: (error) => {
      toast({
        title: "Validation Failed",
        description: error instanceof Error ? error.message : "Failed to validate compliance",
        variant: "destructive",
      });
    },
  });

  const handleValidate = () => {
    if (!selectedJurisdiction || !selectedDocumentType) {
      toast({
        title: "Missing Information",
        description: "Please select both jurisdiction and document type",
        variant: "destructive",
      });
      return;
    }

    validateMutation.mutate({
      jurisdiction: selectedJurisdiction,
      documentType: selectedDocumentType
    });
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'met':
        return <CheckCircle className="h-4 w-4 text-green-600" />;
      case 'not_met':
        return <XCircle className="h-4 w-4 text-red-600" />;
      case 'partial':
        return <AlertTriangle className="h-4 w-4 text-yellow-600" />;
      default:
        return <Shield className="h-4 w-4 text-gray-600" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const variants = {
      met: "bg-green-100 text-green-800",
      not_met: "bg-red-100 text-red-800", 
      partial: "bg-yellow-100 text-yellow-800"
    };
    
    return (
      <Badge className={variants[status as keyof typeof variants] || "bg-gray-100 text-gray-800"}>
        {status.replace('_', ' ').toUpperCase()}
      </Badge>
    );
  };

  const getJurisdictionFlag = (jurisdiction: string) => {
    switch (jurisdiction) {
      case 'NZ':
        return '🇳🇿';
      case 'US':
        return '🇺🇸';
      case 'BOTH':
        return '🌍';
      default:
        return '🏳️';
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center space-x-2">
          <Shield className="h-5 w-5 text-blue-600" />
          <CardTitle>Compliance Validation</CardTitle>
        </div>
        <p className="text-sm text-gray-600">
          Validate "{documentName}" against electronic signature laws
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-sm font-medium text-gray-700 mb-2 block">
              Jurisdiction
            </label>
            <Select value={selectedJurisdiction} onValueChange={setSelectedJurisdiction}>
              <SelectTrigger>
                <SelectValue placeholder="Select jurisdiction" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="NZ">🇳🇿 New Zealand (ETA 2002)</SelectItem>
                <SelectItem value="US">🇺🇸 United States (UETA/ESIGN)</SelectItem>
                <SelectItem value="BOTH">🌍 Both Jurisdictions</SelectItem>
              </SelectContent>
            </Select>
          </div>
          
          <div>
            <label className="text-sm font-medium text-gray-700 mb-2 block">
              Document Type
            </label>
            <Select value={selectedDocumentType} onValueChange={setSelectedDocumentType}>
              <SelectTrigger>
                <SelectValue placeholder="Select document type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="contract">Contract</SelectItem>
                <SelectItem value="agreement">Agreement</SelectItem>
                <SelectItem value="form">Form</SelectItem>
                <SelectItem value="notice">Notice</SelectItem>
                <SelectItem value="other">Other</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        <Button 
          onClick={handleValidate}
          disabled={validateMutation.isPending || !selectedJurisdiction || !selectedDocumentType}
          className="w-full"
        >
          {validateMutation.isPending ? "Validating..." : "Validate Compliance"}
        </Button>

        {validationResult && (
          <div className="mt-6 space-y-4">
            <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
              <div className="flex items-center space-x-3">
                <span className="text-lg">{getJurisdictionFlag(validationResult.jurisdiction)}</span>
                <div>
                  <h4 className="font-medium">Validation Result</h4>
                  <p className="text-sm text-gray-600">
                    {validationResult.jurisdiction} Electronic Signature Laws
                  </p>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                {validationResult.isCompliant ? (
                  <CheckCircle className="h-6 w-6 text-green-600" />
                ) : (
                  <XCircle className="h-6 w-6 text-red-600" />
                )}
                <Badge 
                  className={
                    validationResult.isCompliant 
                      ? "bg-green-100 text-green-800"
                      : "bg-red-100 text-red-800"
                  }
                >
                  {validationResult.isCompliant ? "COMPLIANT" : "NON-COMPLIANT"}
                </Badge>
              </div>
            </div>

            <div>
              <h4 className="font-medium text-sm text-gray-700 mb-3">
                Compliance Requirements
              </h4>
              <div className="space-y-2">
                {validationResult.requirements.map((req, index) => (
                  <div 
                    key={index} 
                    className="flex items-start justify-between p-3 border rounded-lg"
                  >
                    <div className="flex items-start space-x-3 flex-1">
                      {getStatusIcon(req.status)}
                      <div className="flex-1">
                        <p className="text-sm font-medium">{req.requirement}</p>
                        <p className="text-xs text-gray-600 mt-1">{req.description}</p>
                        <p className="text-xs text-blue-600 mt-1">
                          Reference: {req.legalReference}
                        </p>
                      </div>
                    </div>
                    {getStatusBadge(req.status)}
                  </div>
                ))}
              </div>
            </div>

            {validationResult.recommendations && validationResult.recommendations.length > 0 && (
              <div>
                <h4 className="font-medium text-sm text-gray-700 mb-2">
                  Recommendations
                </h4>
                <ul className="text-sm text-gray-600 space-y-1">
                  {validationResult.recommendations.map((rec, index) => (
                    <li key={index} className="flex items-start space-x-2">
                      <span>•</span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}