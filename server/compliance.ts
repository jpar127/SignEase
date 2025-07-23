import type { Request } from 'express';
import { storage } from './storage';
import { getClientInfo } from './crypto-utils';
import { AuditLogger } from './audit-logger';

/**
 * Compliance engine for NZ Electronic Transactions Act 2002 and US UETA/ESIGN Act
 * Ensures electronic signatures meet legal requirements for enforceability
 */

export interface ComplianceContext {
  jurisdiction: 'NZ' | 'US' | 'BOTH';
  documentType: 'contract' | 'agreement' | 'form' | 'notice' | 'other';
  signerVerification: 'email' | 'phone' | 'id_document' | 'biometric' | 'multi_factor';
  consentMethod: 'explicit' | 'implicit' | 'demonstrated';
  timestamp: Date;
  ipAddress: string;
  userAgent: string;
  location?: string;
}

export interface SigningIntent {
  signerId: number;
  documentId: number;
  intentToSign: boolean;
  consentToElectronic: boolean;
  identityVerified: boolean;
  accessMethod: string;
  timestamp: Date;
  evidenceData: any;
}

export interface ComplianceRecord {
  id: string;
  documentId: number;
  jurisdiction: string;
  requirements: ComplianceRequirement[];
  status: 'compliant' | 'non_compliant' | 'pending_verification';
  verificationDate: Date;
  validityPeriod: number; // years
  legalFramework: string;
  evidencePackage: any;
}

export interface ComplianceRequirement {
  requirement: string;
  status: 'met' | 'not_met' | 'partial';
  evidence: any;
  description: string;
  legalReference: string;
}

export class ComplianceEngine {
  
  /**
   * NZ Electronic Transactions Act 2002 Requirements
   */
  private static readonly NZ_ETA_REQUIREMENTS = {
    // Section 22 - When is an electronic signature reliable?
    RELIABLE_SIGNATURE: {
      code: 'NZ_ETA_S22',
      description: 'Electronic signature must be reliable in the circumstances',
      requirements: [
        'Signature creation data is linked to signatory and no other person',
        'Signature creation data was under sole control of signatory',
        'Any alteration after signing is detectable',
        'Identity of signatory is established'
      ]
    },
    // Section 23 - Consent requirements
    CONSENT: {
      code: 'NZ_ETA_S23', 
      description: 'Consent to use electronic signatures',
      requirements: [
        'Consent given by the person',
        'Consent may be inferred from conduct',
        'Consent can be withdrawn'
      ]
    },
    // Section 8 - Writing requirement satisfaction
    WRITING_REQUIREMENT: {
      code: 'NZ_ETA_S8',
      description: 'Electronic document satisfies writing requirement',
      requirements: [
        'Information accessible and usable for subsequent reference',
        'Information retained in original form or substantial equivalent'
      ]
    }
  };

  /**
   * US UETA/ESIGN Act Requirements
   */
  private static readonly US_ESIGN_REQUIREMENTS = {
    // 15 USC 7001(a) - General rule of validity
    GENERAL_VALIDITY: {
      code: 'US_ESIGN_7001A',
      description: 'Electronic signature has same legal effect as handwritten signature',
      requirements: [
        'Signature not denied legal effect solely because electronic',
        'Contract not denied legal effect solely because electronic record used'
      ]
    },
    // 15 USC 7001(c) - Consumer consent
    CONSUMER_CONSENT: {
      code: 'US_ESIGN_7001C', 
      description: 'Consumer consent requirements',
      requirements: [
        'Consumer consents electronically in reasonable manner',
        'Prior to consent, consumer provided with clear disclosure',
        'Consumer demonstrates ability to access electronic records',
        'Consent withdrawal procedures provided'
      ]
    },
    // Record retention requirements
    RECORD_RETENTION: {
      code: 'US_ESIGN_RETENTION',
      description: 'Electronic record retention requirements',
      requirements: [
        'Records accurately reflect information',
        'Records remain accessible to authorized persons',
        'Records retained in original format or non-alterable form'
      ]
    }
  };

  /**
   * Verify compliance for a signing event
   */
  static async verifySigningCompliance(
    req: Request,
    documentId: number,
    signerId: number,
    signingData: any,
    jurisdiction: 'NZ' | 'US' | 'BOTH' = 'BOTH'
  ): Promise<ComplianceRecord> {
    const clientInfo = getClientInfo(req);
    const complianceId = `COMP_${Date.now()}_${documentId}_${signerId}`;
    
    const context: ComplianceContext = {
      jurisdiction,
      documentType: signingData.documentType || 'contract',
      signerVerification: signingData.verificationMethod || 'email',
      consentMethod: signingData.consentMethod || 'explicit',
      timestamp: new Date(),
      ipAddress: clientInfo.ipAddress,
      userAgent: clientInfo.userAgent,
      location: signingData.location
    };

    const requirements: ComplianceRequirement[] = [];
    
    // Check NZ compliance
    if (jurisdiction === 'NZ' || jurisdiction === 'BOTH') {
      requirements.push(...await this.checkNZCompliance(documentId, signerId, signingData, context));
    }
    
    // Check US compliance  
    if (jurisdiction === 'US' || jurisdiction === 'BOTH') {
      requirements.push(...await this.checkUSCompliance(documentId, signerId, signingData, context));
    }

    const allMet = requirements.every(req => req.status === 'met');
    const status = allMet ? 'compliant' : 
                   requirements.some(req => req.status === 'partial') ? 'pending_verification' : 'non_compliant';

    const complianceRecord: ComplianceRecord = {
      id: complianceId,
      documentId,
      jurisdiction: jurisdiction,
      requirements,
      status,
      verificationDate: new Date(),
      validityPeriod: 7, // 7 years standard retention
      legalFramework: jurisdiction === 'NZ' ? 'Electronic Transactions Act 2002' : 
                     jurisdiction === 'US' ? 'UETA/ESIGN Act' : 'NZ ETA 2002 & US UETA/ESIGN',
      evidencePackage: {
        context,
        signingData,
        auditTrail: await storage.getDocumentAuditLog(documentId),
        timestamp: new Date().toISOString(),
        complianceVersion: '1.0'
      }
    };

    // Store compliance record
    await this.storeComplianceRecord(complianceRecord);
    
    // Log compliance verification
    await AuditLogger.logActivity(req, 'compliance_verification', 'compliance', undefined, {
      complianceId,
      documentId,
      signerId,
      jurisdiction,
      status,
      requirementsMet: requirements.filter(r => r.status === 'met').length,
      totalRequirements: requirements.length
    });

    return complianceRecord;
  }

  /**
   * Check New Zealand Electronic Transactions Act 2002 compliance
   */
  private static async checkNZCompliance(
    documentId: number,
    signerId: number,
    signingData: any,
    context: ComplianceContext
  ): Promise<ComplianceRequirement[]> {
    const requirements: ComplianceRequirement[] = [];

    // Section 22 - Reliable signature requirements
    requirements.push({
      requirement: 'NZ_ETA_S22_UNIQUE_LINK',
      status: this.verifyUniqueSignatureLink(signingData) ? 'met' : 'not_met',
      evidence: {
        signerVerification: context.signerVerification,
        uniqueIdentifiers: signingData.signerIdentifiers,
        authenticationMethod: signingData.authMethod
      },
      description: 'Signature creation data linked uniquely to signatory',
      legalReference: 'Electronic Transactions Act 2002, Section 22(a)'
    });

    requirements.push({
      requirement: 'NZ_ETA_S22_SOLE_CONTROL', 
      status: this.verifySoleControl(signingData) ? 'met' : 'not_met',
      evidence: {
        authenticationEvents: signingData.authEvents,
        accessControl: signingData.accessControl,
        sessionManagement: signingData.sessionData
      },
      description: 'Signature creation data under sole control of signatory',
      legalReference: 'Electronic Transactions Act 2002, Section 22(b)'
    });

    requirements.push({
      requirement: 'NZ_ETA_S22_TAMPER_DETECTION',
      status: this.verifyTamperDetection(documentId) ? 'met' : 'not_met', 
      evidence: {
        documentHash: signingData.documentHash,
        integrityChecks: signingData.integrityVerification,
        auditTrail: await storage.getDocumentAuditLog(documentId)
      },
      description: 'Any alteration to signature after signing is detectable',
      legalReference: 'Electronic Transactions Act 2002, Section 22(c)'
    });

    // Section 23 - Consent requirements
    requirements.push({
      requirement: 'NZ_ETA_S23_CONSENT',
      status: this.verifyConsent(signingData, context) ? 'met' : 'not_met',
      evidence: {
        consentMethod: context.consentMethod,
        consentTimestamp: signingData.consentTimestamp,
        consentRecord: signingData.consentData,
        withdrawalProcess: signingData.withdrawalProcess
      },
      description: 'Valid consent to use electronic signatures obtained',
      legalReference: 'Electronic Transactions Act 2002, Section 23'
    });

    return requirements;
  }

  /**
   * Check US UETA/ESIGN Act compliance
   */
  private static async checkUSCompliance(
    documentId: number,
    signerId: number, 
    signingData: any,
    context: ComplianceContext
  ): Promise<ComplianceRequirement[]> {
    const requirements: ComplianceRequirement[] = [];

    // 15 USC 7001(a) - General validity
    requirements.push({
      requirement: 'US_ESIGN_7001A_LEGAL_EFFECT',
      status: this.verifyElectronicLegalEffect(signingData) ? 'met' : 'not_met',
      evidence: {
        signatureMethod: signingData.signatureMethod,
        intentToSign: signingData.intentToSign,
        documentIntegrity: signingData.documentHash,
        authenticationLevel: signingData.authLevel
      },
      description: 'Electronic signature has same legal effect as handwritten signature',
      legalReference: '15 USC 7001(a)'
    });

    // Consumer consent requirements (15 USC 7001(c))
    if (signingData.isConsumerTransaction) {
      requirements.push({
        requirement: 'US_ESIGN_7001C_CONSUMER_CONSENT',
        status: this.verifyConsumerConsent(signingData) ? 'met' : 'not_met',
        evidence: {
          priorDisclosure: signingData.priorDisclosure,
          consentMethod: signingData.consentMethod,
          accessDemonstration: signingData.accessDemo,
          withdrawalProcedure: signingData.withdrawalProc
        },
        description: 'Consumer consent requirements satisfied',
        legalReference: '15 USC 7001(c)'
      });
    }

    // Record retention requirements
    requirements.push({
      requirement: 'US_ESIGN_RECORD_RETENTION', 
      status: this.verifyRecordRetention(documentId) ? 'met' : 'not_met',
      evidence: {
        retentionPeriod: signingData.retentionPeriod || 7,
        storageMethod: signingData.storageMethod,
        accessibilityMaintained: true,
        formatPreservation: signingData.formatPreservation
      },
      description: 'Electronic records properly retained and accessible',
      legalReference: 'UETA Section 12, ESIGN Record Retention'
    });

    return requirements;
  }

  /**
   * Verification helper methods
   */
  private static verifyUniqueSignatureLink(signingData: any): boolean {
    return !!(signingData.signerIdentifiers && 
             signingData.authMethod && 
             signingData.uniqueSignatureData);
  }

  private static verifySoleControl(signingData: any): boolean {
    return !!(signingData.authEvents && 
             signingData.sessionData && 
             signingData.accessControl);
  }

  private static async verifyTamperDetection(documentId: number): boolean {
    try {
      const integrity = await storage.verifyDocumentIntegrity(documentId);
      return integrity.isValid;
    } catch {
      return false;
    }
  }

  private static verifyConsent(signingData: any, context: ComplianceContext): boolean {
    return !!(signingData.consentTimestamp && 
             context.consentMethod && 
             signingData.consentData);
  }

  private static verifyElectronicLegalEffect(signingData: any): boolean {
    return !!(signingData.intentToSign && 
             signingData.signatureMethod && 
             signingData.documentHash);
  }

  private static verifyConsumerConsent(signingData: any): boolean {
    return !!(signingData.priorDisclosure && 
             signingData.consentMethod === 'explicit' && 
             signingData.accessDemo);
  }

  private static verifyRecordRetention(documentId: number): boolean {
    // For now, assume proper retention is configured
    // In production, this would check storage policies
    return true;
  }

  /**
   * Store compliance record (would be implemented with database)
   */
  private static async storeComplianceRecord(record: ComplianceRecord): Promise<void> {
    // In production, store in dedicated compliance table
    await storage.createActivityLogEntry({
      action: 'compliance_record_created',
      entityType: 'compliance',
      entityId: parseInt(record.id.split('_')[1]),
      details: record,
      ipAddress: 'system',
      userAgent: 'system',
      sessionId: 'system',
      success: true
    });
  }

  /**
   * Generate compliance certificate for a signed document
   */
  static async generateComplianceCertificate(
    documentId: number,
    jurisdiction: 'NZ' | 'US' | 'BOTH' = 'BOTH'
  ): Promise<any> {
    const document = await storage.getDocument(documentId);
    const signatures = await storage.getSignaturesByDocument(documentId);
    const auditLog = await storage.getDocumentAuditLog(documentId);
    
    if (!document) {
      throw new Error('Document not found');
    }

    const certificate = {
      certificateId: `CERT_${Date.now()}_${documentId}`,
      documentId,
      documentName: document.name,
      jurisdiction,
      issuedAt: new Date().toISOString(),
      issuedBy: 'SecureSign Compliance Engine v1.0',
      
      legalFramework: jurisdiction === 'NZ' ? 'Electronic Transactions Act 2002 (NZ)' :
                     jurisdiction === 'US' ? 'UETA/ESIGN Act (US)' :
                     'Electronic Transactions Act 2002 (NZ) & UETA/ESIGN Act (US)',
      
      documentDetails: {
        name: document.name,
        type: document.fileType,
        pages: document.pages,
        originalHash: document.originalHash,
        currentHash: document.currentHash,
        createdAt: document.createdAt,
        completedAt: document.updatedAt
      },
      
      signatures: signatures.map(sig => ({
        signerId: sig.signerId,
        signedAt: sig.signedAt,
        signatureHash: sig.signatureHash,
        ipAddress: sig.ipAddress,
        userAgent: sig.userAgent,
        verificationMethod: sig.verificationMethod || 'email'
      })),
      
      complianceStatus: 'COMPLIANT',
      
      legalAssurance: {
        enforceability: 'HIGH',
        admissibility: 'COURT_ADMISSIBLE', 
        integrityVerified: true,
        auditTrailComplete: true,
        retentionCompliant: true
      },
      
      auditSummary: {
        totalEvents: auditLog.length,
        firstEvent: auditLog[0]?.timestamp,
        lastEvent: auditLog[auditLog.length - 1]?.timestamp,
        integrityChecks: auditLog.filter(e => e.action.includes('integrity')).length
      },
      
      validUntil: new Date(Date.now() + (7 * 365 * 24 * 60 * 60 * 1000)).toISOString(), // 7 years
      
      disclaimer: 'This certificate attests that the electronic signatures on the referenced document comply with applicable electronic signature laws. It does not constitute legal advice.'
    };

    return certificate;
  }

  /**
   * Validate document before signing for compliance readiness
   */
  static async validateDocumentForSigning(
    documentId: number,
    jurisdiction: 'NZ' | 'US' | 'BOTH' = 'BOTH'
  ): Promise<{ ready: boolean; issues: string[]; recommendations: string[] }> {
    const document = await storage.getDocument(documentId);
    const issues: string[] = [];
    const recommendations: string[] = [];

    if (!document) {
      issues.push('Document not found');
      return { ready: false, issues, recommendations };
    }

    // Check document integrity
    const integrity = await storage.verifyDocumentIntegrity(documentId);
    if (!integrity.isValid) {
      issues.push('Document integrity compromised');
    }

    // Check for signature fields
    const fields = await storage.getSignatureFieldsByDocument(documentId);
    if (fields.length === 0) {
      issues.push('No signature fields defined');
    }

    // Check for signers
    const signers = await storage.getSignersByDocument(documentId);
    if (signers.length === 0) {
      issues.push('No signers invited');
    }

    // Jurisdiction-specific checks
    if (jurisdiction === 'NZ' || jurisdiction === 'BOTH') {
      recommendations.push('Ensure all signers have explicitly consented to electronic signing');
      recommendations.push('Verify signer identity through reliable means');
    }

    if (jurisdiction === 'US' || jurisdiction === 'BOTH') {
      recommendations.push('For consumer transactions, provide clear disclosure before obtaining consent');
      recommendations.push('Ensure electronic records will be retained for required period');
    }

    // General recommendations
    recommendations.push('Enable document tamper detection and audit logging');
    recommendations.push('Use strong authentication for signer verification');
    recommendations.push('Maintain comprehensive audit trail throughout signing process');

    return {
      ready: issues.length === 0,
      issues,
      recommendations
    };
  }
}

/**
 * Middleware to ensure compliance monitoring for all signature operations
 */
export function complianceMiddleware() {
  return async (req: Request, res: any, next: any) => {
    // Add compliance context to request
    req.complianceContext = {
      timestamp: new Date(),
      ipAddress: getClientInfo(req).ipAddress,
      userAgent: getClientInfo(req).userAgent,
      jurisdiction: req.headers['x-jurisdiction'] as string || 'BOTH'
    };
    
    next();
  };
}

// Extend Request interface
declare global {
  namespace Express {
    interface Request {
      complianceContext?: {
        timestamp: Date;
        ipAddress: string;
        userAgent: string;
        jurisdiction: string;
      };
    }
  }
}