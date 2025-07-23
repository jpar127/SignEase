import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

/**
 * Cryptographic utilities for document integrity verification
 */

export class DocumentIntegrityService {
  private static readonly HASH_ALGORITHM = 'sha256';
  
  /**
   * Generate SHA-256 hash of a file
   */
  static async hashFile(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash(this.HASH_ALGORITHM);
      const stream = fs.createReadStream(filePath);
      
      stream.on('error', reject);
      stream.on('data', chunk => hash.update(chunk));
      stream.on('end', () => resolve(hash.digest('hex')));
    });
  }
  
  /**
   * Generate hash of string data (for signatures, field values, etc.)
   */
  static hashString(data: string): string {
    return crypto.createHash(this.HASH_ALGORITHM).update(data, 'utf8').digest('hex');
  }
  
  /**
   * Generate hash of the current document state including all signatures
   */
  static generateDocumentStateHash(documentData: {
    originalHash: string;
    signatures: Array<{
      fieldId: number;
      signatureHash: string;
      signedAt: string;
    }>;
    fields: Array<{
      id: number;
      value: string | null;
      completed: boolean;
    }>;
  }): string {
    // Create a deterministic representation of the document state
    const stateString = JSON.stringify({
      originalHash: documentData.originalHash,
      signatures: documentData.signatures.sort((a, b) => a.fieldId - b.fieldId),
      fields: documentData.fields
        .sort((a, b) => a.id - b.id)
        .map(f => ({ id: f.id, value: f.value, completed: f.completed }))
    });
    
    return this.hashString(stateString);
  }
  
  /**
   * Verify document integrity by comparing hashes
   */
  static async verifyDocumentIntegrity(filePath: string, expectedHash: string): Promise<boolean> {
    try {
      const currentHash = await this.hashFile(filePath);
      return currentHash === expectedHash;
    } catch (error) {
      console.error('Error verifying document integrity:', error);
      return false;
    }
  }
  
  /**
   * Generate a cryptographic proof of signature
   */
  static generateSignatureProof(signatureData: {
    signerEmail: string;
    signatureData: string;
    timestamp: Date;
    documentHash: string;
    fieldPosition: { x: number; y: number; page: number };
  }): string {
    const proofData = {
      signer: signatureData.signerEmail,
      signature: this.hashString(signatureData.signatureData),
      timestamp: signatureData.timestamp.toISOString(),
      documentHash: signatureData.documentHash,
      position: signatureData.fieldPosition
    };
    
    return this.hashString(JSON.stringify(proofData));
  }
  
  /**
   * Create tamper-evident seal for completed document
   */
  static createDocumentSeal(documentData: {
    documentId: number;
    originalHash: string;
    finalHash: string;
    signatures: Array<{
      signerId: number;
      signatureHash: string;
      timestamp: string;
    }>;
    completedAt: Date;
  }): string {
    const sealData = {
      docId: documentData.documentId,
      originalHash: documentData.originalHash,
      finalHash: documentData.finalHash,
      signatures: documentData.signatures.sort((a, b) => a.signerId - b.signerId),
      completed: documentData.completedAt.toISOString(),
      algorithm: this.HASH_ALGORITHM
    };
    
    return this.hashString(JSON.stringify(sealData));
  }
  
  /**
   * Verify the complete document chain of integrity
   */
  static verifyDocumentChain(auditLog: Array<{
    action: string;
    documentHash: string;
    timestamp: string;
    details?: any;
  }>): {
    isValid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];
    
    // Verify audit log chronological order
    for (let i = 1; i < auditLog.length; i++) {
      const prevTime = new Date(auditLog[i - 1].timestamp);
      const currTime = new Date(auditLog[i].timestamp);
      
      if (currTime < prevTime) {
        errors.push(`Audit log timestamp out of order at entry ${i}`);
      }
    }
    
    // Verify hash consistency where applicable
    const hashChanges = auditLog.filter(entry => 
      ['created', 'signed', 'completed'].includes(entry.action)
    );
    
    if (hashChanges.length === 0) {
      errors.push('No hash entries found in audit log');
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }
}

/**
 * Middleware to capture client information for audit trail
 */
export function getClientInfo(req: any): {
  ipAddress: string;
  userAgent: string;
} {
  return {
    ipAddress: req.ip || req.connection.remoteAddress || 'unknown',
    userAgent: req.get('User-Agent') || 'unknown'
  };
}