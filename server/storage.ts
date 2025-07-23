import { 
  users, documents, signers, signatureFields, signatures, documentAuditLog, activityLog, securityAuditLog,
  complianceRecords, signingIntent,
  type User, type InsertUser,
  type Document, type InsertDocument,
  type Signer, type InsertSigner,
  type SignatureField, type InsertSignatureField,
  type Signature, type InsertSignature,
  type DocumentAuditLog, type InsertAuditLog,
  type ActivityLog, type InsertActivityLog,
  type SecurityAuditLog, type InsertSecurityAudit,
  type ComplianceRecord, type InsertComplianceRecord,
  type SigningIntent, type InsertSigningIntent
} from "@shared/schema";
import { db } from "./db";
import { eq, and, gte, lte } from "drizzle-orm";
import { DocumentIntegrityService } from "./crypto-utils";

export interface IStorage {
  // Users
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUserLastLogin(id: number): Promise<void>;
  updateUser(id: number, updates: Partial<User>): Promise<User>;

  // Documents
  getDocument(id: number): Promise<Document | undefined>;
  getDocumentsByUser(userId: number): Promise<Document[]>;
  createDocument(document: InsertDocument): Promise<Document>;
  updateDocumentStatus(id: number, status: string): Promise<void>;

  // Signers
  getSigner(id: number): Promise<Signer | undefined>;
  getSignersByDocument(documentId: number): Promise<Signer[]>;
  createSigner(signer: InsertSigner): Promise<Signer>;
  updateSignerStatus(id: number, status: string): Promise<void>;

  // Signature Fields
  getSignatureFieldsByDocument(documentId: number): Promise<SignatureField[]>;
  getSignatureFieldsBySigner(signerId: number): Promise<SignatureField[]>;
  createSignatureField(field: InsertSignatureField): Promise<SignatureField>;
  updateSignatureFieldValue(id: number, value: string, completed: boolean): Promise<void>;

  // Signatures
  createSignature(signature: InsertSignature): Promise<Signature>;
  getSignaturesByDocument(documentId: number): Promise<Signature[]>;

  // Document Integrity
  verifyDocumentIntegrity(documentId: number): Promise<{ isValid: boolean; errors: string[] }>;
  updateDocumentHash(documentId: number, newHash: string): Promise<void>;
  createAuditLogEntry(entry: InsertAuditLog): Promise<DocumentAuditLog>;
  getDocumentAuditLog(documentId: number): Promise<DocumentAuditLog[]>;

  // Activity Logging
  createActivityLogEntry(entry: InsertActivityLog): Promise<ActivityLog>;
  getActivityLog(userId?: number, limit?: number): Promise<ActivityLog[]>;
  getActivityLogByDateRange(startDate: Date, endDate: Date): Promise<ActivityLog[]>;

  // Security Audit Logging
  createSecurityAuditEntry(entry: InsertSecurityAudit): Promise<SecurityAuditLog>;
  getSecurityAuditLog(resolved?: boolean): Promise<SecurityAuditLog[]>;
  markSecurityAuditResolved(id: number, resolvedBy: number): Promise<void>;

  // Compliance Management
  createComplianceRecord(record: InsertComplianceRecord): Promise<ComplianceRecord>;
  getComplianceRecord(documentId: number, jurisdiction?: string): Promise<ComplianceRecord | undefined>;
  updateComplianceRecord(id: string, updates: Partial<ComplianceRecord>): Promise<ComplianceRecord>;
  
  // Signing Intent Tracking
  createSigningIntent(intent: InsertSigningIntent): Promise<SigningIntent>;
  getSigningIntent(signerId: number, documentId: number): Promise<SigningIntent | undefined>;
}

export class MemStorage implements IStorage {
  private users: Map<number, User>;
  private documents: Map<number, Document>;
  private signers: Map<number, Signer>;
  private signatureFields: Map<number, SignatureField>;
  private signatures: Map<number, Signature>;
  private currentUserId: number;
  private currentDocumentId: number;
  private currentSignerId: number;
  private currentSignatureFieldId: number;
  private currentSignatureId: number;

  constructor() {
    this.users = new Map();
    this.documents = new Map();
    this.signers = new Map();
    this.signatureFields = new Map();
    this.signatures = new Map();
    this.currentUserId = 1;
    this.currentDocumentId = 1;
    this.currentSignerId = 1;
    this.currentSignatureFieldId = 1;
    this.currentSignatureId = 1;
  }

  // Users
  async getUser(id: number): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(user => user.username === username);
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(user => user.email === email);
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = this.currentUserId++;
    const user: User = { 
      ...insertUser, 
      id,
      emailVerified: false,
      role: "user",
      createdAt: new Date(),
      updatedAt: new Date(),
      lastLoginAt: null,
      firstName: insertUser.firstName || null,
      lastName: insertUser.lastName || null,
      profileImageUrl: null,
      phoneNumber: insertUser.phoneNumber || null
    };
    this.users.set(id, user);
    return user;
  }

  async updateUserLastLogin(id: number): Promise<void> {
    const user = this.users.get(id);
    if (user) {
      this.users.set(id, { ...user, lastLoginAt: new Date() });
    }
  }

  async updateUser(id: number, updates: Partial<User>): Promise<User> {
    const user = this.users.get(id);
    if (!user) {
      throw new Error('User not found');
    }
    const updatedUser = { ...user, ...updates, updatedAt: new Date() };
    this.users.set(id, updatedUser);
    return updatedUser;
  }

  // Documents
  async getDocument(id: number): Promise<Document | undefined> {
    return this.documents.get(id);
  }

  async getDocumentsByUser(userId: number): Promise<Document[]> {
    return Array.from(this.documents.values()).filter(doc => doc.createdBy === userId);
  }

  async createDocument(insertDocument: InsertDocument): Promise<Document> {
    const id = this.currentDocumentId++;
    const document: Document = { 
      ...insertDocument, 
      id, 
      status: "draft",
      createdAt: new Date(),
      pages: insertDocument.pages || 1,
      originalHash: insertDocument.originalHash || null,
      currentHash: insertDocument.currentHash || null,
      hashAlgorithm: "SHA-256"
    };
    this.documents.set(id, document);
    return document;
  }

  async updateDocumentStatus(id: number, status: string): Promise<void> {
    const document = this.documents.get(id);
    if (document) {
      this.documents.set(id, { ...document, status });
    }
  }

  // Signers
  async getSigner(id: number): Promise<Signer | undefined> {
    return this.signers.get(id);
  }

  async getSignersByDocument(documentId: number): Promise<Signer[]> {
    return Array.from(this.signers.values())
      .filter(signer => signer.documentId === documentId)
      .sort((a, b) => a.order - b.order);
  }

  async createSigner(insertSigner: InsertSigner): Promise<Signer> {
    const id = this.currentSignerId++;
    const signer: Signer = { 
      ...insertSigner, 
      id, 
      status: "pending",
      invitedAt: new Date(),
      signedAt: null
    };
    this.signers.set(id, signer);
    return signer;
  }

  async updateSignerStatus(id: number, status: string): Promise<void> {
    const signer = this.signers.get(id);
    if (signer) {
      const updatedSigner = { 
        ...signer, 
        status,
        signedAt: status === "signed" ? new Date() : signer.signedAt
      };
      this.signers.set(id, updatedSigner);
    }
  }

  // Signature Fields
  async getSignatureFieldsByDocument(documentId: number): Promise<SignatureField[]> {
    return Array.from(this.signatureFields.values())
      .filter(field => field.documentId === documentId);
  }

  async getSignatureFieldsBySigner(signerId: number): Promise<SignatureField[]> {
    return Array.from(this.signatureFields.values())
      .filter(field => field.signerId === signerId);
  }

  async createSignatureField(insertField: InsertSignatureField): Promise<SignatureField> {
    const id = this.currentSignatureFieldId++;
    const field: SignatureField = { 
      ...insertField, 
      id,
      completed: false,
      value: insertField.value || null,
      required: insertField.required !== undefined ? insertField.required : true
    };
    this.signatureFields.set(id, field);
    return field;
  }

  async updateSignatureFieldValue(id: number, value: string, completed: boolean): Promise<void> {
    const field = this.signatureFields.get(id);
    if (field) {
      this.signatureFields.set(id, { ...field, value, completed });
    }
  }

  // Signatures
  async createSignature(insertSignature: InsertSignature): Promise<Signature> {
    const id = this.currentSignatureId++;
    const signature: Signature = { 
      ...insertSignature, 
      id, 
      signedAt: new Date(),
      signatureHash: insertSignature.signatureHash || null,
      documentHashAtSigning: insertSignature.documentHashAtSigning || null,
      ipAddress: insertSignature.ipAddress || null,
      userAgent: insertSignature.userAgent || null
    };
    this.signatures.set(id, signature);
    return signature;
  }

  async getSignaturesByDocument(documentId: number): Promise<Signature[]> {
    const signers = await this.getSignersByDocument(documentId);
    const signerIds = signers.map(s => s.id);
    return Array.from(this.signatures.values())
      .filter(signature => signerIds.includes(signature.signerId));
  }

  // Document Integrity Methods (MemStorage)
  async verifyDocumentIntegrity(documentId: number): Promise<{ isValid: boolean; errors: string[] }> {
    return { isValid: true, errors: [] };
  }

  async updateDocumentHash(documentId: number, newHash: string): Promise<void> {
    const document = this.documents.get(documentId);
    if (document) {
      document.currentHash = newHash;
    }
  }

  async createAuditLogEntry(entry: InsertAuditLog): Promise<DocumentAuditLog> {
    const id = Date.now();
    return {
      ...entry,
      id,
      timestamp: new Date()
    } as DocumentAuditLog;
  }

  async getDocumentAuditLog(documentId: number): Promise<DocumentAuditLog[]> {
    return [];
  }

  // Activity Logging Methods (MemStorage)
  async createActivityLogEntry(entry: InsertActivityLog): Promise<ActivityLog> {
    const id = Date.now();
    return {
      ...entry,
      id,
      timestamp: new Date()
    } as ActivityLog;
  }

  async getActivityLog(userId?: number, limit?: number): Promise<ActivityLog[]> {
    return [];
  }

  async getActivityLogByDateRange(startDate: Date, endDate: Date): Promise<ActivityLog[]> {
    return [];
  }

  // Security Audit Methods (MemStorage)
  async createSecurityAuditEntry(entry: InsertSecurityAudit): Promise<SecurityAuditLog> {
    const id = Date.now();
    return {
      ...entry,
      id,
      timestamp: new Date(),
      resolved: false,
      resolvedBy: null,
      resolvedAt: null
    } as SecurityAuditLog;
  }

  async getSecurityAuditLog(resolved?: boolean): Promise<SecurityAuditLog[]> {
    return [];
  }

  async markSecurityAuditResolved(id: number, resolvedBy: number): Promise<void> {
    // No-op for MemStorage
  }

  // Compliance Management Methods (MemStorage)
  async createComplianceRecord(record: InsertComplianceRecord): Promise<ComplianceRecord> {
    return {
      ...record,
      createdAt: new Date()
    } as ComplianceRecord;
  }

  async getComplianceRecord(documentId: number, jurisdiction?: string): Promise<ComplianceRecord | undefined> {
    return undefined;
  }

  async updateComplianceRecord(id: string, updates: Partial<ComplianceRecord>): Promise<ComplianceRecord> {
    return updates as ComplianceRecord;
  }

  // Signing Intent Methods (MemStorage)
  async createSigningIntent(intent: InsertSigningIntent): Promise<SigningIntent> {
    const id = Date.now();
    return {
      ...intent,
      id,
      timestamp: new Date()
    } as SigningIntent;
  }

  async getSigningIntent(signerId: number, documentId: number): Promise<SigningIntent | undefined> {
    return undefined;
  }
}

// Database Storage Implementation
export class DatabaseStorage implements IStorage {
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user || undefined;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user || undefined;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(insertUser)
      .returning();
    return user;
  }

  async updateUserLastLogin(id: number): Promise<void> {
    await db
      .update(users)
      .set({ lastLoginAt: new Date() })
      .where(eq(users.id, id));
  }

  async updateUser(id: number, updates: Partial<User>): Promise<User> {
    const [user] = await db
      .update(users)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(users.id, id))
      .returning();
    return user;
  }

  async getDocument(id: number): Promise<Document | undefined> {
    const [document] = await db.select().from(documents).where(eq(documents.id, id));
    return document || undefined;
  }

  async getDocumentsByUser(userId: number): Promise<Document[]> {
    return await db.select().from(documents).where(eq(documents.createdBy, userId));
  }

  async createDocument(insertDocument: InsertDocument): Promise<Document> {
    const [document] = await db
      .insert(documents)
      .values(insertDocument)
      .returning();
    return document;
  }

  async updateDocumentStatus(id: number, status: string): Promise<void> {
    await db
      .update(documents)
      .set({ status })
      .where(eq(documents.id, id));
  }

  async getSigner(id: number): Promise<Signer | undefined> {
    const [signer] = await db.select().from(signers).where(eq(signers.id, id));
    return signer || undefined;
  }

  async getSignersByDocument(documentId: number): Promise<Signer[]> {
    return await db
      .select()
      .from(signers)
      .where(eq(signers.documentId, documentId))
      .orderBy(signers.order);
  }

  async createSigner(insertSigner: InsertSigner): Promise<Signer> {
    const [signer] = await db
      .insert(signers)
      .values(insertSigner)
      .returning();
    return signer;
  }

  async updateSignerStatus(id: number, status: string): Promise<void> {
    const updateData: any = { status };
    if (status === "signed") {
      updateData.signedAt = new Date();
    }
    await db
      .update(signers)
      .set(updateData)
      .where(eq(signers.id, id));
  }

  async getSignatureFieldsByDocument(documentId: number): Promise<SignatureField[]> {
    return await db
      .select()
      .from(signatureFields)
      .where(eq(signatureFields.documentId, documentId));
  }

  async getSignatureFieldsBySigner(signerId: number): Promise<SignatureField[]> {
    return await db
      .select()
      .from(signatureFields)
      .where(eq(signatureFields.signerId, signerId));
  }

  async createSignatureField(insertField: InsertSignatureField): Promise<SignatureField> {
    const [field] = await db
      .insert(signatureFields)
      .values(insertField)
      .returning();
    return field;
  }

  async updateSignatureFieldValue(id: number, value: string, completed: boolean): Promise<void> {
    await db
      .update(signatureFields)
      .set({ value, completed })
      .where(eq(signatureFields.id, id));
  }

  async createSignature(insertSignature: InsertSignature): Promise<Signature> {
    const [signature] = await db
      .insert(signatures)
      .values(insertSignature)
      .returning();
    return signature;
  }

  async getSignaturesByDocument(documentId: number): Promise<Signature[]> {
    const documentSigners = await this.getSignersByDocument(documentId);
    const signerIds = documentSigners.map(s => s.id);
    
    if (signerIds.length === 0) return [];
    
    // Get all signatures for any of the document signers
    const allSignatures = await db.select().from(signatures);
    return allSignatures.filter(signature => signerIds.includes(signature.signerId));
  }

  // Document Integrity Methods (Database implementation)
  async verifyDocumentIntegrity(documentId: number): Promise<{ isValid: boolean; errors: string[] }> {
    const document = await this.getDocument(documentId);
    if (!document) {
      return { isValid: false, errors: ['Document not found'] };
    }

    const errors: string[] = [];

    // Verify original file integrity if file path exists
    if (document.filePath && document.originalHash) {
      const fileIntegrityValid = await DocumentIntegrityService.verifyDocumentIntegrity(
        document.filePath, 
        document.originalHash
      );
      
      if (!fileIntegrityValid) {
        errors.push('Original document file has been tampered with');
      }
    }

    // Verify signature field consistency
    const signatures = await this.getSignaturesByDocument(documentId);
    const fields = await this.getSignatureFieldsByDocument(documentId);
    
    const completedFields = fields.filter(f => f.completed);
    const signedFields = signatures.map(s => s.signatureFieldId);
    
    for (const field of completedFields) {
      if (!signedFields.includes(field.id)) {
        errors.push(`Field ${field.id} marked as completed but no signature found`);
      }
    }

    // Verify audit log integrity
    const auditLog = await this.getDocumentAuditLog(documentId);
    const chainVerification = DocumentIntegrityService.verifyDocumentChain(
      auditLog.map(entry => ({
        action: entry.action,
        documentHash: entry.documentHash,
        timestamp: entry.timestamp.toISOString(),
        details: entry.details
      }))
    );

    if (!chainVerification.isValid) {
      errors.push(...chainVerification.errors);
    }

    return { isValid: errors.length === 0, errors };
  }

  async updateDocumentHash(documentId: number, newHash: string): Promise<void> {
    await db
      .update(documents)
      .set({ currentHash: newHash })
      .where(eq(documents.id, documentId));
  }

  async createAuditLogEntry(entry: InsertAuditLog): Promise<DocumentAuditLog> {
    const [auditEntry] = await db
      .insert(documentAuditLog)
      .values(entry)
      .returning();
    return auditEntry;
  }

  async getDocumentAuditLog(documentId: number): Promise<DocumentAuditLog[]> {
    return await db
      .select()
      .from(documentAuditLog)
      .where(eq(documentAuditLog.documentId, documentId))
      .orderBy(documentAuditLog.timestamp);
  }

  // Activity Logging Methods (Database)
  async createActivityLogEntry(entry: InsertActivityLog): Promise<ActivityLog> {
    const [logEntry] = await db
      .insert(activityLog)
      .values(entry)
      .returning();
    return logEntry;
  }

  async getActivityLog(userId?: number, limit: number = 100): Promise<ActivityLog[]> {
    let query = db.select().from(activityLog);
    
    if (userId) {
      query = query.where(eq(activityLog.userId, userId));
    }
    
    return await query
      .orderBy(activityLog.timestamp)
      .limit(limit);
  }

  async getActivityLogByDateRange(startDate: Date, endDate: Date): Promise<ActivityLog[]> {
    return await db
      .select()
      .from(activityLog)
      .where(
        and(
          gte(activityLog.timestamp, startDate),
          lte(activityLog.timestamp, endDate)
        )
      )
      .orderBy(activityLog.timestamp);
  }

  // Security Audit Methods (Database)
  async createSecurityAuditEntry(entry: InsertSecurityAudit): Promise<SecurityAuditLog> {
    const [auditEntry] = await db
      .insert(securityAuditLog)
      .values(entry)
      .returning();
    return auditEntry;
  }

  async getSecurityAuditLog(resolved?: boolean): Promise<SecurityAuditLog[]> {
    let query = db.select().from(securityAuditLog);
    
    if (resolved !== undefined) {
      query = query.where(eq(securityAuditLog.resolved, resolved));
    }
    
    return await query.orderBy(securityAuditLog.timestamp);
  }

  async markSecurityAuditResolved(id: number, resolvedBy: number): Promise<void> {
    await db
      .update(securityAuditLog)
      .set({
        resolved: true,
        resolvedBy,
        resolvedAt: new Date()
      })
      .where(eq(securityAuditLog.id, id));
  }

  // Compliance Management Methods (DatabaseStorage)
  async createComplianceRecord(record: InsertComplianceRecord): Promise<ComplianceRecord> {
    const [compliance] = await db
      .insert(complianceRecords)
      .values(record)
      .returning();
    return compliance;
  }

  async getComplianceRecord(documentId: number, jurisdiction?: string): Promise<ComplianceRecord | undefined> {
    let query = db
      .select()
      .from(complianceRecords)
      .where(eq(complianceRecords.documentId, documentId));
    
    if (jurisdiction) {
      query = query.where(eq(complianceRecords.jurisdiction, jurisdiction));
    }
    
    const [record] = await query.orderBy(desc(complianceRecords.createdAt));
    return record;
  }

  async updateComplianceRecord(id: string, updates: Partial<ComplianceRecord>): Promise<ComplianceRecord> {
    const [updated] = await db
      .update(complianceRecords)
      .set(updates)
      .where(eq(complianceRecords.id, id))
      .returning();
    return updated;
  }

  // Signing Intent Methods (DatabaseStorage)
  async createSigningIntent(intent: InsertSigningIntent): Promise<SigningIntent> {
    const [signingIntentRecord] = await db
      .insert(signingIntent)
      .values(intent)
      .returning();
    return signingIntentRecord;
  }

  async getSigningIntent(signerId: number, documentId: number): Promise<SigningIntent | undefined> {
    const [intent] = await db
      .select()
      .from(signingIntent)
      .where(
        and(
          eq(signingIntent.signerId, signerId),
          eq(signingIntent.documentId, documentId)
        )
      );
    return intent;
  }
}

export const storage = new DatabaseStorage();
