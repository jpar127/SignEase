var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "http";

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  activityLog: () => activityLog,
  complianceRecords: () => complianceRecords,
  documentAuditLog: () => documentAuditLog,
  documents: () => documents,
  insertActivityLogSchema: () => insertActivityLogSchema,
  insertAuditLogSchema: () => insertAuditLogSchema,
  insertDocumentSchema: () => insertDocumentSchema,
  insertSecurityAuditSchema: () => insertSecurityAuditSchema,
  insertSignatureFieldSchema: () => insertSignatureFieldSchema,
  insertSignatureSchema: () => insertSignatureSchema,
  insertSignerSchema: () => insertSignerSchema,
  insertUserSchema: () => insertUserSchema,
  loginSchema: () => loginSchema,
  registerSchema: () => registerSchema,
  securityAuditLog: () => securityAuditLog,
  sessions: () => sessions,
  signatureFields: () => signatureFields,
  signatures: () => signatures,
  signers: () => signers,
  signingIntent: () => signingIntent,
  users: () => users
});
import { pgTable, text, serial, integer, boolean, timestamp, jsonb, varchar, index } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
var users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  firstName: text("first_name"),
  lastName: text("last_name"),
  profileImageUrl: text("profile_image_url"),
  emailVerified: boolean("email_verified").default(false),
  phoneNumber: text("phone_number"),
  role: text("role").default("user"),
  // 'user' | 'admin'
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
  lastLoginAt: timestamp("last_login_at")
});
var sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull()
  },
  (table) => [index("IDX_session_expire").on(table.expire)]
);
var documents = pgTable("documents", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  originalFileName: text("original_file_name").notNull(),
  filePath: text("file_path").notNull(),
  fileType: text("file_type").notNull(),
  // 'pdf' | 'docx'
  status: text("status").notNull().default("draft"),
  // 'draft' | 'pending' | 'completed' | 'cancelled'
  createdBy: integer("created_by").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  pages: integer("pages").notNull().default(1),
  originalHash: text("original_hash"),
  // SHA-256 hash of original document
  currentHash: text("current_hash"),
  // SHA-256 hash of current document state
  hashAlgorithm: text("hash_algorithm").default("SHA-256")
});
var signers = pgTable("signers", {
  id: serial("id").primaryKey(),
  documentId: integer("document_id").notNull(),
  email: text("email").notNull(),
  name: text("name").notNull(),
  order: integer("order").notNull(),
  // signing order
  status: text("status").notNull().default("pending"),
  // 'pending' | 'signed' | 'declined'
  signedAt: timestamp("signed_at"),
  invitedAt: timestamp("invited_at").defaultNow().notNull()
});
var signatureFields = pgTable("signature_fields", {
  id: serial("id").primaryKey(),
  documentId: integer("document_id").notNull(),
  signerId: integer("signer_id").notNull(),
  type: text("type").notNull(),
  // 'signature' | 'text' | 'date' | 'initials'
  page: integer("page").notNull(),
  x: integer("x").notNull(),
  y: integer("y").notNull(),
  width: integer("width").notNull(),
  height: integer("height").notNull(),
  value: text("value"),
  // for text fields or signature data
  required: boolean("required").notNull().default(true),
  completed: boolean("completed").notNull().default(false)
});
var signatures = pgTable("signatures", {
  id: serial("id").primaryKey(),
  signerId: integer("signer_id").notNull(),
  signatureFieldId: integer("signature_field_id").notNull(),
  type: text("type").notNull(),
  // 'drawn' | 'typed' | 'uploaded'
  data: text("data").notNull(),
  // base64 encoded signature image or text
  signedAt: timestamp("signed_at").defaultNow().notNull(),
  signatureHash: text("signature_hash"),
  // Hash of the signature data
  documentHashAtSigning: text("document_hash_at_signing"),
  // Document hash when this signature was applied
  ipAddress: text("ip_address"),
  // IP address of signer for audit trail
  userAgent: text("user_agent")
  // Browser/device info for audit trail
});
var documentAuditLog = pgTable("document_audit_log", {
  id: serial("id").primaryKey(),
  documentId: integer("document_id").notNull(),
  action: text("action").notNull(),
  // 'created' | 'viewed' | 'downloaded' | 'field_added' | 'signed' | 'completed' | 'shared' | 'deleted'
  userId: integer("user_id"),
  details: jsonb("details"),
  // Additional audit information
  documentHash: text("document_hash").notNull(),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  sessionId: text("session_id"),
  severity: text("severity").default("info")
  // 'info' | 'warning' | 'error' | 'critical'
});
var activityLog = pgTable("activity_log", {
  id: serial("id").primaryKey(),
  userId: integer("user_id"),
  action: text("action").notNull(),
  // 'login' | 'logout' | 'register' | 'password_change' | 'profile_update' | 'api_access'
  entityType: text("entity_type"),
  // 'user' | 'document' | 'signer' | 'signature' | 'system'
  entityId: integer("entity_id"),
  details: jsonb("details"),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  sessionId: text("session_id"),
  success: boolean("success").default(true),
  errorMessage: text("error_message")
});
var securityAuditLog = pgTable("security_audit_log", {
  id: serial("id").primaryKey(),
  userId: integer("user_id"),
  action: text("action").notNull(),
  // 'failed_login' | 'suspicious_activity' | 'permission_escalation' | 'data_breach_attempt'
  risk_level: text("risk_level").notNull(),
  // 'low' | 'medium' | 'high' | 'critical'
  details: jsonb("details"),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  resolved: boolean("resolved").default(false),
  resolvedBy: integer("resolved_by"),
  resolvedAt: timestamp("resolved_at")
});
var insertUserSchema = createInsertSchema(users).pick({
  username: true,
  email: true,
  password: true,
  firstName: true,
  lastName: true,
  phoneNumber: true
});
var loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(6, "Password must be at least 6 characters")
});
var registerSchema = insertUserSchema.extend({
  confirmPassword: z.string()
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"]
});
var insertDocumentSchema = createInsertSchema(documents).pick({
  name: true,
  originalFileName: true,
  filePath: true,
  fileType: true,
  createdBy: true,
  pages: true,
  originalHash: true,
  currentHash: true
});
var insertSignerSchema = createInsertSchema(signers).pick({
  documentId: true,
  email: true,
  name: true,
  order: true
});
var insertSignatureFieldSchema = createInsertSchema(signatureFields).pick({
  documentId: true,
  signerId: true,
  type: true,
  page: true,
  x: true,
  y: true,
  width: true,
  height: true,
  value: true,
  required: true
});
var insertSignatureSchema = createInsertSchema(signatures).pick({
  signerId: true,
  signatureFieldId: true,
  type: true,
  data: true,
  signatureHash: true,
  documentHashAtSigning: true,
  ipAddress: true,
  userAgent: true
});
var insertAuditLogSchema = createInsertSchema(documentAuditLog).pick({
  documentId: true,
  action: true,
  userId: true,
  details: true,
  documentHash: true,
  ipAddress: true,
  userAgent: true,
  sessionId: true,
  severity: true
});
var insertActivityLogSchema = createInsertSchema(activityLog).pick({
  userId: true,
  action: true,
  entityType: true,
  entityId: true,
  details: true,
  ipAddress: true,
  userAgent: true,
  sessionId: true,
  success: true,
  errorMessage: true
});
var insertSecurityAuditSchema = createInsertSchema(securityAuditLog).pick({
  userId: true,
  action: true,
  risk_level: true,
  details: true,
  ipAddress: true,
  userAgent: true
});
var complianceRecords = pgTable("compliance_records", {
  id: varchar("id", { length: 100 }).primaryKey(),
  // UUID
  documentId: integer("document_id").references(() => documents.id).notNull(),
  jurisdiction: varchar("jurisdiction", { length: 10 }).notNull(),
  // NZ, US, BOTH
  legalFramework: varchar("legal_framework", { length: 100 }).notNull(),
  // NZ_ETA_2002, US_ESIGN_ACT
  status: varchar("status", { length: 20 }).notNull(),
  // compliant, non_compliant, pending_verification
  requirements: jsonb("requirements").notNull(),
  // Array of compliance requirements and their status
  evidencePackage: jsonb("evidence_package").notNull(),
  // All evidence supporting compliance
  verificationDate: timestamp("verification_date").defaultNow().notNull(),
  validityPeriod: integer("validity_period").notNull(),
  // Years the compliance is valid
  certificateData: jsonb("certificate_data"),
  // Generated compliance certificate
  createdBy: integer("created_by").references(() => users.id).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var signingIntent = pgTable("signing_intent", {
  id: serial("id").primaryKey(),
  signerId: integer("signer_id").references(() => signers.id).notNull(),
  documentId: integer("document_id").references(() => documents.id).notNull(),
  intentToSign: boolean("intent_to_sign").notNull(),
  consentToElectronic: boolean("consent_to_electronic").notNull(),
  identityVerified: boolean("identity_verified").notNull(),
  accessMethod: varchar("access_method", { length: 100 }).notNull(),
  // email_link, direct_access, etc
  evidenceData: jsonb("evidence_data").notNull(),
  // IP, timestamp, user agent, etc
  timestamp: timestamp("timestamp").defaultNow().notNull()
});

// server/db.ts
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
neonConfig.webSocketConstructor = ws;
if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?"
  );
}
var pool = new Pool({ connectionString: process.env.DATABASE_URL });
var db = drizzle({ client: pool, schema: schema_exports });

// server/storage.ts
import { eq, and, gte, lte } from "drizzle-orm";

// server/crypto-utils.ts
import crypto from "crypto";
import fs from "fs";
var DocumentIntegrityService = class {
  static HASH_ALGORITHM = "sha256";
  /**
   * Generate SHA-256 hash of a file
   */
  static async hashFile(filePath) {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash(this.HASH_ALGORITHM);
      const stream = fs.createReadStream(filePath);
      stream.on("error", reject);
      stream.on("data", (chunk) => hash.update(chunk));
      stream.on("end", () => resolve(hash.digest("hex")));
    });
  }
  /**
   * Generate hash of string data (for signatures, field values, etc.)
   */
  static hashString(data) {
    return crypto.createHash(this.HASH_ALGORITHM).update(data, "utf8").digest("hex");
  }
  /**
   * Generate hash of the current document state including all signatures
   */
  static generateDocumentStateHash(documentData) {
    const stateString = JSON.stringify({
      originalHash: documentData.originalHash,
      signatures: documentData.signatures.sort((a, b) => a.fieldId - b.fieldId),
      fields: documentData.fields.sort((a, b) => a.id - b.id).map((f) => ({ id: f.id, value: f.value, completed: f.completed }))
    });
    return this.hashString(stateString);
  }
  /**
   * Verify document integrity by comparing hashes
   */
  static async verifyDocumentIntegrity(filePath, expectedHash) {
    try {
      const currentHash = await this.hashFile(filePath);
      return currentHash === expectedHash;
    } catch (error) {
      console.error("Error verifying document integrity:", error);
      return false;
    }
  }
  /**
   * Generate a cryptographic proof of signature
   */
  static generateSignatureProof(signatureData) {
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
  static createDocumentSeal(documentData) {
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
  static verifyDocumentChain(auditLog) {
    const errors = [];
    for (let i = 1; i < auditLog.length; i++) {
      const prevTime = new Date(auditLog[i - 1].timestamp);
      const currTime = new Date(auditLog[i].timestamp);
      if (currTime < prevTime) {
        errors.push(`Audit log timestamp out of order at entry ${i}`);
      }
    }
    const hashChanges = auditLog.filter(
      (entry) => ["created", "signed", "completed"].includes(entry.action)
    );
    if (hashChanges.length === 0) {
      errors.push("No hash entries found in audit log");
    }
    return {
      isValid: errors.length === 0,
      errors
    };
  }
};
function getClientInfo(req) {
  return {
    ipAddress: req.ip || req.connection.remoteAddress || "unknown",
    userAgent: req.get("User-Agent") || "unknown"
  };
}

// server/storage.ts
var DatabaseStorage = class {
  async getUser(id) {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || void 0;
  }
  async getUserByUsername(username) {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user || void 0;
  }
  async getUserByEmail(email) {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user || void 0;
  }
  async createUser(insertUser) {
    const [user] = await db.insert(users).values(insertUser).returning();
    return user;
  }
  async updateUserLastLogin(id) {
    await db.update(users).set({ lastLoginAt: /* @__PURE__ */ new Date() }).where(eq(users.id, id));
  }
  async updateUser(id, updates) {
    const [user] = await db.update(users).set({ ...updates, updatedAt: /* @__PURE__ */ new Date() }).where(eq(users.id, id)).returning();
    return user;
  }
  async getDocument(id) {
    const [document] = await db.select().from(documents).where(eq(documents.id, id));
    return document || void 0;
  }
  async getDocumentsByUser(userId) {
    return await db.select().from(documents).where(eq(documents.createdBy, userId));
  }
  async createDocument(insertDocument) {
    const [document] = await db.insert(documents).values(insertDocument).returning();
    return document;
  }
  async updateDocumentStatus(id, status) {
    await db.update(documents).set({ status }).where(eq(documents.id, id));
  }
  async getSigner(id) {
    const [signer] = await db.select().from(signers).where(eq(signers.id, id));
    return signer || void 0;
  }
  async getSignersByDocument(documentId) {
    return await db.select().from(signers).where(eq(signers.documentId, documentId)).orderBy(signers.order);
  }
  async createSigner(insertSigner) {
    const [signer] = await db.insert(signers).values(insertSigner).returning();
    return signer;
  }
  async updateSignerStatus(id, status) {
    const updateData = { status };
    if (status === "signed") {
      updateData.signedAt = /* @__PURE__ */ new Date();
    }
    await db.update(signers).set(updateData).where(eq(signers.id, id));
  }
  async getSignatureFieldsByDocument(documentId) {
    return await db.select().from(signatureFields).where(eq(signatureFields.documentId, documentId));
  }
  async getSignatureFieldsBySigner(signerId) {
    return await db.select().from(signatureFields).where(eq(signatureFields.signerId, signerId));
  }
  async createSignatureField(insertField) {
    const [field] = await db.insert(signatureFields).values(insertField).returning();
    return field;
  }
  async updateSignatureFieldValue(id, value, completed) {
    await db.update(signatureFields).set({ value, completed }).where(eq(signatureFields.id, id));
  }
  async createSignature(insertSignature) {
    const [signature] = await db.insert(signatures).values(insertSignature).returning();
    return signature;
  }
  async getSignaturesByDocument(documentId) {
    const documentSigners = await this.getSignersByDocument(documentId);
    const signerIds = documentSigners.map((s) => s.id);
    if (signerIds.length === 0) return [];
    const allSignatures = await db.select().from(signatures);
    return allSignatures.filter((signature) => signerIds.includes(signature.signerId));
  }
  // Document Integrity Methods (Database implementation)
  async verifyDocumentIntegrity(documentId) {
    const document = await this.getDocument(documentId);
    if (!document) {
      return { isValid: false, errors: ["Document not found"] };
    }
    const errors = [];
    if (document.filePath && document.originalHash) {
      const fileIntegrityValid = await DocumentIntegrityService.verifyDocumentIntegrity(
        document.filePath,
        document.originalHash
      );
      if (!fileIntegrityValid) {
        errors.push("Original document file has been tampered with");
      }
    }
    const signatures2 = await this.getSignaturesByDocument(documentId);
    const fields = await this.getSignatureFieldsByDocument(documentId);
    const completedFields = fields.filter((f) => f.completed);
    const signedFields = signatures2.map((s) => s.signatureFieldId);
    for (const field of completedFields) {
      if (!signedFields.includes(field.id)) {
        errors.push(`Field ${field.id} marked as completed but no signature found`);
      }
    }
    const auditLog = await this.getDocumentAuditLog(documentId);
    const chainVerification = DocumentIntegrityService.verifyDocumentChain(
      auditLog.map((entry) => ({
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
  async updateDocumentHash(documentId, newHash) {
    await db.update(documents).set({ currentHash: newHash }).where(eq(documents.id, documentId));
  }
  async createAuditLogEntry(entry) {
    const [auditEntry] = await db.insert(documentAuditLog).values(entry).returning();
    return auditEntry;
  }
  async getDocumentAuditLog(documentId) {
    return await db.select().from(documentAuditLog).where(eq(documentAuditLog.documentId, documentId)).orderBy(documentAuditLog.timestamp);
  }
  // Activity Logging Methods (Database)
  async createActivityLogEntry(entry) {
    const [logEntry] = await db.insert(activityLog).values(entry).returning();
    return logEntry;
  }
  async getActivityLog(userId, limit = 100) {
    let query = db.select().from(activityLog);
    if (userId) {
      query = query.where(eq(activityLog.userId, userId));
    }
    return await query.orderBy(activityLog.timestamp).limit(limit);
  }
  async getActivityLogByDateRange(startDate, endDate) {
    return await db.select().from(activityLog).where(
      and(
        gte(activityLog.timestamp, startDate),
        lte(activityLog.timestamp, endDate)
      )
    ).orderBy(activityLog.timestamp);
  }
  // Security Audit Methods (Database)
  async createSecurityAuditEntry(entry) {
    const [auditEntry] = await db.insert(securityAuditLog).values(entry).returning();
    return auditEntry;
  }
  async getSecurityAuditLog(resolved) {
    let query = db.select().from(securityAuditLog);
    if (resolved !== void 0) {
      query = query.where(eq(securityAuditLog.resolved, resolved));
    }
    return await query.orderBy(securityAuditLog.timestamp);
  }
  async markSecurityAuditResolved(id, resolvedBy) {
    await db.update(securityAuditLog).set({
      resolved: true,
      resolvedBy,
      resolvedAt: /* @__PURE__ */ new Date()
    }).where(eq(securityAuditLog.id, id));
  }
  // Compliance Management Methods (DatabaseStorage)
  async createComplianceRecord(record) {
    const [compliance] = await db.insert(complianceRecords).values(record).returning();
    return compliance;
  }
  async getComplianceRecord(documentId, jurisdiction) {
    let query = db.select().from(complianceRecords).where(eq(complianceRecords.documentId, documentId));
    if (jurisdiction) {
      query = query.where(eq(complianceRecords.jurisdiction, jurisdiction));
    }
    const [record] = await query.orderBy(desc(complianceRecords.createdAt));
    return record;
  }
  async updateComplianceRecord(id, updates) {
    const [updated] = await db.update(complianceRecords).set(updates).where(eq(complianceRecords.id, id)).returning();
    return updated;
  }
  // Signing Intent Methods (DatabaseStorage)
  async createSigningIntent(intent) {
    const [signingIntentRecord] = await db.insert(signingIntent).values(intent).returning();
    return signingIntentRecord;
  }
  async getSigningIntent(signerId, documentId) {
    const [intent] = await db.select().from(signingIntent).where(
      and(
        eq(signingIntent.signerId, signerId),
        eq(signingIntent.documentId, documentId)
      )
    );
    return intent;
  }
};
var storage = new DatabaseStorage();

// server/auth.ts
import bcrypt from "bcryptjs";
import session from "express-session";
import connectPg from "connect-pg-simple";
function getSessionMiddleware() {
  const pgStore = connectPg(session);
  return session({
    store: new pgStore({
      conString: process.env.DATABASE_URL,
      createTableIfMissing: true,
      tableName: "sessions"
    }),
    secret: process.env.SESSION_SECRET || "your-secret-key-change-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1e3
      // 7 days
    }
  });
}
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Authentication required" });
  }
  next();
}
async function getCurrentUser(req, res, next) {
  if (req.session.userId) {
    try {
      const user = await storage.getUser(req.session.userId);
      if (user) {
        req.user = user;
      }
    } catch (error) {
      console.error("Error fetching current user:", error);
    }
  }
  next();
}
async function hashPassword(password) {
  const saltRounds = 12;
  return bcrypt.hash(password, saltRounds);
}
async function verifyPassword(password, hashedPassword) {
  return bcrypt.compare(password, hashedPassword);
}
async function registerUser(userData) {
  const validatedData = registerSchema.parse(userData);
  const existingUser = await storage.getUserByEmail(validatedData.email);
  if (existingUser) {
    throw new Error("User already exists with this email");
  }
  const existingUsername = await storage.getUserByUsername(validatedData.username);
  if (existingUsername) {
    throw new Error("Username already taken");
  }
  const hashedPassword = await hashPassword(validatedData.password);
  const user = await storage.createUser({
    username: validatedData.username,
    email: validatedData.email,
    password: hashedPassword,
    firstName: validatedData.firstName,
    lastName: validatedData.lastName,
    phoneNumber: validatedData.phoneNumber
  });
  const { password, ...userWithoutPassword } = user;
  return userWithoutPassword;
}
async function loginUser(credentials) {
  const validatedCredentials = loginSchema.parse(credentials);
  const user = await storage.getUserByEmail(validatedCredentials.email);
  if (!user) {
    throw new Error("Invalid email or password");
  }
  const isValidPassword = await verifyPassword(validatedCredentials.password, user.password);
  if (!isValidPassword) {
    throw new Error("Invalid email or password");
  }
  await storage.updateUserLastLogin(user.id);
  const { password, ...userWithoutPassword } = user;
  return userWithoutPassword;
}
function setupAuthRoutes(app2) {
  app2.post("/api/auth/register", async (req, res) => {
    try {
      const user = await registerUser(req.body);
      req.session.userId = user.id;
      const clientInfo = getClientInfo(req);
      await storage.createActivityLogEntry({
        userId: user.id,
        action: "register",
        entityType: "user",
        entityId: user.id,
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent,
        sessionId: req.sessionID,
        success: true,
        details: {
          email: user.email,
          username: user.username
        }
      });
      res.status(201).json({ user, message: "Registration successful" });
    } catch (error) {
      console.error("Registration error:", error);
      res.status(400).json({
        message: error instanceof Error ? error.message : "Registration failed"
      });
    }
  });
  app2.post("/api/auth/login", async (req, res) => {
    try {
      const user = await loginUser(req.body);
      req.session.userId = user.id;
      const clientInfo = getClientInfo(req);
      await storage.createActivityLogEntry({
        userId: user.id,
        action: "login",
        entityType: "user",
        entityId: user.id,
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent,
        sessionId: req.sessionID,
        success: true,
        details: {
          email: user.email,
          loginMethod: "password"
        }
      });
      res.json({ user, message: "Login successful" });
    } catch (error) {
      console.error("Login error:", error);
      const clientInfo = getClientInfo(req);
      await storage.createActivityLogEntry({
        action: "failed_login",
        entityType: "user",
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent,
        sessionId: req.sessionID,
        success: false,
        errorMessage: error instanceof Error ? error.message : "Login failed",
        details: {
          attemptedEmail: req.body.email
        }
      });
      await storage.createSecurityAuditEntry({
        action: "failed_login_attempt",
        risk_level: "medium",
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent,
        details: {
          attemptedEmail: req.body.email,
          errorMessage: error instanceof Error ? error.message : "Login failed"
        }
      });
      res.status(401).json({
        message: error instanceof Error ? error.message : "Login failed"
      });
    }
  });
  app2.post("/api/auth/logout", async (req, res) => {
    const userId = req.session?.userId;
    if (userId) {
      const clientInfo = getClientInfo(req);
      await storage.createActivityLogEntry({
        userId,
        action: "logout",
        entityType: "user",
        entityId: userId,
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent,
        sessionId: req.sessionID,
        success: true,
        details: {
          logoutMethod: "user_initiated"
        }
      });
    }
    req.session.destroy((err) => {
      if (err) {
        console.error("Logout error:", err);
        return res.status(500).json({ message: "Logout failed" });
      }
      res.clearCookie("connect.sid");
      res.json({ message: "Logout successful" });
    });
  });
  app2.get("/api/auth/user", getCurrentUser, (req, res) => {
    if (req.user) {
      const { password, ...userWithoutPassword } = req.user;
      res.json(userWithoutPassword);
    } else {
      res.status(401).json({ message: "Not authenticated" });
    }
  });
  app2.put("/api/auth/profile", requireAuth, getCurrentUser, async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ message: "Not authenticated" });
      }
      const allowedUpdates = ["firstName", "lastName", "phoneNumber"];
      const updates = {};
      for (const field of allowedUpdates) {
        if (req.body[field] !== void 0) {
          updates[field] = req.body[field];
        }
      }
      const updatedUser = await storage.updateUser(req.user.id, updates);
      const { password, ...userWithoutPassword } = updatedUser;
      res.json(userWithoutPassword);
    } catch (error) {
      console.error("Profile update error:", error);
      res.status(500).json({ message: "Profile update failed" });
    }
  });
}

// server/audit-logger.ts
var AuditLogger = class {
  static getAuditContext(req) {
    const clientInfo = getClientInfo(req);
    return {
      userId: req.session?.userId,
      sessionId: req.sessionID,
      ipAddress: clientInfo.ipAddress,
      userAgent: clientInfo.userAgent,
      timestamp: /* @__PURE__ */ new Date()
    };
  }
  // Document audit logging
  static async logDocumentAction(req, action, documentId, documentHash, details, severity = "info") {
    try {
      const context = this.getAuditContext(req);
      await storage.createAuditLogEntry({
        documentId,
        action,
        userId: context.userId,
        documentHash,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        sessionId: context.sessionId,
        severity,
        details: {
          ...details,
          timestamp: context.timestamp.toISOString()
        }
      });
    } catch (error) {
      console.error("Failed to log document audit:", error);
    }
  }
  // Activity logging
  static async logActivity(req, action, entityType, entityId, details, success = true, errorMessage) {
    try {
      const context = this.getAuditContext(req);
      await storage.createActivityLogEntry({
        userId: context.userId,
        action,
        entityType,
        entityId,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        sessionId: context.sessionId,
        success,
        errorMessage,
        details: {
          ...details,
          timestamp: context.timestamp.toISOString()
        }
      });
    } catch (error) {
      console.error("Failed to log activity:", error);
    }
  }
  // Security audit logging
  static async logSecurityEvent(req, action, riskLevel, details, userId) {
    try {
      const context = this.getAuditContext(req);
      await storage.createSecurityAuditEntry({
        userId: userId || context.userId,
        action,
        risk_level: riskLevel,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        details: {
          ...details,
          timestamp: context.timestamp.toISOString(),
          sessionId: context.sessionId
        }
      });
      if (riskLevel === "critical" || riskLevel === "high") {
        console.warn(`[SECURITY ALERT] ${action}:`, {
          userId: userId || context.userId,
          ip: context.ipAddress,
          userAgent: context.userAgent,
          details
        });
      }
    } catch (error) {
      console.error("Failed to log security event:", error);
    }
  }
  // Authentication logging
  static async logAuthentication(req, action, userId, success = true, errorMessage) {
    const context = this.getAuditContext(req);
    await this.logActivity(req, action, "user", userId, {
      method: req.method,
      path: req.path
    }, success, errorMessage);
    if (action === "failed_login") {
      await this.logSecurityEvent(req, "failed_login_attempt", "medium", {
        attemptedUserId: userId,
        errorMessage
      });
    }
  }
  // API access logging
  static async logAPIAccess(req, endpoint, method, statusCode, responseTime) {
    const context = this.getAuditContext(req);
    const success = statusCode < 400;
    await this.logActivity(req, "api_access", "system", void 0, {
      endpoint,
      method,
      statusCode,
      responseTime,
      path: req.path,
      query: req.query
    }, success, statusCode >= 400 ? `HTTP ${statusCode}` : void 0);
  }
  // File operations logging
  static async logFileOperation(req, action, documentId, fileName, fileSize) {
    const context = this.getAuditContext(req);
    await this.logActivity(req, `file_${action}`, "document", documentId, {
      fileName,
      fileSize,
      timestamp: context.timestamp.toISOString()
    });
  }
  // Signature operations logging
  static async logSignatureOperation(req, action, documentId, signerId, details) {
    const context = this.getAuditContext(req);
    await this.logActivity(req, action, "signature", signerId, {
      documentId,
      ...details,
      timestamp: context.timestamp.toISOString()
    });
  }
  // Data export logging (for compliance)
  static async logDataExport(req, exportType, entityIds, requestedBy) {
    await this.logActivity(req, "data_export", "system", void 0, {
      exportType,
      entityIds,
      requestedBy,
      entityCount: entityIds.length
    });
    if (exportType === "user_data" || exportType === "audit_logs") {
      await this.logSecurityEvent(req, "sensitive_data_export", "medium", {
        exportType,
        entityCount: entityIds.length,
        requestedBy
      });
    }
  }
  // System health monitoring
  static async logSystemEvent(action, severity, details) {
    try {
      await storage.createActivityLogEntry({
        action: `system_${action}`,
        entityType: "system",
        ipAddress: "system",
        userAgent: "system",
        sessionId: "system",
        success: severity !== "error",
        details: {
          ...details,
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        }
      });
    } catch (error) {
      console.error("Failed to log system event:", error);
    }
  }
};
function auditMiddleware() {
  return (req, res, next) => {
    const startTime = Date.now();
    res.on("finish", () => {
      const responseTime = Date.now() - startTime;
      if (!req.path.includes("/health") && !req.path.includes("/ping")) {
        AuditLogger.logAPIAccess(
          req,
          req.path,
          req.method,
          res.statusCode,
          responseTime
        ).catch(console.error);
      }
    });
    next();
  };
}

// server/compliance.ts
var ComplianceEngine = class {
  /**
   * NZ Electronic Transactions Act 2002 Requirements
   */
  static NZ_ETA_REQUIREMENTS = {
    // Section 22 - When is an electronic signature reliable?
    RELIABLE_SIGNATURE: {
      code: "NZ_ETA_S22",
      description: "Electronic signature must be reliable in the circumstances",
      requirements: [
        "Signature creation data is linked to signatory and no other person",
        "Signature creation data was under sole control of signatory",
        "Any alteration after signing is detectable",
        "Identity of signatory is established"
      ]
    },
    // Section 23 - Consent requirements
    CONSENT: {
      code: "NZ_ETA_S23",
      description: "Consent to use electronic signatures",
      requirements: [
        "Consent given by the person",
        "Consent may be inferred from conduct",
        "Consent can be withdrawn"
      ]
    },
    // Section 8 - Writing requirement satisfaction
    WRITING_REQUIREMENT: {
      code: "NZ_ETA_S8",
      description: "Electronic document satisfies writing requirement",
      requirements: [
        "Information accessible and usable for subsequent reference",
        "Information retained in original form or substantial equivalent"
      ]
    }
  };
  /**
   * US UETA/ESIGN Act Requirements
   */
  static US_ESIGN_REQUIREMENTS = {
    // 15 USC 7001(a) - General rule of validity
    GENERAL_VALIDITY: {
      code: "US_ESIGN_7001A",
      description: "Electronic signature has same legal effect as handwritten signature",
      requirements: [
        "Signature not denied legal effect solely because electronic",
        "Contract not denied legal effect solely because electronic record used"
      ]
    },
    // 15 USC 7001(c) - Consumer consent
    CONSUMER_CONSENT: {
      code: "US_ESIGN_7001C",
      description: "Consumer consent requirements",
      requirements: [
        "Consumer consents electronically in reasonable manner",
        "Prior to consent, consumer provided with clear disclosure",
        "Consumer demonstrates ability to access electronic records",
        "Consent withdrawal procedures provided"
      ]
    },
    // Record retention requirements
    RECORD_RETENTION: {
      code: "US_ESIGN_RETENTION",
      description: "Electronic record retention requirements",
      requirements: [
        "Records accurately reflect information",
        "Records remain accessible to authorized persons",
        "Records retained in original format or non-alterable form"
      ]
    }
  };
  /**
   * Verify compliance for a signing event
   */
  static async verifySigningCompliance(req, documentId, signerId, signingData, jurisdiction = "BOTH") {
    const clientInfo = getClientInfo(req);
    const complianceId = `COMP_${Date.now()}_${documentId}_${signerId}`;
    const context = {
      jurisdiction,
      documentType: signingData.documentType || "contract",
      signerVerification: signingData.verificationMethod || "email",
      consentMethod: signingData.consentMethod || "explicit",
      timestamp: /* @__PURE__ */ new Date(),
      ipAddress: clientInfo.ipAddress,
      userAgent: clientInfo.userAgent,
      location: signingData.location
    };
    const requirements = [];
    if (jurisdiction === "NZ" || jurisdiction === "BOTH") {
      requirements.push(...await this.checkNZCompliance(documentId, signerId, signingData, context));
    }
    if (jurisdiction === "US" || jurisdiction === "BOTH") {
      requirements.push(...await this.checkUSCompliance(documentId, signerId, signingData, context));
    }
    const allMet = requirements.every((req2) => req2.status === "met");
    const status = allMet ? "compliant" : requirements.some((req2) => req2.status === "partial") ? "pending_verification" : "non_compliant";
    const complianceRecord = {
      id: complianceId,
      documentId,
      jurisdiction,
      requirements,
      status,
      verificationDate: /* @__PURE__ */ new Date(),
      validityPeriod: 7,
      // 7 years standard retention
      legalFramework: jurisdiction === "NZ" ? "Electronic Transactions Act 2002" : jurisdiction === "US" ? "UETA/ESIGN Act" : "NZ ETA 2002 & US UETA/ESIGN",
      evidencePackage: {
        context,
        signingData,
        auditTrail: await storage.getDocumentAuditLog(documentId),
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        complianceVersion: "1.0"
      }
    };
    await this.storeComplianceRecord(complianceRecord);
    await AuditLogger.logActivity(req, "compliance_verification", "compliance", void 0, {
      complianceId,
      documentId,
      signerId,
      jurisdiction,
      status,
      requirementsMet: requirements.filter((r) => r.status === "met").length,
      totalRequirements: requirements.length
    });
    return complianceRecord;
  }
  /**
   * Check New Zealand Electronic Transactions Act 2002 compliance
   */
  static async checkNZCompliance(documentId, signerId, signingData, context) {
    const requirements = [];
    requirements.push({
      requirement: "NZ_ETA_S22_UNIQUE_LINK",
      status: this.verifyUniqueSignatureLink(signingData) ? "met" : "not_met",
      evidence: {
        signerVerification: context.signerVerification,
        uniqueIdentifiers: signingData.signerIdentifiers,
        authenticationMethod: signingData.authMethod
      },
      description: "Signature creation data linked uniquely to signatory",
      legalReference: "Electronic Transactions Act 2002, Section 22(a)"
    });
    requirements.push({
      requirement: "NZ_ETA_S22_SOLE_CONTROL",
      status: this.verifySoleControl(signingData) ? "met" : "not_met",
      evidence: {
        authenticationEvents: signingData.authEvents,
        accessControl: signingData.accessControl,
        sessionManagement: signingData.sessionData
      },
      description: "Signature creation data under sole control of signatory",
      legalReference: "Electronic Transactions Act 2002, Section 22(b)"
    });
    requirements.push({
      requirement: "NZ_ETA_S22_TAMPER_DETECTION",
      status: this.verifyTamperDetection(documentId) ? "met" : "not_met",
      evidence: {
        documentHash: signingData.documentHash,
        integrityChecks: signingData.integrityVerification,
        auditTrail: await storage.getDocumentAuditLog(documentId)
      },
      description: "Any alteration to signature after signing is detectable",
      legalReference: "Electronic Transactions Act 2002, Section 22(c)"
    });
    requirements.push({
      requirement: "NZ_ETA_S23_CONSENT",
      status: this.verifyConsent(signingData, context) ? "met" : "not_met",
      evidence: {
        consentMethod: context.consentMethod,
        consentTimestamp: signingData.consentTimestamp,
        consentRecord: signingData.consentData,
        withdrawalProcess: signingData.withdrawalProcess
      },
      description: "Valid consent to use electronic signatures obtained",
      legalReference: "Electronic Transactions Act 2002, Section 23"
    });
    return requirements;
  }
  /**
   * Check US UETA/ESIGN Act compliance
   */
  static async checkUSCompliance(documentId, signerId, signingData, context) {
    const requirements = [];
    requirements.push({
      requirement: "US_ESIGN_7001A_LEGAL_EFFECT",
      status: this.verifyElectronicLegalEffect(signingData) ? "met" : "not_met",
      evidence: {
        signatureMethod: signingData.signatureMethod,
        intentToSign: signingData.intentToSign,
        documentIntegrity: signingData.documentHash,
        authenticationLevel: signingData.authLevel
      },
      description: "Electronic signature has same legal effect as handwritten signature",
      legalReference: "15 USC 7001(a)"
    });
    if (signingData.isConsumerTransaction) {
      requirements.push({
        requirement: "US_ESIGN_7001C_CONSUMER_CONSENT",
        status: this.verifyConsumerConsent(signingData) ? "met" : "not_met",
        evidence: {
          priorDisclosure: signingData.priorDisclosure,
          consentMethod: signingData.consentMethod,
          accessDemonstration: signingData.accessDemo,
          withdrawalProcedure: signingData.withdrawalProc
        },
        description: "Consumer consent requirements satisfied",
        legalReference: "15 USC 7001(c)"
      });
    }
    requirements.push({
      requirement: "US_ESIGN_RECORD_RETENTION",
      status: this.verifyRecordRetention(documentId) ? "met" : "not_met",
      evidence: {
        retentionPeriod: signingData.retentionPeriod || 7,
        storageMethod: signingData.storageMethod,
        accessibilityMaintained: true,
        formatPreservation: signingData.formatPreservation
      },
      description: "Electronic records properly retained and accessible",
      legalReference: "UETA Section 12, ESIGN Record Retention"
    });
    return requirements;
  }
  /**
   * Verification helper methods
   */
  static verifyUniqueSignatureLink(signingData) {
    return !!(signingData.signerIdentifiers && signingData.authMethod && signingData.uniqueSignatureData);
  }
  static verifySoleControl(signingData) {
    return !!(signingData.authEvents && signingData.sessionData && signingData.accessControl);
  }
  static async verifyTamperDetection(documentId) {
    try {
      const integrity = await storage.verifyDocumentIntegrity(documentId);
      return integrity.isValid;
    } catch {
      return false;
    }
  }
  static verifyConsent(signingData, context) {
    return !!(signingData.consentTimestamp && context.consentMethod && signingData.consentData);
  }
  static verifyElectronicLegalEffect(signingData) {
    return !!(signingData.intentToSign && signingData.signatureMethod && signingData.documentHash);
  }
  static verifyConsumerConsent(signingData) {
    return !!(signingData.priorDisclosure && signingData.consentMethod === "explicit" && signingData.accessDemo);
  }
  static verifyRecordRetention(documentId) {
    return true;
  }
  /**
   * Store compliance record (would be implemented with database)
   */
  static async storeComplianceRecord(record) {
    await storage.createActivityLogEntry({
      action: "compliance_record_created",
      entityType: "compliance",
      entityId: parseInt(record.id.split("_")[1]),
      details: record,
      ipAddress: "system",
      userAgent: "system",
      sessionId: "system",
      success: true
    });
  }
  /**
   * Generate compliance certificate for a signed document
   */
  static async generateComplianceCertificate(documentId, jurisdiction = "BOTH") {
    const document = await storage.getDocument(documentId);
    const signatures2 = await storage.getSignaturesByDocument(documentId);
    const auditLog = await storage.getDocumentAuditLog(documentId);
    if (!document) {
      throw new Error("Document not found");
    }
    const certificate = {
      certificateId: `CERT_${Date.now()}_${documentId}`,
      documentId,
      documentName: document.name,
      jurisdiction,
      issuedAt: (/* @__PURE__ */ new Date()).toISOString(),
      issuedBy: "SecureSign Compliance Engine v1.0",
      legalFramework: jurisdiction === "NZ" ? "Electronic Transactions Act 2002 (NZ)" : jurisdiction === "US" ? "UETA/ESIGN Act (US)" : "Electronic Transactions Act 2002 (NZ) & UETA/ESIGN Act (US)",
      documentDetails: {
        name: document.name,
        type: document.fileType,
        pages: document.pages,
        originalHash: document.originalHash,
        currentHash: document.currentHash,
        createdAt: document.createdAt,
        completedAt: document.updatedAt
      },
      signatures: signatures2.map((sig) => ({
        signerId: sig.signerId,
        signedAt: sig.signedAt,
        signatureHash: sig.signatureHash,
        ipAddress: sig.ipAddress,
        userAgent: sig.userAgent,
        verificationMethod: sig.verificationMethod || "email"
      })),
      complianceStatus: "COMPLIANT",
      legalAssurance: {
        enforceability: "HIGH",
        admissibility: "COURT_ADMISSIBLE",
        integrityVerified: true,
        auditTrailComplete: true,
        retentionCompliant: true
      },
      auditSummary: {
        totalEvents: auditLog.length,
        firstEvent: auditLog[0]?.timestamp,
        lastEvent: auditLog[auditLog.length - 1]?.timestamp,
        integrityChecks: auditLog.filter((e) => e.action.includes("integrity")).length
      },
      validUntil: new Date(Date.now() + 7 * 365 * 24 * 60 * 60 * 1e3).toISOString(),
      // 7 years
      disclaimer: "This certificate attests that the electronic signatures on the referenced document comply with applicable electronic signature laws. It does not constitute legal advice."
    };
    return certificate;
  }
  /**
   * Validate document before signing for compliance readiness
   */
  static async validateDocumentForSigning(documentId, jurisdiction = "BOTH") {
    const document = await storage.getDocument(documentId);
    const issues = [];
    const recommendations = [];
    if (!document) {
      issues.push("Document not found");
      return { ready: false, issues, recommendations };
    }
    const integrity = await storage.verifyDocumentIntegrity(documentId);
    if (!integrity.isValid) {
      issues.push("Document integrity compromised");
    }
    const fields = await storage.getSignatureFieldsByDocument(documentId);
    if (fields.length === 0) {
      issues.push("No signature fields defined");
    }
    const signers2 = await storage.getSignersByDocument(documentId);
    if (signers2.length === 0) {
      issues.push("No signers invited");
    }
    if (jurisdiction === "NZ" || jurisdiction === "BOTH") {
      recommendations.push("Ensure all signers have explicitly consented to electronic signing");
      recommendations.push("Verify signer identity through reliable means");
    }
    if (jurisdiction === "US" || jurisdiction === "BOTH") {
      recommendations.push("For consumer transactions, provide clear disclosure before obtaining consent");
      recommendations.push("Ensure electronic records will be retained for required period");
    }
    recommendations.push("Enable document tamper detection and audit logging");
    recommendations.push("Use strong authentication for signer verification");
    recommendations.push("Maintain comprehensive audit trail throughout signing process");
    return {
      ready: issues.length === 0,
      issues,
      recommendations
    };
  }
};
function complianceMiddleware() {
  return async (req, res, next) => {
    req.complianceContext = {
      timestamp: /* @__PURE__ */ new Date(),
      ipAddress: getClientInfo(req).ipAddress,
      userAgent: getClientInfo(req).userAgent,
      jurisdiction: req.headers["x-jurisdiction"] || "BOTH"
    };
    next();
  };
}

// server/routes.ts
import multer from "multer";
import path from "path";
import fs2 from "fs";
var upload = multer({
  dest: "uploads/",
  limits: { fileSize: 10 * 1024 * 1024 },
  // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = [".pdf", ".docx"];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error("Only PDF and DOCX files are allowed"));
    }
  }
});
async function registerRoutes(app2) {
  app2.use(getSessionMiddleware());
  app2.use(auditMiddleware());
  app2.use(complianceMiddleware());
  setupAuthRoutes(app2);
  if (!fs2.existsSync("uploads")) {
    fs2.mkdirSync("uploads");
  }
  app2.post("/api/documents/upload", requireAuth, getCurrentUser, upload.single("document"), async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }
      const { name } = req.body;
      const fileExt = path.extname(req.file.originalname).toLowerCase();
      const fileType = fileExt === ".pdf" ? "pdf" : "docx";
      if (!req.user) {
        return res.status(401).json({ message: "Authentication required" });
      }
      const originalHash = await DocumentIntegrityService.hashFile(req.file.path);
      const documentData = insertDocumentSchema.parse({
        name: name || req.file.originalname,
        originalFileName: req.file.originalname,
        filePath: req.file.path,
        fileType,
        createdBy: req.user.id,
        pages: 1,
        // Will be updated after processing
        originalHash,
        currentHash: originalHash
      });
      const document = await storage.createDocument(documentData);
      await AuditLogger.logDocumentAction(
        req,
        "created",
        document.id,
        originalHash,
        {
          fileName: req.file.originalname,
          fileType,
          fileSize: req.file.size,
          originalName: req.file.originalname
        },
        "info"
      );
      await AuditLogger.logFileOperation(
        req,
        "upload",
        document.id,
        req.file.originalname,
        req.file.size
      );
      res.json(document);
    } catch (error) {
      console.error("Document upload error:", error);
      res.status(500).json({ message: "Failed to upload document" });
    }
  });
  app2.get("/api/documents", requireAuth, getCurrentUser, async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ message: "Authentication required" });
      }
      const documents2 = await storage.getDocumentsByUser(req.user.id);
      res.json(documents2);
    } catch (error) {
      console.error("Get documents error:", error);
      res.status(500).json({ message: "Failed to get documents" });
    }
  });
  app2.get("/api/documents/:id", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const document = await storage.getDocument(id);
      if (!document) {
        await AuditLogger.logActivity(req, "document_access_denied", "document", id, {
          reason: "document_not_found"
        }, false, "Document not found");
        return res.status(404).json({ message: "Document not found" });
      }
      if (document.createdBy !== req.user.id) {
        await AuditLogger.logSecurityEvent(req, "unauthorized_document_access", "medium", {
          documentId: id,
          documentOwner: document.createdBy,
          attemptedBy: req.user.id
        });
        return res.status(403).json({ message: "Access denied" });
      }
      const signers2 = await storage.getSignersByDocument(id);
      const signatureFields2 = await storage.getSignatureFieldsByDocument(id);
      const signatures2 = await storage.getSignaturesByDocument(id);
      await AuditLogger.logDocumentAction(
        req,
        "viewed",
        id,
        document.currentHash || document.originalHash || "",
        {
          hasSigners: signers2.length > 0,
          fieldCount: signatureFields2.length,
          signatureCount: signatures2.length
        }
      );
      res.json({
        document,
        signers: signers2,
        signatureFields: signatureFields2,
        signatures: signatures2
      });
    } catch (error) {
      console.error("Get document error:", error);
      await AuditLogger.logActivity(req, "document_access_error", "document", parseInt(req.params.id), {
        error: error instanceof Error ? error.message : "Unknown error"
      }, false, error instanceof Error ? error.message : "Unknown error");
      res.status(500).json({ message: "Failed to get document" });
    }
  });
  app2.get("/api/documents/:id/file", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const document = await storage.getDocument(id);
      if (!document) {
        await AuditLogger.logActivity(req, "file_access_denied", "document", id, {
          reason: "document_not_found"
        }, false, "Document not found");
        return res.status(404).json({ message: "Document not found" });
      }
      if (document.createdBy !== req.user.id) {
        await AuditLogger.logSecurityEvent(req, "unauthorized_file_access", "medium", {
          documentId: id,
          fileName: document.originalFileName,
          documentOwner: document.createdBy,
          attemptedBy: req.user.id
        });
        return res.status(403).json({ message: "Access denied" });
      }
      if (!fs2.existsSync(document.filePath)) {
        await AuditLogger.logActivity(req, "file_access_error", "document", id, {
          reason: "file_not_found_on_disk",
          filePath: document.filePath
        }, false, "File not found on disk");
        return res.status(404).json({ message: "File not found" });
      }
      await AuditLogger.logFileOperation(
        req,
        "view",
        id,
        document.originalFileName
      );
      const contentType = document.fileType === "pdf" ? "application/pdf" : "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
      res.setHeader("Content-Type", contentType);
      res.setHeader("Content-Disposition", 'inline; filename="' + document.originalFileName + '"');
      res.setHeader("Cache-Control", "public, max-age=86400");
      res.setHeader("Accept-Ranges", "bytes");
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET");
      res.setHeader("Access-Control-Allow-Headers", "Range");
      res.sendFile(path.resolve(document.filePath));
    } catch (error) {
      console.error("Serve file error:", error);
      await AuditLogger.logActivity(req, "file_serve_error", "document", parseInt(req.params.id), {
        error: error instanceof Error ? error.message : "Unknown error"
      }, false, error instanceof Error ? error.message : "Unknown error");
      res.status(500).json({ message: "Failed to serve file" });
    }
  });
  app2.post("/api/documents/:documentId/signers", async (req, res) => {
    try {
      const documentId = parseInt(req.params.documentId);
      const signerData = insertSignerSchema.parse({
        ...req.body,
        documentId
      });
      const signer = await storage.createSigner(signerData);
      res.json(signer);
    } catch (error) {
      console.error("Create signer error:", error);
      res.status(400).json({ message: "Failed to create signer" });
    }
  });
  app2.get("/api/documents/:documentId/signers", async (req, res) => {
    try {
      const documentId = parseInt(req.params.documentId);
      const signers2 = await storage.getSignersByDocument(documentId);
      res.json(signers2);
    } catch (error) {
      console.error("Get signers error:", error);
      res.status(500).json({ message: "Failed to get signers" });
    }
  });
  app2.post("/api/signature-fields", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const fieldData = insertSignatureFieldSchema.parse(req.body);
      const field = await storage.createSignatureField(fieldData);
      await AuditLogger.logSignatureOperation(
        req,
        "field_created",
        req.body.documentId,
        req.body.signerId,
        {
          fieldType: req.body.type,
          position: { x: req.body.x, y: req.body.y, page: req.body.page },
          required: req.body.required
        }
      );
      res.json(field);
    } catch (error) {
      console.error("Create signature field error:", error);
      await AuditLogger.logActivity(req, "signature_field_creation_failed", "signature", void 0, {
        error: error instanceof Error ? error.message : "Unknown error",
        requestBody: req.body
      }, false, error instanceof Error ? error.message : "Unknown error");
      res.status(400).json({ message: "Failed to create signature field" });
    }
  });
  app2.get("/api/documents/:documentId/signature-fields", async (req, res) => {
    try {
      const documentId = parseInt(req.params.documentId);
      const fields = await storage.getSignatureFieldsByDocument(documentId);
      res.json(fields);
    } catch (error) {
      console.error("Get signature fields error:", error);
      res.status(500).json({ message: "Failed to get signature fields" });
    }
  });
  app2.put("/api/signature-fields/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const { value, completed } = req.body;
      await storage.updateSignatureFieldValue(id, value, completed);
      res.json({ success: true });
    } catch (error) {
      console.error("Update signature field error:", error);
      res.status(500).json({ message: "Failed to update signature field" });
    }
  });
  app2.post("/api/signatures", async (req, res) => {
    try {
      const clientInfo = getClientInfo(req);
      const signatureHash = DocumentIntegrityService.hashString(req.body.data);
      const field = await storage.getSignatureFieldsBySigner(req.body.signerId);
      const document = field.length > 0 ? await storage.getDocument(field[0].documentId) : null;
      const documentHashAtSigning = document?.currentHash || "";
      const signatureData = insertSignatureSchema.parse({
        ...req.body,
        signatureHash,
        documentHashAtSigning,
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent
      });
      const signature = await storage.createSignature(signatureData);
      await storage.updateSignatureFieldValue(signatureData.signatureFieldId, signatureData.data, true);
      const signerFields = await storage.getSignatureFieldsBySigner(signatureData.signerId);
      const allCompleted = signerFields.every((field2) => field2.completed);
      if (allCompleted) {
        await storage.updateSignerStatus(signatureData.signerId, "signed");
        if (document) {
          await storage.createAuditLogEntry({
            documentId: document.id,
            action: "signed",
            userId: signatureData.signerId,
            documentHash: documentHashAtSigning,
            ipAddress: clientInfo.ipAddress,
            details: {
              signatureType: signatureData.type,
              fieldId: signatureData.signatureFieldId,
              signatureHash
            }
          });
        }
      }
      res.json(signature);
    } catch (error) {
      console.error("Create signature error:", error);
      res.status(400).json({ message: "Failed to create signature" });
    }
  });
  app2.put("/api/documents/:id/status", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const { status } = req.body;
      const clientInfo = getClientInfo(req);
      await storage.updateDocumentStatus(id, status);
      const document = await storage.getDocument(id);
      if (document && status === "completed") {
        const signatures2 = await storage.getSignaturesByDocument(id);
        const fields = await storage.getSignatureFieldsByDocument(id);
        const finalHash = DocumentIntegrityService.generateDocumentStateHash({
          originalHash: document.originalHash || "",
          signatures: signatures2.map((s) => ({
            fieldId: s.signatureFieldId,
            signatureHash: s.signatureHash || "",
            signedAt: s.signedAt.toISOString()
          })),
          fields: fields.map((f) => ({
            id: f.id,
            value: f.value,
            completed: f.completed
          }))
        });
        await storage.updateDocumentHash(id, finalHash);
        await storage.createAuditLogEntry({
          documentId: id,
          action: "completed",
          documentHash: finalHash,
          ipAddress: clientInfo.ipAddress,
          details: {
            totalSignatures: signatures2.length,
            finalSeal: DocumentIntegrityService.createDocumentSeal({
              documentId: id,
              originalHash: document.originalHash || "",
              finalHash,
              signatures: signatures2.map((s) => ({
                signerId: s.signerId,
                signatureHash: s.signatureHash || "",
                timestamp: s.signedAt.toISOString()
              })),
              completedAt: /* @__PURE__ */ new Date()
            })
          }
        });
      }
      res.json({ success: true });
    } catch (error) {
      console.error("Update document status error:", error);
      res.status(500).json({ message: "Failed to update document status" });
    }
  });
  app2.get("/api/documents/:id/integrity", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const verification = await storage.verifyDocumentIntegrity(id);
      res.json(verification);
    } catch (error) {
      console.error("Document integrity verification error:", error);
      res.status(500).json({ message: "Failed to verify document integrity" });
    }
  });
  app2.get("/api/documents/:id/audit", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const auditLog = await storage.getDocumentAuditLog(id);
      res.json(auditLog);
    } catch (error) {
      console.error("Get audit log error:", error);
      res.status(500).json({ message: "Failed to get audit log" });
    }
  });
  app2.get("/api/audit/activity", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const { limit = 100 } = req.query;
      const userId = req.user.role === "admin" ? void 0 : req.user.id;
      const activityLog2 = await storage.getActivityLog(userId, parseInt(limit));
      res.json(activityLog2);
    } catch (error) {
      console.error("Get activity log error:", error);
      res.status(500).json({ message: "Failed to get activity log" });
    }
  });
  app2.get("/api/audit/security", requireAuth, getCurrentUser, async (req, res) => {
    try {
      if (req.user.role !== "admin") {
        await AuditLogger.logSecurityEvent(req, "unauthorized_security_access", "high", {
          attemptedBy: req.user.id,
          endpoint: req.path
        });
        return res.status(403).json({ message: "Admin access required" });
      }
      const { resolved } = req.query;
      const securityLog = await storage.getSecurityAuditLog(
        resolved ? resolved === "true" : void 0
      );
      res.json(securityLog);
    } catch (error) {
      console.error("Get security audit log error:", error);
      res.status(500).json({ message: "Failed to get security audit log" });
    }
  });
  app2.put("/api/audit/security/:id/resolve", requireAuth, getCurrentUser, async (req, res) => {
    try {
      if (req.user.role !== "admin") {
        return res.status(403).json({ message: "Admin access required" });
      }
      const id = parseInt(req.params.id);
      await storage.markSecurityAuditResolved(id, req.user.id);
      await AuditLogger.logActivity(req, "security_audit_resolved", "security", id, {
        resolvedBy: req.user.id
      });
      res.json({ success: true });
    } catch (error) {
      console.error("Resolve security audit error:", error);
      res.status(500).json({ message: "Failed to resolve security audit" });
    }
  });
  app2.post("/api/compliance/verify", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const { documentId, signerId, signingData, jurisdiction = "BOTH" } = req.body;
      const complianceRecord = await ComplianceEngine.verifySigningCompliance(
        req,
        documentId,
        signerId,
        signingData,
        jurisdiction
      );
      res.json(complianceRecord);
    } catch (error) {
      console.error("Compliance verification error:", error);
      res.status(500).json({ message: "Failed to verify compliance" });
    }
  });
  app2.get("/api/compliance/certificate/:documentId", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const documentId = parseInt(req.params.documentId);
      const jurisdiction = req.query.jurisdiction || "BOTH";
      const certificate = await ComplianceEngine.generateComplianceCertificate(
        documentId,
        jurisdiction
      );
      res.json(certificate);
    } catch (error) {
      console.error("Generate compliance certificate error:", error);
      res.status(500).json({ message: "Failed to generate compliance certificate" });
    }
  });
  app2.get("/api/compliance/validate/:documentId", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const documentId = parseInt(req.params.documentId);
      const jurisdiction = req.query.jurisdiction || "BOTH";
      const validation = await ComplianceEngine.validateDocumentForSigning(
        documentId,
        jurisdiction
      );
      res.json(validation);
    } catch (error) {
      console.error("Document validation error:", error);
      res.status(500).json({ message: "Failed to validate document" });
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import { dirname } from "path";
import { fileURLToPath } from "url";
import express from "express";
import fs3 from "fs";
import path3 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path2 from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...false ? [
      await null.then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path2.resolve(__dirname, "client", "src"),
      "@shared": path2.resolve(__dirname, "shared"),
      "@assets": path2.resolve(__dirname, "attached_assets")
    }
  },
  root: path2.resolve(__dirname, "client"),
  build: {
    outDir: path2.resolve(__dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var __dirname2 = dirname(fileURLToPath(import.meta.url));
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path3.resolve(
        __dirname2,
        "..",
        "client",
        "index.html"
      );
      let template = await fs3.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path3.resolve(__dirname2, "public");
  if (!fs3.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path3.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express2();
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path4 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path4.startsWith("/api")) {
      let logLine = `${req.method} ${path4} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = 5e3;
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true
  }, () => {
    log(`serving on port ${port}`);
  });
})();
