import { pgTable, text, serial, integer, boolean, timestamp, jsonb, varchar, index } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  firstName: text("first_name"),
  lastName: text("last_name"),
  profileImageUrl: text("profile_image_url"),
  emailVerified: boolean("email_verified").default(false),
  phoneNumber: text("phone_number"),
  role: text("role").default("user"), // 'user' | 'admin'
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
  lastLoginAt: timestamp("last_login_at"),
});

// Session storage table for authentication
export const sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull(),
  },
  (table) => [index("IDX_session_expire").on(table.expire)],
);

export const documents = pgTable("documents", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  originalFileName: text("original_file_name").notNull(),
  filePath: text("file_path").notNull(),
  fileType: text("file_type").notNull(), // 'pdf' | 'docx'
  status: text("status").notNull().default("draft"), // 'draft' | 'pending' | 'completed' | 'cancelled'
  createdBy: integer("created_by").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  pages: integer("pages").notNull().default(1),
  originalHash: text("original_hash"), // SHA-256 hash of original document
  currentHash: text("current_hash"), // SHA-256 hash of current document state
  hashAlgorithm: text("hash_algorithm").default("SHA-256"),
});

export const signers = pgTable("signers", {
  id: serial("id").primaryKey(),
  documentId: integer("document_id").notNull(),
  email: text("email").notNull(),
  name: text("name").notNull(),
  order: integer("order").notNull(), // signing order
  status: text("status").notNull().default("pending"), // 'pending' | 'signed' | 'declined'
  signedAt: timestamp("signed_at"),
  invitedAt: timestamp("invited_at").defaultNow().notNull(),
});

export const signatureFields = pgTable("signature_fields", {
  id: serial("id").primaryKey(),
  documentId: integer("document_id").notNull(),
  signerId: integer("signer_id").notNull(),
  type: text("type").notNull(), // 'signature' | 'text' | 'date' | 'initials'
  page: integer("page").notNull(),
  x: integer("x").notNull(),
  y: integer("y").notNull(),
  width: integer("width").notNull(),
  height: integer("height").notNull(),
  value: text("value"), // for text fields or signature data
  required: boolean("required").notNull().default(true),
  completed: boolean("completed").notNull().default(false),
});

export const signatures = pgTable("signatures", {
  id: serial("id").primaryKey(),
  signerId: integer("signer_id").notNull(),
  signatureFieldId: integer("signature_field_id").notNull(),
  type: text("type").notNull(), // 'drawn' | 'typed' | 'uploaded'
  data: text("data").notNull(), // base64 encoded signature image or text
  signedAt: timestamp("signed_at").defaultNow().notNull(),
  signatureHash: text("signature_hash"), // Hash of the signature data
  documentHashAtSigning: text("document_hash_at_signing"), // Document hash when this signature was applied
  ipAddress: text("ip_address"), // IP address of signer for audit trail
  userAgent: text("user_agent"), // Browser/device info for audit trail
});

// Comprehensive audit trail tables
export const documentAuditLog = pgTable("document_audit_log", {
  id: serial("id").primaryKey(),
  documentId: integer("document_id").notNull(),
  action: text("action").notNull(), // 'created' | 'viewed' | 'downloaded' | 'field_added' | 'signed' | 'completed' | 'shared' | 'deleted'
  userId: integer("user_id"),
  details: jsonb("details"), // Additional audit information
  documentHash: text("document_hash").notNull(),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  sessionId: text("session_id"),
  severity: text("severity").default("info"), // 'info' | 'warning' | 'error' | 'critical'
});

// System-wide activity logs
export const activityLog = pgTable("activity_log", {
  id: serial("id").primaryKey(),
  userId: integer("user_id"),
  action: text("action").notNull(), // 'login' | 'logout' | 'register' | 'password_change' | 'profile_update' | 'api_access'
  entityType: text("entity_type"), // 'user' | 'document' | 'signer' | 'signature' | 'system'
  entityId: integer("entity_id"),
  details: jsonb("details"),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  sessionId: text("session_id"),
  success: boolean("success").default(true),
  errorMessage: text("error_message"),
});

// Security audit logs for sensitive operations
export const securityAuditLog = pgTable("security_audit_log", {
  id: serial("id").primaryKey(),
  userId: integer("user_id"),
  action: text("action").notNull(), // 'failed_login' | 'suspicious_activity' | 'permission_escalation' | 'data_breach_attempt'
  risk_level: text("risk_level").notNull(), // 'low' | 'medium' | 'high' | 'critical'
  details: jsonb("details"),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  resolved: boolean("resolved").default(false),
  resolvedBy: integer("resolved_by"),
  resolvedAt: timestamp("resolved_at"),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  email: true,
  password: true,
  firstName: true,
  lastName: true,
  phoneNumber: true,
});

export const loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

export const registerSchema = insertUserSchema.extend({
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

export const insertDocumentSchema = createInsertSchema(documents).pick({
  name: true,
  originalFileName: true,
  filePath: true,
  fileType: true,
  createdBy: true,
  pages: true,
  originalHash: true,
  currentHash: true,
});

export const insertSignerSchema = createInsertSchema(signers).pick({
  documentId: true,
  email: true,
  name: true,
  order: true,
});

export const insertSignatureFieldSchema = createInsertSchema(signatureFields).pick({
  documentId: true,
  signerId: true,
  type: true,
  page: true,
  x: true,
  y: true,
  width: true,
  height: true,
  value: true,
  required: true,
});

export const insertSignatureSchema = createInsertSchema(signatures).pick({
  signerId: true,
  signatureFieldId: true,
  type: true,
  data: true,
  signatureHash: true,
  documentHashAtSigning: true,
  ipAddress: true,
  userAgent: true,
});

export const insertAuditLogSchema = createInsertSchema(documentAuditLog).pick({
  documentId: true,
  action: true,
  userId: true,
  details: true,
  documentHash: true,
  ipAddress: true,
  userAgent: true,
  sessionId: true,
  severity: true,
});

export const insertActivityLogSchema = createInsertSchema(activityLog).pick({
  userId: true,
  action: true,
  entityType: true,
  entityId: true,
  details: true,
  ipAddress: true,
  userAgent: true,
  sessionId: true,
  success: true,
  errorMessage: true,
});

export const insertSecurityAuditSchema = createInsertSchema(securityAuditLog).pick({
  userId: true,
  action: true,
  risk_level: true,
  details: true,
  ipAddress: true,
  userAgent: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

export type InsertDocument = z.infer<typeof insertDocumentSchema>;
export type Document = typeof documents.$inferSelect;

export type InsertSigner = z.infer<typeof insertSignerSchema>;
export type Signer = typeof signers.$inferSelect;

export type InsertSignatureField = z.infer<typeof insertSignatureFieldSchema>;
export type SignatureField = typeof signatureFields.$inferSelect;

export type InsertSignature = z.infer<typeof insertSignatureSchema>;
export type Signature = typeof signatures.$inferSelect;

export type InsertAuditLog = z.infer<typeof insertAuditLogSchema>;
export type DocumentAuditLog = typeof documentAuditLog.$inferSelect;

export type InsertActivityLog = z.infer<typeof insertActivityLogSchema>;
export type ActivityLog = typeof activityLog.$inferSelect;

export type InsertSecurityAudit = z.infer<typeof insertSecurityAuditSchema>;
export type SecurityAuditLog = typeof securityAuditLog.$inferSelect;

// Compliance records for electronic signature law adherence
export const complianceRecords = pgTable("compliance_records", {
  id: varchar("id", { length: 100 }).primaryKey(), // UUID
  documentId: integer("document_id").references(() => documents.id).notNull(),
  jurisdiction: varchar("jurisdiction", { length: 10 }).notNull(), // NZ, US, BOTH
  legalFramework: varchar("legal_framework", { length: 100 }).notNull(), // NZ_ETA_2002, US_ESIGN_ACT
  status: varchar("status", { length: 20 }).notNull(), // compliant, non_compliant, pending_verification
  requirements: jsonb("requirements").notNull(), // Array of compliance requirements and their status
  evidencePackage: jsonb("evidence_package").notNull(), // All evidence supporting compliance
  verificationDate: timestamp("verification_date").defaultNow().notNull(),
  validityPeriod: integer("validity_period").notNull(), // Years the compliance is valid
  certificateData: jsonb("certificate_data"), // Generated compliance certificate
  createdBy: integer("created_by").references(() => users.id).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Signing intent records for demonstrating user consent and intent
export const signingIntent = pgTable("signing_intent", {
  id: serial("id").primaryKey(),
  signerId: integer("signer_id").references(() => signers.id).notNull(),
  documentId: integer("document_id").references(() => documents.id).notNull(),
  intentToSign: boolean("intent_to_sign").notNull(),
  consentToElectronic: boolean("consent_to_electronic").notNull(),
  identityVerified: boolean("identity_verified").notNull(),
  accessMethod: varchar("access_method", { length: 100 }).notNull(), // email_link, direct_access, etc
  evidenceData: jsonb("evidence_data").notNull(), // IP, timestamp, user agent, etc
  timestamp: timestamp("timestamp").defaultNow().notNull(),
});

export type InsertComplianceRecord = typeof complianceRecords.$inferInsert;
export type ComplianceRecord = typeof complianceRecords.$inferSelect;

export type InsertSigningIntent = typeof signingIntent.$inferInsert;
export type SigningIntent = typeof signingIntent.$inferSelect;
