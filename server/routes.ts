import type { Express, Request } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertDocumentSchema, insertSignerSchema, insertSignatureFieldSchema, insertSignatureSchema } from "@shared/schema";
import { DocumentIntegrityService, getClientInfo } from "./crypto-utils";
import { getSessionMiddleware, setupAuthRoutes, requireAuth, getCurrentUser } from "./auth";
import { AuditLogger, auditMiddleware } from "./audit-logger";
import { ComplianceEngine, complianceMiddleware } from "./compliance";
import multer from "multer";
import path from "path";
import fs from "fs";

interface MulterRequest extends Request {
  file?: Express.Multer.File;
}

const upload = multer({ 
  dest: "uploads/",
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
    const allowedTypes = ['.pdf', '.docx'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only PDF and DOCX files are allowed'));
    }
  }
});

export async function registerRoutes(app: Express): Promise<Server> {
  // Session middleware
  app.use(getSessionMiddleware());
  
  // Audit middleware for comprehensive logging
  app.use(auditMiddleware());
  
  // Compliance middleware for legal requirements
  app.use(complianceMiddleware());
  
  // Setup authentication routes
  setupAuthRoutes(app);
  
  // Create uploads directory if it doesn't exist
  if (!fs.existsSync("uploads")) {
    fs.mkdirSync("uploads");
  }

  // Document routes
  app.post("/api/documents/upload", requireAuth, getCurrentUser, upload.single('document'), async (req: MulterRequest, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }

      const { name } = req.body;
      const fileExt = path.extname(req.file.originalname).toLowerCase();
      const fileType = fileExt === '.pdf' ? 'pdf' : 'docx';
      
      // Use authenticated user ID
      if (!req.user) {
        return res.status(401).json({ message: "Authentication required" });
      }

      // Generate hash for document integrity
      const originalHash = await DocumentIntegrityService.hashFile(req.file.path);

      const documentData = insertDocumentSchema.parse({
        name: name || req.file.originalname,
        originalFileName: req.file.originalname,
        filePath: req.file.path,
        fileType,
        createdBy: req.user.id,
        pages: 1, // Will be updated after processing
        originalHash,
        currentHash: originalHash
      });

      const document = await storage.createDocument(documentData);

      // Log document creation with comprehensive audit trail
      await AuditLogger.logDocumentAction(
        req,
        'created',
        document.id,
        originalHash,
        {
          fileName: req.file.originalname,
          fileType,
          fileSize: req.file.size,
          originalName: req.file.originalname
        },
        'info'
      );

      await AuditLogger.logFileOperation(
        req,
        'upload',
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

  app.get("/api/documents", requireAuth, getCurrentUser, async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ message: "Authentication required" });
      }
      
      const documents = await storage.getDocumentsByUser(req.user.id);
      res.json(documents);
    } catch (error) {
      console.error("Get documents error:", error);
      res.status(500).json({ message: "Failed to get documents" });
    }
  });

  app.get("/api/documents/:id", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const document = await storage.getDocument(id);
      
      if (!document) {
        await AuditLogger.logActivity(req, 'document_access_denied', 'document', id, {
          reason: 'document_not_found'
        }, false, 'Document not found');
        return res.status(404).json({ message: "Document not found" });
      }

      // Verify user has access to this document
      if (document.createdBy !== req.user.id) {
        await AuditLogger.logSecurityEvent(req, 'unauthorized_document_access', 'medium', {
          documentId: id,
          documentOwner: document.createdBy,
          attemptedBy: req.user.id
        });
        return res.status(403).json({ message: "Access denied" });
      }

      const signers = await storage.getSignersByDocument(id);
      const signatureFields = await storage.getSignatureFieldsByDocument(id);
      const signatures = await storage.getSignaturesByDocument(id);

      // Log document access
      await AuditLogger.logDocumentAction(
        req,
        'viewed',
        id,
        document.currentHash || document.originalHash || '',
        {
          hasSigners: signers.length > 0,
          fieldCount: signatureFields.length,
          signatureCount: signatures.length
        }
      );

      res.json({
        document,
        signers,
        signatureFields,
        signatures
      });
    } catch (error) {
      console.error("Get document error:", error);
      await AuditLogger.logActivity(req, 'document_access_error', 'document', parseInt(req.params.id), {
        error: error instanceof Error ? error.message : 'Unknown error'
      }, false, error instanceof Error ? error.message : 'Unknown error');
      res.status(500).json({ message: "Failed to get document" });
    }
  });

  // Serve uploaded files with access logging
  app.get("/api/documents/:id/file", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const document = await storage.getDocument(id);
      
      if (!document) {
        await AuditLogger.logActivity(req, 'file_access_denied', 'document', id, {
          reason: 'document_not_found'
        }, false, 'Document not found');
        return res.status(404).json({ message: "Document not found" });
      }

      // Verify user has access to this document
      if (document.createdBy !== req.user.id) {
        await AuditLogger.logSecurityEvent(req, 'unauthorized_file_access', 'medium', {
          documentId: id,
          fileName: document.originalFileName,
          documentOwner: document.createdBy,
          attemptedBy: req.user.id
        });
        return res.status(403).json({ message: "Access denied" });
      }

      if (!fs.existsSync(document.filePath)) {
        await AuditLogger.logActivity(req, 'file_access_error', 'document', id, {
          reason: 'file_not_found_on_disk',
          filePath: document.filePath
        }, false, 'File not found on disk');
        return res.status(404).json({ message: "File not found" });
      }

      // Log file access
      await AuditLogger.logFileOperation(
        req,
        'view',
        id,
        document.originalFileName
      );

      // Set proper headers for PDF viewing
      const contentType = document.fileType === 'pdf' ? 'application/pdf' : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Disposition', 'inline; filename="' + document.originalFileName + '"');
      res.setHeader('Cache-Control', 'public, max-age=86400');
      res.setHeader('Accept-Ranges', 'bytes');
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET');
      res.setHeader('Access-Control-Allow-Headers', 'Range');
      
      res.sendFile(path.resolve(document.filePath));
    } catch (error) {
      console.error("Serve file error:", error);
      await AuditLogger.logActivity(req, 'file_serve_error', 'document', parseInt(req.params.id), {
        error: error instanceof Error ? error.message : 'Unknown error'
      }, false, error instanceof Error ? error.message : 'Unknown error');
      res.status(500).json({ message: "Failed to serve file" });
    }
  });

  // Generate PDF viewing token
  app.get("/api/documents/:id/pdf-token", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const document = await storage.getDocument(id);
      
      if (!document) {
        return res.status(404).json({ message: "Document not found" });
      }

      // Verify user has access to this document
      if (document.createdBy !== req.user.id) {
        return res.status(403).json({ message: "Access denied" });
      }

      // Generate a temporary token (valid for 1 hour)
      const token = Buffer.from(JSON.stringify({
        documentId: id,
        userId: req.user.id,
        expires: Date.now() + 3600000 // 1 hour
      })).toString('base64');

      res.json({ token });
    } catch (error) {
      console.error("Generate PDF token error:", error);
      res.status(500).json({ message: "Failed to generate PDF token" });
    }
  });

  // PDF route with token-based authentication for iframe viewing
  app.get("/api/documents/:id/pdf", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const token = req.query.token as string;
      
      const document = await storage.getDocument(id);
      
      if (!document) {
        return res.status(404).send('Document not found');
      }

      // Verify token if provided, otherwise check session
      let hasAccess = false;
      
      if (token) {
        try {
          const tokenData = JSON.parse(Buffer.from(token, 'base64').toString());
          if (tokenData.documentId === id && 
              tokenData.expires > Date.now() &&
              document.createdBy === tokenData.userId) {
            hasAccess = true;
          }
        } catch (e) {
          // Invalid token, continue to session check
        }
      }
      
      // Fallback to session authentication
      if (!hasAccess && req.session && req.session.userId && document.createdBy === req.session.userId) {
        hasAccess = true;
      }
      
      if (!hasAccess) {
        return res.status(401).send('Authentication required');
      }

      if (!fs.existsSync(document.filePath)) {
        return res.status(404).json({ message: "File not found" });
      }

      // Only serve PDF files through this route
      if (document.fileType !== 'pdf') {
        return res.status(400).json({ message: "This endpoint only serves PDF files" });
      }

      // Set headers that Chrome accepts for iframe embedding
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', 'inline; filename="' + document.originalFileName + '"');
      res.setHeader('Cache-Control', 'public, max-age=86400');
      res.setHeader('Accept-Ranges', 'bytes');
      res.setHeader('X-Frame-Options', 'SAMEORIGIN');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Referrer-Policy', 'same-origin');
      
      res.sendFile(path.resolve(document.filePath));
    } catch (error) {
      console.error("Serve PDF error:", error);
      res.status(500).json({ message: "Failed to serve PDF" });
    }
  });

  // Signer routes
  app.post("/api/documents/:documentId/signers", async (req, res) => {
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

  app.get("/api/documents/:documentId/signers", async (req, res) => {
    try {
      const documentId = parseInt(req.params.documentId);
      const signers = await storage.getSignersByDocument(documentId);
      res.json(signers);
    } catch (error) {
      console.error("Get signers error:", error);
      res.status(500).json({ message: "Failed to get signers" });
    }
  });

  // Signature field routes
  app.post("/api/signature-fields", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const fieldData = insertSignatureFieldSchema.parse(req.body);
      const field = await storage.createSignatureField(fieldData);
      
      // Log signature field creation
      await AuditLogger.logSignatureOperation(
        req,
        'field_created',
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
      await AuditLogger.logActivity(req, 'signature_field_creation_failed', 'signature', undefined, {
        error: error instanceof Error ? error.message : 'Unknown error',
        requestBody: req.body
      }, false, error instanceof Error ? error.message : 'Unknown error');
      res.status(400).json({ message: "Failed to create signature field" });
    }
  });

  app.get("/api/documents/:documentId/signature-fields", async (req, res) => {
    try {
      const documentId = parseInt(req.params.documentId);
      const fields = await storage.getSignatureFieldsByDocument(documentId);
      res.json(fields);
    } catch (error) {
      console.error("Get signature fields error:", error);
      res.status(500).json({ message: "Failed to get signature fields" });
    }
  });

  app.put("/api/signature-fields/:id", async (req, res) => {
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

  // Signature routes
  app.post("/api/signatures", async (req, res) => {
    try {
      const clientInfo = getClientInfo(req);
      
      // Generate signature hash for integrity
      const signatureHash = DocumentIntegrityService.hashString(req.body.data);
      
      // Get current document state for hash
      const field = await storage.getSignatureFieldsBySigner(req.body.signerId);
      const document = field.length > 0 ? await storage.getDocument(field[0].documentId) : null;
      const documentHashAtSigning = document?.currentHash || '';

      const signatureData = insertSignatureSchema.parse({
        ...req.body,
        signatureHash,
        documentHashAtSigning,
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent
      });

      const signature = await storage.createSignature(signatureData);
      
      // Update the signature field as completed
      await storage.updateSignatureFieldValue(signatureData.signatureFieldId, signatureData.data, true);
      
      // Check if all fields for this signer are completed
      const signerFields = await storage.getSignatureFieldsBySigner(signatureData.signerId);
      const allCompleted = signerFields.every(field => field.completed);
      
      if (allCompleted) {
        await storage.updateSignerStatus(signatureData.signerId, "signed");
        
        // Create audit log entry for signature
        if (document) {
          await storage.createAuditLogEntry({
            documentId: document.id,
            action: 'signed',
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

  // Update document status
  app.put("/api/documents/:id/status", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const { status } = req.body;
      const clientInfo = getClientInfo(req);

      await storage.updateDocumentStatus(id, status);

      // Create audit log entry for status change
      const document = await storage.getDocument(id);
      if (document && status === 'completed') {
        // Generate final document hash when completed
        const signatures = await storage.getSignaturesByDocument(id);
        const fields = await storage.getSignatureFieldsByDocument(id);
        
        const finalHash = DocumentIntegrityService.generateDocumentStateHash({
          originalHash: document.originalHash || '',
          signatures: signatures.map(s => ({
            fieldId: s.signatureFieldId,
            signatureHash: s.signatureHash || '',
            signedAt: s.signedAt.toISOString()
          })),
          fields: fields.map(f => ({
            id: f.id,
            value: f.value,
            completed: f.completed
          }))
        });

        await storage.updateDocumentHash(id, finalHash);

        // Create completion audit entry
        await storage.createAuditLogEntry({
          documentId: id,
          action: 'completed',
          documentHash: finalHash,
          ipAddress: clientInfo.ipAddress,
          details: {
            totalSignatures: signatures.length,
            finalSeal: DocumentIntegrityService.createDocumentSeal({
              documentId: id,
              originalHash: document.originalHash || '',
              finalHash,
              signatures: signatures.map(s => ({
                signerId: s.signerId,
                signatureHash: s.signatureHash || '',
                timestamp: s.signedAt.toISOString()
              })),
              completedAt: new Date()
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

  // Document integrity verification endpoint
  app.get("/api/documents/:id/integrity", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const verification = await storage.verifyDocumentIntegrity(id);
      res.json(verification);
    } catch (error) {
      console.error("Document integrity verification error:", error);
      res.status(500).json({ message: "Failed to verify document integrity" });
    }
  });

  // Document audit log endpoint
  app.get("/api/documents/:id/audit", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const auditLog = await storage.getDocumentAuditLog(id);
      res.json(auditLog);
    } catch (error) {
      console.error("Get audit log error:", error);
      res.status(500).json({ message: "Failed to get audit log" });
    }
  });

  // System audit log endpoints
  app.get("/api/audit/activity", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const { limit = 100 } = req.query;
      const userId = req.user.role === 'admin' ? undefined : req.user.id;
      const activityLog = await storage.getActivityLog(userId, parseInt(limit as string));
      res.json(activityLog);
    } catch (error) {
      console.error("Get activity log error:", error);
      res.status(500).json({ message: "Failed to get activity log" });
    }
  });

  app.get("/api/audit/security", requireAuth, getCurrentUser, async (req, res) => {
    try {
      // Only allow admin users to view security audit logs
      if (req.user.role !== 'admin') {
        await AuditLogger.logSecurityEvent(req, 'unauthorized_security_access', 'high', {
          attemptedBy: req.user.id,
          endpoint: req.path
        });
        return res.status(403).json({ message: "Admin access required" });
      }

      const { resolved } = req.query;
      const securityLog = await storage.getSecurityAuditLog(
        resolved ? resolved === 'true' : undefined
      );
      res.json(securityLog);
    } catch (error) {
      console.error("Get security audit log error:", error);
      res.status(500).json({ message: "Failed to get security audit log" });
    }
  });

  app.put("/api/audit/security/:id/resolve", requireAuth, getCurrentUser, async (req, res) => {
    try {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ message: "Admin access required" });
      }

      const id = parseInt(req.params.id);
      await storage.markSecurityAuditResolved(id, req.user.id);
      
      await AuditLogger.logActivity(req, 'security_audit_resolved', 'security', id, {
        resolvedBy: req.user.id
      });

      res.json({ success: true });
    } catch (error) {
      console.error("Resolve security audit error:", error);
      res.status(500).json({ message: "Failed to resolve security audit" });
    }
  });

  // Compliance endpoints
  app.post("/api/compliance/verify", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const { documentId, signerId, signingData, jurisdiction = 'BOTH' } = req.body;
      
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

  app.get("/api/compliance/certificate/:documentId", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const documentId = parseInt(req.params.documentId);
      const jurisdiction = req.query.jurisdiction as string || 'BOTH';
      
      const certificate = await ComplianceEngine.generateComplianceCertificate(
        documentId,
        jurisdiction as 'NZ' | 'US' | 'BOTH'
      );
      
      res.json(certificate);
    } catch (error) {
      console.error("Generate compliance certificate error:", error);
      res.status(500).json({ message: "Failed to generate compliance certificate" });
    }
  });

  app.get("/api/compliance/validate/:documentId", requireAuth, getCurrentUser, async (req, res) => {
    try {
      const documentId = parseInt(req.params.documentId);
      const jurisdiction = req.query.jurisdiction as string || 'BOTH';
      
      const validation = await ComplianceEngine.validateDocumentForSigning(
        documentId,
        jurisdiction as 'NZ' | 'US' | 'BOTH'
      );
      
      res.json(validation);
    } catch (error) {
      console.error("Document validation error:", error);
      res.status(500).json({ message: "Failed to validate document" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
