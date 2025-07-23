import type { Request } from 'express';
import { storage } from './storage';
import { getClientInfo } from './crypto-utils';

export interface AuditContext {
  userId?: number;
  sessionId?: string;
  ipAddress: string;
  userAgent: string;
  timestamp: Date;
}

export class AuditLogger {
  private static getAuditContext(req: Request): AuditContext {
    const clientInfo = getClientInfo(req);
    return {
      userId: req.session?.userId,
      sessionId: req.sessionID,
      ipAddress: clientInfo.ipAddress,
      userAgent: clientInfo.userAgent,
      timestamp: new Date(),
    };
  }

  // Document audit logging
  static async logDocumentAction(
    req: Request,
    action: string,
    documentId: number,
    documentHash: string,
    details?: any,
    severity: string = 'info'
  ) {
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
          timestamp: context.timestamp.toISOString(),
        },
      });
    } catch (error) {
      console.error('Failed to log document audit:', error);
    }
  }

  // Activity logging
  static async logActivity(
    req: Request,
    action: string,
    entityType?: string,
    entityId?: number,
    details?: any,
    success: boolean = true,
    errorMessage?: string
  ) {
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
          timestamp: context.timestamp.toISOString(),
        },
      });
    } catch (error) {
      console.error('Failed to log activity:', error);
    }
  }

  // Security audit logging
  static async logSecurityEvent(
    req: Request,
    action: string,
    riskLevel: string,
    details?: any,
    userId?: number
  ) {
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
          sessionId: context.sessionId,
        },
      });

      // Log critical security events to console immediately
      if (riskLevel === 'critical' || riskLevel === 'high') {
        console.warn(`[SECURITY ALERT] ${action}:`, {
          userId: userId || context.userId,
          ip: context.ipAddress,
          userAgent: context.userAgent,
          details,
        });
      }
    } catch (error) {
      console.error('Failed to log security event:', error);
    }
  }

  // Authentication logging
  static async logAuthentication(
    req: Request,
    action: 'login' | 'logout' | 'register' | 'failed_login',
    userId?: number,
    success: boolean = true,
    errorMessage?: string
  ) {
    const context = this.getAuditContext(req);
    
    // Log to activity log
    await this.logActivity(req, action, 'user', userId, {
      method: req.method,
      path: req.path,
    }, success, errorMessage);

    // Log failed logins as security events
    if (action === 'failed_login') {
      await this.logSecurityEvent(req, 'failed_login_attempt', 'medium', {
        attemptedUserId: userId,
        errorMessage,
      });
    }
  }

  // API access logging
  static async logAPIAccess(
    req: Request,
    endpoint: string,
    method: string,
    statusCode: number,
    responseTime?: number
  ) {
    const context = this.getAuditContext(req);
    const success = statusCode < 400;
    
    await this.logActivity(req, 'api_access', 'system', undefined, {
      endpoint,
      method,
      statusCode,
      responseTime,
      path: req.path,
      query: req.query,
    }, success, statusCode >= 400 ? `HTTP ${statusCode}` : undefined);
  }

  // File operations logging
  static async logFileOperation(
    req: Request,
    action: 'upload' | 'download' | 'view' | 'delete',
    documentId: number,
    fileName: string,
    fileSize?: number
  ) {
    const context = this.getAuditContext(req);
    
    await this.logActivity(req, `file_${action}`, 'document', documentId, {
      fileName,
      fileSize,
      timestamp: context.timestamp.toISOString(),
    });
  }

  // Signature operations logging
  static async logSignatureOperation(
    req: Request,
    action: 'field_created' | 'signature_added' | 'signer_invited' | 'document_completed',
    documentId: number,
    signerId?: number,
    details?: any
  ) {
    const context = this.getAuditContext(req);
    
    await this.logActivity(req, action, 'signature', signerId, {
      documentId,
      ...details,
      timestamp: context.timestamp.toISOString(),
    });
  }

  // Data export logging (for compliance)
  static async logDataExport(
    req: Request,
    exportType: string,
    entityIds: number[],
    requestedBy: number
  ) {
    await this.logActivity(req, 'data_export', 'system', undefined, {
      exportType,
      entityIds,
      requestedBy,
      entityCount: entityIds.length,
    });

    // Log as security event for sensitive exports
    if (exportType === 'user_data' || exportType === 'audit_logs') {
      await this.logSecurityEvent(req, 'sensitive_data_export', 'medium', {
        exportType,
        entityCount: entityIds.length,
        requestedBy,
      });
    }
  }

  // System health monitoring
  static async logSystemEvent(
    action: string,
    severity: string,
    details?: any
  ) {
    try {
      await storage.createActivityLogEntry({
        action: `system_${action}`,
        entityType: 'system',
        ipAddress: 'system',
        userAgent: 'system',
        sessionId: 'system',
        success: severity !== 'error',
        details: {
          ...details,
          timestamp: new Date().toISOString(),
        },
      });
    } catch (error) {
      console.error('Failed to log system event:', error);
    }
  }
}

// Middleware for automatic API logging
export function auditMiddleware() {
  return (req: Request, res: any, next: any) => {
    const startTime = Date.now();
    
    // Log the request
    res.on('finish', () => {
      const responseTime = Date.now() - startTime;
      
      // Only log non-health check endpoints
      if (!req.path.includes('/health') && !req.path.includes('/ping')) {
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