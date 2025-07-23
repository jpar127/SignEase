import bcrypt from 'bcryptjs';
import session from 'express-session';
import connectPg from 'connect-pg-simple';
import type { Express, Request, Response, NextFunction } from 'express';
import { storage } from './storage';
import { loginSchema, registerSchema } from '@shared/schema';
import { getClientInfo } from './crypto-utils';

// Session configuration
export function getSessionMiddleware() {
  const pgStore = connectPg(session);
  
  return session({
    store: new pgStore({
      conString: process.env.DATABASE_URL,
      createTableIfMissing: true,
      tableName: 'sessions'
    }),
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
  });
}

// Authentication middleware
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  next();
}

// Optional authentication middleware
export function optionalAuth(req: Request, res: Response, next: NextFunction) {
  // Adds user info to request if logged in, but doesn't require it
  next();
}

// Get current user middleware
export async function getCurrentUser(req: Request, res: Response, next: NextFunction) {
  if (req.session.userId) {
    try {
      const user = await storage.getUser(req.session.userId);
      if (user) {
        req.user = user;
      }
    } catch (error) {
      console.error('Error fetching current user:', error);
    }
  }
  next();
}

// Hash password
export async function hashPassword(password: string): Promise<string> {
  const saltRounds = 12;
  return bcrypt.hash(password, saltRounds);
}

// Verify password
export async function verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
  return bcrypt.compare(password, hashedPassword);
}

// Register user
export async function registerUser(userData: any) {
  const validatedData = registerSchema.parse(userData);
  
  // Check if user already exists
  const existingUser = await storage.getUserByEmail(validatedData.email);
  if (existingUser) {
    throw new Error('User already exists with this email');
  }

  const existingUsername = await storage.getUserByUsername(validatedData.username);
  if (existingUsername) {
    throw new Error('Username already taken');
  }

  // Hash password
  const hashedPassword = await hashPassword(validatedData.password);

  // Create user
  const user = await storage.createUser({
    username: validatedData.username,
    email: validatedData.email,
    password: hashedPassword,
    firstName: validatedData.firstName,
    lastName: validatedData.lastName,
    phoneNumber: validatedData.phoneNumber,
  });

  // Remove password from response
  const { password, ...userWithoutPassword } = user;
  return userWithoutPassword;
}

// Login user
export async function loginUser(credentials: any) {
  const validatedCredentials = loginSchema.parse(credentials);
  
  // Find user by email
  const user = await storage.getUserByEmail(validatedCredentials.email);
  if (!user) {
    throw new Error('Invalid email or password');
  }

  // Verify password
  const isValidPassword = await verifyPassword(validatedCredentials.password, user.password);
  if (!isValidPassword) {
    throw new Error('Invalid email or password');
  }

  // Update last login
  await storage.updateUserLastLogin(user.id);

  // Remove password from response
  const { password, ...userWithoutPassword } = user;
  return userWithoutPassword;
}

// Setup authentication routes
export function setupAuthRoutes(app: Express) {
  // Register route
  app.post('/api/auth/register', async (req, res) => {
    try {
      const user = await registerUser(req.body);
      
      // Log in the user immediately after registration
      req.session.userId = user.id;
      
      // Create activity log for registration
      const clientInfo = getClientInfo(req);
      await storage.createActivityLogEntry({
        userId: user.id,
        action: 'register',
        entityType: 'user',
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

      res.status(201).json({ user, message: 'Registration successful' });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(400).json({ 
        message: error instanceof Error ? error.message : 'Registration failed' 
      });
    }
  });

  // Login route
  app.post('/api/auth/login', async (req, res) => {
    try {
      const user = await loginUser(req.body);
      
      // Set session
      req.session.userId = user.id;
      
      // Create activity log for login
      const clientInfo = getClientInfo(req);
      await storage.createActivityLogEntry({
        userId: user.id,
        action: 'login',
        entityType: 'user',
        entityId: user.id,
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent,
        sessionId: req.sessionID,
        success: true,
        details: {
          email: user.email,
          loginMethod: 'password'
        }
      });

      res.json({ user, message: 'Login successful' });
    } catch (error) {
      console.error('Login error:', error);
      
      // Log failed login attempt
      const clientInfo = getClientInfo(req);
      await storage.createActivityLogEntry({
        action: 'failed_login',
        entityType: 'user',
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent,
        sessionId: req.sessionID,
        success: false,
        errorMessage: error instanceof Error ? error.message : 'Login failed',
        details: {
          attemptedEmail: req.body.email
        }
      });

      // Log as security event for multiple failed attempts
      await storage.createSecurityAuditEntry({
        action: 'failed_login_attempt',
        risk_level: 'medium',
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent,
        details: {
          attemptedEmail: req.body.email,
          errorMessage: error instanceof Error ? error.message : 'Login failed'
        }
      });

      res.status(401).json({ 
        message: error instanceof Error ? error.message : 'Login failed' 
      });
    }
  });

  // Logout route
  app.post('/api/auth/logout', async (req, res) => {
    const userId = req.session?.userId;
    
    // Log logout activity
    if (userId) {
      const clientInfo = getClientInfo(req);
      await storage.createActivityLogEntry({
        userId,
        action: 'logout',
        entityType: 'user',
        entityId: userId,
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent,
        sessionId: req.sessionID,
        success: true,
        details: {
          logoutMethod: 'user_initiated'
        }
      });
    }

    req.session.destroy((err) => {
      if (err) {
        console.error('Logout error:', err);
        return res.status(500).json({ message: 'Logout failed' });
      }
      res.clearCookie('connect.sid');
      res.json({ message: 'Logout successful' });
    });
  });

  // Get current user route
  app.get('/api/auth/user', getCurrentUser, (req, res) => {
    if (req.user) {
      const { password, ...userWithoutPassword } = req.user;
      res.json(userWithoutPassword);
    } else {
      res.status(401).json({ message: 'Not authenticated' });
    }
  });

  // Update profile route
  app.put('/api/auth/profile', requireAuth, getCurrentUser, async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ message: 'Not authenticated' });
      }

      const allowedUpdates = ['firstName', 'lastName', 'phoneNumber'];
      const updates: any = {};
      
      for (const field of allowedUpdates) {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];
        }
      }

      const updatedUser = await storage.updateUser(req.user.id, updates);
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.json(userWithoutPassword);
    } catch (error) {
      console.error('Profile update error:', error);
      res.status(500).json({ message: 'Profile update failed' });
    }
  });
}

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      user?: any;
    }
  }
}

declare module 'express-session' {
  interface SessionData {
    userId: number;
  }
}