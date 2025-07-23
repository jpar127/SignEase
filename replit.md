# SecureSign - Digital Document Signing Platform

## Overview

SecureSign is a full-stack digital document signing application built with modern web technologies. The application allows users to upload documents, add signature fields, invite signers, and complete the signing process electronically. It features a React frontend with TypeScript, an Express.js backend, and uses PostgreSQL with Drizzle ORM for data persistence.

## System Architecture

### Frontend Architecture
- **Framework**: React with TypeScript using Vite as the build tool
- **UI Components**: shadcn/ui component library built on Radix UI primitives
- **Styling**: Tailwind CSS with CSS variables for theming
- **State Management**: TanStack Query (React Query) for server state management
- **Routing**: Wouter for client-side routing
- **Canvas Operations**: Custom signature canvas component for drawing signatures

### Backend Architecture
- **Runtime**: Node.js with Express.js framework
- **Language**: TypeScript with ES modules
- **Development**: tsx for development server with hot reloading
- **File Handling**: Multer for document upload processing
- **Session Management**: Configured for PostgreSQL session storage

### Database Architecture
- **Database**: PostgreSQL with connection pooling via Neon Database
- **ORM**: Drizzle ORM with Drizzle Kit for migrations
- **Schema**: Comprehensive relational schema supporting users, documents, signers, signature fields, and signatures

## Key Components

### Document Management System
- **Upload Processing**: Supports PDF and DOCX file types with 10MB size limit
- **File Storage**: Local file system storage in uploads directory
- **Document Status Tracking**: Draft, pending, completed, and cancelled states
- **Multi-page Support**: Page-based signature field positioning

### Signature Workflow Engine
- **Signer Management**: Order-based sequential signing process
- **Field Types**: Support for signatures, text fields, dates, and initials
- **Signature Methods**: 
  - Hand-drawn signatures via canvas
  - Typed signatures with font styling
  - Uploaded signature images
- **Position Tracking**: Pixel-perfect field positioning on document pages

### User Interface Components
- **Dashboard**: Document overview with status indicators and quick actions
- **Document Viewer**: PDF rendering with signature field overlay
- **Signature Modal**: Multi-tab interface for different signature creation methods
- **Upload Modal**: Drag-and-drop document upload with progress tracking

## Data Flow

### Document Upload Flow
1. User selects document via upload modal
2. Client validates file type and size
3. FormData sent to `/api/documents/upload` endpoint
4. Server processes file with Multer middleware
5. Document metadata stored in database
6. File saved to local uploads directory

### Signing Process Flow
1. Document creator adds signature fields and invites signers
2. Signers receive invitations with document access
3. Each signer completes their assigned fields in order
4. Signature data stored as base64 encoded images
5. Document status updated upon completion

### Data Persistence Layer
- **Users**: Authentication and profile management
- **Documents**: File metadata and status tracking
- **Signers**: Invitation management and signing order
- **Signature Fields**: Positioning and field type definitions
- **Signatures**: Completed signature data storage

## External Dependencies

### Core Framework Dependencies
- React ecosystem (React, React DOM, React Query)
- Express.js with TypeScript support
- Drizzle ORM with PostgreSQL driver

### UI and Styling
- Radix UI primitives for accessible components
- Tailwind CSS for utility-first styling
- Lucide React for consistent iconography

### Development Tools
- Vite for fast development and building
- TypeScript for type safety
- Replit-specific plugins for development environment

### File Processing
- Multer for multipart form handling
- Path utilities for file system operations

## Deployment Strategy

### Development Environment
- **Runtime**: Node.js 20 with Replit modules
- **Database**: PostgreSQL 16 via Replit modules
- **Development Server**: Runs on port 5000 with Vite HMR
- **File Storage**: Local uploads directory (gitignored)

### Production Build Process
1. Vite builds client-side assets to `dist/public`
2. esbuild bundles server code to `dist/index.js`
3. Static assets served from built client bundle
4. Database migrations applied via Drizzle Kit

### Environment Configuration
- **Database URL**: Required environment variable for PostgreSQL connection
- **File Uploads**: Configured for 10MB limit with type restrictions
- **Session Storage**: PostgreSQL-backed sessions for user authentication

## Changelog

```
Changelog:
- June 25, 2025. Initial setup with in-memory storage
- June 25, 2025. Migrated to PostgreSQL database with Drizzle ORM
- June 25, 2025. Added signer invitation modal for multi-party workflow
- June 25, 2025. Implemented cryptographic document integrity verification with SHA-256 hashing, audit trails, and tamper detection
- June 25, 2025. Added comprehensive user authentication system with login/register, session management, and identity verification
- June 25, 2025. Built comprehensive audit trails and logging system with activity logs, security monitoring, and compliance reporting
- June 26, 2025. Added compliance features for NZ Electronic Transactions Act 2002 and US UETA/ESIGN Act with legal validation and certificates
- July 1, 2025. Fixed post-login navigation issue and completed compliance implementation with validation, certificates, and dashboard
- July 21, 2025. Fixed production deployment error (ERR_INVALID_ARG_TYPE paths[0] undefined) by creating custom build script that properly handles import.meta.dirname in Node.js ES modules production builds
- July 21, 2025. Resolved SelectItem React error in audit logs component that was preventing UI components from loading properly
- July 23, 2025. Implemented modern PDF viewer using iframe technology similar to HelloSign with interactive signature field overlays, professional navigation controls, and enhanced document viewing capabilities
```

## User Preferences

```
Preferred communication style: Simple, everyday language.
```