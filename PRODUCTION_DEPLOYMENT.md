# Production Deployment Guide

## Issue Resolution

The production deployment was failing with `ERR_INVALID_ARG_TYPE: The "paths[0]" argument must be of type string. Received undefined` because `import.meta.dirname` becomes `undefined` when bundled by esbuild in production builds.

## Solution

Created a custom build script that properly handles ES module path resolution for production:

### 1. Use the Custom Production Build

```bash
# Instead of: npm run build
# Use this command:
node scripts/build-production.js
```

This custom build:
- First builds the client with Vite
- Then builds the server with esbuild using a plugin that replaces `import.meta.dirname` with proper `__dirname` resolution
- Adds necessary path polyfills for Node.js ES modules

### 2. Production Server Startup

After building, start the server with:

```bash
NODE_ENV=production node dist/index.js
```

### 3. PM2 Configuration

Update your PM2 configuration to use the correct build process:

```bash
# Build the application
node scripts/build-production.js

# Start with PM2
pm2 start dist/index.js --name "singease-api" --env NODE_ENV=production
```

### 4. Environment Variables

Ensure these environment variables are set in production:
- `NODE_ENV=production`
- `DATABASE_URL` (your PostgreSQL connection string)
- `SESSION_SECRET` (for session management)
- Any other required environment variables from your .env file

### 5. File Structure After Build

```
dist/
├── index.js          # Server bundle (with fixed path resolution)
└── public/           # Client static files
    ├── index.html
    └── assets/
        ├── index-*.css
        └── index-*.js
```

## Alternative Quick Fix

If you want to use the standard build process, you can manually fix the built file:

1. Run: `npm run build`
2. Edit `dist/index.js` and replace all instances of `import.meta.dirname` with a hardcoded path or use the custom build script above.

## Testing the Fix

To test locally:
```bash
# Build with the custom script
node scripts/build-production.js

# Test the production build (make sure port 5000 is free)
NODE_ENV=production node dist/index.js

# The server should start without the ERR_INVALID_ARG_TYPE error
```

The application should now deploy successfully to your production server without path resolution errors.