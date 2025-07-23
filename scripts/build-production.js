#!/usr/bin/env node

import { build } from 'esbuild';
import { spawn } from 'child_process';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Step 1: Build the client with Vite
console.log('Building client with Vite...');
const viteBuild = spawn('npx', ['vite', 'build'], { 
  stdio: 'inherit', 
  cwd: join(__dirname, '..') 
});

viteBuild.on('close', async (code) => {
  if (code !== 0) {
    console.error('Vite build failed');
    process.exit(1);
  }

  // Step 2: Build the server with esbuild and proper dirname handling
  console.log('Building server with esbuild...');
  
  // Custom plugin to replace import.meta.dirname with proper __dirname resolution
  const importMetaDirnamePlugin = {
    name: 'import-meta-dirname',
    setup(build) {
      build.onLoad({ filter: /\.ts$|\.js$/ }, async (args) => {
        const fs = await import('fs/promises');
        const contents = await fs.readFile(args.path, 'utf8');
        
        // Replace import.meta.dirname with __dirname
        let transformedContents = contents.replace(
          /import\.meta\.dirname/g,
          '__dirname'
        );
        
        // Add __dirname polyfill at the top of server files that need it
        if (transformedContents.includes('__dirname') && 
            !transformedContents.includes('const __dirname = dirname(fileURLToPath(import.meta.url))') &&
            args.path.includes('server/')) {
          transformedContents = `import { dirname } from 'path';
import { fileURLToPath } from 'url';
const __dirname = dirname(fileURLToPath(import.meta.url));

${transformedContents}`;
        }
        
        return {
          contents: transformedContents,
          loader: args.path.endsWith('.ts') ? 'ts' : 'js',
        };
      });
    },
  };

  try {
    await build({
      entryPoints: ['server/index.ts'],
      platform: 'node',
      packages: 'external',
      bundle: true,
      format: 'esm',
      outdir: 'dist',
      plugins: [importMetaDirnamePlugin],
      define: {
        'process.env.NODE_ENV': '"production"'
      },
    });
    console.log('Production build completed successfully!');
  } catch (error) {
    console.error('Server build failed:', error);
    process.exit(1);
  }
});