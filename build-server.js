import { build } from 'esbuild';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Custom plugin to replace import.meta.dirname with proper __dirname resolution
const importMetaDirnamePlugin = {
  name: 'import-meta-dirname',
  setup(build) {
    build.onLoad({ filter: /\.ts$|\.js$/ }, async (args) => {
      const fs = await import('fs/promises');
      const contents = await fs.readFile(args.path, 'utf8');
      
      // Replace import.meta.dirname with proper __dirname resolution
      const transformedContents = contents.replace(
        /import\.meta\.dirname/g,
        '__dirname'
      );
      
      // Add __dirname polyfill at the top of the file if needed
      let finalContents = transformedContents;
      if (transformedContents.includes('__dirname') && !transformedContents.includes('import { dirname }')) {
        finalContents = `import { dirname } from 'path';
import { fileURLToPath } from 'url';
const __dirname = dirname(fileURLToPath(import.meta.url));

${transformedContents}`;
      }
      
      return {
        contents: finalContents,
        loader: 'ts',
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
  });
  console.log('Server built successfully');
} catch (error) {
  console.error('Build failed:', error);
  process.exit(1);
}