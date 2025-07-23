import { dirname } from 'path';
import { fileURLToPath } from 'url';

// Polyfill for import.meta.dirname in production builds
if (typeof import.meta.dirname === 'undefined') {
  import.meta.dirname = dirname(fileURLToPath(import.meta.url));
}

export const __dirname = dirname(fileURLToPath(import.meta.url));