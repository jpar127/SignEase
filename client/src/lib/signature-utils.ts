// Utility functions for signature handling

export interface SignatureData {
  type: 'drawn' | 'typed' | 'uploaded';
  data: string; // base64 encoded image
  timestamp: Date;
}

export function createTypedSignature(
  name: string,
  fontStyle: 'elegant' | 'professional' | 'modern' = 'elegant'
): string {
  const canvas = document.createElement('canvas');
  canvas.width = 400;
  canvas.height = 100;
  const ctx = canvas.getContext('2d');

  if (!ctx) throw new Error('Canvas context not available');

  // Set background
  ctx.fillStyle = 'white';
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Configure font based on style
  ctx.fillStyle = 'black';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';

  switch (fontStyle) {
    case 'elegant':
      ctx.font = 'italic bold 32px serif';
      break;
    case 'professional':
      ctx.font = 'bold 28px sans-serif';
      break;
    case 'modern':
      ctx.font = 'italic 30px cursive';
      break;
  }

  // Draw the signature
  ctx.fillText(name, canvas.width / 2, canvas.height / 2);

  return canvas.toDataURL();
}

export function resizeSignature(
  signatureDataUrl: string,
  width: number,
  height: number
): Promise<string> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d');

      if (!ctx) {
        reject(new Error('Canvas context not available'));
        return;
      }

      // Clear background
      ctx.fillStyle = 'transparent';
      ctx.fillRect(0, 0, width, height);

      // Draw resized signature
      ctx.drawImage(img, 0, 0, width, height);

      resolve(canvas.toDataURL());
    };
    img.onerror = () => reject(new Error('Failed to load signature image'));
    img.src = signatureDataUrl;
  });
}

export function validateSignatureData(data: string): boolean {
  // Basic validation for base64 image data
  const base64Pattern = /^data:image\/(png|jpeg|jpg|gif);base64,/;
  return base64Pattern.test(data);
}

export function extractSignatureBounds(signatureDataUrl: string): Promise<{
  width: number;
  height: number;
  hasContent: boolean;
}> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');

      if (!ctx) {
        reject(new Error('Canvas context not available'));
        return;
      }

      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const data = imageData.data;

      // Check if there's any non-transparent pixel
      let hasContent = false;
      for (let i = 3; i < data.length; i += 4) {
        if (data[i] > 0) { // Alpha channel
          hasContent = true;
          break;
        }
      }

      resolve({
        width: img.width,
        height: img.height,
        hasContent,
      });
    };
    img.onerror = () => reject(new Error('Failed to load signature image'));
    img.src = signatureDataUrl;
  });
}
