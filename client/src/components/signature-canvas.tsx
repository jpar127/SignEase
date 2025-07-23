import { useRef, useEffect, forwardRef, useImperativeHandle } from "react";

interface SignatureCanvasProps {
  width: number;
  height: number;
  className?: string;
}

export interface SignatureCanvasRef {
  clear: () => void;
  getSignatureData: () => string | null;
}

export const SignatureCanvas = forwardRef<SignatureCanvasRef, SignatureCanvasProps>(
  ({ width, height, className }, ref) => {
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const isDrawingRef = useRef(false);
    const hasContentRef = useRef(false);

    useImperativeHandle(ref, () => ({
      clear: () => {
        const canvas = canvasRef.current;
        if (canvas) {
          const ctx = canvas.getContext('2d');
          if (ctx) {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            hasContentRef.current = false;
          }
        }
      },
      getSignatureData: () => {
        const canvas = canvasRef.current;
        if (canvas && hasContentRef.current) {
          return canvas.toDataURL();
        }
        return null;
      },
    }));

    useEffect(() => {
      const canvas = canvasRef.current;
      if (!canvas) return;

      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      // Set up canvas for smooth drawing
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      ctx.strokeStyle = '#000000';
      ctx.lineWidth = 2;

      const getCoordinates = (event: MouseEvent | TouchEvent) => {
        const rect = canvas.getBoundingClientRect();
        const scaleX = canvas.width / rect.width;
        const scaleY = canvas.height / rect.height;

        if (event instanceof MouseEvent) {
          return {
            x: (event.clientX - rect.left) * scaleX,
            y: (event.clientY - rect.top) * scaleY,
          };
        } else {
          const touch = event.touches[0];
          return {
            x: (touch.clientX - rect.left) * scaleX,
            y: (touch.clientY - rect.top) * scaleY,
          };
        }
      };

      const startDrawing = (event: MouseEvent | TouchEvent) => {
        event.preventDefault();
        isDrawingRef.current = true;
        const { x, y } = getCoordinates(event);
        ctx.beginPath();
        ctx.moveTo(x, y);
      };

      const draw = (event: MouseEvent | TouchEvent) => {
        if (!isDrawingRef.current) return;
        event.preventDefault();
        
        const { x, y } = getCoordinates(event);
        ctx.lineTo(x, y);
        ctx.stroke();
        hasContentRef.current = true;
      };

      const stopDrawing = () => {
        if (isDrawingRef.current) {
          isDrawingRef.current = false;
          ctx.closePath();
        }
      };

      // Mouse events
      canvas.addEventListener('mousedown', startDrawing);
      canvas.addEventListener('mousemove', draw);
      canvas.addEventListener('mouseup', stopDrawing);
      canvas.addEventListener('mouseout', stopDrawing);

      // Touch events for mobile
      canvas.addEventListener('touchstart', startDrawing);
      canvas.addEventListener('touchmove', draw);
      canvas.addEventListener('touchend', stopDrawing);

      return () => {
        canvas.removeEventListener('mousedown', startDrawing);
        canvas.removeEventListener('mousemove', draw);
        canvas.removeEventListener('mouseup', stopDrawing);
        canvas.removeEventListener('mouseout', stopDrawing);
        canvas.removeEventListener('touchstart', startDrawing);
        canvas.removeEventListener('touchmove', draw);
        canvas.removeEventListener('touchend', stopDrawing);
      };
    }, []);

    return (
      <canvas
        ref={canvasRef}
        width={width}
        height={height}
        className={`border-0 cursor-crosshair ${className || ''}`}
        style={{ touchAction: 'none' }}
      />
    );
  }
);

SignatureCanvas.displayName = 'SignatureCanvas';
