import React, { useEffect, useRef, useState, useCallback } from 'react';
import * as pdfjs from 'pdfjs-dist';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ZoomIn, ZoomOut, RotateCw, Download, ChevronLeft, ChevronRight } from 'lucide-react';

// Configure PDF.js worker with local fallback
pdfjs.GlobalWorkerOptions.workerSrc = new URL(
  'pdfjs-dist/build/pdf.worker.min.js',
  import.meta.url
).toString();

interface PDFViewerProps {
  url: string;
  onPageChange?: (page: number, totalPages: number) => void;
  onLoad?: (totalPages: number) => void;
  className?: string;
}

interface PDFPageProps {
  page: pdfjs.PDFPageProxy;
  scale: number;
  rotation: number;
  onRender?: () => void;
}

const PDFPage: React.FC<PDFPageProps> = ({ page, scale, rotation, onRender }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const renderPage = async () => {
      if (!canvasRef.current || !page) return;

      const canvas = canvasRef.current;
      const context = canvas.getContext('2d');
      if (!context) return;

      const viewport = page.getViewport({ scale, rotation });
      canvas.height = viewport.height;
      canvas.width = viewport.width;

      const renderContext = {
        canvasContext: context,
        viewport: viewport,
      };

      try {
        await page.render(renderContext).promise;
        onRender?.();
      } catch (error) {
        console.error('Error rendering PDF page:', error);
      }
    };

    renderPage();
  }, [page, scale, rotation, onRender]);

  return (
    <canvas
      ref={canvasRef}
      className="border border-gray-200 shadow-sm mx-auto block"
      style={{ maxWidth: '100%', height: 'auto' }}
    />
  );
};

export const PDFViewer: React.FC<PDFViewerProps> = ({
  url,
  onPageChange,
  onLoad,
  className = "",
}) => {
  const [pdf, setPdf] = useState<pdfjs.PDFDocumentProxy | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(0);
  const [scale, setScale] = useState(1.2);
  const [rotation, setRotation] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [currentPageProxy, setCurrentPageProxy] = useState<pdfjs.PDFPageProxy | null>(null);

  // Load PDF document
  useEffect(() => {
    const loadPDF = async () => {
      try {
        setLoading(true);
        setError(null);
        
        const loadingTask = pdfjs.getDocument(url);
        const pdfDocument = await loadingTask.promise;
        
        setPdf(pdfDocument);
        setTotalPages(pdfDocument.numPages);
        onLoad?.(pdfDocument.numPages);
        
        // Load first page
        const page = await pdfDocument.getPage(1);
        setCurrentPageProxy(page);
        
        setLoading(false);
      } catch (err) {
        console.error('Error loading PDF:', err);
        setError('Failed to load PDF document');
        setLoading(false);
      }
    };

    if (url) {
      loadPDF();
    }
  }, [url, onLoad]);

  // Load specific page
  const loadPage = useCallback(async (pageNumber: number) => {
    if (!pdf || pageNumber < 1 || pageNumber > totalPages) return;
    
    try {
      const page = await pdf.getPage(pageNumber);
      setCurrentPageProxy(page);
      setCurrentPage(pageNumber);
      onPageChange?.(pageNumber, totalPages);
    } catch (err) {
      console.error('Error loading page:', err);
    }
  }, [pdf, totalPages, onPageChange]);

  // Navigation handlers
  const goToPreviousPage = () => {
    if (currentPage > 1) {
      loadPage(currentPage - 1);
    }
  };

  const goToNextPage = () => {
    if (currentPage < totalPages) {
      loadPage(currentPage + 1);
    }
  };

  // Zoom handlers
  const zoomIn = () => setScale(prev => Math.min(prev + 0.2, 3));
  const zoomOut = () => setScale(prev => Math.max(prev - 0.2, 0.5));

  // Rotation handler
  const rotate = () => setRotation(prev => (prev + 90) % 360);

  // Download handler
  const downloadPDF = () => {
    const link = document.createElement('a');
    link.href = url;
    link.download = 'document.pdf';
    link.click();
  };

  if (loading) {
    return (
      <div className={`flex items-center justify-center p-8 ${className}`}>
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading PDF document...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`flex items-center justify-center p-8 ${className}`}>
        <Card className="p-6 max-w-md">
          <div className="text-center">
            <div className="text-red-600 mb-4">
              <svg className="h-12 w-12 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.96-.833-2.73 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
            </div>
            <h3 className="text-lg font-medium text-gray-900 mb-2">Failed to load PDF</h3>
            <p className="text-gray-600">{error}</p>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className={`bg-gray-50 ${className}`}>
      {/* Toolbar */}
      <div className="bg-white border-b border-gray-200 p-4 flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center space-x-2">
          <Button
            variant="outline"
            size="sm"
            onClick={goToPreviousPage}
            disabled={currentPage <= 1}
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
          
          <span className="text-sm font-medium px-3 py-1 bg-gray-100 rounded">
            {currentPage} of {totalPages}
          </span>
          
          <Button
            variant="outline"
            size="sm"
            onClick={goToNextPage}
            disabled={currentPage >= totalPages}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>

        <div className="flex items-center space-x-2">
          <Button variant="outline" size="sm" onClick={zoomOut}>
            <ZoomOut className="h-4 w-4" />
          </Button>
          
          <span className="text-sm font-medium px-2">
            {Math.round(scale * 100)}%
          </span>
          
          <Button variant="outline" size="sm" onClick={zoomIn}>
            <ZoomIn className="h-4 w-4" />
          </Button>
          
          <Button variant="outline" size="sm" onClick={rotate}>
            <RotateCw className="h-4 w-4" />
          </Button>
          
          <Button variant="outline" size="sm" onClick={downloadPDF}>
            <Download className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* PDF Content */}
      <div className="p-6 overflow-auto" style={{ height: 'calc(100vh - 200px)' }}>
        {currentPageProxy && (
          <div className="flex justify-center">
            <PDFPage
              page={currentPageProxy}
              scale={scale}
              rotation={rotation}
              onRender={() => console.log(`Page ${currentPage} rendered`)}
            />
          </div>
        )}
      </div>
    </div>
  );
};

export default PDFViewer;