import React, { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { 
  ZoomIn, 
  ZoomOut, 
  ChevronLeft, 
  ChevronRight, 
  Download,
  FileSignature,
  Type,
  Calendar,
  CheckCircle,
  Clock,
  Pen
} from 'lucide-react';

interface SignatureField {
  id: number;
  type: string;
  page: number;
  x: number;
  y: number;
  width: number;
  height: number;
  value?: string;
  completed: boolean;
  signerId: number;
}

interface Signer {
  id: number;
  name: string;
  email: string;
  status: string;
  order: number;
}

interface ModernPDFViewerProps {
  documentId: number;
  signatureFields: SignatureField[];
  signers: Signer[];
  currentSignerId?: number;
  onFieldClick: (field: SignatureField) => void;
  onPageClick?: (event: React.MouseEvent, page: number) => void;
  isAddingField?: boolean;
  className?: string;
}

export const ModernPDFViewer: React.FC<ModernPDFViewerProps> = ({
  documentId,
  signatureFields,
  signers,
  currentSignerId,
  onFieldClick,
  onPageClick,
  isAddingField = false,
  className = "",
}) => {
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [scale, setScale] = useState(1.2);
  const [loading, setLoading] = useState(true);
  const [pdfToken, setPdfToken] = useState<string | null>(null);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  // Get PDF viewing token
  useEffect(() => {
    const fetchPdfToken = async () => {
      try {
        const response = await fetch(`/api/documents/${documentId}/pdf-token`);
        if (response.ok) {
          const data = await response.json();
          setPdfToken(data.token);
        } else {
          console.error('Failed to get PDF token');
        }
      } catch (error) {
        console.error('Error fetching PDF token:', error);
      }
    };

    fetchPdfToken();
  }, [documentId]);

  const pdfUrl = pdfToken ? 
    `/api/documents/${documentId}/pdf?token=${encodeURIComponent(pdfToken)}` : 
    `/api/documents/${documentId}/pdf`;

  const handlePageClick = (event: React.MouseEvent) => {
    if (isAddingField && onPageClick) {
      const iframe = iframeRef.current;
      if (iframe) {
        const rect = iframe.getBoundingClientRect();
        const x = event.clientX - rect.left;
        const y = event.clientY - rect.top;
        
        // Create a synthetic event with the adjusted coordinates
        const syntheticEvent = {
          ...event,
          currentTarget: iframe,
          clientX: x + rect.left,
          clientY: y + rect.top,
        } as React.MouseEvent;
        
        onPageClick(syntheticEvent, currentPage);
      }
    }
  };

  const getFieldIcon = (type: string) => {
    switch (type) {
      case 'signature':
        return <FileSignature className="h-3 w-3" />;
      case 'text':
        return <Type className="h-3 w-3" />;
      case 'date':
        return <Calendar className="h-3 w-3" />;
      default:
        return <Pen className="h-3 w-3" />;
    }
  };

  const getFieldStyle = (field: SignatureField) => {
    const signer = signers.find(s => s.id === field.signerId);
    const isCurrentUser = field.signerId === currentSignerId;
    const isCompleted = field.completed;
    
    let bgColor = 'bg-blue-100 border-blue-300';
    let textColor = 'text-blue-700';
    
    if (isCompleted) {
      bgColor = 'bg-green-100 border-green-300';
      textColor = 'text-green-700';
    } else if (isCurrentUser) {
      bgColor = 'bg-yellow-100 border-yellow-300';
      textColor = 'text-yellow-700';
    }
    
    return `${bgColor} ${textColor} border-2 border-dashed cursor-pointer hover:opacity-80 transition-opacity`;
  };

  const pageFields = signatureFields.filter(field => field.page === currentPage);

  return (
    <div className={`bg-gray-50 ${className}`}>
      {/* Toolbar */}
      <div className="bg-white border-b border-gray-200 p-4 flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center space-x-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
            disabled={currentPage <= 1}
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
          
          <Badge variant="outline">
            Page {currentPage} of {totalPages}
          </Badge>
          
          <Button
            variant="outline"
            size="sm"
            onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
            disabled={currentPage >= totalPages}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>

        <div className="flex items-center space-x-2">
          <Button variant="outline" size="sm" onClick={() => setScale(Math.max(0.5, scale - 0.2))}>
            <ZoomOut className="h-4 w-4" />
          </Button>
          
          <span className="text-sm font-medium px-2">
            {Math.round(scale * 100)}%
          </span>
          
          <Button variant="outline" size="sm" onClick={() => setScale(Math.min(3, scale + 0.2))}>
            <ZoomIn className="h-4 w-4" />
          </Button>
          
          <Button variant="outline" size="sm">
            <Download className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* PDF Content with Overlay */}
      <div className="relative overflow-auto" style={{ height: 'calc(100vh - 300px)' }}>
        <div 
          className={`relative ${isAddingField ? 'cursor-crosshair' : 'cursor-default'}`}
          onClick={handlePageClick}
          style={{
            transform: `scale(${scale})`,
            transformOrigin: 'top center',
            width: '100%',
            minHeight: '800px',
          }}
        >
          {/* PDF Viewer - Use object tag as fallback for better Chrome compatibility */}
          <object
            data={`${pdfUrl}#page=${currentPage}&zoom=${Math.round(scale * 100)}&view=FitH`}
            type="application/pdf"
            className="w-full h-full border-0"
            style={{ minHeight: '800px' }}
            title={`Document page ${currentPage}`}
            onLoad={() => {
              setLoading(false);
              console.log('PDF object loaded successfully');
            }}
          >
            {/* Fallback iframe if object doesn't work */}
            <iframe
              ref={iframeRef}
              src={`${pdfUrl}#page=${currentPage}&zoom=${Math.round(scale * 100)}&view=FitH`}
              className="w-full h-full border-0"
              style={{ minHeight: '800px' }}
              title={`Document page ${currentPage}`}
              onLoad={() => {
                setLoading(false);
                console.log('PDF iframe loaded successfully');
              }}
              onError={() => {
                console.error('Error loading PDF');
                setLoading(false);
              }}
            >
              {/* Final fallback message */}
              <p className="p-4 text-center">
                Your browser doesn't support PDF viewing. 
                <a href={pdfUrl} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline ml-1">
                  Click here to download the PDF
                </a>
              </p>
            </iframe>
          </object>
          
          {/* Signature Fields Overlay */}
          <div className="absolute inset-0 pointer-events-none">
            {pageFields.map((field) => {
              const adjustedX = field.x * scale;
              const adjustedY = field.y * scale;
              const adjustedWidth = field.width * scale;
              const adjustedHeight = field.height * scale;

              return (
                <div
                  key={field.id}
                  className={`absolute pointer-events-auto ${getFieldStyle(field)}`}
                  style={{
                    left: `${adjustedX}px`,
                    top: `${adjustedY}px`,
                    width: `${adjustedWidth}px`,
                    height: `${adjustedHeight}px`,
                    zIndex: 10,
                  }}
                  onClick={(e) => {
                    e.stopPropagation();
                    onFieldClick(field);
                  }}
                >
                  <div className="flex items-center justify-between h-full p-1 text-xs">
                    <div className="flex items-center space-x-1">
                      {getFieldIcon(field.type)}
                      <span className="truncate">
                        {field.completed ? (
                          field.value || 'Signed'
                        ) : (
                          field.type
                        )}
                      </span>
                    </div>
                    
                    {field.completed && (
                      <CheckCircle className="h-3 w-3 text-green-600" />
                    )}
                    
                    {!field.completed && field.signerId === currentSignerId && (
                      <Clock className="h-3 w-3 text-yellow-600" />
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {loading && (
          <div className="absolute inset-0 flex items-center justify-center bg-white bg-opacity-75">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
              <p className="text-gray-600">Loading PDF document...</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ModernPDFViewer;