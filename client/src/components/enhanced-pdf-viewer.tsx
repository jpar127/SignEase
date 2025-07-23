import React, { useState, useRef, useEffect } from 'react';
import PDFViewer from './pdf-viewer';
import SignatureFieldOverlay from './signature-field-overlay';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ZoomIn, ZoomOut, RotateCw, ChevronLeft, ChevronRight } from 'lucide-react';

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

interface EnhancedPDFViewerProps {
  documentId: number;
  documentUrl: string;
  signatureFields: SignatureField[];
  signers: Signer[];
  currentSignerId?: number;
  onFieldClick: (field: SignatureField) => void;
  onPageClick?: (event: React.MouseEvent, page: number) => void;
  isAddingField?: boolean;
  className?: string;
}

export const EnhancedPDFViewer: React.FC<EnhancedPDFViewerProps> = ({
  documentId,
  documentUrl,
  signatureFields,
  signers,
  currentSignerId,
  onFieldClick,
  onPageClick,
  isAddingField = false,
  className = "",
}) => {
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(0);
  const [scale, setScale] = useState(1.2);
  const containerRef = useRef<HTMLDivElement>(null);

  const handlePageClick = (event: React.MouseEvent) => {
    if (isAddingField && onPageClick) {
      onPageClick(event, currentPage);
    }
  };

  return (
    <div className={`relative bg-gray-50 ${className}`}>
      {/* Enhanced toolbar */}
      <div className="bg-white border-b border-gray-200 p-4 flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <Badge variant="outline">
            Page {currentPage} of {totalPages}
          </Badge>
          {isAddingField && (
            <Badge className="bg-blue-100 text-blue-800">
              Click to place field
            </Badge>
          )}
        </div>
        
        <div className="flex items-center space-x-2">
          <span className="text-sm text-gray-600">
            {Math.round(scale * 100)}%
          </span>
        </div>
      </div>

      {/* PDF container with overlay */}
      <div 
        ref={containerRef}
        className={`relative ${isAddingField ? 'cursor-crosshair' : 'cursor-default'}`}
        onClick={handlePageClick}
      >
        <PDFViewer
          url={documentUrl}
          onPageChange={(page, total) => {
            setCurrentPage(page);
            setTotalPages(total);
          }}
          onLoad={(total) => {
            setTotalPages(total);
          }}
          className="w-full"
        />
        
        {/* Signature fields overlay */}
        <SignatureFieldOverlay
          fields={signatureFields}
          currentPage={currentPage}
          signers={signers}
          currentSignerId={currentSignerId}
          scale={scale}
          onFieldClick={onFieldClick}
        />
      </div>
    </div>
  );
};

export default EnhancedPDFViewer;