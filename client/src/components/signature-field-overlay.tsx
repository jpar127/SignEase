import React from 'react';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { FileSignature, Type, Calendar, CheckCircle, Clock, Pen } from 'lucide-react';

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

interface SignatureFieldOverlayProps {
  fields: SignatureField[];
  currentPage: number;
  signers: Signer[];
  currentSignerId?: number;
  scale: number;
  onFieldClick: (field: SignatureField) => void;
  className?: string;
}

export const SignatureFieldOverlay: React.FC<SignatureFieldOverlayProps> = ({
  fields,
  currentPage,
  signers,
  currentSignerId,
  scale,
  onFieldClick,
  className = "",
}) => {
  const pageFields = fields.filter(field => field.page === currentPage);

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

  const getFieldTitle = (field: SignatureField) => {
    const signer = signers.find(s => s.id === field.signerId);
    const signerName = signer?.name || 'Unknown';
    
    if (field.completed) {
      return `${field.type} - Completed by ${signerName}`;
    } else if (field.signerId === currentSignerId) {
      return `${field.type} - Your field`;
    } else {
      return `${field.type} - Awaiting ${signerName}`;
    }
  };

  return (
    <div className={`absolute inset-0 pointer-events-none ${className}`}>
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
            onClick={() => onFieldClick(field)}
            title={getFieldTitle(field)}
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
  );
};

export default SignatureFieldOverlay;