import { useState, useRef, useEffect } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SignatureCanvas } from "./signature-canvas";
import { Pen, Keyboard, Upload, X, Check, Eraser } from "lucide-react";

interface SignatureModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSignatureComplete: (signatureData: string, type: 'drawn' | 'typed' | 'uploaded') => void;
  field: any;
}

export function SignatureModal({ open, onOpenChange, onSignatureComplete, field }: SignatureModalProps) {
  const [activeTab, setActiveTab] = useState("draw");
  const [typedName, setTypedName] = useState("");
  const [selectedFont, setSelectedFont] = useState("elegant");
  const [uploadedImage, setUploadedImage] = useState<string | null>(null);
  const canvasRef = useRef<any>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) {
      // Reset form when modal closes
      setTypedName("");
      setUploadedImage(null);
      if (canvasRef.current) {
        canvasRef.current.clear();
      }
    }
  }, [open]);

  const handleSaveDrawnSignature = () => {
    if (canvasRef.current) {
      const signatureData = canvasRef.current.getSignatureData();
      if (signatureData) {
        onSignatureComplete(signatureData, 'drawn');
      }
    }
  };

  const handleSaveTypedSignature = () => {
    if (typedName.trim()) {
      // Create a canvas to render the typed signature
      const canvas = document.createElement('canvas');
      canvas.width = 400;
      canvas.height = 100;
      const ctx = canvas.getContext('2d');
      
      if (ctx) {
        ctx.fillStyle = 'white';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        ctx.fillStyle = 'black';
        const fontSize = selectedFont === 'elegant' ? '32px' : selectedFont === 'professional' ? '28px' : '30px';
        const fontFamily = selectedFont === 'elegant' ? 'serif' : selectedFont === 'professional' ? 'sans-serif' : 'cursive';
        const fontStyle = selectedFont === 'elegant' ? 'italic' : selectedFont === 'modern' ? 'italic' : 'normal';
        const fontWeight = selectedFont === 'professional' ? 'bold' : selectedFont === 'elegant' ? 'bold' : 'normal';
        
        ctx.font = `${fontStyle} ${fontWeight} ${fontSize} ${fontFamily}`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(typedName, canvas.width / 2, canvas.height / 2);
        
        const signatureData = canvas.toDataURL();
        onSignatureComplete(signatureData, 'typed');
      }
    }
  };

  const handleSaveUploadedSignature = () => {
    if (uploadedImage) {
      onSignatureComplete(uploadedImage, 'uploaded');
    }
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setUploadedImage(e.target?.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const fonts = [
    { id: 'elegant', name: 'Elegant Script', style: 'font-bold italic text-2xl font-serif' },
    { id: 'professional', name: 'Professional', style: 'font-semibold text-2xl font-sans' },
    { id: 'modern', name: 'Modern Italic', style: 'font-light italic text-2xl font-sans' },
  ];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center space-x-2">
            <Pen className="w-5 h-5" />
            <span>Create Your Signature</span>
          </DialogTitle>
        </DialogHeader>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="draw" className="flex items-center space-x-2">
              <Pen className="w-4 h-4" />
              <span>Draw</span>
            </TabsTrigger>
            <TabsTrigger value="type" className="flex items-center space-x-2">
              <Keyboard className="w-4 h-4" />
              <span>Type</span>
            </TabsTrigger>
            <TabsTrigger value="upload" className="flex items-center space-x-2">
              <Upload className="w-4 h-4" />
              <span>Upload</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="draw" className="space-y-4">
            <p className="text-sm text-gray-600">
              Draw your signature in the box below using your mouse or finger on touch devices.
            </p>
            
            <div className="border-2 border-gray-300 rounded-lg bg-white">
              <SignatureCanvas ref={canvasRef} width={600} height={200} />
            </div>
            
            <div className="flex justify-between">
              <Button
                variant="outline"
                onClick={() => canvasRef.current?.clear()}
              >
                <Eraser className="w-4 h-4 mr-2" />
                Clear
              </Button>
              <div className="flex space-x-2">
                <Button variant="outline" onClick={() => onOpenChange(false)}>
                  Cancel
                </Button>
                <Button onClick={handleSaveDrawnSignature} className="bg-primary hover:bg-blue-700">
                  <Check className="w-4 h-4 mr-2" />
                  Apply Signature
                </Button>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="type" className="space-y-4">
            <p className="text-sm text-gray-600">
              Type your name to create a signature.
            </p>
            
            <div className="space-y-4">
              <Input
                value={typedName}
                onChange={(e) => setTypedName(e.target.value)}
                placeholder="Enter your full name"
                className="text-lg"
              />
              
              <div className="grid grid-cols-1 gap-3">
                {fonts.map((font) => (
                  <div
                    key={font.id}
                    className={`border-2 rounded-lg p-4 cursor-pointer text-center transition-colors ${
                      selectedFont === font.id
                        ? 'border-primary bg-blue-50'
                        : 'border-gray-300 hover:border-primary hover:bg-blue-50'
                    }`}
                    onClick={() => setSelectedFont(font.id)}
                  >
                    <p className={`${font.style} text-gray-800`}>
                      {typedName || 'Your Name Here'}
                    </p>
                    <p className="text-xs text-gray-500 mt-1">{font.name}</p>
                  </div>
                ))}
              </div>
            </div>
            
            <div className="flex justify-between">
              <div></div>
              <div className="flex space-x-2">
                <Button variant="outline" onClick={() => onOpenChange(false)}>
                  Cancel
                </Button>
                <Button
                  onClick={handleSaveTypedSignature}
                  disabled={!typedName.trim()}
                  className="bg-primary hover:bg-blue-700"
                >
                  <Check className="w-4 h-4 mr-2" />
                  Apply Signature
                </Button>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="upload" className="space-y-4">
            <p className="text-sm text-gray-600">
              Upload an image of your signature (PNG, JPG, or GIF format).
            </p>
            
            {uploadedImage ? (
              <div className="border-2 border-gray-300 rounded-lg p-4 text-center">
                <img
                  src={uploadedImage}
                  alt="Uploaded signature"
                  className="max-h-32 mx-auto"
                />
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-2"
                  onClick={() => {
                    setUploadedImage(null);
                    if (fileInputRef.current) {
                      fileInputRef.current.value = '';
                    }
                  }}
                >
                  <X className="w-4 h-4 mr-2" />
                  Remove
                </Button>
              </div>
            ) : (
              <div
                className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-primary hover:bg-blue-50 transition-colors cursor-pointer"
                onClick={() => fileInputRef.current?.click()}
              >
                <Upload className="mx-auto h-12 w-12 text-gray-400 mb-4" />
                <p className="text-gray-600 mb-2">Click to upload or drag and drop</p>
                <p className="text-xs text-gray-500">PNG, JPG, GIF up to 2MB</p>
                <input
                  ref={fileInputRef}
                  type="file"
                  className="hidden"
                  accept="image/*"
                  onChange={handleFileUpload}
                />
              </div>
            )}
            
            <div className="flex justify-between">
              <div></div>
              <div className="flex space-x-2">
                <Button variant="outline" onClick={() => onOpenChange(false)}>
                  Cancel
                </Button>
                <Button
                  onClick={handleSaveUploadedSignature}
                  disabled={!uploadedImage}
                  className="bg-primary hover:bg-blue-700"
                >
                  <Check className="w-4 h-4 mr-2" />
                  Apply Signature
                </Button>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
