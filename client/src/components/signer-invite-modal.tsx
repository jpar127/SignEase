import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { UserPlus, X, Plus, Mail } from "lucide-react";

interface SignerInviteModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  documentId: number;
  onInviteComplete: () => void;
}

interface SignerData {
  name: string;
  email: string;
  order: number;
}

export function SignerInviteModal({ open, onOpenChange, documentId, onInviteComplete }: SignerInviteModalProps) {
  const [signers, setSigners] = useState<SignerData[]>([
    { name: "", email: "", order: 1 }
  ]);
  const { toast } = useToast();

  const inviteSignersMutation = useMutation({
    mutationFn: async (signerData: SignerData[]) => {
      const promises = signerData.map(signer => 
        apiRequest("POST", `/api/documents/${documentId}/signers`, signer)
      );
      await Promise.all(promises);
    },
    onSuccess: () => {
      toast({
        title: "Signers invited successfully",
        description: "All signers have been added to the document.",
      });
      onInviteComplete();
      resetForm();
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to invite signers",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const resetForm = () => {
    setSigners([{ name: "", email: "", order: 1 }]);
  };

  const addSigner = () => {
    setSigners([...signers, { name: "", email: "", order: signers.length + 1 }]);
  };

  const removeSigner = (index: number) => {
    if (signers.length > 1) {
      const newSigners = signers.filter((_, i) => i !== index);
      // Update order numbers
      const reorderedSigners = newSigners.map((signer, i) => ({
        ...signer,
        order: i + 1
      }));
      setSigners(reorderedSigners);
    }
  };

  const updateSigner = (index: number, field: keyof SignerData, value: string | number) => {
    const newSigners = [...signers];
    newSigners[index] = { ...newSigners[index], [field]: value };
    setSigners(newSigners);
  };

  const handleInvite = () => {
    const validSigners = signers.filter(s => s.name.trim() && s.email.trim());
    if (validSigners.length === 0) {
      toast({
        title: "No valid signers",
        description: "Please add at least one signer with name and email.",
        variant: "destructive",
      });
      return;
    }
    inviteSignersMutation.mutate(validSigners);
  };

  const handleClose = () => {
    if (!inviteSignersMutation.isPending) {
      onOpenChange(false);
      resetForm();
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center space-x-2">
            <UserPlus className="w-5 h-5" />
            <span>Invite Signers</span>
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-6">
          <p className="text-sm text-gray-600">
            Add people who need to sign this document. They will sign in the order you specify.
          </p>

          <div className="space-y-4">
            {signers.map((signer, index) => (
              <div key={index} className="border rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="font-medium text-gray-900">
                    Signer {index + 1}
                  </h4>
                  {signers.length > 1 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => removeSigner(index)}
                    >
                      <X className="w-4 h-4" />
                    </Button>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="space-y-2">
                    <Label htmlFor={`name-${index}`}>Full Name</Label>
                    <Input
                      id={`name-${index}`}
                      value={signer.name}
                      onChange={(e) => updateSigner(index, 'name', e.target.value)}
                      placeholder="Enter full name"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor={`email-${index}`}>Email Address</Label>
                    <Input
                      id={`email-${index}`}
                      type="email"
                      value={signer.email}
                      onChange={(e) => updateSigner(index, 'email', e.target.value)}
                      placeholder="Enter email address"
                    />
                  </div>
                </div>

                <div className="text-xs text-gray-500">
                  Signing order: {signer.order}
                </div>
              </div>
            ))}
          </div>

          <Button
            variant="outline"
            onClick={addSigner}
            className="w-full border-dashed"
          >
            <Plus className="w-4 h-4 mr-2" />
            Add Another Signer
          </Button>

          <div className="flex justify-end space-x-3 pt-4 border-t">
            <Button
              variant="outline"
              onClick={handleClose}
              disabled={inviteSignersMutation.isPending}
            >
              Cancel
            </Button>
            <Button
              onClick={handleInvite}
              disabled={inviteSignersMutation.isPending}
              className="bg-primary hover:bg-blue-700"
            >
              {inviteSignersMutation.isPending ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Inviting...
                </>
              ) : (
                <>
                  <Mail className="w-4 h-4 mr-2" />
                  Invite Signers
                </>
              )}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}