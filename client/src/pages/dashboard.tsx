import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DocumentUploadModal } from "@/components/document-upload-modal";
import { FileSignature, Plus, FileText, Clock, CheckCircle, Users, LogOut, User, Shield } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";

interface Document {
  id: number;
  name: string;
  status: string;
  createdAt: string;
  pages: number;
}

export default function Dashboard() {
  const [showUploadModal, setShowUploadModal] = useState(false);
  const { user, logout } = useAuth();
  const { toast } = useToast();

  const { data: documents = [], isLoading, refetch, error } = useQuery<Document[]>({
    queryKey: ["/api/documents"],
  });

  // Debug logging for troubleshooting
  console.log("Dashboard state:", { 
    documents: documents?.length, 
    isLoading, 
    error: error?.message,
    user: user?.username 
  });

  const handleLogout = async () => {
    try {
      await logout();
      toast({
        title: "Logged out",
        description: "You have been successfully logged out.",
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to log out. Please try again.",
        variant: "destructive",
      });
    }
  };



  const getStatusBadge = (status: string) => {
    switch (status) {
      case "completed":
        return <Badge className="bg-green-100 text-green-800"><CheckCircle className="w-3 h-3 mr-1" />Completed</Badge>;
      case "pending":
        return <Badge className="bg-yellow-100 text-yellow-800"><Clock className="w-3 h-3 mr-1" />Pending</Badge>;
      case "draft":
        return <Badge variant="secondary"><FileText className="w-3 h-3 mr-1" />Draft</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <FileSignature className="h-8 w-8 text-primary" />
                <span className="text-xl font-bold text-gray-900">SecureSign</span>
              </div>
              <nav className="hidden md:flex space-x-8 ml-8">
                <Link href="/" className="text-primary font-medium border-b-2 border-primary pb-4">Documents</Link>
                <Link href="/audit-logs" className="text-gray-500 hover:text-gray-700 pb-4">Audit Logs</Link>
                <a href="#" className="text-gray-500 hover:text-gray-700 pb-4">Compliance</a>
                <a href="#" className="text-gray-500 hover:text-gray-700 pb-4">Team</a>
              </nav>
            </div>
            <div className="flex items-center space-x-4">
              <Button onClick={() => setShowUploadModal(true)} className="bg-primary hover:bg-blue-700">
                <Plus className="w-4 h-4 mr-2" />
                New Document
              </Button>
              <div className="relative">
                <button className="flex items-center space-x-2 bg-gray-100 rounded-full p-2 hover:bg-gray-200 transition-colors">
                  <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center text-white text-sm font-medium">
                    JD
                  </div>
                </button>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-gray-900 mb-2">My Documents</h1>
          <p className="text-gray-600">Manage your documents and signature requests</p>
        </div>

        {/* Documents Grid */}
        {isLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[...Array(6)].map((_, i) => (
              <Card key={i} className="animate-pulse">
                <CardHeader>
                  <div className="h-4 bg-gray-200 rounded w-3/4"></div>
                  <div className="h-3 bg-gray-200 rounded w-1/2"></div>
                </CardHeader>
                <CardContent>
                  <div className="h-20 bg-gray-200 rounded"></div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : documents && documents.length === 0 ? (
          <div className="text-center py-12">
            <FileText className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No documents</h3>
            <p className="mt-1 text-sm text-gray-500">Get started by uploading a new document.</p>
            <div className="mt-6">
              <Button onClick={() => setShowUploadModal(true)} className="bg-primary hover:bg-blue-700">
                <Plus className="w-4 h-4 mr-2" />
                Upload Document
              </Button>
            </div>
          </div>
        ) : Array.isArray(documents) && documents.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {documents.map((document) => (
              <Card key={document.id} className="hover:shadow-lg transition-shadow cursor-pointer">
                <Link href={`/document/${document.id}`}>
                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <CardTitle className="text-lg font-semibold text-gray-900 truncate">
                        {document.name}
                      </CardTitle>
                      {getStatusBadge(document.status)}
                    </div>
                    <p className="text-sm text-gray-500">
                      Created {new Date(document.createdAt).toLocaleDateString()}
                    </p>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center justify-between text-sm text-gray-600">
                      <div className="flex items-center space-x-2">
                        <FileText className="w-4 h-4" />
                        <span>{document.pages} page{document.pages !== 1 ? 's' : ''}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Users className="w-4 h-4" />
                        <span>View details</span>
                      </div>
                    </div>
                  </CardContent>
                </Link>
              </Card>
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <FileText className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No documents</h3>
            <p className="mt-1 text-sm text-gray-500">Get started by uploading a new document.</p>
            <div className="mt-6">
              <Button onClick={() => setShowUploadModal(true)} className="bg-primary hover:bg-blue-700">
                <Plus className="w-4 h-4 mr-2" />
                Upload Document
              </Button>
            </div>
          </div>
        )}
      </div>

      <DocumentUploadModal 
        open={showUploadModal} 
        onOpenChange={setShowUploadModal}
        onUploadComplete={() => {
          setShowUploadModal(false);
          refetch();
        }}
      />
    </div>
  );
}
