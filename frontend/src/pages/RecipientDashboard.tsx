import React, { useState, useEffect } from 'react';
import { FileText, Loader2, AlertCircle, RefreshCw } from 'lucide-react';
import { recipientApi } from '../api';
import { DocumentItem, User } from '../types';
import { DocumentViewer } from '../components/DocumentViewer';

interface RecipientDashboardProps {
  user: User;
}

export const RecipientDashboard: React.FC<RecipientDashboardProps> = ({ user }) => {
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Selected document to open in Viewer modal
  const [selectedDoc, setSelectedDoc] = useState<DocumentItem | null>(null);

  useEffect(() => {
    fetchDocuments();
  }, []);

  const fetchDocuments = async () => {
    setLoading(true);
    setError(null);
    try {
      const docs = await recipientApi.getDocuments();
      setDocuments(docs);
    } catch (err: any) {
      setError('Could not load documents from server.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-4 py-8">
      {/* Header Welcome */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">
            Welcome, {user.name}
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Access documents securely shared with you
          </p>
        </div>

        <button
          onClick={fetchDocuments}
          className="p-2 text-gray-500 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
          title="Refresh Documents"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Error notification */}
      {error && (
        <div className="mb-6 rounded-lg bg-red-50 p-3.5 flex items-start space-x-2.5 text-sm text-red-700 border border-red-100">
          <AlertCircle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* My Documents Section */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold text-gray-900 mb-4">My Documents</h2>

        {loading ? (
          <div className="bg-white rounded-xl border border-gray-200 p-12 text-center">
            <Loader2 className="w-8 h-8 text-blue-600 animate-spin mx-auto mb-3" />
            <p className="text-sm text-gray-500 font-medium">Loading documents from MySQL...</p>
          </div>
        ) : documents.length === 0 ? (
          <div className="bg-white rounded-xl border border-dashed border-gray-300 p-12 text-center">
            <FileText className="w-12 h-12 text-gray-400 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-gray-800">No documents assigned</h3>
            <p className="text-xs text-gray-500 mt-1">
              When documents are sent to you by an admin, they will appear here.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
            {documents.map((doc) => (
              <div
                key={doc.id}
                className="bg-white rounded-xl border border-gray-200 p-6 shadow-sm hover:shadow-md transition-shadow flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start space-x-3 mb-4">
                    <div className="w-10 h-10 bg-blue-50 text-blue-600 rounded-lg flex items-center justify-center flex-shrink-0">
                      <FileText className="w-5 h-5" />
                    </div>
                    <div className="overflow-hidden">
                      <h3
                        className="font-semibold text-gray-900 text-base truncate"
                        title={doc.filename}
                      >
                        {doc.filename}
                      </h3>
                      <p className="text-xs text-gray-500 mt-0.5 font-medium">
                        Shared by {doc.shared_by}
                      </p>
                    </div>
                  </div>

                  <div className="mb-6 inline-flex items-center space-x-1.5 px-2.5 py-1 bg-green-50 text-green-700 text-xs font-semibold rounded-md border border-green-200">
                    <span className="w-1.5 h-1.5 rounded-full bg-green-500"></span>
                    <span>Status: {doc.status}</span>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => setSelectedDoc(doc)}
                  className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg shadow-sm text-sm uppercase tracking-wider transition-colors text-center"
                >
                  OPEN
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Screen 4: Open Document Viewer */}
      {selectedDoc && (
        <DocumentViewer
          documentId={selectedDoc.id}
          filename={selectedDoc.filename}
          onClose={() => setSelectedDoc(null)}
        />
      )}
    </div>
  );
};
