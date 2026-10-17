import React, { useState, useEffect, useRef } from 'react';
import {
  Upload, CheckCircle2, FileText, UserCheck, AlertCircle,
  Loader2, Shield
} from 'lucide-react';
import { adminApi } from '../api';
import { RecipientOption, SendDocumentResponse, AdminStats } from '../types';

export const AdminDashboard: React.FC = () => {
  const [recipients, setRecipients] = useState<RecipientOption[]>([]);
  const [selectedRecipientId, setSelectedRecipientId] = useState<string>('USER-ALICE-01');
  const [file, setFile] = useState<File | null>(null);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sentSuccess, setSentSuccess] = useState<SendDocumentResponse | null>(null);
  const [stats, setStats] = useState<AdminStats | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetchRecipients();
    fetchStats();
  }, []);

  const fetchRecipients = async () => {
    try {
      const data = await adminApi.getRecipients();
      setRecipients(data);
      if (data.length > 0) {
        setSelectedRecipientId(data[0].id);
      }
    } catch {
      setError('Could not load recipient list.');
    }
  };

  const fetchStats = async () => {
    try {
      const s = await adminApi.getStats();
      setStats(s);
    } catch {
      // Non-blocking stats load
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selectedFile = e.target.files[0];
      if (!selectedFile.name.toLowerCase().endsWith('.pdf')) {
        setError('Please select a valid PDF file.');
        setFile(null);
        return;
      }
      setFile(selectedFile);
      setError(null);
      setSentSuccess(null);
    }
  };

  const handleSendDocument = async () => {
    if (!file) {
      setError('Please choose a PDF document first.');
      return;
    }
    if (!selectedRecipientId) {
      setError('Please select a recipient.');
      return;
    }

    setSending(true);
    setError(null);

    try {
      const res = await adminApi.sendDocument(file, selectedRecipientId);
      setSentSuccess(res);
      setFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      fetchStats();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to send document.');
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-4 py-8">
      {/* Dashboard Title */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Admin Dashboard</h1>
        <p className="text-sm text-gray-500 mt-1">Upload and distribute encrypted documents to recipients</p>
      </div>

      {/* Security Summary Card */}
      <div className="mb-8 bg-white border border-gray-200 rounded-xl p-5 shadow-sm">
        <div className="text-xs font-bold uppercase tracking-wider text-gray-500 mb-3 flex items-center space-x-1.5">
          <Shield className="w-4 h-4 text-blue-600" />
          <span>Secure Distribution Summary</span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="bg-gray-50 p-3.5 rounded-lg border border-gray-100">
            <span className="text-[11px] font-medium text-gray-500 block">Documents</span>
            <span className="text-xl font-bold text-gray-900 mt-0.5 block">
              {stats?.documents_count ?? '—'}
            </span>
          </div>
          <div className="bg-gray-50 p-3.5 rounded-lg border border-gray-100">
            <span className="text-[11px] font-medium text-gray-500 block">Recipients</span>
            <span className="text-xl font-bold text-gray-900 mt-0.5 block">
              {stats?.recipients_count ?? '—'}
            </span>
          </div>
          <div className="bg-gray-50 p-3.5 rounded-lg border border-gray-100">
            <span className="text-[11px] font-medium text-gray-500 block">Access Events</span>
            <span className="text-xl font-bold text-blue-600 mt-0.5 block">
              {stats?.access_events_count ?? '—'}
            </span>
          </div>
          <div className="bg-gray-50 p-3.5 rounded-lg border border-gray-100">
            <span className="text-[11px] font-medium text-gray-500 block">Protected Copies</span>
            <span className="text-xl font-bold text-green-600 mt-0.5 block">
              {stats?.protected_copies_count ?? '—'}
            </span>
          </div>
        </div>
      </div>

      {/* Success Notification Banner */}
      {sentSuccess && (
        <div className="mb-6 bg-green-50 border border-green-200 rounded-xl p-5 fade-in">
          <div className="flex items-start space-x-3">
            <CheckCircle2 className="w-6 h-6 text-green-600 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="text-base font-semibold text-green-900">
                ✓ Document sent successfully
              </h3>
              <p className="text-sm text-green-700 mt-1 font-medium">
                {sentSuccess.filename} → {sentSuccess.recipient_name}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Main Card: Send a Document */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 sm:p-8">
        <h2 className="text-xl font-bold text-gray-900 mb-6">Send a Document</h2>

        {error && (
          <div className="mb-6 rounded-lg bg-red-50 p-3.5 flex items-start space-x-2.5 text-sm text-red-700 border border-red-100">
            <AlertCircle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="space-y-6">
          {/* Step 1: File Upload */}
          <div>
            <label className="block text-xs font-semibold text-gray-700 uppercase tracking-wider mb-2">
              Choose PDF
            </label>

            <input
              type="file"
              ref={fileInputRef}
              accept=".pdf,application/pdf"
              onChange={handleFileChange}
              className="hidden"
              id="pdf-upload"
            />

            {!file ? (
              <label
                htmlFor="pdf-upload"
                className="border-2 border-dashed border-gray-300 rounded-xl p-8 flex flex-col items-center justify-center cursor-pointer hover:border-blue-500 hover:bg-blue-50/40 transition-colors"
              >
                <div className="w-12 h-12 bg-blue-50 text-blue-600 rounded-full flex items-center justify-center mb-3">
                  <Upload className="w-6 h-6" />
                </div>
                <span className="text-sm font-semibold text-gray-800">
                  Click to choose PDF document
                </span>
                <span className="text-xs text-gray-500 mt-1">Accepts .pdf files</span>
              </label>
            ) : (
              <div className="border border-gray-200 rounded-xl p-4 bg-gray-50 flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 bg-blue-100 text-blue-600 rounded-lg flex items-center justify-center">
                    <FileText className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-xs text-gray-500 font-medium">Document</div>
                    <div className="text-sm font-semibold text-gray-900">{file.name}</div>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setFile(null);
                    if (fileInputRef.current) fileInputRef.current.value = '';
                  }}
                  className="text-xs font-medium text-red-600 hover:text-red-700 px-2 py-1"
                >
                  Change
                </button>
              </div>
            )}
          </div>

          {/* Step 2: Recipient Selection */}
          {file && (
            <div className="fade-in pt-2">
              <label className="block text-xs font-semibold text-gray-700 uppercase tracking-wider mb-2">
                Send to
              </label>

              <div className="space-y-2">
                {recipients.map((rec) => (
                  <label
                    key={rec.id}
                    className={`flex items-center space-x-3 p-3.5 rounded-lg border cursor-pointer transition-colors ${
                      selectedRecipientId === rec.id
                        ? 'border-blue-600 bg-blue-50/50'
                        : 'border-gray-200 hover:bg-gray-50'
                    }`}
                  >
                    <input
                      type="radio"
                      name="recipient"
                      value={rec.id}
                      checked={selectedRecipientId === rec.id}
                      onChange={() => setSelectedRecipientId(rec.id)}
                      className="w-4 h-4 text-blue-600 border-gray-300 focus:ring-blue-500"
                    />
                    <div className="flex items-center space-x-2">
                      <UserCheck className="w-4 h-4 text-gray-500" />
                      <span className="text-sm font-medium text-gray-900">{rec.name}</span>
                    </div>
                  </label>
                ))}
              </div>
            </div>
          )}

          {/* Step 3: Send Action */}
          {file && (
            <div className="pt-4 fade-in">
              <button
                type="button"
                onClick={handleSendDocument}
                disabled={sending}
                className="w-full py-3 px-6 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg shadow-sm transition-colors text-sm uppercase tracking-wider flex items-center justify-center space-x-2 disabled:opacity-75"
              >
                {sending ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    <span>Processing & Sending...</span>
                  </>
                ) : (
                  <span>SEND DOCUMENT</span>
                )}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
