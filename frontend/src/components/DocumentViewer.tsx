import React, { useState, useEffect, useRef } from 'react';
import {
  CheckCircle2, Loader2, ArrowLeft, FileText, Download,
  ShieldCheck, Check, ChevronDown, ChevronUp, XCircle,
  Eye, Shield
} from 'lucide-react';
import { recipientApi } from '../api';
import { PrepareStatusResponse } from '../types';

interface DocumentViewerProps {
  documentId: string;
  filename: string;
  onClose: () => void;
}

interface StepDefinition {
  key: string;
  runningLabel: string;
  completedLabel: string;
}

const SECURITY_STEPS: StepDefinition[] = [
  {
    key: 'auth_verification',
    runningLabel: 'Verifying access authorization',
    completedLabel: 'Access authorization verified'
  },
  {
    key: 'document_retrieval',
    runningLabel: 'Loading encrypted document',
    completedLabel: 'Encrypted document retrieved'
  },
  {
    key: 'secure_decryption',
    runningLabel: 'Decrypting document securely',
    completedLabel: 'Document decrypted securely'
  },
  {
    key: 'session_generation',
    runningLabel: 'Generating unique session',
    completedLabel: 'Unique session generated'
  },
  {
    key: 'watermark_generation',
    runningLabel: 'Generating forensic watermark',
    completedLabel: 'Forensic watermark generated'
  },
  {
    key: 'watermark_embedding',
    runningLabel: 'Embedding watermark into PDF',
    completedLabel: 'Watermark embedded into PDF'
  },
  {
    key: 'event_recording',
    runningLabel: 'Recording secure access event',
    completedLabel: 'Secure access event recorded'
  },
  {
    key: 'dsa_signing',
    runningLabel: 'Signing access event with ML-DSA-65',
    completedLabel: 'ML-DSA-65 signature generated'
  },
  {
    key: 'pdf_preparation',
    runningLabel: 'Preparing protected PDF',
    completedLabel: 'Protected PDF prepared'
  }
];

type ModalView = 'processing' | 'success' | 'viewing' | 'failed';

export const DocumentViewer: React.FC<DocumentViewerProps> = ({
  documentId,
  filename,
  onClose
}) => {
  const [view, setView] = useState<ModalView>('processing');
  const [completedSteps, setCompletedSteps] = useState<string[]>([]);
  const [currentStep, setCurrentStep] = useState<string | null>('auth_verification');
  const [watermarkId, setWatermarkId] = useState<string | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [protectedPdfBlob, setProtectedPdfBlob] = useState<Blob | null>(null);
  const [pdfUrl, setPdfUrl] = useState<string | null>(null);
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [showDetails, setShowDetails] = useState<boolean>(false);

  const isMountedRef = useRef(true);
  const pollTimerRef = useRef<any>(null);

  // Clean filename properly without trailing .pdf or extra dots
  const cleanName = filename.replace(/\.pdf$/i, '').trim();
  const protectedFilename = `SecureShare_${cleanName || 'Document'}_protected.pdf`;

  useEffect(() => {
    isMountedRef.current = true;
    let vUrl: string | null = null;
    let dUrl: string | null = null;

    const startPreparation = async () => {
      try {
        setView('processing');
        setCompletedSteps([]);
        setCurrentStep('auth_verification');
        setErrorMessage(null);

        // 1. Trigger background preparation job
        const prepRes = await recipientApi.prepareDocument(documentId);
        if (!isMountedRef.current) return;
        const currentJobId = prepRes.job_id;

        // 2. Poll job status until completed or failed
        const poll = async () => {
          if (!isMountedRef.current) return;
          try {
            const statusRes: PrepareStatusResponse = await recipientApi.getPrepareStatus(currentJobId);
            if (!isMountedRef.current) return;

            setCompletedSteps(statusRes.completed_steps || []);
            if (statusRes.current_step) {
              setCurrentStep(statusRes.current_step);
            }
            if (statusRes.watermark_id) {
              setWatermarkId(statusRes.watermark_id);
            }
            if (statusRes.session_id) {
              setSessionId(statusRes.session_id);
            }

            if (statusRes.status === 'COMPLETED') {
              // Fetch the raw watermarked PDF binary
              const blob = await recipientApi.downloadProtectedPdf(currentJobId);
              if (!isMountedRef.current) return;

              const arrayBuffer = await (blob as Blob).arrayBuffer();

              // Verify PDF Magic Bytes (%PDF-)
              const firstBytes = new Uint8Array(arrayBuffer.slice(0, 5));
              const header = new TextDecoder().decode(firstBytes);
              if (header !== "%PDF-") {
                console.error('[DOWNLOAD ERROR] Invalid PDF Header:', header);
                setView('failed');
                setErrorMessage('Server did not return a valid PDF document (missing %PDF- header).');
                return;
              }

              // Construct dedicated application/pdf Blob
              const cleanBlob = new Blob([arrayBuffer], { type: 'application/pdf' });

              console.log('[PROTECTED PDF]');
              console.log('filename =', protectedFilename);
              console.log('mime =', cleanBlob.type);
              console.log('size =', cleanBlob.size);
              console.log('header =', header);
              console.log('watermark =', statusRes.watermark_id);
              console.log('session =', statusRes.session_id);

              vUrl = URL.createObjectURL(cleanBlob);
              dUrl = URL.createObjectURL(cleanBlob);

              setProtectedPdfBlob(cleanBlob);
              setPdfUrl(vUrl);
              setDownloadUrl(dUrl);
              setView('success');
              return;
            }

            if (statusRes.status === 'FAILED') {
              setView('failed');
              setErrorMessage(statusRes.error || 'Document processing failed.');
              return;
            }

            // Continue polling
            pollTimerRef.current = setTimeout(poll, 150);
          } catch (pollErr: any) {
            if (!isMountedRef.current) return;
            setView('failed');
            setErrorMessage(
              pollErr.response?.data?.detail || 'Failed to communicate with security backend.'
            );
          }
        };

        poll();
      } catch (err: any) {
        if (!isMountedRef.current) return;
        setView('failed');
        setErrorMessage(
          err.response?.data?.detail || 'Failed to initiate secure document open.'
        );
      }
    };

    startPreparation();

    return () => {
      isMountedRef.current = false;
      if (pollTimerRef.current) {
        clearTimeout(pollTimerRef.current);
      }
      if (vUrl) {
        URL.revokeObjectURL(vUrl);
      }
      if (dUrl) {
        URL.revokeObjectURL(dUrl);
      }
    };
  }, [documentId]);

  return (
    <div className="fixed inset-0 z-50 bg-gray-900/60 backdrop-blur-sm flex flex-col items-center justify-center p-4">
      {/* 1. REAL-TIME BACKGROUND SECURITY PROCESSING MODAL */}
      {view === 'processing' && (
        <div className="bg-white rounded-2xl shadow-2xl p-7 max-w-lg w-full border border-gray-100 fade-in animate-scale-up">
          {/* Header */}
          <div className="text-center pb-4 border-b border-gray-100">
            <div className="w-12 h-12 bg-blue-50 text-blue-600 rounded-full flex items-center justify-center mx-auto mb-3 shadow-inner">
              <Shield className="w-6 h-6 text-blue-600 animate-pulse" />
            </div>
            <h3 className="text-xl font-bold text-gray-900 tracking-tight">
              Preparing document...
            </h3>
            <p className="text-xs font-semibold text-blue-600 uppercase tracking-wider mt-1">
              Security Processing
            </p>
            <p className="text-xs text-gray-500 mt-0.5 truncate max-w-sm mx-auto font-medium">
              {filename}
            </p>
          </div>

          {/* Step-by-step Real Backend Security Pipeline List */}
          <div className="py-4 space-y-2.5">
            {SECURITY_STEPS.map((step) => {
              const isCompleted = completedSteps.includes(step.key);
              const isRunning = !isCompleted && currentStep === step.key;

              return (
                <div
                  key={step.key}
                  className={`flex items-center justify-between px-3.5 py-2 rounded-lg text-xs font-medium transition-all ${
                    isCompleted
                      ? 'bg-green-50/70 text-green-900 border border-green-100/60'
                      : isRunning
                      ? 'bg-blue-50/80 text-blue-900 border border-blue-200 shadow-sm'
                      : 'bg-gray-50/60 text-gray-400 border border-gray-100'
                  }`}
                >
                  <div className="flex items-center space-x-2.5">
                    {/* Step State Icon */}
                    <div className="w-4 h-4 flex items-center justify-center flex-shrink-0">
                      {isCompleted ? (
                        <Check className="w-4 h-4 text-green-600 stroke-[3]" />
                      ) : isRunning ? (
                        <Loader2 className="w-3.5 h-3.5 text-blue-600 animate-spin" />
                      ) : (
                        <span className="w-2.5 h-2.5 rounded-full border-2 border-gray-300 inline-block" />
                      )}
                    </div>

                    {/* Step Label */}
                    <span className={`text-xs ${isCompleted ? 'text-green-800 font-semibold' : isRunning ? 'text-blue-900 font-semibold' : 'text-gray-500'}`}>
                      {isCompleted ? step.completedLabel : step.runningLabel}
                    </span>
                  </div>

                  {/* Right Status Badge */}
                  <span className="text-[10px] uppercase font-bold tracking-wider">
                    {isCompleted ? (
                      <span className="text-green-600">Done</span>
                    ) : isRunning ? (
                      <span className="text-blue-600 animate-pulse">Running</span>
                    ) : (
                      <span className="text-gray-400">Pending</span>
                    )}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Footer note */}
          <div className="pt-3 border-t border-gray-100 text-center">
            <p className="text-[11px] text-gray-500 font-medium">
              All security operations are performed automatically in the background.
            </p>
          </div>
        </div>
      )}

      {/* 2. SUCCESS SCREEN MODAL */}
      {view === 'success' && (
        <div className="bg-white rounded-2xl shadow-2xl p-7 max-w-lg w-full border border-gray-100 fade-in animate-scale-up">
          {/* Header */}
          <div className="text-center pb-4 border-b border-gray-100">
            <div className="w-14 h-14 bg-green-50 text-green-600 rounded-full flex items-center justify-center mx-auto mb-3 shadow-inner">
              <CheckCircle2 className="w-8 h-8 text-green-600" />
            </div>
            <h3 className="text-xl font-bold text-gray-900 tracking-tight flex items-center justify-center space-x-1.5">
              <span>✓ Document Opened Securely</span>
            </h3>
            <p className="text-sm text-gray-600 mt-1 font-medium">
              Your protected document is ready.
            </p>
          </div>

          {/* Security checks completed checklist */}
          <div className="py-4 space-y-2">
            <div className="text-[11px] font-bold text-gray-400 uppercase tracking-wider mb-2">
              Security Checks Completed:
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <div className="flex items-center space-x-2 text-gray-700">
                <Check className="w-4 h-4 text-green-600 flex-shrink-0 stroke-[2.5]" />
                <span>Access authorization verified</span>
              </div>
              <div className="flex items-center space-x-2 text-gray-700">
                <Check className="w-4 h-4 text-green-600 flex-shrink-0 stroke-[2.5]" />
                <span>Document decrypted securely</span>
              </div>
              <div className="flex items-center space-x-2 text-gray-700">
                <Check className="w-4 h-4 text-green-600 flex-shrink-0 stroke-[2.5]" />
                <span>Unique forensic watermark applied</span>
              </div>
              <div className="flex items-center space-x-2 text-gray-700">
                <Check className="w-4 h-4 text-green-600 flex-shrink-0 stroke-[2.5]" />
                <span>Secure access event recorded</span>
              </div>
              <div className="flex items-center space-x-2 text-gray-700">
                <Check className="w-4 h-4 text-green-600 flex-shrink-0 stroke-[2.5]" />
                <span>ML-DSA-65 signature generated</span>
              </div>
              <div className="flex items-center space-x-2 text-gray-700">
                <Check className="w-4 h-4 text-green-600 flex-shrink-0 stroke-[2.5]" />
                <span>Protected PDF prepared</span>
              </div>
            </div>
          </div>

          {/* Non-sensitive Watermark & Session Identifier Box */}
          <div className="mb-5 bg-gradient-to-r from-blue-50/70 to-indigo-50/70 border border-blue-100 rounded-xl p-3.5 text-xs">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-[10px] font-bold text-blue-700 uppercase tracking-wider block">
                  Watermark ID
                </span>
                <span className="font-mono font-bold text-blue-900 text-sm">
                  {watermarkId || 'WM-GENERATED'}
                </span>
              </div>
              {sessionId && (
                <div className="text-right">
                  <span className="text-[10px] font-bold text-blue-700 uppercase tracking-wider block">
                    Session ID
                  </span>
                  <span className="font-mono font-bold text-blue-900 text-sm">
                    {sessionId}
                  </span>
                </div>
              )}
            </div>
            <p className="text-[10px] text-gray-500 mt-2">
              Non-sensitive forensic tracking identifier physically embedded into your copy.
            </p>
          </div>

          {/* Action Buttons */}
          <div className="space-y-2.5">
            {/* Native <a> element with real download attribute and stable object URL */}
            <a
              href={downloadUrl || '#'}
              download={protectedFilename}
              onClick={() => {
                console.log('[DOWNLOAD] Downloading protected PDF bytes:', protectedPdfBlob?.size, 'bytes');
              }}
              className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-semibold rounded-xl shadow-md flex items-center justify-center space-x-2 text-sm uppercase tracking-wider transition-all transform hover:-translate-y-0.5 cursor-pointer no-underline select-none"
            >
              <Download className="w-4 h-4" />
              <span>Download Protected PDF</span>
            </a>

            <div className="grid grid-cols-2 gap-2.5">
              <button
                type="button"
                onClick={() => setView('viewing')}
                className="py-2.5 px-3 bg-gray-100 hover:bg-gray-200 text-gray-800 font-semibold rounded-xl text-xs flex items-center justify-center space-x-1.5 transition-colors cursor-pointer"
              >
                <Eye className="w-3.5 h-3.5 text-gray-600" />
                <span>Open Protected PDF</span>
              </button>

              <button
                type="button"
                onClick={onClose}
                className="py-2.5 px-3 bg-gray-50 hover:bg-gray-100 text-gray-600 font-medium rounded-xl text-xs border border-gray-200 transition-colors cursor-pointer"
              >
                Back to Documents
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 3. FAILURE SCREEN MODAL */}
      {view === 'failed' && (
        <div className="bg-white rounded-2xl shadow-2xl p-7 max-w-md w-full text-center border border-red-100 fade-in animate-scale-up">
          <div className="w-14 h-14 bg-red-50 text-red-600 rounded-full flex items-center justify-center mx-auto mb-3 shadow-inner">
            <XCircle className="w-8 h-8 text-red-600" />
          </div>
          <h3 className="text-xl font-bold text-red-800">Document Processing Failed</h3>
          <div className="mt-3 p-3 bg-red-50/80 border border-red-200 rounded-xl text-xs text-red-700 font-medium text-left">
            {errorMessage || 'Access authorization or document decryption failed.'}
          </div>
          <p className="text-xs text-gray-500 mt-3">
            For security reasons, unwatermarked or unverified document content cannot be returned.
          </p>
          <button
            type="button"
            onClick={onClose}
            className="mt-6 w-full py-2.5 bg-gray-900 text-white text-xs font-semibold rounded-xl hover:bg-gray-800 transition-colors uppercase tracking-wider cursor-pointer"
          >
            Close
          </button>
        </div>
      )}

      {/* 4. IN-BROWSER PDF VIEWER (EXACT WATERMARKED BLOB URL) */}
      {view === 'viewing' && pdfUrl && (
        <div className="bg-white rounded-2xl shadow-2xl w-full max-w-5xl h-[90vh] flex flex-col overflow-hidden border border-gray-200 fade-in">
          {/* Top Bar Header */}
          <div className="bg-white px-6 py-3.5 border-b border-gray-200 flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <button
                onClick={() => setView('success')}
                className="p-1.5 rounded-lg text-gray-500 hover:text-gray-900 hover:bg-gray-100 transition-colors cursor-pointer"
                title="Back to security overview"
              >
                <ArrowLeft className="w-5 h-5" />
              </button>
              <div className="flex items-center space-x-2">
                <FileText className="w-5 h-5 text-blue-600" />
                <span className="font-semibold text-gray-900 text-sm sm:text-base truncate max-w-xs sm:max-w-md">
                  {protectedFilename}
                </span>
              </div>
            </div>

            <div className="flex items-center space-x-2.5">
              <a
                href={downloadUrl || '#'}
                download={protectedFilename}
                className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-sm transition-colors uppercase tracking-wider cursor-pointer no-underline select-none"
                title="Download this watermarked secure copy"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download Protected PDF</span>
              </a>
              <button
                type="button"
                onClick={onClose}
                className="px-3 py-1.5 bg-gray-900 text-white text-xs font-medium rounded-lg hover:bg-gray-800 transition-colors cursor-pointer"
              >
                Close Viewer
              </button>
            </div>
          </div>

          {/* Sub-bar with Security Verification Badges */}
          <div className="bg-gray-50 px-6 py-2 border-b border-gray-200 flex flex-wrap items-center justify-between gap-2 text-xs">
            <div className="flex items-center space-x-3 flex-wrap gap-y-1 text-gray-700">
              <span className="font-semibold text-gray-900 flex items-center space-x-1">
                <ShieldCheck className="w-4 h-4 text-green-600 mr-1" />
                Protected Copy
              </span>
              {watermarkId && (
                <span className="inline-flex items-center px-2 py-0.5 rounded bg-blue-100 text-blue-800 font-mono font-semibold text-[11px]">
                  {watermarkId}
                </span>
              )}
              {sessionId && (
                <span className="inline-flex items-center px-2 py-0.5 rounded bg-purple-100 text-purple-800 font-mono font-semibold text-[11px]">
                  {sessionId}
                </span>
              )}
              <span className="flex items-center space-x-1 text-green-700 font-medium">
                <Check className="w-3.5 h-3.5 text-green-600" />
                <span>ML-DSA-65 Signed</span>
              </span>
            </div>

            <button
              type="button"
              onClick={() => setShowDetails(!showDetails)}
              className="text-gray-500 hover:text-gray-800 font-medium flex items-center space-x-1 transition-colors text-xs py-0.5 px-1.5 rounded hover:bg-gray-200/60 cursor-pointer"
            >
              <span>{showDetails ? 'Hide Security Details' : 'View Security Details'}</span>
              {showDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>
          </div>

          {/* Expandable Safe Security Details */}
          {showDetails && (
            <div className="bg-blue-50/70 border-b border-blue-100 px-6 py-2.5 grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs fade-in">
              <div>
                <span className="text-gray-500 block text-[10px] uppercase font-semibold">Encryption</span>
                <span className="font-semibold text-gray-900">AES-256-GCM</span>
              </div>
              <div>
                <span className="text-gray-500 block text-[10px] uppercase font-semibold">Key Protection</span>
                <span className="font-semibold text-gray-900">ML-KEM-768</span>
              </div>
              <div>
                <span className="text-gray-500 block text-[10px] uppercase font-semibold">Forensic Watermark</span>
                <span className="font-semibold text-gray-900">Physical DWT-DCT</span>
              </div>
              <div>
                <span className="text-gray-500 block text-[10px] uppercase font-semibold">Access Signature</span>
                <span className="font-semibold text-gray-900">ML-DSA-65</span>
              </div>
              <div>
                <span className="text-gray-500 block text-[10px] uppercase font-semibold">Evidence Ledger</span>
                <span className="font-semibold text-green-700">Recorded</span>
              </div>
            </div>
          )}

          {/* Actual Watermarked PDF Viewer Iframe */}
          <div className="flex-1 bg-gray-100 w-full h-full relative">
            <iframe
              src={pdfUrl ? `${pdfUrl}#toolbar=0&navpanes=0` : ''}
              title={protectedFilename}
              className="w-full h-full border-0"
            />
          </div>
        </div>
      )}
    </div>
  );
};
