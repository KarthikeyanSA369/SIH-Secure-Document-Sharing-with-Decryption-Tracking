import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldAlert, Upload, FileText, CheckCircle2, AlertTriangle,
  XCircle, Loader2, ChevronDown, ChevronUp, Clock, User,
  RefreshCw, Layers, ShieldCheck, Download, Copy, Check, FileJson
} from 'lucide-react';
import { investigatorApi } from '../api';
import { InvestigationResult, InvestigationStage, InvestigationHistoryItem } from '../types';

const INITIAL_STAGES: InvestigationStage[] = [
  { id: 1, name: 'Document received', status: 'PENDING' },
  { id: 2, name: 'Calculating document fingerprint', status: 'PENDING' },
  { id: 3, name: 'Searching for forensic watermark', status: 'PENDING' },
  { id: 4, name: 'Recovering watermark identifier', status: 'PENDING' },
  { id: 5, name: 'Searching access records', status: 'PENDING' },
  { id: 6, name: 'Verifying ML-DSA-65 signature', status: 'PENDING' },
  { id: 7, name: 'Verifying document integrity', status: 'PENDING' },
  { id: 8, name: 'Checking immutable evidence record', status: 'PENDING' },
  { id: 9, name: 'Preparing investigation result', status: 'PENDING' }
];

export const InvestigatorDashboard: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [stages, setStages] = useState<InvestigationStage[]>(INITIAL_STAGES);
  const [progressPercent, setProgressPercent] = useState<number>(0);
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showTechnicalEvidence, setShowTechnicalEvidence] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [downloadingReport, setDownloadingReport] = useState(false);
  const [history, setHistory] = useState<InvestigationHistoryItem[]>([]);

  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const data = await investigatorApi.getHistory();
      setHistory(data);
    } catch {
      // Non-blocking history load
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
      setResult(null);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const handleAnalyze = async () => {
    if (!file) {
      setError('Please choose a PDF document to analyze.');
      return;
    }

    setAnalyzing(true);
    setError(null);
    setResult(null);
    setShowTechnicalEvidence(false);

    // Progressive stage simulation while awaiting API response
    const currentStages: InvestigationStage[] = INITIAL_STAGES.map((s) => ({ ...s, status: 'PENDING' }));
    setStages(currentStages);
    setProgressPercent(10);

    const apiPromise = investigatorApi.analyzeDocument(file);

    // Smooth visual progression
    currentStages[0].status = 'COMPLETED';
    currentStages[1].status = 'PROCESSING';
    setStages([...currentStages]);
    setProgressPercent(22);

    await new Promise((r) => setTimeout(r, 350));
    currentStages[1].status = 'COMPLETED';
    currentStages[2].status = 'PROCESSING';
    currentStages[3].status = 'PROCESSING';
    setStages([...currentStages]);
    setProgressPercent(45);

    try {
      const data = await apiPromise;

      // Sync backend stages
      await new Promise((r) => setTimeout(r, 350));
      currentStages[2].status = data.stages[2]?.status || 'COMPLETED';
      currentStages[3].status = data.stages[3]?.status || 'COMPLETED';
      currentStages[4].status = 'PROCESSING';
      setStages([...currentStages]);
      setProgressPercent(68);

      await new Promise((r) => setTimeout(r, 350));
      currentStages[4].status = data.stages[4]?.status || 'COMPLETED';
      currentStages[5].status = data.stages[5]?.status || 'COMPLETED';
      currentStages[6].status = data.stages[6]?.status || 'COMPLETED';
      currentStages[7].status = data.stages[7]?.status || 'COMPLETED';
      currentStages[8].status = 'COMPLETED';
      setStages(data.stages);
      setProgressPercent(100);

      await new Promise((r) => setTimeout(r, 300));
      setResult(data);
      fetchHistory(); // refresh history table
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to analyze document.');
      currentStages.forEach((s) => {
        if (s.status === 'PROCESSING') s.status = 'FAILED';
      });
      setStages([...currentStages]);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleReset = () => {
    setFile(null);
    setResult(null);
    setError(null);
    setStages(INITIAL_STAGES);
    setProgressPercent(0);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleCopy = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleDownloadReport = async () => {
    if (!result) return;
    setDownloadingReport(true);
    try {
      const payload = {
        investigation_id: result.investigation_id || 'INV-0001',
        status: result.status,
        status_label: result.status_label,
        document_filename: result.document_filename || file?.name || 'Project_Report.pdf',
        document_sha256: result.technical_evidence?.document_sha256,
        watermark_id: result.watermark_id,
        access_event_id: result.access_event_id,
        session_id: result.session_id,
        recipient_identity: result.recipient_identity,
        access_timestamp: result.access_timestamp,
        technical_evidence: result.technical_evidence
      };

      const blob = await investigatorApi.downloadReport(payload);
      const url = URL.createObjectURL(new Blob([blob], { type: 'application/pdf' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `Forensic_Investigation_Report_${result.investigation_id || 'INV-0001'}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setError('Failed to generate PDF report.');
    } finally {
      setDownloadingReport(false);
    }
  };

  const handleExportJSON = () => {
    if (!result) return;
    const exportData = {
      investigation_id: result.investigation_id || 'INV-0001',
      document_name: result.document_filename || file?.name || 'Project_Report.pdf',
      document_sha256: result.technical_evidence?.document_sha256 || '',
      watermark_id: result.watermark_id || 'N/A',
      access_event_id: result.access_event_id || 'N/A',
      session_id: result.session_id || 'N/A',
      recipient: result.recipient_identity || 'N/A',
      timestamp: result.technical_evidence?.timestamp || result.access_timestamp || new Date().toISOString(),
      signature_algorithm: 'ML-DSA-65',
      signature_verified: result.status === 'MATCH_FOUND',
      document_integrity_verified: result.status === 'MATCH_FOUND',
      ledger_status: 'NOT_IMPLEMENTED'
    };

    const jsonStr = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Forensic_Evidence_${result.investigation_id || 'INV-0001'}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900 flex items-center space-x-2.5">
          <ShieldAlert className="w-6 h-6 text-blue-600" />
          <span>Forensic Investigation</span>
        </h1>
        <p className="text-sm text-gray-500 mt-1">
          Analyze a suspected leaked document and verify its cryptographic provenance.
        </p>
      </div>

      {/* Visual Pipeline Flow */}
      <div className="mb-8 bg-white border border-gray-200 rounded-xl p-4 shadow-sm">
        <div className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-2.5">
          Forensic Provenance Pipeline
        </div>
        <div className="flex items-center justify-between flex-wrap gap-2 text-xs font-semibold">
          <div className="flex items-center space-x-1.5 bg-gray-100 text-gray-800 px-3 py-1.5 rounded-lg border border-gray-200">
            <FileText className="w-3.5 h-3.5 text-blue-600" />
            <span>LEAKED PDF</span>
          </div>
          <span className="text-gray-400 font-bold hidden sm:inline">→</span>
          <div className="flex items-center space-x-1.5 bg-blue-50 text-blue-800 px-3 py-1.5 rounded-lg border border-blue-200">
            <Layers className="w-3.5 h-3.5 text-blue-600" />
            <span>FORENSIC WATERMARK</span>
          </div>
          <span className="text-gray-400 font-bold hidden sm:inline">→</span>
          <div className="flex items-center space-x-1.5 bg-indigo-50 text-indigo-800 px-3 py-1.5 rounded-lg border border-indigo-200">
            <Clock className="w-3.5 h-3.5 text-indigo-600" />
            <span>ACCESS EVENT</span>
          </div>
          <span className="text-gray-400 font-bold hidden sm:inline">→</span>
          <div className="flex items-center space-x-1.5 bg-purple-50 text-purple-800 px-3 py-1.5 rounded-lg border border-purple-200">
            <ShieldCheck className="w-3.5 h-3.5 text-purple-600" />
            <span>CRYPTOGRAPHIC VERIFICATION</span>
          </div>
          <span className="text-gray-400 font-bold hidden sm:inline">→</span>
          <div className="flex items-center space-x-1.5 bg-green-50 text-green-800 px-3 py-1.5 rounded-lg border border-green-200">
            <CheckCircle2 className="w-3.5 h-3.5 text-green-600" />
            <span>PROVENANCE RESULT</span>
          </div>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="mb-6 rounded-lg bg-red-50 p-4 flex items-start space-x-3 text-sm text-red-700 border border-red-100 fade-in">
          <AlertTriangle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Upload Card (when not analyzing and no result) */}
      {!analyzing && !result && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 sm:p-8 fade-in">
          <h2 className="text-xl font-bold text-gray-900 mb-2">Analyze Leaked Document</h2>
          <p className="text-sm text-gray-600 mb-6">
            Upload a suspected leaked PDF to search for its forensic watermark and verify the associated access record.
          </p>

          <div className="space-y-6">
            <div>
              <label className="block text-xs font-semibold text-gray-700 uppercase tracking-wider mb-2">
                Upload Suspected Leaked PDF
              </label>

              <input
                type="file"
                ref={fileInputRef}
                accept=".pdf,application/pdf"
                onChange={handleFileChange}
                className="hidden"
                id="leaked-pdf-upload"
              />

              {!file ? (
                <label
                  htmlFor="leaked-pdf-upload"
                  className="border-2 border-dashed border-gray-300 rounded-xl p-8 flex flex-col items-center justify-center cursor-pointer hover:border-blue-500 hover:bg-blue-50/40 transition-colors"
                >
                  <div className="w-12 h-12 bg-blue-50 text-blue-600 rounded-full flex items-center justify-center mb-3">
                    <Upload className="w-6 h-6" />
                  </div>
                  <span className="text-sm font-semibold text-gray-800">
                    Click to choose PDF document
                  </span>
                  <span className="text-xs text-gray-500 mt-1">PDF files only</span>
                </label>
              ) : (
                <div className="border border-gray-200 rounded-xl p-4 bg-gray-50 flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 bg-blue-100 text-blue-600 rounded-lg flex items-center justify-center">
                      <FileText className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="text-sm font-semibold text-gray-900">{file.name}</div>
                      <div className="text-xs text-gray-500 font-medium">
                        Size: {formatFileSize(file.size)}
                      </div>
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

            {file && (
              <div className="pt-2 fade-in">
                <button
                  type="button"
                  onClick={handleAnalyze}
                  className="w-full py-3 px-6 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg shadow-sm transition-colors text-sm uppercase tracking-wider flex items-center justify-center space-x-2"
                >
                  <span>ANALYZE DOCUMENT</span>
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Analysis Loading Panel */}
      {analyzing && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 sm:p-8 fade-in">
          <div className="flex items-center justify-between mb-6 pb-4 border-b border-gray-100">
            <div>
              <h2 className="text-xl font-bold text-gray-900">Investigating Document</h2>
              <p className="text-sm text-gray-500 mt-0.5">SecureShare is analyzing the evidence</p>
            </div>
            <div className="text-right">
              <span className="text-2xl font-extrabold text-blue-600">{progressPercent}%</span>
            </div>
          </div>

          {/* Progress Bar */}
          <div className="w-full bg-gray-100 rounded-full h-2 mb-6 overflow-hidden">
            <div
              className="bg-blue-600 h-2 rounded-full transition-all duration-300"
              style={{ width: `${progressPercent}%` }}
            ></div>
          </div>

          {/* 9 Stages List */}
          <div className="space-y-3.5 mb-6">
            {stages.map((st) => (
              <div key={st.id} className="flex items-center space-x-3 text-sm">
                {st.status === 'COMPLETED' && (
                  <CheckCircle2 className="w-5 h-5 text-green-600 flex-shrink-0" />
                )}
                {st.status === 'PROCESSING' && (
                  <Loader2 className="w-5 h-5 text-blue-600 animate-spin flex-shrink-0" />
                )}
                {st.status === 'PENDING' && (
                  <div className="w-5 h-5 rounded-full border-2 border-gray-300 flex-shrink-0"></div>
                )}
                {st.status === 'FAILED' && (
                  <XCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}

                <div className="flex-1 flex items-center justify-between">
                  <span
                    className={`font-medium ${
                      st.status === 'COMPLETED'
                        ? 'text-gray-900'
                        : st.status === 'PROCESSING'
                        ? 'text-blue-700 font-semibold'
                        : st.status === 'FAILED'
                        ? 'text-red-700'
                        : 'text-gray-400'
                    }`}
                  >
                    {st.name}
                  </span>
                  {st.detail && (
                    <span className="text-xs text-gray-500 ml-2 truncate max-w-[200px]">
                      {st.detail}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>

          <p className="text-xs text-gray-500 text-center italic">
            Please wait while evidence is verified.
          </p>
        </div>
      )}

      {/* Investigation Results */}
      {!analyzing && result && (
        <div className="space-y-6 fade-in">
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
            {/* Result Header Banner */}
            <div
              className={`p-6 border-b flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 ${
                result.status === 'MATCH_FOUND'
                  ? 'bg-green-50/80 border-green-200'
                  : result.status === 'NO_WATERMARK'
                  ? 'bg-amber-50/80 border-amber-200'
                  : 'bg-red-50/80 border-red-200'
              }`}
            >
              <div>
                <div className="text-xs uppercase font-bold tracking-wider text-gray-500 mb-1">
                  {result.title}
                </div>
                <h2
                  className={`text-xl font-bold tracking-tight ${
                    result.status === 'MATCH_FOUND'
                      ? 'text-green-900'
                      : result.status === 'NO_WATERMARK'
                      ? 'text-amber-900'
                      : 'text-red-900'
                  }`}
                >
                  {result.status_label}
                </h2>
              </div>

              <div>
                {result.status === 'MATCH_FOUND' && (
                  <span className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 bg-green-600 text-white rounded-lg text-xs font-bold shadow-sm uppercase tracking-wider">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>VERIFIED MATCH</span>
                  </span>
                )}
                {result.status === 'NO_WATERMARK' && (
                  <span className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 bg-amber-600 text-white rounded-lg text-xs font-bold shadow-sm uppercase tracking-wider">
                    <AlertTriangle className="w-4 h-4" />
                    <span>NO WATERMARK</span>
                  </span>
                )}
                {(result.status === 'EVENT_NOT_FOUND' || result.status === 'SIGNATURE_FAILED' || result.status === 'INTEGRITY_FAILED') && (
                  <span className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 bg-red-600 text-white rounded-lg text-xs font-bold shadow-sm uppercase tracking-wider">
                    <XCircle className="w-4 h-4" />
                    <span>VERIFICATION FAILED</span>
                  </span>
                )}
              </div>
            </div>

            {/* Content Body */}
            <div className="p-6 sm:p-8 space-y-6">
              {/* MATCH FOUND Details Grid */}
              {result.status === 'MATCH_FOUND' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 bg-gray-50 p-5 rounded-xl border border-gray-200">
                  <div>
                    <div className="text-xs text-gray-500 font-medium">Document</div>
                    <div className="text-sm font-semibold text-gray-900 mt-0.5">
                      {result.document_filename || 'Project_Report.pdf'}
                    </div>
                  </div>

                  <div>
                    <div className="text-xs text-gray-500 font-medium">Watermark ID</div>
                    <div className="text-sm font-mono font-semibold text-blue-700 mt-0.5">
                      {result.watermark_id}
                    </div>
                  </div>

                  <div>
                    <div className="text-xs text-gray-500 font-medium">Access Event</div>
                    <div className="text-sm font-mono font-semibold text-gray-900 mt-0.5">
                      {result.access_event_id}
                    </div>
                  </div>

                  <div>
                    <div className="text-xs text-gray-500 font-medium">
                      Recipient Cryptographic Identity
                    </div>
                    <div className="text-sm font-semibold text-gray-900 mt-0.5 flex items-center space-x-1.5">
                      <User className="w-4 h-4 text-blue-600" />
                      <span>{result.recipient_identity}</span>
                    </div>
                  </div>

                  <div>
                    <div className="text-xs text-gray-500 font-medium">Session</div>
                    <div className="text-sm font-mono font-semibold text-gray-900 mt-0.5">
                      {result.session_id}
                    </div>
                  </div>

                  <div>
                    <div className="text-xs text-gray-500 font-medium">Access Time</div>
                    <div className="text-sm font-semibold text-gray-900 mt-0.5 flex items-center space-x-1.5">
                      <Clock className="w-4 h-4 text-gray-500" />
                      <span>{result.access_timestamp}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Verification Checklist */}
              <div>
                <h3 className="text-xs font-semibold text-gray-700 uppercase tracking-wider mb-3">
                  Verification Summary
                </h3>
                <div className="space-y-2">
                  {result.verification_checks.map((chk, idx) => (
                    <div key={idx} className="flex items-center space-x-2.5 text-sm">
                      {chk.verified ? (
                        <CheckCircle2 className="w-4 h-4 text-green-600 flex-shrink-0" />
                      ) : (
                        <XCircle className="w-4 h-4 text-gray-400 flex-shrink-0" />
                      )}
                      <span className={chk.verified ? 'text-gray-900 font-medium' : 'text-gray-500'}>
                        {chk.label}
                      </span>
                    </div>
                  ))}
                  <div className="flex items-center space-x-2.5 text-sm">
                    <div className="w-4 h-4 rounded-full border border-gray-400 flex items-center justify-center flex-shrink-0">
                      <div className="w-1.5 h-1.5 bg-gray-400 rounded-full"></div>
                    </div>
                    <span className="text-gray-500 font-medium">
                      Ledger verification pending
                    </span>
                  </div>
                </div>
              </div>

              {/* Forensic Statements / What this means */}
              <div className="p-4 bg-blue-50/70 border border-blue-100 rounded-xl space-y-2">
                <div className="text-xs font-bold uppercase tracking-wider text-blue-900">
                  What this means
                </div>
                <p className="text-sm text-gray-900 font-medium leading-relaxed">
                  {result.forensic_statement}
                </p>
                <p className="text-xs text-gray-600 leading-relaxed pt-1">
                  {result.attribution_disclaimer}
                </p>
              </div>

              {/* Explanations (for no-watermark or failed cases) */}
              {result.explanations && result.explanations.length > 0 && (
                <div className="p-4 bg-gray-50 rounded-lg border border-gray-200">
                  <h4 className="text-xs font-semibold text-gray-700 uppercase tracking-wider mb-2">
                    Possible Explanations:
                  </h4>
                  <ul className="list-disc list-inside space-y-1 text-xs text-gray-600">
                    {result.explanations.map((exp, i) => (
                      <li key={i}>{exp}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Expandable Technical Evidence Drawer */}
              {result.technical_evidence && (
                <div className="border border-gray-200 rounded-xl overflow-hidden">
                  <button
                    type="button"
                    onClick={() => setShowTechnicalEvidence(!showTechnicalEvidence)}
                    className="w-full px-5 py-3.5 bg-gray-50 hover:bg-gray-100 flex items-center justify-between text-xs font-semibold text-gray-700 uppercase tracking-wider transition-colors"
                  >
                    <span className="flex items-center space-x-2">
                      <Layers className="w-4 h-4 text-blue-600" />
                      <span>View Technical Evidence</span>
                    </span>
                    {showTechnicalEvidence ? (
                      <ChevronUp className="w-4 h-4" />
                    ) : (
                      <ChevronDown className="w-4 h-4" />
                    )}
                  </button>

                  {showTechnicalEvidence && (
                    <div className="p-5 bg-white space-y-4 text-xs text-gray-700 border-t border-gray-200 font-mono">
                      <div>
                        <div className="flex items-center justify-between font-semibold text-gray-500 uppercase text-[11px] mb-1 font-sans">
                          <span>Document SHA-256</span>
                          <button
                            type="button"
                            onClick={() => handleCopy('sha256', result.technical_evidence!.document_sha256)}
                            className="inline-flex items-center space-x-1 text-blue-600 hover:text-blue-800 lowercase text-[10px]"
                          >
                            {copiedKey === 'sha256' ? <Check className="w-3 h-3 text-green-600" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedKey === 'sha256' ? 'copied' : 'copy'}</span>
                          </button>
                        </div>
                        <div className="bg-gray-50 p-2.5 rounded-lg border border-gray-200 break-all select-all">
                          {result.technical_evidence.document_sha256}
                        </div>
                      </div>

                      {result.technical_evidence.watermark_id && (
                        <div>
                          <div className="flex items-center justify-between font-semibold text-gray-500 uppercase text-[11px] mb-1 font-sans">
                            <span>Watermark ID</span>
                            <button
                              type="button"
                              onClick={() => handleCopy('watermark', result.technical_evidence!.watermark_id!)}
                              className="inline-flex items-center space-x-1 text-blue-600 hover:text-blue-800 lowercase text-[10px]"
                            >
                              {copiedKey === 'watermark' ? <Check className="w-3 h-3 text-green-600" /> : <Copy className="w-3 h-3" />}
                              <span>{copiedKey === 'watermark' ? 'copied' : 'copy'}</span>
                            </button>
                          </div>
                          <div className="bg-gray-50 p-2.5 rounded-lg border border-gray-200 break-all select-all">
                            {result.technical_evidence.watermark_id}
                          </div>
                        </div>
                      )}

                      {result.technical_evidence.session_id && (
                        <div>
                          <div className="font-semibold text-gray-500 uppercase text-[11px] mb-1 font-sans">
                            Session ID
                          </div>
                          <div className="bg-gray-50 p-2.5 rounded-lg border border-gray-200 break-all">
                            {result.technical_evidence.session_id}
                          </div>
                        </div>
                      )}

                      {result.technical_evidence.event_hash && (
                        <div>
                          <div className="flex items-center justify-between font-semibold text-gray-500 uppercase text-[11px] mb-1 font-sans">
                            <span>Event Hash (Canonical SHA-256)</span>
                            <button
                              type="button"
                              onClick={() => handleCopy('event_hash', result.technical_evidence!.event_hash!)}
                              className="inline-flex items-center space-x-1 text-blue-600 hover:text-blue-800 lowercase text-[10px]"
                            >
                              {copiedKey === 'event_hash' ? <Check className="w-3 h-3 text-green-600" /> : <Copy className="w-3 h-3" />}
                              <span>{copiedKey === 'event_hash' ? 'copied' : 'copy'}</span>
                            </button>
                          </div>
                          <div className="bg-gray-50 p-2.5 rounded-lg border border-gray-200 break-all select-all">
                            {result.technical_evidence.event_hash}
                          </div>
                        </div>
                      )}

                      <div>
                        <div className="font-semibold text-gray-500 uppercase text-[11px] mb-1 font-sans">
                          Signature Algorithm
                        </div>
                        <div className="bg-gray-50 p-2.5 rounded-lg border border-gray-200 break-all">
                          {result.technical_evidence.signature_algorithm}
                        </div>
                      </div>

                      {result.technical_evidence.signature_preview && (
                        <div>
                          <div className="font-semibold text-gray-500 uppercase text-[11px] mb-1 font-sans">
                            ML-DSA-65 Signature Snippet
                          </div>
                          <div className="bg-gray-50 p-2.5 rounded-lg border border-gray-200 break-all select-all">
                            {result.technical_evidence.signature_preview}
                          </div>
                        </div>
                      )}

                      {result.technical_evidence.key_identifier && (
                        <div>
                          <div className="font-semibold text-gray-500 uppercase text-[11px] mb-1 font-sans">
                            Key Identifier
                          </div>
                          <div className="bg-gray-50 p-2.5 rounded-lg border border-gray-200 break-all">
                            {result.technical_evidence.key_identifier}
                          </div>
                        </div>
                      )}

                      {result.technical_evidence.timestamp && (
                        <div>
                          <div className="font-semibold text-gray-500 uppercase text-[11px] mb-1 font-sans">
                            Timestamp (ISO UTC)
                          </div>
                          <div className="bg-gray-50 p-2.5 rounded-lg border border-gray-200 break-all">
                            {result.technical_evidence.timestamp}
                          </div>
                        </div>
                      )}

                      <div>
                        <div className="font-semibold text-gray-500 uppercase text-[11px] mb-1 font-sans">
                          Immutable Ledger Status
                        </div>
                        <div className="bg-gray-50 p-2.5 rounded-lg border border-gray-200 text-amber-700 font-medium">
                          {result.technical_evidence.ledger_status} ({result.technical_evidence.ledger_message})
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Action Buttons */}
              <div className="pt-2 flex flex-col sm:flex-row gap-3">
                {result.status === 'MATCH_FOUND' && (
                  <>
                    <button
                      type="button"
                      onClick={handleDownloadReport}
                      disabled={downloadingReport}
                      className="flex-1 py-2.5 px-4 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg shadow-sm text-xs uppercase tracking-wider transition-colors flex items-center justify-center space-x-2 disabled:opacity-75"
                    >
                      {downloadingReport ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <Download className="w-4 h-4" />
                      )}
                      <span>DOWNLOAD EVIDENCE REPORT</span>
                    </button>

                    <button
                      type="button"
                      onClick={handleExportJSON}
                      className="flex-1 py-2.5 px-4 bg-gray-800 hover:bg-gray-700 text-white font-semibold rounded-lg shadow-sm text-xs uppercase tracking-wider transition-colors flex items-center justify-center space-x-2"
                    >
                      <FileJson className="w-4 h-4" />
                      <span>EXPORT EVIDENCE JSON</span>
                    </button>
                  </>
                )}

                <button
                  type="button"
                  onClick={handleReset}
                  className="py-2.5 px-4 bg-gray-100 hover:bg-gray-200 text-gray-800 font-semibold rounded-lg border border-gray-300 text-xs uppercase tracking-wider transition-colors flex items-center justify-center space-x-2"
                >
                  <RefreshCw className="w-4 h-4" />
                  <span>Analyze Another Document</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Recent Investigations History Table */}
      <div className="mt-10 bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-gray-900">Recent Investigations</h3>
            <p className="text-xs text-gray-500 mt-0.5">Recorded forensic provenance analysis sessions</p>
          </div>
          <button
            type="button"
            onClick={fetchHistory}
            className="p-1 text-gray-400 hover:text-gray-600 rounded transition-colors"
            title="Refresh history"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>

        {history.length === 0 ? (
          <div className="p-8 text-center text-xs text-gray-500">
            No investigations conducted yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-50 border-b border-gray-200 text-gray-500 uppercase text-[10px] font-semibold">
                <tr>
                  <th className="px-6 py-3">Investigation ID</th>
                  <th className="px-6 py-3">Document</th>
                  <th className="px-6 py-3">Status</th>
                  <th className="px-6 py-3">Recipient Identity</th>
                  <th className="px-6 py-3">Verification</th>
                  <th className="px-6 py-3">Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {history.map((item, idx) => (
                  <tr key={idx} className="hover:bg-gray-50/60 transition-colors">
                    <td className="px-6 py-3.5 font-mono font-semibold text-blue-600">
                      {item.investigation_id}
                    </td>
                    <td className="px-6 py-3.5 font-medium text-gray-900">
                      {item.document_name}
                    </td>
                    <td className="px-6 py-3.5">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold ${
                          item.status === 'MATCH_FOUND'
                            ? 'bg-green-100 text-green-800'
                            : item.status === 'NO_WATERMARK'
                            ? 'bg-amber-100 text-amber-800'
                            : 'bg-red-100 text-red-800'
                        }`}
                      >
                        {item.status_label}
                      </span>
                    </td>
                    <td className="px-6 py-3.5 text-gray-700">
                      {item.recipient_identity || '—'}
                    </td>
                    <td className="px-6 py-3.5 text-gray-700 font-medium">
                      {item.verification_status}
                    </td>
                    <td className="px-6 py-3.5 text-gray-500">
                      {item.timestamp}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
