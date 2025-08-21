'use client';

import { useState } from 'react';

interface Vulnerability {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  solution?: string;
  cve?: string;
  reference?: string;
}

interface Port {
  number: string;
  state: 'open' | 'closed' | 'filtered';
  service: string;
  version?: string;
}

interface ScanResultsData {
  target: string;
  timestamp: string;
  scanType: string;
  status: 'completed' | 'failed' | 'in-progress';
  ports?: Port[];
  vulnerabilities?: Vulnerability[];
  services?: any[];
  summary?: {
    openPorts: number;
    vulnerabilities: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
    };
    scanDuration: string;
  };
}

interface ScanResultsProps {
  results: ScanResultsData | null;
  loading: boolean;
}

// SVG Icons
const CheckCircleIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const XCircleIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const AlertCircleIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const ClockIcon = () => (
  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const ShieldIcon = ({ className = "w-16 h-16" }: { className?: string }) => (
  <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
);

const ExternalLinkIcon = () => (
  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
  </svg>
);

const CopyIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
  </svg>
);

const ChevronDownIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
  </svg>
);

const ChevronUpIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
  </svg>
);

export default function ScanResults({ results, loading }: ScanResultsProps) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['summary']));
  const [copiedText, setCopiedText] = useState<string>('');

  const toggleSection = (section: string) => {
    const newSections = new Set(expandedSections);
    if (newSections.has(section)) {
      newSections.delete(section);
    } else {
      newSections.add(section);
    }
    setExpandedSections(newSections);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(''), 2000);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
      case 'high': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
      case 'medium': return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200';
      case 'low': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200';
      default: return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <XCircleIcon />;
      case 'high': return <XCircleIcon />;
      case 'medium': return <AlertCircleIcon />;
      case 'low': return <AlertCircleIcon />;
      default: return <CheckCircleIcon />;
    }
  };

  if (loading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
          <span className="ml-3 text-gray-600 dark:text-gray-300">Scanning in progress...</span>
        </div>
      </div>
    );
  }

  if (!results) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 text-center py-12">
        <ShieldIcon className="w-16 h-16 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-gray-600 dark:text-gray-300">
          No scan results yet
        </h3>
        <p className="text-gray-500 dark:text-gray-400">
          Run a scan to see detailed security analysis results
        </p>
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg overflow-hidden">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-500 to-blue-600 p-6 text-white">
        <div className="flex justify-between items-start">
          <div>
            <h2 className="text-2xl font-bold mb-2">Scan Results</h2>
            <p className="opacity-90">{results.target}</p>
            <div className="flex items-center mt-2 space-x-4 text-sm">
              <span className="flex items-center">
                <ClockIcon />
                <span className="ml-1">{new Date(results.timestamp).toLocaleString()}</span>
              </span>
              <span className="bg-blue-700 px-2 py-1 rounded-full text-xs">
                {results.scanType} scan
              </span>
            </div>
          </div>
          <button
            onClick={() => copyToClipboard(JSON.stringify(results, null, 2))}
            className="bg-white/20 hover:bg-white/30 p-2 rounded-lg transition-colors"
            title="Copy results to clipboard"
          >
            <CopyIcon />
          </button>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Summary Section */}
        {results.summary && (
          <div className="border rounded-lg overflow-hidden">
            <button
              onClick={() => toggleSection('summary')}
              className="w-full p-4 bg-gray-50 dark:bg-gray-700 flex justify-between items-center"
            >
              <h3 className="font-semibold text-lg">Summary</h3>
              {expandedSections.has('summary') ? (
                <ChevronUpIcon />
              ) : (
                <ChevronDownIcon />
              )}
            </button>
            {expandedSections.has('summary') && (
              <div className="p-4 space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  <div className="text-center p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
                    <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                      {results.summary.openPorts}
                    </div>
                    <div className="text-sm">Open Ports</div>
                  </div>
                  <div className="text-center p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
                    <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                      {results.summary.vulnerabilities.critical || 0}
                    </div>
                    <div className="text-sm">Critical</div>
                  </div>
                  <div className="text-center p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
                    <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                      {results.summary.vulnerabilities.high}
                    </div>
                    <div className="text-sm">High Risk</div>
                  </div>
                  <div className="text-center p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
                    <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
                      {results.summary.vulnerabilities.medium}
                    </div>
                    <div className="text-sm">Medium Risk</div>
                  </div>
                  <div className="text-center p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                    <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                      {results.summary.scanDuration}
                    </div>
                    <div className="text-sm">Duration</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Ports Section */}
        {results.ports && results.ports.length > 0 && (
          <div className="border rounded-lg overflow-hidden">
            <button
              onClick={() => toggleSection('ports')}
              className="w-full p-4 bg-gray-50 dark:bg-gray-700 flex justify-between items-center"
            >
              <h3 className="font-semibold text-lg">Open Ports ({results.ports.length})</h3>
              {expandedSections.has('ports') ? (
                <ChevronUpIcon />
              ) : (
                <ChevronDownIcon />
              )}
            </button>
            {expandedSections.has('ports') && (
              <div className="p-4">
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left p-2">Port</th>
                        <th className="text-left p-2">State</th>
                        <th className="text-left p-2">Service</th>
                        <th className="text-left p-2">Version</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.ports.map((port: Port, index: number) => (
                        <tr key={index} className="border-b last:border-b-0">
                          <td className="p-2 font-mono">{port.number}</td>
                          <td className="p-2">
                            <span className={`px-2 py-1 rounded-full text-xs ${
                              port.state === 'open' 
                                ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                                : 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200'
                            }`}>
                              {port.state}
                            </span>
                          </td>
                          <td className="p-2">{port.service}</td>
                          <td className="p-2 text-sm text-gray-600 dark:text-gray-400">
                            {port.version || 'Unknown'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Vulnerabilities Section */}
        {results.vulnerabilities && results.vulnerabilities.length > 0 && (
          <div className="border rounded-lg overflow-hidden">
            <button
              onClick={() => toggleSection('vulnerabilities')}
              className="w-full p-4 bg-gray-50 dark:bg-gray-700 flex justify-between items-center"
            >
              <h3 className="font-semibold text-lg">
                Vulnerabilities ({results.vulnerabilities.length})
              </h3>
              {expandedSections.has('vulnerabilities') ? (
                <ChevronUpIcon />
              ) : (
                <ChevronDownIcon />
              )}
            </button>
            {expandedSections.has('vulnerabilities') && (
              <div className="p-4 space-y-4">
                {results.vulnerabilities.map((vuln: Vulnerability, index: number) => (
                  <div key={index} className="border rounded-lg p-4">
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center">
                        <span className={`p-2 rounded-full mr-3 ${getSeverityColor(vuln.severity)}`}>
                          {getSeverityIcon(vuln.severity)}
                        </span>
                        <span className="font-semibold capitalize">{vuln.severity} severity</span>
                      </div>
                      {vuln.cve && (
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${vuln.cve}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center text-blue-500 hover:text-blue-700 text-sm"
                        >
                          {vuln.cve}
                          <ExternalLinkIcon />
                        </a>
                      )}
                    </div>
                    <p className="text-gray-700 dark:text-gray-300 mb-3">{vuln.description}</p>
                    {vuln.solution && (
                      <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-lg">
                        <h4 className="font-semibold text-blue-800 dark:text-blue-200 mb-2">
                          Recommended Solution
                        </h4>
                        <p className="text-blue-700 dark:text-blue-300">{vuln.solution}</p>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Raw JSON (Collapsible) */}
        <div className="border rounded-lg overflow-hidden">
          <button
            onClick={() => toggleSection('raw')}
            className="w-full p-4 bg-gray-50 dark:bg-gray-700 flex justify-between items-center"
          >
            <h3 className="font-semibold text-lg">Raw Data</h3>
            {expandedSections.has('raw') ? (
              <ChevronUpIcon />
            ) : (
              <ChevronDownIcon />
            )}
          </button>
          {expandedSections.has('raw') && (
            <div className="p-4 bg-gray-50 dark:bg-gray-900">
              <pre className="bg-white dark:bg-gray-800 p-4 rounded-lg overflow-x-auto text-sm">
                {JSON.stringify(results, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>

      {/* Copy success notification */}
      {copiedText && (
        <div className="fixed bottom-4 right-4 bg-green-500 text-white px-4 py-2 rounded-lg shadow-lg">
          Copied to clipboard!
        </div>
      )}
    </div>
  );
}