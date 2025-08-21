'use client';

import { useState } from 'react';

interface ScanFormProps {
  onSubmit: (target: string, scanType: string) => void;
  loading: boolean;
  scanTypes: string[];
}

// SVG Icons
const TargetIcon = () => (
  <svg className="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z" />
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v8m-4-4h8" />
  </svg>
);

const ShieldIcon = () => (
  <svg className="w-8 h-8 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
);

const ZapIcon = () => (
  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
  </svg>
);

const ScanIcon = () => (
  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
  </svg>
);

const WebIcon = () => (
  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
  </svg>
);

const AlertIcon = () => (
  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const scanTypeDescriptions = {
  quick: "Fast port scan (100 most common ports)",
  full: "Comprehensive scan with version detection",
  stealth: "Slower, less detectable scan",
  vulnerability: "Vulnerability assessment using NSE scripts",
  web: "Web application vulnerability scan using Nikto"
};

export default function ScanForm({ onSubmit, loading, scanTypes }: ScanFormProps) {
  const [target, setTarget] = useState('');
  const [selectedScanType, setSelectedScanType] = useState('quick');
  const [showTooltip, setShowTooltip] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (target.trim() && isValidTarget(target, selectedScanType)) {
      onSubmit(target.trim(), selectedScanType);
    }
  };

  const isValidTarget = (input: string, scanType: string) => {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
    const urlRegex = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
    
    // For web scans, allow URLs and domains
    if (scanType === 'web') {
      return ipRegex.test(input) || domainRegex.test(input) || urlRegex.test(input) || input.startsWith('http://') || input.startsWith('https://');
    }
    
    // For network scans, allow IPs and domains
    return ipRegex.test(input) || domainRegex.test(input);
  };

  const getScanTypeIcon = (type: string) => {
    switch (type) {
      case 'quick': return <ZapIcon />;
      case 'full': return <ScanIcon />;
      case 'stealth': return <ShieldIcon />;
      case 'web': return <WebIcon />;
      default: return <ScanIcon />;
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 mb-6">
      <div className="flex items-center mb-4">
        <ShieldIcon />
        <h2 className="text-2xl font-bold text-gray-800 dark:text-white ml-3">Security Scanner</h2>
      </div>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            Target URL or IP Address
          </label>
          <div className="relative">
            <div className="absolute left-3 top-1/2 transform -translate-y-1/2">
              <TargetIcon />
            </div>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={
                selectedScanType === 'web' 
                  ? "Enter target (e.g., example.com, https://example.com, 192.168.1.1)"
                  : "Enter target (e.g., 192.168.1.1, example.com)"
              }
              className="w-full pl-10 pr-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:text-white transition-colors"
              disabled={loading}
            />
          </div>
          {target && !isValidTarget(target, selectedScanType) && (
            <p className="text-sm text-red-500 mt-1 flex items-center">
              <AlertIcon />
              <span className="ml-1">
                {selectedScanType === 'web' 
                  ? "Please enter a valid IP address, domain, or URL"
                  : "Please enter a valid IP address or domain"}
              </span>
            </p>
          )}
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            Scan Type
          </label>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
            {scanTypes.map((type) => (
              <div 
                key={type}
                className="relative"
                onMouseEnter={() => setShowTooltip(type)}
                onMouseLeave={() => setShowTooltip(null)}
              >
                <button
                  type="button"
                  onClick={() => setSelectedScanType(type)}
                  className={`w-full p-3 rounded-lg border-2 text-center transition-all ${
                    selectedScanType === type
                      ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300'
                      : 'border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:border-gray-400'
                  }`}
                  disabled={loading}
                >
                  <div className="flex items-center justify-center">
                    {getScanTypeIcon(type)}
                    <span className="ml-2">{type.charAt(0).toUpperCase() + type.slice(1)}</span>
                  </div>
                </button>
                
                {showTooltip === type && (
                  <div className="absolute z-10 w-48 p-2 mt-1 text-sm text-gray-700 bg-white border border-gray-200 rounded-lg shadow-lg dark:bg-gray-800 dark:text-gray-300 dark:border-gray-600">
                    {scanTypeDescriptions[type as keyof typeof scanTypeDescriptions]}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        <button
          type="submit"
          disabled={loading || !isValidTarget(target, selectedScanType)}
          className="w-full bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 disabled:from-gray-400 disabled:to-gray-500 text-white font-semibold py-3 px-4 rounded-lg transition-all duration-200 transform hover:scale-105 disabled:scale-100 disabled:cursor-not-allowed shadow-md"
        >
          {loading ? (
            <div className="flex items-center justify-center">
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
              Scanning...
            </div>
          ) : (
            `Start ${selectedScanType.charAt(0).toUpperCase() + selectedScanType.slice(1)} Scan`
          )}
        </button>
      </form>
    </div>
  );
}