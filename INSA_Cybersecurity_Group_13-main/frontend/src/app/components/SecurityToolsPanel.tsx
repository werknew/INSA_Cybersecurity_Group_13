'use client';
import React, { useState, useEffect } from 'react';
import { 
  FaSearch, 
  FaGlobe, 
  FaShieldAlt, 
  FaNetworkWired, 
  FaCertificate,
  FaExclamationTriangle,
  FaCheckCircle,
  FaSpinner,
  FaInfoCircle,
  FaExternalLinkAlt,
  FaRobot
} from 'react-icons/fa';

interface SecurityToolsPanelProps {
  onToolResult?: (tool: string, result: any) => void;
}

interface ToolResult {
  success: boolean;
  error?: string;
  source?: string;
  input_used?: string;
  original_input?: string;
  data?: any;
  note?: string;
  suggestions?: string[];
}

export default function SecurityToolsPanel({ onToolResult }: SecurityToolsPanelProps) {
  const [activeTool, setActiveTool] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<{[key: string]: ToolResult}>({});
  const [inputValue, setInputValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [toolsStatus, setToolsStatus] = useState<any>(null);

  const tools = [
    {
      id: 'shodan',
      name: 'Shodan Lookup',
      description: 'Internet-wide device intelligence',
      icon: FaNetworkWired,
      inputPlaceholder: 'Enter IP address or domain',
      color: 'text-blue-400',
      inputType: 'ip'
    },
    {
      id: 'virustotal-ip',
      name: 'VirusTotal IP',
      description: 'IP reputation analysis',
      icon: FaShieldAlt,
      inputPlaceholder: 'Enter IP address or domain',
      color: 'text-green-400',
      inputType: 'ip'
    },
    {
      id: 'abuseipdb',
      name: 'AbuseIPDB',
      description: 'IP abuse reputation',
      icon: FaExclamationTriangle,
      inputPlaceholder: 'Enter IP address or domain',
      color: 'text-red-400',
      inputType: 'ip'
    },
    {
      id: 'dns',
      name: 'DNS Lookup',
      description: 'DNS record analysis',
      icon: FaGlobe,
      inputPlaceholder: 'Enter domain (example.com)',
      color: 'text-purple-400',
      inputType: 'domain'
    },
    {
      id: 'whois',
      name: 'WHOIS Lookup',
      description: 'Domain registration info',
      icon: FaInfoCircle,
      inputPlaceholder: 'Enter domain (example.com)',
      color: 'text-orange-400',
      inputType: 'domain'
    },
    {
      id: 'security-headers',
      name: 'Security Headers',
      description: 'HTTP security headers check',
      icon: FaShieldAlt,
      inputPlaceholder: 'Enter URL (https://example.com)',
      color: 'text-cyan-400',
      inputType: 'url'
    },
    {
      id: 'ssl-certificate',
      name: 'SSL Certificate',
      description: 'SSL/TLS certificate info',
      icon: FaCertificate,
      inputPlaceholder: 'Enter domain (example.com)',
      color: 'text-yellow-400',
      inputType: 'domain'
    },
    {
      id: 'domain-analysis',
      name: 'Full Domain Analysis',
      description: 'Comprehensive domain security',
      icon: FaSearch,
      inputPlaceholder: 'Enter domain (example.com)',
      color: 'text-pink-400',
      inputType: 'domain'
    }
  ];

  useEffect(() => {
    const checkToolsStatus = async () => {
      try {
        const token = localStorage.getItem('security_scanner_token');
        const response = await fetch('http://localhost:5000/api/tools/status', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        if (response.ok) {
          const status = await response.json();
          setToolsStatus(status);
        }
      } catch (error) {
        console.error('Failed to check tools status:', error);
      }
    };

    checkToolsStatus();
  }, []);

  const runTool = async (toolId: string, input: string) => {
    if (!input.trim()) {
      setError('Please enter a value');
      return;
    }

    setLoading(true);
    setError(null);
    setActiveTool(toolId);

    try {
      const token = localStorage.getItem('security_scanner_token');
      let endpoint = '';
      let method = 'GET';
      let body = null;

      switch (toolId) {
        case 'shodan':
          endpoint = `/api/tools/shodan/${encodeURIComponent(input)}`;
          break;
        case 'virustotal-ip':
          endpoint = `/api/tools/virustotal/ip/${encodeURIComponent(input)}`;
          break;
        case 'abuseipdb':
          endpoint = `/api/tools/abuseipdb/${encodeURIComponent(input)}`;
          break;
        case 'dns':
          endpoint = `/api/tools/dns/${encodeURIComponent(input)}`;
          break;
        case 'whois':
          endpoint = `/api/tools/whois/${encodeURIComponent(input)}`;
          break;
        case 'security-headers':
          endpoint = '/api/tools/security-headers';
          method = 'POST';
          body = JSON.stringify({ url: input });
          break;
        case 'ssl-certificate':
          endpoint = `/api/tools/ssl-certificate/${encodeURIComponent(input)}`;
          break;
        case 'domain-analysis':
          endpoint = `/api/tools/domain-analysis/${encodeURIComponent(input)}`;
          break;
        default:
          throw new Error('Unknown tool');
      }

      const response = await fetch(`http://localhost:5000${endpoint}`, {
        method,
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(errorData.error || `Tool failed: ${response.status}`);
      }

      const result = await response.json();
      
      setResults(prev => ({
        ...prev,
        [toolId]: result
      }));

      onToolResult?.(toolId, result);

    } catch (err: any) {
      setError(err.message);
      // Set a failed result for the tool
      setResults(prev => ({
        ...prev,
        [toolId]: {
          success: false,
          error: err.message
        }
      }));
    } finally {
      setLoading(false);
    }
  };

  const renderResult = (toolId: string, result: ToolResult) => {
    if (!result || typeof result !== 'object') {
      return (
        <div className="p-4 bg-red-500/20 border border-red-500/30 rounded-lg text-red-400">
          Invalid result format received from tool
        </div>
      );
    }

    if (!result.success) {
      return (
        <div className="p-4 bg-red-500/20 border border-red-500/30 rounded-lg">
          <div className="flex items-center gap-2 text-red-400 mb-2">
            <FaExclamationTriangle />
            <span className="font-semibold">Error</span>
          </div>
          <p className="text-red-400 mb-3">{result.error || 'Unknown error occurred'}</p>
          
          {result.suggestions && Array.isArray(result.suggestions) && (
            <div className="mt-3">
              <p className="text-yellow-400 text-sm mb-2">Suggestions:</p>
              <ul className="text-yellow-400/80 text-sm list-disc list-inside space-y-1">
                {result.suggestions.map((suggestion: string, index: number) => (
                  <li key={index}>{suggestion}</li>
                ))}
              </ul>
            </div>
          )}
          
          {result.input_used && (
            <p className="text-gray-400 text-sm mt-2">
              Input used: <code className="bg-gray-700 px-1 rounded">{result.input_used}</code>
            </p>
          )}
        </div>
      );
    }

    // Show source information
    const sourceInfo = result.source ? (
      <div className="mb-4 p-2 bg-gray-700/30 rounded text-sm">
        <span className="text-gray-400">Source: </span>
        <span className={result.source === 'demo' ? 'text-yellow-400' : 'text-green-400'}>
          {result.source === 'demo' ? 'Demo Data' : 'Live API'}
        </span>
        {result.note && (
          <span className="text-gray-400 ml-2">• {result.note}</span>
        )}
      </div>
    ) : null;

    switch (toolId) {
      case 'shodan':
        return (
          <div className="space-y-4">
            {sourceInfo}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">Organization</p>
                <p className="text-white font-semibold">{result.data?.org || 'Unknown'}</p>
              </div>
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">Operating System</p>
                <p className="text-white font-semibold">{result.data?.os || 'Unknown'}</p>
              </div>
            </div>
            
            {result.data?.ports && result.data.ports.length > 0 && (
              <div>
                <p className="text-gray-400 text-sm mb-2">Open Ports</p>
                <div className="flex flex-wrap gap-2">
                  {result.data.ports.map((port: number, index: number) => (
                    <span key={index} className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-sm">
                      {port}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {result.data?.services && result.data.services.length > 0 && (
              <div>
                <p className="text-gray-400 text-sm mb-2">Services</p>
                <div className="space-y-2">
                  {result.data.services.slice(0, 5).map((service: any, index: number) => (
                    <div key={index} className="p-2 bg-gray-700/30 rounded">
                      <p className="text-white text-sm">
                        Port {service.port}: {service.service} {service.version}
                      </p>
                      {service.banner && (
                        <p className="text-gray-400 text-xs mt-1 truncate">{service.banner}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );

      case 'virustotal-ip':
        return (
          <div className="space-y-4">
            {sourceInfo}
            <div className="grid grid-cols-3 gap-4">
              <div className="p-3 bg-gray-700/30 rounded-lg text-center">
                <p className="text-2xl font-bold text-green-400">
                  {result.data?.last_analysis_stats?.harmless || 0}
                </p>
                <p className="text-gray-400 text-sm">Clean</p>
              </div>
              <div className="p-3 bg-gray-700/30 rounded-lg text-center">
                <p className="text-2xl font-bold text-red-400">
                  {result.data?.last_analysis_stats?.malicious || 0}
                </p>
                <p className="text-gray-400 text-sm">Malicious</p>
              </div>
              <div className="p-3 bg-gray-700/30 rounded-lg text-center">
                <p className="text-2xl font-bold text-yellow-400">
                  {result.data?.reputation || 0}
                </p>
                <p className="text-gray-400 text-sm">Reputation</p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">AS Owner</p>
                <p className="text-white font-semibold">{result.data?.as_owner || 'Unknown'}</p>
              </div>
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">Country</p>
                <p className="text-white font-semibold">{result.data?.country || 'Unknown'}</p>
              </div>
            </div>
          </div>
        );

      case 'abuseipdb':
        return (
          <div className="space-y-4">
            {sourceInfo}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 bg-gray-700/30 rounded-lg text-center">
                <p className={`text-2xl font-bold ${
                  (result.data?.abuse_confidence_score || 0) >= 80 ? 'text-red-400' :
                  (result.data?.abuse_confidence_score || 0) >= 50 ? 'text-orange-400' : 'text-green-400'
                }`}>
                  {result.data?.abuse_confidence_score || 0}%
                </p>
                <p className="text-gray-400 text-sm">Abuse Score</p>
              </div>
              <div className="p-3 bg-gray-700/30 rounded-lg text-center">
                <p className="text-2xl font-bold text-white">
                  {result.data?.total_reports || 0}
                </p>
                <p className="text-gray-400 text-sm">Total Reports</p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">ISP</p>
                <p className="text-white font-semibold">{result.data?.isp || 'Unknown'}</p>
              </div>
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">Country</p>
                <p className="text-white font-semibold">{result.data?.country_code || 'Unknown'}</p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">Whitelisted</p>
                <p className={`font-semibold ${result.data?.is_whitelisted ? 'text-green-400' : 'text-red-400'}`}>
                  {result.data?.is_whitelisted ? 'Yes' : 'No'}
                </p>
              </div>
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">Public IP</p>
                <p className={`font-semibold ${result.data?.is_public ? 'text-green-400' : 'text-red-400'}`}>
                  {result.data?.is_public ? 'Yes' : 'No'}
                </p>
              </div>
            </div>
          </div>
        );

      case 'dns':
        return (
          <div className="space-y-4">
            {sourceInfo}
            {result.data?.results && typeof result.data.results === 'object' ? (
              Object.entries(result.data.results).map(([type, records]: [string, any]) => (
                <div key={type}>
                  <p className="text-gray-400 text-sm mb-2">{type} Records</p>
                  <div className="space-y-1">
                    {Array.isArray(records) && records.map((record: string, index: number) => (
                      <div key={index} className="p-2 bg-gray-700/30 rounded text-sm font-mono text-white">
                        {record}
                      </div>
                    ))}
                  </div>
                </div>
              ))
            ) : (
              <div className="text-gray-400 text-center py-4">
                No DNS records found
              </div>
            )}
          </div>
        );

      case 'whois':
        return (
          <div className="space-y-4">
            {sourceInfo}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">Registrar</p>
                <p className="text-white font-semibold">{result.data?.registrar || 'Unknown'}</p>
              </div>
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">Creation Date</p>
                <p className="text-white font-semibold">{result.data?.creation_date || 'Unknown'}</p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">Expiration Date</p>
                <p className="text-white font-semibold">{result.data?.expiration_date || 'Unknown'}</p>
              </div>
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">Status</p>
                <p className="text-white font-semibold">{result.data?.status || 'Unknown'}</p>
              </div>
            </div>

            {result.data?.name_servers && result.data.name_servers.length > 0 && (
              <div>
                <p className="text-gray-400 text-sm mb-2">Name Servers</p>
                <div className="space-y-1">
                  {result.data.name_servers.slice(0, 5).map((ns: string, index: number) => (
                    <div key={index} className="p-2 bg-gray-700/30 rounded text-sm text-white">
                      {ns}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );

      case 'security-headers':
        return (
          <div className="space-y-4">
            {sourceInfo}
            <div className="flex items-center gap-4">
              <div className="p-3 bg-gray-700/30 rounded-lg text-center">
                <p className="text-2xl font-bold text-white">
                  {result.data?.security_score || 0}/{result.data?.max_score || 7}
                </p>
                <p className="text-gray-400 text-sm">Security Score</p>
              </div>
              <div className="p-3 bg-gray-700/30 rounded-lg text-center">
                <p className={`text-2xl font-bold ${
                  result.data?.grade === 'A' ? 'text-green-400' :
                  result.data?.grade === 'B' ? 'text-yellow-400' :
                  result.data?.grade === 'C' ? 'text-orange-400' : 'text-red-400'
                }`}>
                  {result.data?.grade || 'F'}
                </p>
                <p className="text-gray-400 text-sm">Grade</p>
              </div>
            </div>

            {result.data?.security_headers && (
              <div>
                <p className="text-gray-400 text-sm mb-2">Security Headers</p>
                <div className="space-y-2">
                  {Object.entries(result.data.security_headers).map(([header, value]: [string, any]) => (
                    <div key={header} className="flex justify-between items-center p-2 bg-gray-700/30 rounded">
                      <span className="text-gray-300 text-sm">{header}</span>
                      <span className={`text-sm ${value ? 'text-green-400' : 'text-red-400'}`}>
                        {value ? <FaCheckCircle /> : 'Missing'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );

      case 'ssl-certificate':
        return (
          <div className="space-y-4">
            {sourceInfo}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">Issuer</p>
                <p className="text-white font-semibold text-sm">{result.data?.issuer || 'Unknown'}</p>
              </div>
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">Expires In</p>
                <p className={`text-xl font-bold ${
                  (result.data?.days_until_expiry || 0) < 30 ? 'text-red-400' :
                  (result.data?.days_until_expiry || 0) < 90 ? 'text-orange-400' : 'text-green-400'
                }`}>
                  {result.data?.days_until_expiry || 0} days
                </p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">Valid From</p>
                <p className="text-white text-sm">
                  {result.data?.not_valid_before ? 
                    new Date(result.data.not_valid_before).toLocaleDateString() : 'Unknown'
                  }
                </p>
              </div>
              <div className="p-3 bg-gray-700/30 rounded-lg">
                <p className="text-gray-400 text-sm">Valid Until</p>
                <p className="text-white text-sm">
                  {result.data?.not_valid_after ? 
                    new Date(result.data.not_valid_after).toLocaleDateString() : 'Unknown'
                  }
                </p>
              </div>
            </div>

            <div className="p-3 bg-gray-700/30 rounded-lg">
              <p className="text-gray-400 text-sm">Subject</p>
              <p className="text-white text-sm">{result.data?.subject || 'Unknown'}</p>
            </div>
          </div>
        );

      case 'domain-analysis':
        return (
          <div className="space-y-4">
            {sourceInfo}
            {result.data?.dns_records && (
              <div>
                <p className="text-gray-400 text-sm mb-2">DNS Records Found</p>
                <div className="flex flex-wrap gap-2">
                  {Object.keys(result.data.dns_records).map((type) => (
                    <span key={type} className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-sm">
                      {type} ({Array.isArray(result.data.dns_records[type]) ? result.data.dns_records[type].length : 0})
                    </span>
                  ))}
                </div>
              </div>
            )}

            {result.data?.security_headers && (
              <div>
                <p className="text-gray-400 text-sm mb-2">Security Headers Grade</p>
                <span className={`px-3 py-1 rounded text-sm font-semibold ${
                  result.data.security_headers.grade === 'A' ? 'bg-green-500/20 text-green-400' :
                  result.data.security_headers.grade === 'B' ? 'bg-yellow-500/20 text-yellow-400' :
                  result.data.security_headers.grade === 'C' ? 'bg-orange-500/20 text-orange-400' : 'bg-red-500/20 text-red-400'
                }`}>
                  {result.data.security_headers.grade} ({result.data.security_headers.security_score}/{result.data.security_headers.max_score})
                </span>
              </div>
            )}

            {result.data?.ssl_certificate && (
              <div>
                <p className="text-gray-400 text-sm mb-2">SSL Certificate</p>
                <span className={`px-3 py-1 rounded text-sm font-semibold ${
                  (result.data.ssl_certificate.days_until_expiry || 0) > 30 ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                }`}>
                  Expires in {result.data.ssl_certificate.days_until_expiry} days
                </span>
              </div>
            )}

            {result.data?.whois && (
              <div>
                <p className="text-gray-400 text-sm mb-2">WHOIS Information</p>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div>
                    <span className="text-gray-500">Registrar:</span>
                    <span className="text-white ml-2">{result.data.whois.registrar}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">Created:</span>
                    <span className="text-white ml-2">{result.data.whois.creation_date}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        );

      default:
        return (
          <div className="space-y-4">
            {sourceInfo}
            <div className="p-4 bg-gray-700/30 rounded-lg">
              <pre className="text-sm text-white overflow-auto max-h-60">
                {JSON.stringify(result.data || result, null, 2)}
              </pre>
            </div>
          </div>
        );
    }
  };

  return (
    <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700 p-6">
      <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-3">
        <FaRobot className="text-blue-400" />
        Advanced Security Tools
      </h2>

      {/* Tools Status */}
      {toolsStatus?.demo_mode && (
        <div className="mb-4 p-3 bg-yellow-500/20 border border-yellow-500/30 rounded-lg text-yellow-400 text-sm">
          <p>🔧 <strong>Demo Mode Active</strong></p>
          <p className="mt-1">Some tools are using demo data. Add API keys to .env for real results.</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {!toolsStatus.tools_available?.shodan && (
              <span className="px-2 py-1 bg-gray-700/50 rounded text-xs">Shodan: Demo</span>
            )}
            {!toolsStatus.tools_available?.virustotal && (
              <span className="px-2 py-1 bg-gray-700/50 rounded text-xs">VirusTotal: Demo</span>
            )}
            {!toolsStatus.tools_available?.abuseipdb && (
              <span className="px-2 py-1 bg-gray-700/50 rounded text-xs">AbuseIPDB: Demo</span>
            )}
          </div>
        </div>
      )}

      {/* Tool Selection */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        {tools.map((tool) => (
          <button
            key={tool.id}
            onClick={() => setActiveTool(activeTool === tool.id ? null : tool.id)}
            className={`p-3 rounded-lg border transition-all ${
              activeTool === tool.id
                ? 'bg-blue-500/20 border-blue-500/50 text-blue-400'
                : 'bg-gray-700/50 border-gray-600 text-gray-300 hover:border-gray-500'
            }`}
          >
            <div className="flex flex-col items-center gap-2">
              <tool.icon className={`text-xl ${tool.color}`} />
              <span className="text-xs font-semibold text-center">{tool.name}</span>
            </div>
          </button>
        ))}
      </div>

      {/* Tool Input */}
      {activeTool && (
        <div className="mb-6 p-4 bg-gray-700/30 rounded-lg border border-gray-600">
          <div className="flex gap-3">
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder={tools.find(t => t.id === activeTool)?.inputPlaceholder}
              className="flex-1 bg-gray-600/50 border border-gray-500 rounded-lg px-4 py-2 text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              onKeyPress={(e) => e.key === 'Enter' && runTool(activeTool, inputValue)}
            />
            <button
              onClick={() => runTool(activeTool, inputValue)}
              disabled={loading}
              className="px-6 py-2 bg-gradient-to-r from-blue-500 to-purple-500 text-white rounded-lg font-semibold hover:shadow-lg transition-all disabled:opacity-50 flex items-center gap-2"
            >
              {loading ? <FaSpinner className="animate-spin" /> : <FaSearch />}
              {loading ? 'Running...' : 'Run Tool'}
            </button>
          </div>
          
          {error && (
            <div className="mt-3 p-3 bg-red-500/20 border border-red-500/30 rounded-lg text-red-400 text-sm">
              {error}
            </div>
          )}

          {/* Input Examples */}
          <div className="mt-3 text-xs text-gray-500">
            <span className="font-semibold">Try: </span>
            {activeTool === 'shodan' && '8.8.8.8, 1.1.1.1, google.com'}
            {activeTool === 'virustotal-ip' && '8.8.8.8, 1.1.1.1, malware.com'}
            {activeTool === 'abuseipdb' && '8.8.8.8, 1.1.1.1, 192.168.1.1'}
            {activeTool === 'dns' && 'google.com, github.com, example.com'}
            {activeTool === 'whois' && 'google.com, github.com, example.com'}
            {activeTool === 'security-headers' && 'https://google.com, https://github.com'}
            {activeTool === 'ssl-certificate' && 'google.com, github.com, example.com'}
            {activeTool === 'domain-analysis' && 'google.com, github.com, example.com'}
          </div>
        </div>
      )}

      {/* Results Display */}
      {activeTool && results[activeTool] && (
        <div className="border-t border-gray-600 pt-6">
          <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            {tools.find(t => t.id === activeTool)?.icon && 
              React.createElement(tools.find(t => t.id === activeTool)!.icon, { 
                className: tools.find(t => t.id === activeTool)!.color 
              })
            }
            {tools.find(t => t.id === activeTool)?.name} Results
            {results[activeTool]?.input_used && results[activeTool].input_used !== inputValue && (
              <span className="text-sm text-gray-400 font-normal">
                (for {results[activeTool].input_used})
              </span>
            )}
          </h3>
          {renderResult(activeTool, results[activeTool])}
        </div>
      )}

      {/* No Tool Selected */}
      {!activeTool && (
        <div className="text-center py-8 text-gray-500">
          <FaSearch className="text-4xl mx-auto mb-4 opacity-50" />
          <p>Select a security tool to begin analysis</p>
          <p className="text-sm mt-2">Choose from the available tools above</p>
          <div className="mt-4 grid grid-cols-2 gap-2 text-xs text-gray-600">
            <div>• IP Intelligence</div>
            <div>• DNS Analysis</div>
            <div>• Security Headers</div>
            <div>• SSL Certificates</div>
          </div>
        </div>
      )}
    </div>
  );
}