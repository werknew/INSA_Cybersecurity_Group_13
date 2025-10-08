// app/scans/page.tsx
'use client';
import React, { useState, useEffect } from 'react';
import SecurityLayout from '../components/Layout';
import SecurityCard from '../components/Card';
import ProtectedRoute from '../components/ProtectedRoute';
import { useAuth } from '../components/AuthContext';
import AIAnalysisPanel from '../components/AIAnalysisPanel';
import SecurityToolsPanel from '../components/SecurityToolsPanel';
import { 
  FaSearch, 
  FaExclamationTriangle, 
  FaCheckCircle, 
  FaBug, 
  FaNetworkWired,
  FaPlay,
  FaRadiation,
  FaShieldAlt,
  FaClock,
  FaServer,
  FaGlobe,
  FaStop,
  FaTrash,
  FaSync,
  FaRobot,
  FaBrain
} from 'react-icons/fa';
import io, { Socket } from 'socket.io-client';

interface Scan {
  id: number;
  target: string;
  type: string;
  status: 'running' | 'completed' | 'failed' | 'terminated';
  start_time: string;
  progress: number;
  vulnerabilities_found: number;
  results?: any[];
  error?: string;
  user_email?: string;
}

interface Vulnerability {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  port?: string;
  protocol?: string;
  service?: string;
  evidence: string;
  solution: string;
  cve?: string;
  type: string;
  ai_analysis?: any;
  ai_priority_score?: number;
  ai_priority_reason?: string;
  ai_recommended_timeline?: string;
}

export default function ScansPage() {
  const [scanType, setScanType] = useState('quick');
  const [target, setTarget] = useState('');
  const [scans, setScans] = useState<Scan[]>([]);
  const [scanning, setScanning] = useState(false);
  const [stats, setStats] = useState({
    total_scans: 0,
    completed_scans: 0,
    running_scans: 0,
    vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 }
  });
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [socket, setSocket] = useState<Socket | null>(null);
  const [backendStatus, setBackendStatus] = useState<'connected' | 'disconnected' | 'checking'>('checking');
  const [terminatingScan, setTerminatingScan] = useState<number | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<any>(null);
  const [showAIPanel, setShowAIPanel] = useState(false);
  
  const { token } = useAuth();

  // Initialize socket connection
  useEffect(() => {
    if (!token) return;

    const newSocket = io('http://localhost:5000', {
      auth: {
        token: token
      }
    });
    
    newSocket.on('connect', () => {
      console.log('✅ Connected to backend');
      setBackendStatus('connected');
    });

    newSocket.on('disconnect', () => {
      console.log('❌ Disconnected from backend');
      setBackendStatus('disconnected');
    });

    newSocket.on('scan_progress', (data) => {
      console.log('📊 Scan progress:', data);
      setScans(prev => prev.map(scan => 
        scan.id === data.scan_id 
          ? { ...scan, progress: data.progress }
          : scan
      ));
      
      // Update selected scan if it's the one in progress
      if (selectedScan && selectedScan.id === data.scan_id) {
        setSelectedScan(prev => prev ? { ...prev, progress: data.progress } : null);
      }
    });

    newSocket.on('scan_completed', (data) => {
      console.log('🎉 Scan completed:', data);
      fetchScans();
      fetchStats();
    });

    newSocket.on('scan_terminated', (data) => {
      console.log('🛑 Scan terminated:', data);
      fetchScans();
      fetchStats();
      setTerminatingScan(null);
    });

    setSocket(newSocket);

    return () => {
      newSocket.close();
    };
  }, [token]);

  // Fetch initial data
  useEffect(() => {
    if (token) {
      checkBackendHealth();
      fetchScans();
      fetchStats();
      
      const interval = setInterval(() => {
        fetchScans();
      }, 2000);

      return () => clearInterval(interval);
    }
  }, [token]);

  const checkBackendHealth = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/health');
      if (response.ok) {
        setBackendStatus('connected');
      } else {
        setBackendStatus('disconnected');
      }
    } catch (error) {
      setBackendStatus('disconnected');
    }
  };

  const fetchScans = async () => {
    if (!token) return;
    
    try {
      const response = await fetch('http://localhost:5000/api/scans', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (!response.ok) throw new Error('Failed to fetch scans');
      const data = await response.json();
      setScans(data);
    } catch (error) {
      console.error('Failed to fetch scans:', error);
    }
  };

  const fetchStats = async () => {
    if (!token) return;
    
    try {
      const response = await fetch('http://localhost:5000/api/stats', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (!response.ok) throw new Error('Failed to fetch stats');
      const data = await response.json();
      setStats(data);
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  };

  const fetchVulnerabilities = async (scanId: number) => {
    if (!token) return;
    
    try {
      const response = await fetch(`http://localhost:5000/api/scan/${scanId}/vulnerabilities`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (!response.ok) throw new Error('Failed to fetch vulnerabilities');
      const data = await response.json();
      setVulnerabilities(data);
    } catch (error) {
      console.error('Failed to fetch vulnerabilities:', error);
    }
  };

  const handleStartScan = async () => {
    if (!target.trim()) {
      alert('Please enter a target IP or URL.');
      return;
    }

    if (backendStatus !== 'connected') {
      alert('Backend is not connected. Please make sure the Python backend is running on port 5000.');
      return;
    }

    if (!token) {
      alert('Authentication required. Please log in again.');
      return;
    }

    setScanning(true);
    try {
      const response = await fetch('http://localhost:5000/api/scan', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ 
          target: target.trim(), 
          scanType: scanType 
        })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to start scan');
      }
      
      const result = await response.json();
      console.log('🚀 Scan started successfully:', result);
      
      // Refresh scans list
      fetchScans();
      fetchStats();
      
    } catch (error: any) {
      console.error('❌ Failed to start scan:', error);
      alert(`Failed to start scan: ${error.message || 'Unknown error'}`);
    } finally {
      setScanning(false);
      setTarget('');
    }
  };

  const handleTerminateScan = async (scanId: number) => {
    if (!confirm('Are you sure you want to terminate this scan?')) {
      return;
    }

    if (!token) {
      alert('Authentication required. Please log in again.');
      return;
    }

    setTerminatingScan(scanId);
    try {
      const response = await fetch(`http://localhost:5000/api/scan/${scanId}/terminate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to terminate scan');
      }
      
      console.log('🛑 Scan terminated successfully');
      
    } catch (error: any) {
      console.error('❌ Failed to terminate scan:', error);
      alert(`Failed to terminate scan: ${error.message || 'Unknown error'}`);
      setTerminatingScan(null);
    }
  };

  const handleScanSelect = async (scan: Scan) => {
    setSelectedScan(scan);
    setAiAnalysis(null);
    setShowAIPanel(false);
    
    if (scan.status === 'completed') {
      await fetchVulnerabilities(scan.id);
    }
  };

  const clearSelectedScan = () => {
    setSelectedScan(null);
    setVulnerabilities([]);
    setAiAnalysis(null);
    setShowAIPanel(false);
  };

  const handleAIAnalysisComplete = (analysis: any) => {
    setAiAnalysis(analysis);
    // Update vulnerabilities with AI prioritization
    if (analysis.prioritized_vulnerabilities) {
      setVulnerabilities(analysis.prioritized_vulnerabilities);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-400 bg-green-500/20 border-green-500/30';
      case 'running': return 'text-blue-400 bg-blue-500/20 border-blue-500/30';
      case 'failed': return 'text-red-400 bg-red-500/20 border-red-500/30';
      case 'terminated': return 'text-orange-400 bg-orange-500/20 border-orange-500/30';
      default: return 'text-gray-400 bg-gray-500/20 border-gray-500/30';
    }
  };

  const getScanIcon = (type: string) => {
    switch (type) {
      case 'web': return <FaGlobe className="text-purple-400" />;
      case 'full': return <FaServer className="text-orange-400" />;
      case 'stealth': return <FaShieldAlt className="text-green-400" />;
      default: return <FaSearch className="text-blue-400" />;
    }
  };

  const getEstimatedTime = (scanType: string): string => {
    const times = {
      'quick': '1-2 minutes',
      'web': '2-3 minutes', 
      'stealth': '2-4 minutes',
      'vulnerability': '3-5 minutes',
      'full': '4-6 minutes'
    };
    return times[scanType as keyof typeof times] || '2-5 minutes';
  };

  const getAIPriorityColor = (score: number) => {
    if (score >= 0.8) return 'text-red-400';
    if (score >= 0.6) return 'text-orange-400';
    if (score >= 0.4) return 'text-yellow-400';
    return 'text-green-400';
  };

  return (
    <ProtectedRoute>
      <SecurityLayout>
        {/* Header with Connection Status */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-white to-gray-300 bg-clip-text text-transparent mb-2">
                Security Scans
              </h1>
              <p className="text-gray-400">Fast vulnerability assessments with AI-powered analysis</p>
            </div>
            <div className="flex items-center gap-4">
              <button 
                onClick={fetchScans}
                className="px-4 py-2 bg-gray-700/50 border border-gray-600 rounded-lg text-gray-300 hover:bg-gray-600/50 transition-colors flex items-center gap-2"
              >
                <FaSync />
                Refresh
              </button>
              <div className={`px-4 py-2 rounded-lg border ${
                backendStatus === 'connected' 
                  ? 'bg-green-500/20 text-green-400 border-green-500/30' 
                  : 'bg-red-500/20 text-red-400 border-red-500/30'
              }`}>
                {backendStatus === 'connected' ? '✅ Connected' : '❌ Disconnected'}
              </div>
            </div>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <SecurityCard 
            title="Total Scans" 
            value={stats.total_scans}
            icon={<FaNetworkWired />}
            severity="info"
          />
          <SecurityCard 
            title="Critical Issues" 
            value={stats.vulnerabilities.critical}
            icon={<FaRadiation />}
            severity="critical"
          />
          <SecurityCard 
            title="High Risk" 
            value={stats.vulnerabilities.high}
            icon={<FaExclamationTriangle />}
            severity="high"
          />
          <SecurityCard 
            title="Active Scans" 
            value={stats.running_scans}
            icon={<FaClock />}
            severity="low"
          />
        </div>

        <div className="grid lg:grid-cols-2 gap-8">
          {/* Scan Control Panel */}
          <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700 p-6">
            <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-3">
              <FaSearch className="text-blue-400" />
              New Security Scan
            </h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-semibold text-gray-300 mb-2">
                  Scan Type
                </label>
                <select
                  value={scanType}
                  onChange={e => setScanType(e.target.value)}
                  className="w-full bg-gray-700/50 border border-gray-600 rounded-lg px-4 py-3 text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                >
                  <option value="quick">🚀 Quick Scan (Fastest)</option>
                  <option value="web">🌐 Web Scan (HTTP services)</option>
                  <option value="stealth">🕵️ Stealth Scan (Slower)</option>
                  <option value="vulnerability">🎯 Vulnerability Scan</option>
                  <option value="full">🔍 Full Scan (Comprehensive)</option>
                </select>
                <p className="text-xs text-gray-500 mt-1">
                  Estimated time: {getEstimatedTime(scanType)}
                </p>
              </div>

              <div>
                <label className="block text-sm font-semibold text-gray-300 mb-2">
                  Target
                </label>
                <input
                  type="text"
                  placeholder="scanme.nmap.org, example.com, or 192.168.1.1"
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  className="w-full bg-gray-700/50 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Try: scanme.nmap.org (test target) or your local network
                </p>
              </div>

              <button
                onClick={handleStartScan}
                disabled={scanning || backendStatus !== 'connected' || !token}
                className="w-full bg-gradient-to-r from-green-500 to-blue-500 text-white py-3 rounded-lg font-bold shadow-lg hover:shadow-blue-500/25 transform hover:scale-105 transition-all duration-200 disabled:opacity-50 disabled:transform-none flex items-center justify-center gap-2"
              >
                {scanning ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    Starting Scan...
                  </>
                ) : (
                  <>
                    <FaPlay />
                    Start Fast Scan
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Scan History with Termination */}
          <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700 p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-white">Scan History</h2>
              <div className="text-sm text-gray-400">
                {stats.running_scans > 0 && `${stats.running_scans} running`}
              </div>
            </div>
            
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {scans.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  <FaSearch className="text-4xl mx-auto mb-4 opacity-50" />
                  <p>No security scans yet</p>
                  <p className="text-sm mt-2">Start a scan to see results here</p>
                </div>
              ) : (
                scans.map(scan => (
                  <div 
                    key={scan.id} 
                    className={`p-4 rounded-lg border transition-all ${
                      selectedScan?.id === scan.id 
                        ? 'bg-blue-500/20 border-blue-500/50 scale-105' 
                        : 'bg-gray-700/50 border-gray-600 hover:border-gray-500 hover:scale-105'
                    }`}
                    onClick={() => handleScanSelect(scan)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3 flex-1">
                        <div className="p-2 rounded-lg bg-gray-600/50">
                          {getScanIcon(scan.type)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="font-semibold text-white truncate">{scan.target}</p>
                          <div className="flex items-center gap-2 mt-1">
                            <span className="text-sm text-gray-400 capitalize">{scan.type}</span>
                            <span className="text-xs text-gray-500">
                              {new Date(scan.start_time).toLocaleTimeString()}
                            </span>
                          </div>
                          {scan.user_email && (
                            <p className="text-xs text-gray-500">By: {scan.user_email}</p>
                          )}
                        </div>
                      </div>
                      
                      <div className="text-right flex items-center gap-3">
                        <div className="flex flex-col items-end">
                          <span className={`px-2 py-1 rounded text-xs font-bold ${getStatusColor(scan.status)}`}>
                            {scan.status}
                          </span>
                          {scan.status === 'running' && (
                            <div className="mt-1 flex items-center gap-2">
                              <div className="w-16 h-1 bg-gray-600 rounded-full overflow-hidden">
                                <div 
                                  className="h-full bg-green-500 rounded-full transition-all duration-300"
                                  style={{ width: `${scan.progress}%` }}
                                />
                              </div>
                              <span className="text-xs text-gray-400">{scan.progress}%</span>
                            </div>
                          )}
                          {scan.status === 'completed' && scan.vulnerabilities_found > 0 && (
                            <span className="text-xs text-red-400 mt-1">
                              {scan.vulnerabilities_found} issues
                            </span>
                          )}
                        </div>
                        
                        {scan.status === 'running' && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleTerminateScan(scan.id);
                            }}
                            disabled={terminatingScan === scan.id}
                            className="p-2 text-red-400 hover:bg-red-500/20 rounded-lg transition-colors disabled:opacity-50"
                            title="Terminate Scan"
                          >
                            {terminatingScan === scan.id ? (
                              <div className="w-4 h-4 border-2 border-red-400 border-t-transparent rounded-full animate-spin" />
                            ) : (
                              <FaStop />
                            )}
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
<div className="mt-8">
  <SecurityToolsPanel 
    onToolResult={(tool, result) => {
      console.log(`Tool ${tool} completed:`, result);
      // You can integrate tool results with your scan data
    }}
  />
</div>
        {/* Scan Results Panel */}
        {selectedScan && (
          <div className="mt-8 bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700 p-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-xl font-bold text-white">
                  Scan Results: {selectedScan.target}
                </h2>
                <p className="text-gray-400 text-sm">
                  {selectedScan.type} scan • Started {new Date(selectedScan.start_time).toLocaleString()}
                  {selectedScan.user_email && ` • By: ${selectedScan.user_email}`}
                </p>
              </div>
              <div className="flex items-center gap-3">
                {selectedScan.status === 'completed' && vulnerabilities.length > 0 && (
                  <button
                    onClick={() => setShowAIPanel(!showAIPanel)}
                    className={`px-4 py-2 rounded-lg border transition-colors flex items-center gap-2 ${
                      showAIPanel 
                        ? 'bg-purple-500/20 text-purple-400 border-purple-500/30' 
                        : 'bg-gray-700/50 text-gray-300 border-gray-600 hover:bg-gray-600/50'
                    }`}
                  >
                    <FaRobot />
                    {showAIPanel ? 'Hide AI Analysis' : 'Show AI Analysis'}
                  </button>
                )}
                <button
                  onClick={clearSelectedScan}
                  className="px-4 py-2 bg-gray-700/50 border border-gray-600 rounded-lg text-gray-300 hover:bg-gray-600/50 transition-colors"
                >
                  Close
                </button>
                <span className={`px-3 py-1 rounded-full text-sm font-bold ${getStatusColor(selectedScan.status)}`}>
                  {selectedScan.status}
                </span>
              </div>
            </div>

            {selectedScan.status === 'running' && (
              <div className="text-center py-12">
                <div className="w-20 h-20 border-4 border-green-500 border-t-transparent rounded-full animate-spin mx-auto mb-6"></div>
                <p className="text-green-400 font-semibold text-xl mb-2">Scan in Progress</p>
                <p className="text-gray-400 mb-4">Scanning {selectedScan.target} - This should take {getEstimatedTime(selectedScan.type)}</p>
                
                <div className="w-80 h-3 bg-gray-700 rounded-full mx-auto overflow-hidden mb-4">
                  <div 
                    className="h-full bg-gradient-to-r from-green-500 to-blue-500 rounded-full transition-all duration-1000"
                    style={{ width: `${selectedScan.progress}%` }}
                  />
                </div>
                <p className="text-gray-400 text-lg mb-2">{selectedScan.progress}% Complete</p>
                
                <div className="flex justify-center gap-4 mt-6">
                  <button
                    onClick={() => handleTerminateScan(selectedScan.id)}
                    disabled={terminatingScan === selectedScan.id}
                    className="px-6 py-2 bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg hover:bg-red-500/30 transition-colors disabled:opacity-50 flex items-center gap-2"
                  >
                    {terminatingScan === selectedScan.id ? (
                      <>
                        <div className="w-4 h-4 border-2 border-red-400 border-t-transparent rounded-full animate-spin" />
                        Terminating...
                      </>
                    ) : (
                      <>
                        <FaStop />
                        Stop Scan
                      </>
                    )}
                  </button>
                </div>
              </div>
            )}

            {selectedScan.status === 'terminated' && (
              <div className="text-center py-8">
                <FaStop className="text-orange-400 text-5xl mx-auto mb-4" />
                <p className="text-orange-400 font-semibold text-xl mb-2">Scan Terminated</p>
                <p className="text-gray-400">The scan was stopped by user request</p>
              </div>
            )}

            {selectedScan.status === 'failed' && (
              <div className="text-center py-8">
                <FaExclamationTriangle className="text-red-400 text-5xl mx-auto mb-4" />
                <p className="text-red-400 font-semibold text-xl mb-2">Scan Failed</p>
                <p className="text-gray-400 mb-4">{selectedScan.error}</p>
              </div>
            )}

            {selectedScan.status === 'completed' && (
              <div>
                {/* AI Analysis Panel */}
                {showAIPanel && (
                  <div className="mb-8">
                    <AIAnalysisPanel 
                      scanId={selectedScan.id}
                      vulnerabilities={vulnerabilities}
                      onAnalysisComplete={handleAIAnalysisComplete}
                    />
                  </div>
                )}

                <div className="mb-6 p-4 bg-gray-700/30 rounded-lg border border-gray-600">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-white font-semibold text-lg">
                        🎯 Scan Completed
                      </p>
                      <p className="text-gray-400">
                        Found {vulnerabilities.length} security issues
                        {aiAnalysis && (
                          <span className="text-purple-400 ml-2">
                            • AI Analysis: {aiAnalysis.prioritized_vulnerabilities?.length || vulnerabilities.length} prioritized
                          </span>
                        )}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-2xl font-bold text-white">{vulnerabilities.length}</p>
                      <p className="text-gray-400">Total Findings</p>
                    </div>
                  </div>
                </div>

                {vulnerabilities.length === 0 ? (
                  <div className="text-center py-12">
                    <FaShieldAlt className="text-green-400 text-5xl mx-auto mb-4" />
                    <p className="text-green-400 font-semibold text-xl mb-2">No Vulnerabilities Found</p>
                    <p className="text-gray-400">The target appears to be secure based on this scan</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="flex items-center gap-4 mb-4">
                      <h3 className="text-lg font-bold text-white">Security Findings</h3>
                      <div className="flex gap-2">
                        {vulnerabilities.filter(v => v.severity === 'critical').length > 0 && (
                          <span className="px-2 py-1 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-xs">
                            {vulnerabilities.filter(v => v.severity === 'critical').length} Critical
                          </span>
                        )}
                        {vulnerabilities.filter(v => v.severity === 'high').length > 0 && (
                          <span className="px-2 py-1 bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded text-xs">
                            {vulnerabilities.filter(v => v.severity === 'high').length} High
                          </span>
                        )}
                        {aiAnalysis && (
                          <span className="px-2 py-1 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded text-xs flex items-center gap-1">
                            <FaBrain />
                            AI Prioritized
                          </span>
                        )}
                      </div>
                    </div>

                    {vulnerabilities.map((vuln) => (
                      <div key={vuln.id} className={`p-4 rounded-lg border-l-4 ${
                        vuln.severity === 'critical' ? 'border-l-red-500 bg-red-500/10' :
                        vuln.severity === 'high' ? 'border-l-orange-500 bg-orange-500/10' :
                        vuln.severity === 'medium' ? 'border-l-yellow-500 bg-yellow-500/10' :
                        'border-l-blue-500 bg-blue-500/10'
                      }`}>
                        <div className="flex items-start justify-between mb-3">
                          <div className="flex-1">
                            <h3 className="font-bold text-white text-lg flex items-center gap-2">
                              {vuln.title}
                              {vuln.ai_priority_score && (
                                <span className={`text-sm font-normal ${getAIPriorityColor(vuln.ai_priority_score)}`}>
                                  (AI Priority: {(vuln.ai_priority_score * 100).toFixed(0)}%)
                                </span>
                              )}
                            </h3>
                            {vuln.ai_priority_reason && (
                              <p className="text-purple-400 text-sm mt-1">
                                🤖 {vuln.ai_priority_reason}
                              </p>
                            )}
                          </div>
                          <span className={`px-3 py-1 rounded text-sm font-bold ml-4 ${getSeverityColor(vuln.severity)}`}>
                            {vuln.severity.toUpperCase()}
                          </span>
                        </div>
                        
                        <p className="text-gray-300 mb-3">{vuln.description}</p>
                        
                        <div className="grid md:grid-cols-2 gap-4 mb-3">
                          {vuln.port && (
                            <div>
                              <p className="text-sm text-gray-400 mb-1"><strong>Port/Service:</strong></p>
                              <p className="text-sm text-white">
                                {vuln.port}/{vuln.protocol} {vuln.service && `(${vuln.service})`}
                              </p>
                            </div>
                          )}
                          
                          {vuln.cve && (
                            <div>
                              <p className="text-sm text-gray-400 mb-1"><strong>CVE:</strong></p>
                              <p className="text-sm text-red-400 font-mono">{vuln.cve}</p>
                            </div>
                          )}

                          {vuln.ai_recommended_timeline && (
                            <div>
                              <p className="text-sm text-gray-400 mb-1"><strong>AI Timeline:</strong></p>
                              <p className="text-sm text-green-400 capitalize">{vuln.ai_recommended_timeline.replace('_', ' ')}</p>
                            </div>
                          )}
                        </div>

                        {/* AI Analysis Details */}
                        {vuln.ai_analysis && (
                          <div className="mb-3 p-3 bg-purple-500/10 rounded-lg border border-purple-500/20">
                            <p className="text-purple-400 font-semibold mb-2">🤖 AI Analysis:</p>
                            <div className="grid md:grid-cols-2 gap-3 text-sm">
                              <div>
                                <p className="text-gray-400 mb-1"><strong>Business Impact:</strong></p>
                                <p className="text-white">{vuln.ai_analysis.business_impact}</p>
                              </div>
                              <div>
                                <p className="text-gray-400 mb-1"><strong>Exploitation Likelihood:</strong></p>
                                <p className="text-orange-400 capitalize">{vuln.ai_analysis.exploitation_likelihood}</p>
                              </div>
                              {vuln.ai_analysis.immediate_actions && (
                                <div className="md:col-span-2">
                                  <p className="text-gray-400 mb-1"><strong>Immediate Actions:</strong></p>
                                  <ul className="text-white list-disc list-inside">
                                    {vuln.ai_analysis.immediate_actions.map((action: string, index: number) => (
                                      <li key={index}>{action}</li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                        
                        <div className="mb-3">
                          <p className="text-sm text-gray-400 mb-1"><strong>Evidence:</strong></p>
                          <code className="text-xs bg-gray-900/80 p-3 rounded block text-gray-300 font-mono whitespace-pre-wrap">
                            {vuln.evidence}
                          </code>
                        </div>
                        
                        <div>
                          <p className="text-sm text-green-400 mb-1"><strong>Solution:</strong></p>
                          <p className="text-sm text-gray-300">{vuln.solution}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </SecurityLayout>
    </ProtectedRoute>
  );
}