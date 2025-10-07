// app/page.tsx - Dashboard
'use client';
import React, { useState, useEffect } from 'react';
import SecurityLayout from './components/Layout';
import SecurityCard from './components/Card';
import ProtectedRoute from './components/ProtectedRoute';
import { useAuth } from './components/AuthContext';
import { 
  FaShieldAlt, 
  FaExclamationTriangle, 
  FaNetworkWired, 
  FaChartLine,
  FaSearch,
  FaGlobe,
  FaDatabase,
  FaUserSecret,
  FaClock,
  FaCheckCircle,
  FaRadiation
} from 'react-icons/fa';

interface Stats {
  total_scans: number;
  completed_scans: number;
  running_scans: number;
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  tools_available: any;
}

interface Scan {
  id: number;
  target: string;
  scan_type: string;
  status: 'running' | 'completed' | 'failed' | 'terminated';
  start_time: string;
  end_time: string;
  vulnerabilities_found: number;
  progress: number;
  user_email?: string;
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats>({
    total_scans: 0,
    completed_scans: 0,
    running_scans: 0,
    vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    tools_available: {}
  });
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const { token } = useAuth();

  useEffect(() => {
    if (token) {
      fetchDashboardData();
      const interval = setInterval(fetchDashboardData, 5000);
      return () => clearInterval(interval);
    }
  }, [token]);

  const fetchDashboardData = async () => {
    if (!token) return;

    try {
      const headers = {
        'Authorization': `Bearer ${token}`
      };

      const [statsRes, scansRes, assetsRes] = await Promise.all([
        fetch('http://localhost:5000/api/stats', { headers }),
        fetch('http://localhost:5000/api/scans?limit=5', { headers }),
        fetch('http://localhost:5000/api/assets', { headers })
      ]);

      if (statsRes.ok) setStats(await statsRes.json());
      if (scansRes.ok) setRecentScans(await scansRes.json());
      if (assetsRes.ok) setAssets(await assetsRes.json());
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-blue-400';
      default: return 'text-gray-400';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-400';
      case 'running': return 'text-blue-400';
      case 'failed': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  return (
    <ProtectedRoute>
      <SecurityLayout>
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold bg-gradient-to-r from-white to-cyan-400 bg-clip-text text-transparent mb-2">
            Security Dashboard
          </h1>
          <p className="text-gray-400">Comprehensive vulnerability assessment platform</p>
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <SecurityCard 
            title="Total Scans" 
            value={stats.total_scans}
            icon={<FaSearch />}
            trend={12}
            subtitle="Security assessments"
            severity="info"
          />
          <SecurityCard 
            title="Critical Issues" 
            value={stats.vulnerabilities.critical}
            icon={<FaRadiation />}
            trend={-5}
            subtitle="Immediate attention required"
            severity="critical"
          />
          <SecurityCard 
            title="High Risk" 
            value={stats.vulnerabilities.high}
            icon={<FaExclamationTriangle />}
            trend={8}
            subtitle="Priority fixes needed"
            severity="high"
          />
          <SecurityCard 
            title="Active Scans" 
            value={stats.running_scans}
            icon={<FaClock />}
            subtitle="Currently running"
            severity="low"
          />
        </div>

        <div className="grid lg:grid-cols-2 gap-8">
          {/* Recent Scans */}
          <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700 p-6">
            <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
              <FaClock className="text-blue-400" />
              Recent Scans
            </h2>
            
            <div className="space-y-3">
              {recentScans.map(scan => (
                <div key={scan.id} className="flex items-center justify-between p-3 bg-gray-700/30 rounded-lg border border-gray-600">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${
                      scan.scan_type === 'web' ? 'bg-purple-500/20 text-purple-400' :
                      scan.scan_type === 'full' ? 'bg-orange-500/20 text-orange-400' :
                      'bg-blue-500/20 text-blue-400'
                    }`}>
                      <FaSearch />
                    </div>
                    <div>
                      <p className="font-semibold text-white">{scan.target}</p>
                      <p className="text-sm text-gray-400 capitalize">{scan.scan_type} scan</p>
                      {scan.user_email && (
                        <p className="text-xs text-gray-500">By: {scan.user_email}</p>
                      )}
                    </div>
                  </div>
                  
                  <div className="text-right">
                    <span className={`text-sm font-bold ${getStatusColor(scan.status)}`}>
                      {scan.status}
                    </span>
                    {scan.status === 'completed' && scan.vulnerabilities_found > 0 && (
                      <p className="text-xs text-red-400">{scan.vulnerabilities_found} issues</p>
                    )}
                  </div>
                </div>
              ))}
              {recentScans.length === 0 && (
                <div className="text-center py-8 text-gray-500">
                  <FaSearch className="text-4xl mx-auto mb-4 opacity-50" />
                  <p>No scans yet</p>
                  <p className="text-sm mt-2">Start your first scan to see results here</p>
                </div>
              )}
            </div>
          </div>

          {/* Discovered Assets */}
          <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700 p-6">
            <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
              <FaNetworkWired className="text-green-400" />
              Discovered Assets
            </h2>
            
            <div className="space-y-3">
              {assets.map(asset => (
                <div key={asset.asset} className="flex items-center justify-between p-3 bg-gray-700/30 rounded-lg border border-gray-600">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-green-500/20 text-green-400">
                      <FaGlobe />
                    </div>
                    <div>
                      <p className="font-semibold text-white">{asset.asset}</p>
                      <p className="text-sm text-gray-400">{asset.scan_count} scans</p>
                    </div>
                  </div>
                  
                  <div className="text-right">
                    <p className="text-sm text-gray-400">
                      Last: {new Date(asset.last_scanned).toLocaleDateString()}
                    </p>
                  </div>
                </div>
              ))}
              {assets.length === 0 && (
                <div className="text-center py-8 text-gray-500">
                  <FaNetworkWired className="text-4xl mx-auto mb-4 opacity-50" />
                  <p>No assets discovered</p>
                  <p className="text-sm mt-2">Run scans to discover network assets</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Tools Status */}
        <div className="mt-8 bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700 p-6">
          <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
            <FaShieldAlt className="text-cyan-400" />
            Security Tools Status
          </h2>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Object.entries(stats.tools_available).map(([tool, available]) => (
              <div key={tool} className="flex items-center gap-3 p-3 bg-gray-700/30 rounded-lg border border-gray-600">
                <div className={`p-2 rounded-lg ${
                  available ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                }`}>
                  {tool === 'nmap' && <FaNetworkWired />}
                  {tool === 'nikto' && <FaGlobe />}
                  {tool === 'sqlmap' && <FaDatabase />}
                </div>
                <div>
                  <p className="font-semibold text-white capitalize">{tool}</p>
                  <p className={`text-sm ${available ? 'text-green-400' : 'text-red-400'}`}>
                    {available ? 'Available' : 'Not Available'}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Vulnerability Distribution */}
        <div className="mt-8 bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700 p-6">
          <h2 className="text-xl font-bold text-white mb-6">Vulnerability Distribution</h2>
          
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {Object.entries(stats.vulnerabilities).map(([severity, count]) => (
              <div key={severity} className="text-center p-4 bg-gray-700/30 rounded-lg border border-gray-600">
                <p className={`text-2xl font-bold mb-1 ${getSeverityColor(severity)}`}>
                  {count}
                </p>
                <p className="text-sm text-gray-400 capitalize">{severity}</p>
              </div>
            ))}
          </div>
        </div>
      </SecurityLayout>
    </ProtectedRoute>
  );
}