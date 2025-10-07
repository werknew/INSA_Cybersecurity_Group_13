// app/reports/page.tsx
'use client';
import React, { useState, useEffect } from 'react';
import SecurityLayout from '../components/Layout';
import SecurityCard from '../components/Card';
import ProtectedRoute from '../components/ProtectedRoute';
import { useAuth } from '../components/AuthContext';
import { 
  FaFilePdf, 
  FaFileCode, 
  FaFileCsv, 
  FaFileAlt, 
  FaDownload,
  FaArchive,
  FaChartBar,
  FaHistory,
  FaTrash,
  FaEye,
  FaPrint
} from 'react-icons/fa';

interface Scan {
  id: number;
  target: string;
  type: string;
  status: 'running' | 'completed' | 'failed' | 'terminated';
  start_time: string;
  progress: number;
  vulnerabilities_found: number;
  user_email?: string;
}

interface Report {
  id: string;
  scan_id: number;
  type: string;
  filename: string;
  generated_at: string;
  size: number;
  user_email?: string;
}

interface VulnerabilityStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export default function ReportsPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [generatingReport, setGeneratingReport] = useState<string | null>(null);
  const [stats, setStats] = useState({
    total_scans: 0,
    completed_scans: 0,
    total_reports: 0,
    vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 } as VulnerabilityStats
  });

  const { token } = useAuth();

  useEffect(() => {
    if (token) {
      fetchScans();
      fetchReports();
      fetchStats();
      
      const interval = setInterval(() => {
        fetchScans();
        fetchReports();
      }, 5000);

      return () => clearInterval(interval);
    }
  }, [token]);

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

  const fetchReports = async () => {
    if (!token) return;
    
    try {
      const response = await fetch('http://localhost:5000/api/reports', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (!response.ok) throw new Error('Failed to fetch reports');
      const data = await response.json();
      setReports(data);
    } catch (error) {
      console.error('Failed to fetch reports:', error);
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

  const generateReport = async (scanId: number, reportType: string) => {
    if (!token) {
      alert('Authentication required. Please log in again.');
      return;
    }

    setGeneratingReport(`${scanId}-${reportType}`);
    try {
      const response = await fetch(`http://localhost:5000/api/scan/${scanId}/report`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ type: reportType })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to generate report');
      }
      
      const result = await response.json();
      alert(`Report generated successfully! Download URL: ${result.download_url}`);
      fetchReports();
      
    } catch (error: any) {
      alert(`Failed to generate report: ${error.message}`);
    } finally {
      setGeneratingReport(null);
    }
  };

  const downloadReport = async (reportId: string, filename: string) => {
    if (!token) {
      alert('Authentication required. Please log in again.');
      return;
    }

    try {
      const response = await fetch(`http://localhost:5000/api/report/${reportId}/download`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (!response.ok) throw new Error('Download failed');
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
    } catch (error: any) {
      alert(`Download failed: ${error.message}`);
    }
  };

  const deleteReport = async (reportId: string) => {
    if (!token) {
      alert('Authentication required. Please log in again.');
      return;
    }

    if (!confirm('Are you sure you want to delete this report?')) {
      return;
    }

    try {
      const response = await fetch(`http://localhost:5000/api/report/${reportId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to delete report');
      }
      
      alert('Report deleted successfully');
      fetchReports();
      
    } catch (error: any) {
      alert(`Failed to delete report: ${error.message}`);
    }
  };

  const getReportIcon = (type: string) => {
    switch (type) {
      case 'pdf': return <FaFilePdf className="text-red-500" />;
      case 'json': return <FaFileCode className="text-yellow-500" />;
      case 'csv': return <FaFileCsv className="text-green-500" />;
      case 'executive': return <FaFileAlt className="text-blue-500" />;
      case 'zip': return <FaArchive className="text-purple-500" />;
      default: return <FaFileAlt className="text-gray-500" />;
    }
  };

  const getReportTypeName = (type: string) => {
    const names: { [key: string]: string } = {
      'pdf': 'PDF Report',
      'json': 'JSON Export',
      'csv': 'CSV Data',
      'executive': 'Executive Summary',
      'zip': 'Complete Package'
    };
    return names[type] || type;
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const completedScans = scans.filter(scan => scan.status === 'completed');

  return (
    <ProtectedRoute>
      <SecurityLayout>
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold bg-gradient-to-r from-white to-gray-300 bg-clip-text text-transparent mb-2">
            Security Reports
          </h1>
          <p className="text-gray-400">Generate and download comprehensive security assessment reports</p>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <SecurityCard 
            title="Total Scans" 
            value={stats.total_scans}
            icon={<FaHistory />}
            severity="info"
          />
          <SecurityCard 
            title="Completed Scans" 
            value={stats.completed_scans}
            icon={<FaChartBar />}
            severity="low"
          />
          <SecurityCard 
            title="Generated Reports" 
            value={stats.total_reports}
            icon={<FaFilePdf />}
            severity="medium"
          />
          <SecurityCard 
            title="Critical Findings" 
            value={stats.vulnerabilities.critical}
            icon={<FaFileAlt />}
            severity="critical"
          />
        </div>

        <div className="grid lg:grid-cols-2 gap-8">
          {/* Scan Selection & Report Generation */}
          <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700 p-6">
            <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-3">
              <FaFilePdf className="text-red-400" />
              Generate New Report
            </h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-semibold text-gray-300 mb-2">
                  Select Completed Scan
                </label>
                <select
                  onChange={e => setSelectedScan(completedScans.find(s => s.id === parseInt(e.target.value)) || null)}
                  className="w-full bg-gray-700/50 border border-gray-600 rounded-lg px-4 py-3 text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                  disabled={!token}
                >
                  <option value="">Choose a completed scan...</option>
                  {completedScans.map(scan => (
                    <option key={scan.id} value={scan.id}>
                      {scan.target} - {scan.type} ({scan.vulnerabilities_found} findings)
                      {scan.user_email && ` - By: ${scan.user_email}`}
                    </option>
                  ))}
                </select>
                {!token && (
                  <p className="text-red-400 text-sm mt-1">Authentication required</p>
                )}
              </div>

              {selectedScan && (
                <div className="p-4 bg-gray-700/30 rounded-lg border border-gray-600">
                  <h3 className="font-semibold text-white mb-2">Selected Scan:</h3>
                  <p className="text-gray-300">{selectedScan.target}</p>
                  <div className="flex gap-4 text-sm text-gray-400 mt-1">
                    <span>Type: {selectedScan.type}</span>
                    <span>Findings: {selectedScan.vulnerabilities_found}</span>
                    <span>Date: {new Date(selectedScan.start_time).toLocaleDateString()}</span>
                  </div>
                  {selectedScan.user_email && (
                    <p className="text-xs text-gray-500 mt-1">Created by: {selectedScan.user_email}</p>
                  )}
                </div>
              )}

              <div>
                <label className="block text-sm font-semibold text-gray-300 mb-2">
                  Report Type
                </label>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { type: 'pdf', name: 'PDF Report', desc: 'Professional PDF', icon: <FaFilePdf /> },
                    { type: 'json', name: 'JSON Export', desc: 'Machine-readable', icon: <FaFileCode /> },
                    { type: 'csv', name: 'CSV Data', desc: 'Spreadsheet format', icon: <FaFileCsv /> },
                    { type: 'executive', name: 'Executive', desc: 'Summary report', icon: <FaFileAlt /> },
                    { type: 'zip', name: 'Complete Package', desc: 'All formats', icon: <FaArchive />, colSpan: true }
                  ].map((report) => (
                    <button
                      key={report.type}
                      onClick={() => selectedScan && generateReport(selectedScan.id, report.type)}
                      disabled={!selectedScan || generatingReport === `${selectedScan.id}-${report.type}` || !token}
                      className={`p-4 bg-gray-700/50 border border-gray-600 rounded-lg hover:border-blue-500 transition-all disabled:opacity-50 disabled:cursor-not-allowed ${
                        report.colSpan ? 'col-span-2' : ''
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div className="text-xl">
                          {report.icon}
                        </div>
                        <div className="text-left">
                          <p className="font-semibold text-white text-sm">{report.name}</p>
                          <p className="text-gray-400 text-xs">{report.desc}</p>
                        </div>
                      </div>
                      {generatingReport === `${selectedScan?.id}-${report.type}` && (
                        <div className="mt-2">
                          <div className="w-full h-1 bg-gray-600 rounded-full overflow-hidden">
                            <div className="h-full bg-blue-500 rounded-full animate-pulse"></div>
                          </div>
                        </div>
                      )}
                    </button>
                  ))}
                </div>
                {!token && (
                  <p className="text-red-400 text-sm mt-2">Please log in to generate reports</p>
                )}
              </div>
            </div>
          </div>

          {/* Generated Reports */}
          <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700 p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-white">Generated Reports</h2>
              <button 
                onClick={fetchReports}
                disabled={!token}
                className="px-3 py-1 bg-gray-700/50 border border-gray-600 rounded-lg text-gray-300 hover:bg-gray-600/50 transition-colors text-sm disabled:opacity-50"
              >
                Refresh
              </button>
            </div>
            
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {!token ? (
                <div className="text-center py-8 text-gray-500">
                  <FaFilePdf className="text-4xl mx-auto mb-4 opacity-50" />
                  <p>Authentication Required</p>
                  <p className="text-sm mt-2">Please log in to view reports</p>
                </div>
              ) : reports.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  <FaFilePdf className="text-4xl mx-auto mb-4 opacity-50" />
                  <p>No reports generated yet</p>
                  <p className="text-sm mt-2">Generate your first report from a completed scan</p>
                </div>
              ) : (
                reports.map(report => {
                  const relatedScan = scans.find(s => s.id === report.scan_id);
                  return (
                    <div key={report.id} className="p-4 bg-gray-700/50 rounded-lg border border-gray-600">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3 flex-1">
                          <div className="text-2xl">
                            {getReportIcon(report.type)}
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="font-semibold text-white truncate">
                              {getReportTypeName(report.type)}
                            </p>
                            <div className="flex items-center gap-3 mt-1 text-xs text-gray-400">
                              <span>Scan: {relatedScan?.target || 'Unknown'}</span>
                              <span>Size: {formatFileSize(report.size)}</span>
                              <span>{new Date(report.generated_at).toLocaleDateString()}</span>
                            </div>
                            {report.user_email && (
                              <p className="text-xs text-gray-500 mt-1">Generated by: {report.user_email}</p>
                            )}
                          </div>
                        </div>
                        
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => downloadReport(report.id, report.filename)}
                            disabled={!token}
                            className="p-2 text-green-400 hover:bg-green-500/20 rounded-lg transition-colors disabled:opacity-50"
                            title="Download Report"
                          >
                            <FaDownload />
                          </button>
                          <button
                            onClick={() => {
                              // View report details - you can implement a modal or expandable view
                              alert(`Report Details:\nType: ${getReportTypeName(report.type)}\nScan: ${relatedScan?.target}\nGenerated: ${new Date(report.generated_at).toLocaleString()}\nSize: ${formatFileSize(report.size)}`);
                            }}
                            className="p-2 text-blue-400 hover:bg-blue-500/20 rounded-lg transition-colors"
                            title="View Details"
                          >
                            <FaEye />
                          </button>
                          <button
                            onClick={() => deleteReport(report.id)}
                            disabled={!token}
                            className="p-2 text-red-400 hover:bg-red-500/20 rounded-lg transition-colors disabled:opacity-50"
                            title="Delete Report"
                          >
                            <FaTrash />
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* Report Types Explanation */}
        <div className="mt-8 bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700 p-6">
          <h2 className="text-xl font-bold text-white mb-6">Report Types</h2>
          
          <div className="grid md:grid-cols-2 lg:grid-cols-5 gap-4">
            {[
              {
                type: 'pdf',
                icon: <FaFilePdf className="text-red-400 text-2xl" />,
                title: 'PDF Report',
                description: 'Professional formatted report with charts, tables, and executive summary',
                features: ['Executive Summary', 'Detailed Findings', 'Risk Assessment', 'Recommendations']
              },
              {
                type: 'json',
                icon: <FaFileCode className="text-yellow-400 text-2xl" />,
                title: 'JSON Export',
                description: 'Machine-readable format for integration with other security tools',
                features: ['Structured Data', 'API Integration', 'Automated Processing', 'Full Metadata']
              },
              {
                type: 'csv',
                icon: <FaFileCsv className="text-green-400 text-2xl" />,
                title: 'CSV Data',
                description: 'Spreadsheet-friendly format for data analysis and custom reporting',
                features: ['Excel Compatible', 'Data Analysis', 'Custom Reporting', 'Import Ready']
              },
              {
                type: 'executive',
                icon: <FaFileAlt className="text-blue-400 text-2xl" />,
                title: 'Executive Summary',
                description: 'High-level summary for management and non-technical stakeholders',
                features: ['Business Focus', 'Risk Overview', 'Key Findings', 'Action Plan']
              },
              {
                type: 'zip',
                icon: <FaArchive className="text-purple-400 text-2xl" />,
                title: 'Complete Package',
                description: 'All report formats combined in a single downloadable package',
                features: ['All Formats', 'Log Files', 'Complete Data', 'Archive Ready']
              }
            ].map((reportType) => (
              <div key={reportType.type} className="p-4 bg-gray-700/30 rounded-lg border border-gray-600">
                <div className="flex items-center gap-3 mb-3">
                  {reportType.icon}
                  <h3 className="font-bold text-white">{reportType.title}</h3>
                </div>
                <p className="text-gray-400 text-sm mb-3">{reportType.description}</p>
                <ul className="text-xs text-gray-500 space-y-1">
                  {reportType.features.map((feature, index) => (
                    <li key={index}>• {feature}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </SecurityLayout>
    </ProtectedRoute>
  );
}