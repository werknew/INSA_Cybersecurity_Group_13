'use client';
import React, { useState } from 'react';
import { FaRobot, FaBrain, FaLightbulb, FaExclamationTriangle, FaChartLine } from 'react-icons/fa';

interface AIAnalysisPanelProps {
  scanId: number;
  vulnerabilities: any[];
  onAnalysisComplete?: (analysis: any) => void;
}

export default function AIAnalysisPanel({ scanId, vulnerabilities, onAnalysisComplete }: AIAnalysisPanelProps) {
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const runAIAnalysis = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const token = localStorage.getItem('security_scanner_token');
      const response = await fetch(`http://localhost:5000/api/scan/${scanId}/ai-analysis`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error('Failed to get AI analysis');
      }

      const data = await response.json();
      setAnalysis(data);
      onAnalysisComplete?.(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="bg-gray-800/50 border border-blue-500/30 rounded-lg p-6 text-center">
        <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
        <p className="text-blue-400">AI is analyzing vulnerabilities...</p>
        <p className="text-gray-400 text-sm mt-2">This may take a few moments</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-gray-800/50 border border-red-500/30 rounded-lg p-6">
        <div className="flex items-center gap-3 text-red-400 mb-4">
          <FaExclamationTriangle />
          <h3 className="font-bold">AI Analysis Failed</h3>
        </div>
        <p className="text-gray-400 mb-4">{error}</p>
        <button
          onClick={runAIAnalysis}
          className="px-4 py-2 bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg hover:bg-red-500/30 transition-colors"
        >
          Retry Analysis
        </button>
      </div>
    );
  }

  if (analysis) {
    return (
      <div className="bg-gray-800/50 border border-green-500/30 rounded-lg p-6">
        <div className="flex items-center gap-3 text-green-400 mb-6">
          <FaRobot className="text-2xl" />
          <h3 className="font-bold text-xl">AI Security Analysis</h3>
        </div>

        {/* Priority Overview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className="bg-gray-700/30 p-4 rounded-lg border border-blue-500/20">
            <div className="flex items-center gap-2 mb-2">
              <FaChartLine className="text-blue-400" />
              <span className="text-blue-400 font-semibold">Priority Score</span>
            </div>
            <p className="text-2xl font-bold text-white">
              {analysis.prioritized_vulnerabilities?.[0]?.ai_priority_score?.toFixed(2) || 'N/A'}
            </p>
            <p className="text-gray-400 text-sm">Top Vulnerability</p>
          </div>

          <div className="bg-gray-700/30 p-4 rounded-lg border border-green-500/20">
            <div className="flex items-center gap-2 mb-2">
              <FaLightbulb className="text-green-400" />
              <span className="text-green-400 font-semibold">AI Insights</span>
            </div>
            <p className="text-2xl font-bold text-white">
              {analysis.ai_insights?.critical_insights?.length || 0}
            </p>
            <p className="text-gray-400 text-sm">Critical Findings</p>
          </div>

          <div className="bg-gray-700/30 p-4 rounded-lg border border-purple-500/20">
            <div className="flex items-center gap-2 mb-2">
              <FaBrain className="text-purple-400" />
              <span className="text-purple-400 font-semibold">Anomalies</span>
            </div>
            <p className="text-2xl font-bold text-white">
              {analysis.anomalies_detected?.length || 0}
            </p>
            <p className="text-gray-400 text-sm">Detected</p>
          </div>
        </div>

        {/* Top Priority Vulnerabilities */}
        {analysis.prioritized_vulnerabilities?.slice(0, 3).map((vuln: any, index: number) => (
          <div key={index} className="mb-4 p-4 bg-gray-700/30 rounded-lg border-l-4 border-orange-500">
            <div className="flex justify-between items-start mb-2">
              <h4 className="font-semibold text-white">{vuln.title}</h4>
              <span className="px-2 py-1 bg-orange-500/20 text-orange-400 rounded text-sm">
                Priority: {(vuln.ai_priority_score * 100).toFixed(0)}%
              </span>
            </div>
            <p className="text-gray-400 text-sm mb-2">{vuln.ai_priority_reason}</p>
            <p className="text-green-400 text-sm">Timeline: {vuln.ai_recommended_timeline}</p>
          </div>
        ))}

        <button
          onClick={runAIAnalysis}
          className="w-full mt-4 px-4 py-2 bg-green-500/20 text-green-400 border border-green-500/30 rounded-lg hover:bg-green-500/30 transition-colors"
        >
          Refresh AI Analysis
        </button>
      </div>
    );
  }

  return (
    <div className="bg-gray-800/50 border border-purple-500/30 rounded-lg p-6 text-center">
      <FaRobot className="text-4xl text-purple-400 mx-auto mb-4" />
      <h3 className="text-xl font-bold text-white mb-2">AI-Powered Security Analysis</h3>
      <p className="text-gray-400 mb-4">
        Get intelligent vulnerability prioritization, risk assessment, and remediation recommendations powered by AI.
      </p>
      <button
        onClick={runAIAnalysis}
        className="px-6 py-3 bg-gradient-to-r from-purple-500 to-blue-500 text-white rounded-lg font-semibold hover:shadow-lg transition-all"
      >
        Run AI Analysis
      </button>
      <p className="text-gray-500 text-sm mt-3">
        Requires AI API keys to be configured
      </p>
    </div>
  );
}