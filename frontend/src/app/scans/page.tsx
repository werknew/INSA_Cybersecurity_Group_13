'use client';
import React, { useState } from 'react';
import Layout from '../components/Layout';
import Card from '../components/Card';
import { FaExclamationTriangle, FaCheckCircle, FaBug, FaNetworkWired } from 'react-icons/fa';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend);

export default function ScansPage() {
  const [scanType, setScanType] = useState('Quick Scan');
  const [target, setTarget] = useState('');
  const [port, setPort] = useState('');
  const [scanResults, setScanResults] = useState<number[]>([]);
  const [scanning, setScanning] = useState(false);

  const handleStartScan = () => {
    if (!target) {
      alert('Please enter a target IP or URL.');
      return;
    }
    setScanning(true);
    setScanResults([]);

    // Mock scan progress
    let step = 0;
    const interval = setInterval(() => {
      step++;
      setScanResults(prev => [...prev, Math.floor(Math.random() * 10 + step * 5)]);
      if (step >= 10) {
        clearInterval(interval);
        setScanning(false);
      }
    }, 500);
  };

  const chartData = {
    labels: scanResults.map((_, idx) => `Step ${idx + 1}`),
    datasets: [
      {
        label: 'Vulnerabilities Found',
        data: scanResults,
        borderColor: '#3b82f6',
        backgroundColor: '#3b82f6',
      },
    ],
  };

  return (
    <Layout>
      <h2 className="text-4xl font-bold mb-6 text-black">Scans</h2>

      {/* Scan Form */}
      <div className="bg-white shadow-md rounded p-6 max-w-lg mb-8">
        <h3 className="text-2xl font-bold mb-4 text-black">New Scan</h3>

        <label className="block mb-2 font-semibold text-black">Scan Type</label>
        <select
          value={scanType}
          onChange={e => setScanType(e.target.value)}
          className="w-full border rounded p-2 mb-4"
        >
          <option>Quick Scan</option>
          <option>Full Scan</option>
          <option>Stealth Scan</option>
          <option>Vulnerability Scan</option>
          <option>Web Scan</option>
        </select>

        <label className="block mb-2 font-semibold text-black">Target</label>
        <input
          type="text"
          placeholder="Enter IP or URL"
          value={target}
          onChange={e => setTarget(e.target.value)}
          className="w-full border rounded p-2 mb-4"
        />

        <label className="block mb-2 font-semibold text-black">Port (optional)</label>
        <input
          type="text"
          placeholder="e.g., 80,443"
          value={port}
          onChange={e => setPort(e.target.value)}
          className="w-full border rounded p-2 mb-4"
        />

        <button
          onClick={handleStartScan}
          disabled={scanning}
          className="bg-blue-600 text-white px-6 py-2 rounded hover:bg-blue-700 transition disabled:opacity-50"
        >
          {scanning ? 'Scanning...' : 'Start Scan'}
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <Card title="Total Scans" icon={<FaNetworkWired />} value={scanResults.length} textClass="text-black" />
        <Card title="Vulnerabilities" icon={<FaExclamationTriangle />} value={scanResults.reduce((a, b) => a + b, 0)} textClass="text-black" />
        <Card title="Critical Issues" icon={<FaBug />} value={Math.floor(Math.random() * 5)} textClass="text-black" />
        <Card title="Successful Scans" icon={<FaCheckCircle />} value={Math.floor(Math.random() * 10)} textClass="text-black" />
      </div>

      {/* Scan Results Chart */}
      <div className="bg-white shadow-md rounded p-6">
        <h3 className="text-2xl font-bold mb-4 text-black">Scan Progress</h3>
        {scanResults.length === 0 ? (
          <p className="text-black">No scan data yet. Start a scan to see results.</p>
        ) : (
          <Line data={chartData} />
        )}
      </div>
    </Layout>
  );
}
