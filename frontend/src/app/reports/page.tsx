'use client';
import React from 'react';
import Layout from '../components/Layout';

type ScanReport = {
  id: number;
  scanType: string;
  target: string;
  port: string;
  date: string;
  status: 'Completed' | 'Failed' | 'In Progress';
  severity: 'Low' | 'Medium' | 'High';
};

// Example/mock data
const reports: ScanReport[] = [
  { id: 1, scanType: 'Quick Scan', target: '192.168.1.1', port: '80', date: '2025-09-26', status: 'Completed', severity: 'Medium' },
  { id: 2, scanType: 'Full Scan', target: 'example.com', port: '443', date: '2025-09-25', status: 'Completed', severity: 'High' },
  { id: 3, scanType: 'Web Scan', target: '192.168.0.10', port: '8080', date: '2025-09-24', status: 'Failed', severity: 'Low' },
];

const severityColor = (severity: string) => {
  switch (severity) {
    case 'High': return 'bg-red-500 text-white';
    case 'Medium': return 'bg-yellow-400 text-black';
    case 'Low': return 'bg-green-500 text-white';
    default: return 'bg-gray-200 text-black';
  }
};

export default function ReportsPage() {
  return (
    <Layout>
      <h2 className="text-4xl font-bold mb-6 text-black">Reports</h2>

      <div className="bg-white shadow-md rounded p-6 overflow-x-auto">
        <table className="min-w-full border-collapse">
          <thead>
            <tr className="bg-gray-100 text-black">
              <th className="px-4 py-2 text-left">Scan Type</th>
              <th className="px-4 py-2 text-left">Target</th>
              <th className="px-4 py-2 text-left">Port</th>
              <th className="px-4 py-2 text-left">Date</th>
              <th className="px-4 py-2 text-left">Status</th>
              <th className="px-4 py-2 text-left">Severity</th>
            </tr>
          </thead>
          <tbody>
            {reports.map(report => (
              <tr key={report.id} className="border-b">
                <td className="px-4 py-2 text-black">{report.scanType}</td>
                <td className="px-4 py-2 text-black">{report.target}</td>
                <td className="px-4 py-2 text-black">{report.port}</td>
                <td className="px-4 py-2 text-black">{report.date}</td>
                <td className={`px-4 py-2 font-semibold ${report.status === 'Completed' ? 'text-green-600' : report.status === 'Failed' ? 'text-red-600' : 'text-yellow-600'}`}>
                  {report.status}
                </td>
                <td className={`px-4 py-2 font-semibold rounded ${severityColor(report.severity)}`}>
                  {report.severity}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}
