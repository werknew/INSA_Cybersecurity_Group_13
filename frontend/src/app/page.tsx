'use client';
import React from 'react';
import Layout from './components/Layout';
import Card from './components/Card';
import ScanCharts from './components/ScanCharts';
import { FaExclamationTriangle, FaBug, FaNetworkWired, FaCheckCircle } from 'react-icons/fa';

export default function HomePage() {
  return (
    <Layout>
      <h2 className="text-4xl font-bold mb-8 text-gray-800">Dashboard</h2>

      {/* Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card title="Active Scans" value={2} icon={<FaNetworkWired />} color="bg-gradient-to-r from-blue-500 to-indigo-500" />
        <Card title="Completed Scans" value={15} icon={<FaCheckCircle />} color="bg-gradient-to-r from-green-500 to-emerald-500" />
        <Card title="Vulnerabilities" value={7} icon={<FaBug />} color="bg-gradient-to-r from-yellow-400 to-orange-400" />
        <Card title="Critical Alerts" value={1} icon={<FaExclamationTriangle />} color="bg-gradient-to-r from-red-500 to-pink-500" />
      </div>

      {/* Charts */}
      <ScanCharts />

      {/* Recent Scans Table */}
      <div className="mt-10 bg-white shadow-lg rounded-xl p-6">
        <h3 className="font-bold text-xl mb-4">Recent Scans</h3>
        <div className="overflow-x-auto">
          <table className="w-full table-auto border-collapse text-left">
            <thead>
              <tr className="bg-gray-100">
                <th className="px-4 py-2">ID</th>
                <th className="px-4 py-2">Type</th>
                <th className="px-4 py-2">Target</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Vulnerabilities</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b hover:bg-gray-50">
                <td className="px-4 py-2">001</td>
                <td className="px-4 py-2">Quick</td>
                <td className="px-4 py-2">192.168.1.10</td>
                <td className="px-4 py-2">Running</td>
                <td className="px-4 py-2">0</td>
              </tr>
              <tr className="border-b hover:bg-gray-50">
                <td className="px-4 py-2">002</td>
                <td className="px-4 py-2">Full</td>
                <td className="px-4 py-2">example.com</td>
                <td className="px-4 py-2">Completed</td>
                <td className="px-4 py-2">5</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </Layout>
  );
}
