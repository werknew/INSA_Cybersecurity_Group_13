'use client';
import React, { useState } from 'react';
import Layout from '../components/Layout';

export default function SettingsPage() {
  const [defaultScan, setDefaultScan] = useState('Quick Scan');
  const [scanInterval, setScanInterval] = useState(24); // hours
  const [notifications, setNotifications] = useState(true);
  const [ipPreset, setIpPreset] = useState('');
  const [portPreset, setPortPreset] = useState('');

  const handleSave = () => {
    alert('Settings saved!');
    // Later: connect to backend to persist settings
  };

  return (
    <Layout>
      <h2 className="text-4xl font-bold mb-6 text-black">Settings</h2>

      <div className="bg-white shadow-md rounded p-6 max-w-2xl space-y-6">
        {/* Default Scan Type */}
        <div>
          <label className="block font-semibold mb-2 text-black">Default Scan Type</label>
          <select
            value={defaultScan}
            onChange={e => setDefaultScan(e.target.value)}
            className="w-full border rounded p-2"
          >
            <option>Quick Scan</option>
            <option>Full Scan</option>
            <option>Stealth Scan</option>
            <option>Vulnerability Scan</option>
            <option>Web Scan</option>
          </select>
        </div>

        {/* Scan Interval */}
        <div>
          <label className="block font-semibold mb-2 text-black">Scan Interval (hours)</label>
          <input
            type="number"
            min={1}
            value={scanInterval}
            onChange={e => setScanInterval(Number(e.target.value))}
            className="w-full border rounded p-2"
          />
        </div>

        {/* Notifications Toggle */}
        <div className="flex items-center justify-between">
          <span className="font-semibold text-black">Enable Notifications</span>
          <input
            type="checkbox"
            checked={notifications}
            onChange={e => setNotifications(e.target.checked)}
            className="h-5 w-5"
          />
        </div>

        {/* IP Preset */}
        <div>
          <label className="block font-semibold mb-2 text-black">IP Preset</label>
          <input
            type="text"
            placeholder="e.g., 192.168.1.1,192.168.1.2"
            value={ipPreset}
            onChange={e => setIpPreset(e.target.value)}
            className="w-full border rounded p-2"
          />
        </div>

        {/* Port Preset */}
        <div>
          <label className="block font-semibold mb-2 text-black">Port Preset</label>
          <input
            type="text"
            placeholder="e.g., 80,443,8080"
            value={portPreset}
            onChange={e => setPortPreset(e.target.value)}
            className="w-full border rounded p-2"
          />
        </div>

        {/* Save Button */}
        <button
          onClick={handleSave}
          className="bg-blue-600 text-white px-6 py-2 rounded hover:bg-blue-700 transition"
        >
          Save Settings
        </button>
      </div>
    </Layout>
  );
}
