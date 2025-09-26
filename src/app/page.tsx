'use client';

import { useState } from 'react';
import ScanForm from '@/app/components/ScanForm';
import ScanResults from '@/app/components/ScanResults';

export default function Home() {
  const [results, setResults] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async (target: string, scanType: string) => {
    setLoading(true);
    setError(null);
    setResults(null);
    
    try {
      const response = await fetch('http://localhost:5000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, scanType }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        setError(data.error || 'Failed to scan target');
      } else if (data.status === 'error') {
        setError(data.output || 'Scan failed');
      } else {
        setResults(data);
      }
    } catch (err) {
      setError('Failed to connect to scanner service. Make sure the backend is running.');
      console.error('Scan error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="container mx-auto p-4 max-w-6xl min-h-screen">
      <div className="text-center mb-8">
        <h1 className="text-4xl font-bold text-gray-800 dark:text-white mb-2">
          🔍 Automated Vulnerability Scanner
        </h1>


      </div>
      
      <ScanForm 
        onSubmit={handleScan} 
        loading={loading} 
        scanTypes={['quick', 'full', 'stealth', 'vulnerability', 'web']}
      />
      
      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg mb-6">
          <strong>Error:</strong> {error}
        </div>
      )}
      
      <ScanResults results={results} loading={loading} />
    </main>
  );
}