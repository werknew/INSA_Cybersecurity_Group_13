'use client';

import { useState, useEffect } from 'react';

interface ScanFormProps {
  onSubmit: (target: string, scanType: string) => void;
  loading: boolean;
  scanTypes: string[];
}

const icons: Record<string, JSX.Element> = {
  quick: <svg className="w-6 h-6 text-yellow-400 transition-transform duration-300" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>,
  full: <svg className="w-6 h-6 text-green-400 transition-transform duration-300" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" /></svg>,
  stealth: <svg className="w-6 h-6 text-blue-400 transition-transform duration-300" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>,
  web: <svg className="w-6 h-6 text-purple-400 transition-transform duration-300" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg>
};

const descriptions: Record<string, string> = {
  quick: "Fast scan of the most common ports",
  full: "Deep scan with version detection",
  stealth: "Undetectable and slower scan",
  vulnerability: "Check for vulnerabilities via scripts",
  web: "Scan web applications for security issues"
};

export default function ScanForm({ onSubmit, loading, scanTypes }: ScanFormProps) {
  const [target, setTarget] = useState('');
  const [selected, setSelected] = useState('quick');
  const [hovered, setHovered] = useState<string | null>(null);
  const [particles, setParticles] = useState<{ x: number; y: number; size: number; speed: number; }[]>([]);

  useEffect(() => {
    const p = Array.from({ length: 50 }, () => ({
      x: Math.random() * window.innerWidth,
      y: Math.random() * window.innerHeight,
      size: Math.random() * 4 + 1,
      speed: Math.random() * 0.3 + 0.1
    }));
    setParticles(p);

    const interval = setInterval(() => {
      setParticles(prev =>
        prev.map(p => ({ ...p, y: p.y + p.speed > window.innerHeight ? 0 : p.y + p.speed }))
      );
    }, 30);
    return () => clearInterval(interval);
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (target.trim() && validateTarget(target, selected)) onSubmit(target.trim(), selected);
  };

  const validateTarget = (input: string, type: string) => {
    const ip = /^(\d{1,3}\.){3}\d{1,3}$/;
    const domain = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
    const url = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
    if (type === 'web') return ip.test(input) || domain.test(input) || url.test(input) || input.startsWith('http');
    return ip.test(input) || domain.test(input);
  };

  return (
    <div className="relative p-10 overflow-hidden w-full min-h-screen flex flex-col items-center justify-start bg-black animate-bgGradient">
      {particles.map((p, i) => (
        <div
          key={i}
          className="absolute bg-purple-400 rounded-full"
          style={{ left: p.x, top: p.y, width: p.size, height: p.size, opacity: 0.6 }}
        ></div>
      ))}

      <div className="flex items-center space-x-4 relative z-10 mb-12">
        <svg className="w-12 h-12 text-green-400 animate-spin-slow" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 2v4m0 12v4m8-8h-4M4 12H0m15.364-6.364l-2.828 2.828M6.464 17.536l-2.828 2.828m12.728 0l2.828-2.828M6.464 6.464L3.636 9.292" />
        </svg>
        <h2 className="text-5xl font-extrabold text-green-400 animate-pulse-slow">
          Security Scanner
        </h2>
      </div>

      <form onSubmit={handleSubmit} className="relative z-10 w-full max-w-4xl space-y-6">
        <div>
          <label className="block font-semibold mb-2 text-white">Target</label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Enter domain, IP, or URL"
            className="w-full p-4 rounded-xl bg-gray-900 border-2 border-gray-700 focus:border-green-400 focus:ring-2 focus:ring-green-300 transition-all duration-300 outline-none text-white shadow-inner"
            disabled={loading}
          />
          {target && !validateTarget(target, selected) && (
            <p className="mt-2 text-red-500">Invalid target for selected scan</p>
          )}
        </div>

        <div>
          <label className="block font-semibold mb-4 text-white">Scan Type</label>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6">
            {scanTypes.map(type => {
              const isSelected = selected === type;
              const isHovered = hovered === type;
              return (
                <div
                  key={type}
                  className={`relative flex flex-col items-center p-6 rounded-2xl border-2 cursor-pointer transition-all duration-300 shadow-lg
                    ${isSelected ? 'border-green-400 bg-gray-800 scale-105 shadow-2xl animate-pulse' : 'border-gray-700 bg-gray-800 hover:border-green-400 hover:shadow-xl hover:scale-105'}
                  `}
                  onClick={() => setSelected(type)}
                  onMouseEnter={() => setHovered(type)}
                  onMouseLeave={() => setHovered(null)}
                >
                  <div className={`transition-transform duration-500 ${isHovered || isSelected ? 'animate-bounce' : ''}`}>
                    {icons[type]}
                  </div>
                  <span className="mt-4 font-bold text-lg capitalize text-white">{type}</span>
                  {isHovered && (
                    <div className="absolute bottom-full mb-2 w-48 p-2 text-sm text-gray-300 bg-gray-900 border border-gray-700 rounded-lg shadow-lg transform -translate-y-2 opacity-0 animate-slideFadeIn">
                      {descriptions[type]}
                    </div>
                  )}
                  {isHovered && <div className="absolute inset-0 rounded-2xl border-2 border-green-400 blur-md opacity-50 animate-pulse"></div>}
                </div>
              );
            })}
          </div>
        </div>

        <button
          type="submit"
          disabled={loading || !validateTarget(target, selected)}
          className="relative w-full p-4 rounded-2xl bg-gradient-to-r from-green-400 to-blue-500 font-bold text-lg overflow-hidden shadow-lg transform transition-all duration-300 hover:scale-105 hover:shadow-2xl disabled:opacity-50 disabled:cursor-not-allowed text-white"
        >
          {loading ? (
            <div className="flex items-center justify-center space-x-3">
              <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-white"></div>
              <span>Scanning...</span>
            </div>
          ) : (
            `Start ${selected.charAt(0).toUpperCase() + selected.slice(1)} Scan`
          )}
        </button>
      </form>

      <style jsx>{`
        @keyframes slideFadeIn {
          0% { opacity: 0; transform: translateY(10px); }
          100% { opacity: 1; transform: translateY(0); }
        }
        .animate-slideFadeIn { animation: slideFadeIn 0.3s forwards; }

        @keyframes bgGradient {
          0% { background-position: 0% 50%; }
          50% { background-position: 100% 50%; }
          100% { background-position: 0% 50%; }
        }
        .animate-bgGradient { 
          background: linear-gradient(-45deg, #010101, #0f0c29, #00111a); 
          background-size: 600% 600%; 
          animation: bgGradient 30s ease infinite; 
        }

        @keyframes pulseSlow {
          0%, 100% { text-shadow: 0 0 4px #00ff99, 0 0 8px #00ccff, 0 0 12px #00ffcc; }
          50% { text-shadow: 0 0 8px #00ff99, 0 0 16px #00ccff, 0 0 24px #00ffcc; }
        }
        .animate-pulse-slow { animation: pulseSlow 2s infinite; }

        @keyframes spinSlow {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        .animate-spin-slow { animation: spinSlow 10s linear infinite; }
      `}</style>
    </div>
  );
}
