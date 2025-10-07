'use client';
import React from 'react';
import SecuritySidebar from './Sidebar';
import { useAuth } from './AuthContext';

interface SecurityLayoutProps {
  children: React.ReactNode;
}

const SecurityLayout: React.FC<SecurityLayoutProps> = ({ children }) => {
  const { user, logout } = useAuth();

  return (
    <div className="flex min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
      <SecuritySidebar />
      <main className="flex-1 p-6 ml-20">
        {/* Header with User Info */}
        <div className="flex justify-between items-center mb-6 p-4 bg-gray-800/50 rounded-xl border border-gray-700">
          <div>
            <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
            <p className="text-gray-400">Welcome back, {user?.email}</p>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div className={`w-3 h-3 rounded-full ${
                user?.role === 'admin' ? 'bg-red-500' : 
                user?.role === 'user' ? 'bg-blue-500' : 'bg-green-500'
              }`}></div>
              <span className="text-gray-300 capitalize">{user?.role}</span>
            </div>
            <button
              onClick={logout}
              className="px-4 py-2 bg-gray-700/50 border border-gray-600 rounded-lg text-gray-300 hover:bg-gray-600/50 transition-colors"
            >
              Logout
            </button>
          </div>
        </div>
        
        <div className="max-w-7xl mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
};

export default SecurityLayout;