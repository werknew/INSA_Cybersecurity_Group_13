// components/SecurityLayout.tsx
'use client';
import React from 'react';
import SecuritySidebar from './Sidebar';

interface SecurityLayoutProps {
  children: React.ReactNode;
}

const SecurityLayout: React.FC<SecurityLayoutProps> = ({ children }) => {
  return (
    <div className="flex min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
      <SecuritySidebar />
      <main className="flex-1 p-6 ml-20">
        <div className="max-w-7xl mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
};

export default SecurityLayout;