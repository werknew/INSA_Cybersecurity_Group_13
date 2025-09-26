'use client';
import React from 'react';
import Link from 'next/link';
import { FaHome, FaTasks, FaCogs, FaShieldAlt } from 'react-icons/fa';

const Sidebar = () => {
  return (
    <aside className="w-64 bg-gradient-to-b from-blue-600 to-indigo-700 text-white h-screen p-6 flex flex-col">
      <h2 className="text-2xl font-bold mb-8">Vulnerability Scanner</h2>
      <nav className="flex-1 flex flex-col space-y-3">
        <Link href="/" className="flex items-center gap-3 p-3 rounded hover:bg-white/20 transition">
          <FaHome /> <span>Dashboard</span>
        </Link>
        <Link href="/scans" className="flex items-center gap-3 p-3 rounded hover:bg-white/20 transition">
          <FaTasks /> <span>Scans</span>
        </Link>
        <Link href="/reports" className="flex items-center gap-3 p-3 rounded hover:bg-white/20 transition">
          <FaShieldAlt /> <span>Reports</span>
        </Link>
        <Link href="/settings" className="flex items-center gap-3 p-3 rounded hover:bg-white/20 transition">
          <FaCogs /> <span>Settings</span>
        </Link>
      </nav>
    </aside>
  );
};

export default Sidebar;
