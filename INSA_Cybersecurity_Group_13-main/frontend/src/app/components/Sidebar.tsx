'use client';
import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAuth } from './AuthContext';
import { 
  FaShieldAlt, 
  FaSearch, 
  FaFileAlt, 
  FaCog,
  FaRadiation,
  FaUserShield,
  FaUser,
  FaSignOutAlt
} from 'react-icons/fa';

const SecuritySidebar = () => {
  const pathname = usePathname();
  const { user, logout } = useAuth();

  const navItems = [
    { href: '/', icon: FaShieldAlt, label: 'Dashboard', color: 'text-blue-400' },
    { href: '/scans', icon: FaSearch, label: 'Scans', color: 'text-green-400' },
    { href: '/vulnerabilities', icon: FaRadiation, label: 'Vulnerabilities', color: 'text-red-400' },
    { href: '/reports', icon: FaFileAlt, label: 'Reports', color: 'text-purple-400' },
    { href: '/settings', icon: FaCog, label: 'Settings', color: 'text-gray-400' },
  ];

  return (
    <aside className="w-20 bg-gray-800/90 backdrop-blur-lg border-r border-gray-700 h-screen fixed left-0 top-0 flex flex-col items-center py-6 space-y-8">
      {/* Logo */}
      <div className="p-3 bg-gradient-to-br from-red-500 to-orange-500 rounded-xl shadow-lg">
        <FaUserShield className="text-white text-2xl" />
      </div>

      {/* Navigation */}
      <nav className="flex-1 flex flex-col space-y-6">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href;
          
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`group relative p-3 rounded-xl transition-all duration-200 ${
                isActive 
                  ? 'bg-gray-700 shadow-inner border border-gray-600' 
                  : 'hover:bg-gray-700/50'
              }`}
              title={item.label}
            >
              <Icon className={`text-xl transition-transform duration-200 group-hover:scale-110 ${
                isActive ? item.color : 'text-gray-400 group-hover:' + item.color
              }`} />
              
              {/* Active indicator */}
              {isActive && (
                <div className="absolute -right-1 top-1/2 transform -translate-y-1/2 w-1 h-6 bg-red-500 rounded-l"></div>
              )}
            </Link>
          );
        })}
      </nav>

      {/* User Info & Logout */}
      <div className="flex flex-col items-center space-y-4">
        <div className="p-2 bg-cyan-500/20 rounded-lg border border-cyan-500/30" title={user?.email}>
          <FaUser className="text-cyan-400 text-lg" />
        </div>
        
        <button
          onClick={logout}
          className="p-2 bg-red-500/20 rounded-lg border border-red-500/30 hover:bg-red-500/30 transition-colors"
          title="Logout"
        >
          <FaSignOutAlt className="text-red-400 text-lg" />
        </button>
      </div>
    </aside>
  );
};

export default SecuritySidebar;