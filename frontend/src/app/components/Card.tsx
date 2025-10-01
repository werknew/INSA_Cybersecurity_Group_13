// components/SecurityCard.tsx
'use client';
import React from 'react';

interface SecurityCardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  trend?: number;
  subtitle?: string;
}

const SecurityCard: React.FC<SecurityCardProps> = ({ 
  title, 
  value, 
  icon, 
  severity = 'info',
  trend,
  subtitle
}) => {
  const severityConfig = {
    critical: {
      bg: 'bg-red-500/10',
      border: 'border-red-500/30',
      text: 'text-red-400',
      glow: 'shadow-red-500/20'
    },
    high: {
      bg: 'bg-orange-500/10',
      border: 'border-orange-500/30',
      text: 'text-orange-400',
      glow: 'shadow-orange-500/20'
    },
    medium: {
      bg: 'bg-yellow-500/10',
      border: 'border-yellow-500/30',
      text: 'text-yellow-400',
      glow: 'shadow-yellow-500/20'
    },
    low: {
      bg: 'bg-blue-500/10',
      border: 'border-blue-500/30',
      text: 'text-blue-400',
      glow: 'shadow-blue-500/20'
    },
    info: {
      bg: 'bg-gray-500/10',
      border: 'border-gray-500/30',
      text: 'text-gray-400',
      glow: 'shadow-gray-500/20'
    }
  };

  const config = severityConfig[severity];

  return (
    <div className={`relative p-6 rounded-xl border ${config.border} ${config.bg} backdrop-blur-sm transition-all duration-300 hover:scale-105 hover:${config.glow} hover:shadow-xl`}>
      <div className="flex items-center justify-between mb-4">
        <div className={`p-3 rounded-lg ${config.bg} border ${config.border}`}>
          <div className={config.text}>
            {icon}
          </div>
        </div>
        
        {trend !== undefined && (
          <div className={`px-2 py-1 rounded-full text-xs font-bold ${
            trend >= 0 
              ? 'bg-red-500/20 text-red-400 border border-red-500/30' 
              : 'bg-green-500/20 text-green-400 border border-green-500/30'
          }`}>
            {trend >= 0 ? '↗' : '↘'} {Math.abs(trend)}%
          </div>
        )}
      </div>
      
      <div>
        <p className="text-gray-400 text-sm font-medium mb-1">{title}</p>
        <p className={`text-3xl font-bold mb-1 ${config.text}`}>{value}</p>
        {subtitle && (
          <p className="text-gray-500 text-xs">{subtitle}</p>
        )}
      </div>

      {/* Animated pulse for critical items */}
      {severity === 'critical' && (
        <div className="absolute -top-1 -right-1">
          <div className="w-3 h-3 bg-red-500 rounded-full animate-ping"></div>
          <div className="w-3 h-3 bg-red-500 rounded-full absolute top-0 right-0"></div>
        </div>
      )}
    </div>
  );
};

export default SecurityCard;