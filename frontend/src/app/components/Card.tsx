'use client';
import React from 'react';

interface CardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  color?: string;
}

const Card: React.FC<CardProps> = ({ title, value, icon, color }) => {
  return (
    <div
      className={`flex items-center p-6 rounded-xl shadow-xl transform transition-transform duration-300 hover:scale-105 ${color || 'bg-gradient-to-r from-blue-500 to-indigo-500'} text-white`}
    >
      <div className="text-5xl mr-5">{icon}</div>
      <div>
        <p className="text-sm font-semibold opacity-80">{title}</p>
        <p className="text-3xl font-bold">{value}</p>
      </div>
    </div>
  );
};

export default Card;
