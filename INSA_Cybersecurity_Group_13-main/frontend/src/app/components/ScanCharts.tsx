'use client';
import React from 'react';
import { Bar, Pie } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, BarElement, ArcElement, Tooltip, Legend);

const ScanCharts = () => {
  const barData = {
    labels: ['Quick', 'Full', 'Web', 'Stealth'],
    datasets: [
      {
        label: 'Vulnerabilities Found',
        data: [2, 5, 3, 1],
        backgroundColor: ['#3b82f6', '#6366f1', '#10b981', '#f59e0b'],
        borderRadius: 6,
      },
    ],
  };

  const pieData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [
      {
        data: [1, 3, 4, 2],
        backgroundColor: ['#ef4444', '#f97316', '#facc15', '#22c55e'],
      },
    ],
  };

  return (
    <div className="grid md:grid-cols-2 gap-6 mt-8">
      <div className="bg-white p-6 rounded-xl shadow-lg">
        <h3 className="font-bold text-lg mb-4">Vulnerabilities by Scan Type</h3>
        <Bar data={barData} />
      </div>
      <div className="bg-white p-6 rounded-xl shadow-lg">
        <h3 className="font-bold text-lg mb-4">Vulnerabilities by Severity</h3>
        <Pie data={pieData} />
      </div>
    </div>
  );
};

export default ScanCharts;
