import React, { useEffect, useState } from 'react';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Tooltip, Legend } from 'chart.js';
import { Bar } from 'react-chartjs-2';
import { useAuth } from '../../context/AuthContext';
import { Loader2 } from 'lucide-react';

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

const TopOffenders = () => {
  const { authFetch } = useAuth();
  const [data, setData] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await authFetch('/api/alerts/top-offenders');
        if (res.ok) {
          const offenders = await res.json();
          setData({
            labels: offenders.map(o => o.ip),
            datasets: [
              {
                label: 'Total Alerts (24h)',
                data: offenders.map(o => o.alerts),
                backgroundColor: 'rgba(59, 130, 246, 0.8)',
                borderRadius: 4,
                barThickness: 16
              }
            ]
          });
        }
      } catch (err) {
        console.error("Failed to fetch top offenders", err);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 300000); // refresh every 5 min
    return () => clearInterval(interval);
  }, [authFetch]);

  const options = {
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: {
        grid: { color: 'rgba(55, 65, 81, 0.2)' },
        ticks: { color: '#94a3b8' },
        beginAtZero: true
      },
      y: {
        grid: { display: false },
        ticks: { color: '#e2e8f0', font: { family: 'monospace' } }
      }
    },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: 'rgba(22, 30, 46, 0.9)',
        titleColor: '#e2e8f0',
        bodyColor: '#e2e8f0',
        borderColor: 'rgba(55, 65, 81, 0.4)',
        borderWidth: 1,
        padding: 12
      }
    }
  };

  return (
    <div style={{ height: '300px', width: '100%', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
      {!data ? (
        <Loader2 className="spinner" />
      ) : (
        <Bar data={data} options={options} />
      )}
    </div>
  );
};

export default TopOffenders;
