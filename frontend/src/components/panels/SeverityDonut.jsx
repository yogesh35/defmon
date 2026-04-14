import React, { useEffect, useState } from 'react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';
import { useAuth } from '../../context/AuthContext';
import { Loader2 } from 'lucide-react';

ChartJS.register(ArcElement, Tooltip, Legend);

const SeverityDonut = () => {
  const { authFetch } = useAuth();
  const [data, setData] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await authFetch('/api/alerts/summary');
        if (res.ok) {
          const counts = await res.json();
          setData({
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [
              {
                data: [
                  counts.Critical || 0,
                  counts.High || 0,
                  counts.Medium || 0,
                  counts.Low || 0
                ],
                backgroundColor: [
                  '#ef4444', // Critical
                  '#f97316', // High
                  '#facc15', // Medium
                  '#3b82f6'  // Low
                ],
                borderColor: 'rgba(11, 15, 25, 1)',
                borderWidth: 4,
                hoverOffset: 4
              }
            ]
          });
        }
      } catch (err) {
        console.error("Failed to fetch alert summary", err);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [authFetch]);

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '75%',
    plugins: {
      legend: {
        position: 'right',
        labels: {
          color: '#e2e8f0',
          usePointStyle: true,
          padding: 20
        }
      },
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

  const totalAlerts = data
    ? data.datasets[0].data.reduce((acc, value) => acc + value, 0)
    : 0;

  return (
    <div style={{ height: '240px', width: '100%', display: 'flex', justifyContent: 'center', alignItems: 'center', position: 'relative' }}>
      {!data ? (
        <Loader2 className="spinner" />
      ) : (
        <>
          <Doughnut data={data} options={options} />
          <div
            style={{
              position: 'absolute',
              textAlign: 'center',
              pointerEvents: 'none',
            }}
          >
            <div style={{ fontSize: '1.4rem', fontWeight: 700 }}>{totalAlerts}</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>24h alerts</div>
          </div>
        </>
      )}
    </div>
  );
};

export default SeverityDonut;
