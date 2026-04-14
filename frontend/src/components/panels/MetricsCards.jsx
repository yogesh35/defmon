import React, { useEffect, useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { ShieldAlert, AlertTriangle, AlertCircle, Info } from 'lucide-react';

const MetricsCards = () => {
  const { authFetch } = useAuth();
  const [summary, setSummary] = useState({ Critical: 0, High: 0, Medium: 0, Low: 0 });

  useEffect(() => {
    const fetchSummary = async () => {
      try {
        const res = await authFetch('/api/alerts/summary');
        if (res.ok) {
          const data = await res.json();
          setSummary(data);
        }
      } catch (err) {
        console.error('Failed to load alert summary', err);
      }
    };
    
    fetchSummary();
    const interval = setInterval(fetchSummary, 10000);
    return () => clearInterval(interval);
  }, [authFetch]);

  const totalAlerts =
    (summary.Critical || 0) +
    (summary.High || 0) +
    (summary.Medium || 0) +
    (summary.Low || 0);

  return (
    <>
      <div className="glass-panel" style={{ padding: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
          <div style={{ background: 'rgba(59, 130, 246, 0.2)', padding: '0.75rem', borderRadius: '12px' }}>
            <ShieldAlert size={24} color="var(--critical)" />
          </div>
          <div>
            <div className="text-sm text-secondary font-medium">Critical Alerts</div>
            <div className="text-xs text-muted">Last 24 hours</div>
          </div>
        </div>
        <div className="metric-value">{summary.Critical || 0}</div>
      </div>

      <div className="glass-panel" style={{ padding: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
          <div style={{ background: 'rgba(34, 197, 94, 0.2)', padding: '0.75rem', borderRadius: '12px' }}>
            <AlertTriangle size={24} color="var(--high)" />
          </div>
          <div>
            <div className="text-sm text-secondary font-medium">High Alerts</div>
            <div className="text-xs text-muted">Last 24 hours</div>
          </div>
        </div>
        <div className="metric-value">{summary.High || 0}</div>
      </div>

      <div className="glass-panel" style={{ padding: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
          <div style={{ background: 'rgba(250, 204, 21, 0.2)', padding: '0.75rem', borderRadius: '12px' }}>
            <AlertCircle size={24} color="var(--medium)" />
          </div>
          <div>
            <div className="text-sm text-secondary font-medium">Medium Alerts</div>
            <div className="text-xs text-muted">Last 24 hours</div>
          </div>
        </div>
        <div className="metric-value">{summary.Medium || 0}</div>
      </div>

      <div className="glass-panel" style={{ padding: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
          <div style={{ background: 'rgba(59, 130, 246, 0.2)', padding: '0.75rem', borderRadius: '12px' }}>
            <Info size={24} color="var(--accent-blue)" />
          </div>
          <div>
            <div className="text-sm text-secondary font-medium">Total Alerts</div>
            <div className="text-xs text-muted">Critical + High + Medium + Low</div>
          </div>
        </div>
        <div className="metric-value">{totalAlerts}</div>
      </div>
    </>
  );
};

export default MetricsCards;
