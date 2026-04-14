import React, { useEffect, useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { Download, ShieldCheck, Siren, Radar, Ban, Workflow } from 'lucide-react';

const StatPill = ({ icon: Icon, label, value, tone }) => (
  <div style={{
    border: '1px solid var(--panel-border)',
    background: 'rgba(255,255,255,0.02)',
    borderRadius: '10px',
    padding: '0.9rem',
  }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
      <Icon size={16} color={tone} />
      <span className="text-xs text-secondary">{label}</span>
    </div>
    <div style={{ fontSize: '1.25rem', fontWeight: 700 }}>{value}</div>
  </div>
);

const ExecutiveOverview = () => {
  const { authFetch } = useAuth();
  const [overview, setOverview] = useState(null);

  useEffect(() => {
    const fetchOverview = async () => {
      try {
        const res = await authFetch('/api/overview');
        if (!res.ok) return;
        setOverview(await res.json());
      } catch (err) {
        console.error('Failed to fetch executive overview', err);
      }
    };

    fetchOverview();
    const interval = setInterval(fetchOverview, 10000);
    return () => clearInterval(interval);
  }, [authFetch]);

  const handleDownloadReport = async () => {
    try {
      const res = await authFetch('/api/reports/daily/download');
      if (!res.ok) return;
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'defmon_daily_report.json';
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to download daily report', err);
    }
  };

  if (!overview) {
    return (
      <div className="text-muted" style={{ padding: '0.75rem 0' }}>
        Loading executive overview...
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: '1.1rem' }}>Executive Security Overview</div>
          <div className="text-xs text-muted">Updated {new Date(overview.generated_at).toLocaleString()}</div>
        </div>
        <button className="btn btn-primary" onClick={handleDownloadReport}>
          <Download size={14} />
          Download Daily SOC Report
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '0.75rem' }}>
        <StatPill icon={Siren} label="Alerts (24h)" value={overview.alerts_24h} tone="var(--high)" />
        <StatPill icon={ShieldCheck} label="Critical (24h)" value={overview.critical_24h} tone="var(--critical)" />
        <StatPill icon={Radar} label="Open Incidents" value={overview.open_incidents} tone="var(--accent-blue)" />
        <StatPill icon={Ban} label="Blocked IPs" value={overview.blocked_ips} tone="var(--closed)" />
        <StatPill icon={Workflow} label="SOAR Actions (24h)" value={overview.actions_24h} tone="var(--accent-blue)" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.75rem' }}>
        <div style={{ border: '1px solid var(--panel-border)', borderRadius: '10px', padding: '0.75rem' }}>
          <div className="text-xs text-muted" style={{ marginBottom: '0.25rem' }}>Top Rule (24h)</div>
          <div style={{ fontWeight: 600 }}>
            {overview.top_rule ? `${overview.top_rule.rule_id} (${overview.top_rule.count})` : 'No data'}
          </div>
        </div>
        <div style={{ border: '1px solid var(--panel-border)', borderRadius: '10px', padding: '0.75rem' }}>
          <div className="text-xs text-muted" style={{ marginBottom: '0.25rem' }}>Top Attacker (24h)</div>
          <div style={{ fontWeight: 600 }}>
            {overview.top_attacker ? `${overview.top_attacker.ip} (${overview.top_attacker.count})` : 'No data'}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ExecutiveOverview;
