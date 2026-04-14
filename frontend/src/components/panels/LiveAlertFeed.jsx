import React, { useState, useEffect } from 'react';
import { useWebSocket } from '../../context/WebSocketContext';
import { useAuth } from '../../context/AuthContext';
import { ShieldAlert, AlertTriangle, AlertCircle, Info } from 'lucide-react';

const SeverityIcon = ({ severity }) => {
  switch (severity) {
    case 'Critical': return <ShieldAlert size={16} />;
    case 'High': return <AlertTriangle size={16} />;
    case 'Medium': return <AlertCircle size={16} />;
    default: return <Info size={16} />;
  }
};

const LiveAlertFeed = () => {
  const { alerts } = useWebSocket();
  const { user, authFetch } = useAuth();
  const canTriage = user?.role === 'admin' || user?.role === 'analyst';
  const [animatedIds, setAnimatedIds] = useState(new Set());
  const [localStatuses, setLocalStatuses] = useState({});

  // Simple hook to track new rows for slide-down animation
  useEffect(() => {
    if (alerts.length > 0) {
      const latestId = alerts[0].id;
      if (!animatedIds.has(latestId)) {
        setAnimatedIds(prev => new Set(prev).add(latestId));
      }
    }
  }, [alerts]);

  const handleStatusUpdate = async (alertId, nextStatus) => {
    if (!alertId || !canTriage) return;
    try {
      const res = await authFetch(`/api/alerts/${alertId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: nextStatus }),
      });
      if (res.ok) {
        const data = await res.json();
        setLocalStatuses((prev) => ({ ...prev, [data.alert_id]: data.status }));
      }
    } catch (err) {
      console.error('Failed to update alert status', err);
    }
  };

  return (
    <div className="table-container" style={{ maxHeight: '400px', overflowY: 'auto' }}>
      <table>
        <thead style={{ position: 'sticky', top: 0, background: 'rgba(22, 30, 46, 0.95)', zIndex: 1, backdropFilter: 'blur(8px)' }}>
          <tr>
            <th>Time</th>
            <th>IP Address</th>
            <th>Rule ID</th>
            <th>Severity</th>
            <th>Status</th>
            {canTriage && <th>Actions</th>}
          </tr>
        </thead>
        <tbody>
          {alerts.length === 0 ? (
            <tr>
              <td colSpan={canTriage ? '6' : '5'} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                Waiting for incoming alerts...
              </td>
            </tr>
          ) : (
            alerts.map((alert, idx) => {
              // The first element added recently gets the animation
              const isNew = animatedIds.has(alert.id) && idx === 0;
              const effectiveStatus = localStatuses[alert.alert_id] || alert.status;
              return (
                <tr key={`${alert.id}-${alert.alert_id}`} className={isNew ? 'animate-slide-down' : ''}>
                  <td className="text-muted text-sm">
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </td>
                  <td style={{ fontFamily: 'monospace' }}>{alert.ip}</td>
                  <td>{alert.rule_id}</td>
                  <td>
                    <span className={`badge badge-${alert.severity.toLowerCase()} flex items-center gap-1`}>
                      <SeverityIcon severity={alert.severity} />
                      {alert.severity}
                    </span>
                  </td>
                  <td>
                    <span className={`badge badge-${effectiveStatus.toLowerCase()}`}>
                      {effectiveStatus}
                    </span>
                  </td>
                  {canTriage && (
                    <td>
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                          onClick={() => handleStatusUpdate(alert.alert_id, 'acknowledged')}
                          disabled={effectiveStatus === 'acknowledged' || effectiveStatus === 'resolved'}
                        >
                          Ack
                        </button>
                        <button
                          className="btn btn-primary"
                          style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                          onClick={() => handleStatusUpdate(alert.alert_id, 'resolved')}
                          disabled={effectiveStatus === 'resolved'}
                        >
                          Resolve
                        </button>
                      </div>
                    </td>
                  )}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
};

export default LiveAlertFeed;
