import React, { useEffect, useState } from 'react';
import { useAuth } from '../../context/AuthContext';

const AuditTrail = () => {
  const { authFetch } = useAuth();
  const [rows, setRows] = useState([]);

  useEffect(() => {
    const fetchAudit = async () => {
      try {
        const res = await authFetch('/api/audit?limit=50');
        if (res.ok) {
          const data = await res.json();
          setRows(data);
        }
      } catch (err) {
        console.error('Failed to load audit trail', err);
      }
    };

    fetchAudit();
    const interval = setInterval(fetchAudit, 10000);
    return () => clearInterval(interval);
  }, [authFetch]);

  return (
    <div className="table-container" style={{ maxHeight: '320px', overflowY: 'auto' }}>
      <table>
        <thead style={{ position: 'sticky', top: 0, background: 'rgba(22, 30, 46, 0.95)', zIndex: 1 }}>
          <tr>
            <th>Time</th>
            <th>Action</th>
            <th>Target</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan="4" style={{ textAlign: 'center', padding: '1rem', color: 'var(--text-muted)' }}>
                No SOAR actions recorded yet.
              </td>
            </tr>
          ) : (
            rows.map((row) => (
              <tr key={row.id}>
                <td className="text-muted text-sm">{row.timestamp ? new Date(row.timestamp).toLocaleTimeString() : '-'}</td>
                <td>{row.action}</td>
                <td style={{ fontFamily: 'monospace' }}>{row.target}</td>
                <td className="text-muted text-sm">{row.details || '-'}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
};

export default AuditTrail;
