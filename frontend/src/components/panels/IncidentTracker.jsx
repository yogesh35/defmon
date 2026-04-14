import React, { useEffect, useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { Loader2, ChevronRight, ShieldAlert } from 'lucide-react';

const IncidentTracker = () => {
  const { authFetch, user } = useAuth();
  const canManageIncidents = user?.role === 'admin' || user?.role === 'analyst';
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedRow, setExpandedRow] = useState(null);
  
  // Filters
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  useEffect(() => {
    const fetchIncidents = async () => {
      setLoading(true);
      try {
        const query = new URLSearchParams();
        if (statusFilter) query.append('status', statusFilter);
        if (severityFilter) query.append('severity', severityFilter);
        query.append('limit', '50');

        const res = await authFetch(`/api/incidents?${query.toString()}`);
        if (res.ok) {
          const data = await res.json();
          setIncidents(data);
        }
      } catch (err) {
        console.error("Failed to load incidents", err);
      } finally {
        setLoading(false);
      }
    };

    fetchIncidents();
  }, [authFetch, statusFilter, severityFilter]);

  const updateIncidentStatus = async (caseId, nextStatus) => {
    try {
      const res = await authFetch(`/api/incidents/${caseId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: nextStatus }),
      });
      if (res.ok) {
        const data = await res.json();
        setIncidents((prev) => prev.map((inc) => {
          if (inc.case_id !== caseId) return inc;
          return {
            ...inc,
            status: data.status,
            closed_at: data.closed_at,
          };
        }));
      }
    } catch (err) {
      console.error('Failed to update incident status', err);
    }
  };

  return (
    <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div className="glass-panel-header" style={{ gap: '1rem', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0, fontSize: '1.125rem' }}>Active Incidents Tracker</h2>
        
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
          <select 
            value={statusFilter} 
            onChange={(e) => setStatusFilter(e.target.value)}
            style={{ width: 'auto', padding: '0.5rem 1rem' }}
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="closed">Closed</option>
          </select>
          
          <select 
            value={severityFilter} 
            onChange={(e) => setSeverityFilter(e.target.value)}
            style={{ width: 'auto', padding: '0.5rem 1rem' }}
          >
            <option value="">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>
      </div>
      
      <div className="glass-panel-body" style={{ flex: 1, padding: 0, overflow: 'auto' }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '4rem' }}>
            <Loader2 className="spinner" />
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead style={{ position: 'sticky', top: 0, background: 'rgba(22, 30, 46, 0.95)', zIndex: 1, backdropFilter: 'blur(8px)' }}>
                <tr>
                  <th style={{ width: '40px' }}></th>
                  <th>Case ID</th>
                  <th>Date</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Source IP</th>
                </tr>
              </thead>
              <tbody>
                {incidents.length === 0 ? (
                  <tr>
                    <td colSpan="6" style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                      No incidents match the filters.
                    </td>
                  </tr>
                ) : (
                  incidents.map((inc) => (
                    <React.Fragment key={inc.id}>
                      <tr 
                        style={{ cursor: 'pointer' }} 
                        onClick={() => setExpandedRow(expandedRow === inc.id ? null : inc.id)}
                      >
                        <td>
                          <ChevronRight 
                            size={16} 
                            style={{ 
                              transform: expandedRow === inc.id ? 'rotate(90deg)' : 'none',
                              transition: 'transform 0.2s',
                              color: 'var(--text-muted)' 
                            }} 
                          />
                        </td>
                        <td style={{ fontFamily: 'monospace' }}>{inc.case_id.split('-')[0]}</td>
                        <td className="text-muted">{new Date(inc.created_at).toLocaleString()}</td>
                        <td>
                          <span className={`badge badge-${inc.severity.toLowerCase()}`}>
                            {inc.severity}
                          </span>
                        </td>
                        <td>
                          <span className={`badge badge-${inc.status.toLowerCase()}`}>
                            {inc.status}
                          </span>
                        </td>
                        <td style={{ fontFamily: 'monospace' }}>{inc.alert?.ip || 'N/A'}</td>
                      </tr>
                      
                      {expandedRow === inc.id && (
                        <tr style={{ background: 'rgba(0,0,0,0.2)' }}>
                          <td colSpan="6" style={{ padding: 0, borderBottom: '1px solid var(--panel-border)' }}>
                            <div className="animate-slide-down" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                <h3 style={{ fontSize: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                  <ShieldAlert size={18} color="var(--accent-blue)" />
                                  Incident Context
                                </h3>
                                <div className="text-secondary text-sm font-monospace">UUID: {inc.case_id}</div>
                              </div>
                              
                              <p className="text-muted" style={{ lineHeight: 1.5, background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: '8px' }}>
                                {inc.description}
                              </p>
                              
                              {inc.alert && (
                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
                                  <div>
                                    <div className="text-xs text-muted mb-1 uppercase">Trigger Rule</div>
                                    <div className="font-medium">{inc.alert.rule_id}</div>
                                  </div>
                                  {inc.closed_at && (
                                    <div>
                                      <div className="text-xs text-muted mb-1 uppercase">Closed Timestamp</div>
                                      <div className="font-medium">{new Date(inc.closed_at).toLocaleString()}</div>
                                    </div>
                                  )}
                                </div>
                              )}

                              {canManageIncidents && (
                                <div style={{ display: 'flex', gap: '0.75rem' }}>
                                  {inc.status === 'closed' ? (
                                    <button
                                      className="btn btn-secondary"
                                      onClick={() => updateIncidentStatus(inc.case_id, 'open')}
                                    >
                                      Reopen Incident
                                    </button>
                                  ) : (
                                    <button
                                      className="btn btn-primary"
                                      onClick={() => updateIncidentStatus(inc.case_id, 'closed')}
                                    >
                                      Close Incident
                                    </button>
                                  )}
                                </div>
                              )}
                              
                              {/* Future Phase: SOAR modifications would be injected here dependent on JWT roles */}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default IncidentTracker;
