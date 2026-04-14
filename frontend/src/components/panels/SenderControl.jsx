import React, { useEffect, useMemo, useState } from 'react';
import { useAuth } from '../../context/AuthContext';

const SenderControl = () => {
  const { authFetch } = useAuth();
  const [senders, setSenders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newAllowedIp, setNewAllowedIp] = useState('');
  const [secretNotice, setSecretNotice] = useState('');

  const stats = useMemo(() => {
    const blocked = senders.filter((s) => s.is_blocked).length;
    const inactive = senders.filter((s) => !s.is_active).length;
    return { total: senders.length, blocked, inactive };
  }, [senders]);

  const loadSenders = async () => {
    setLoading(true);
    try {
      const res = await authFetch('/api/senders');
      if (!res.ok) {
        setSenders([]);
        return;
      }
      const data = await res.json();
      setSenders(data);
    } catch (err) {
      console.error('Failed to load senders', err);
      setSenders([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSenders();
    const interval = setInterval(loadSenders, 10000);
    return () => clearInterval(interval);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const createSender = async (e) => {
    e.preventDefault();
    if (!newName.trim()) return;

    setCreating(true);
    setSecretNotice('');
    try {
      const res = await authFetch('/api/senders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newName.trim(),
          description: newDescription.trim(),
          allowed_ip: newAllowedIp.trim() || null,
        }),
      });

      if (!res.ok) {
        const errorText = await res.text();
        setSecretNotice(`Create failed: ${errorText}`);
        return;
      }

      const data = await res.json();
      setSecretNotice(`Sender key for ${data.sender.name}: ${data.api_key}`);
      setNewName('');
      setNewDescription('');
      setNewAllowedIp('');
      await loadSenders();
    } catch (err) {
      console.error('Failed to create sender', err);
      setSecretNotice('Create failed due to network/server error.');
    } finally {
      setCreating(false);
    }
  };

  const patchSender = async (senderId, route, body) => {
    setSecretNotice('');
    try {
      const res = await authFetch(`/api/senders/${senderId}/${route}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        setSecretNotice(`Action failed for sender ${senderId}`);
        return;
      }
      await loadSenders();
    } catch (err) {
      console.error('Sender action failed', err);
      setSecretNotice('Sender action failed due to network/server error.');
    }
  };

  const revokeKey = async (senderId, senderName) => {
    setSecretNotice('');
    try {
      const res = await authFetch(`/api/senders/${senderId}/revoke-key`, {
        method: 'POST',
      });
      if (!res.ok) {
        setSecretNotice(`Key revoke failed for ${senderName}`);
        return;
      }
      const data = await res.json();
      setSecretNotice(`New key for ${senderName}: ${data.api_key}`);
      await loadSenders();
    } catch (err) {
      console.error('Failed to revoke sender key', err);
      setSecretNotice('Key revoke failed due to network/server error.');
    }
  };

  const deleteSender = async (senderId, senderName) => {
    const ok = window.confirm(`Delete sender ${senderName}? This cannot be undone.`);
    if (!ok) return;

    setSecretNotice('');
    try {
      const res = await authFetch(`/api/senders/${senderId}`, { method: 'DELETE' });
      if (!res.ok) {
        setSecretNotice(`Delete failed for ${senderName}`);
        return;
      }
      await loadSenders();
    } catch (err) {
      console.error('Failed to delete sender', err);
      setSecretNotice('Delete failed due to network/server error.');
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
        <span className="badge" style={{ background: 'rgba(59,130,246,0.12)', color: 'var(--accent-blue)' }}>
          Total: {stats.total}
        </span>
        <span className="badge" style={{ background: 'rgba(239,68,68,0.15)', color: '#fca5a5' }}>
          Blocked: {stats.blocked}
        </span>
        <span className="badge" style={{ background: 'rgba(250,204,21,0.16)', color: '#fde047' }}>
          Inactive: {stats.inactive}
        </span>
      </div>

      <form onSubmit={createSender} style={{ display: 'grid', gridTemplateColumns: '2fr 2fr 1.5fr auto', gap: '0.75rem' }}>
        <input
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          placeholder="Sender name"
          required
        />
        <input
          value={newDescription}
          onChange={(e) => setNewDescription(e.target.value)}
          placeholder="Description"
        />
        <input
          value={newAllowedIp}
          onChange={(e) => setNewAllowedIp(e.target.value)}
          placeholder="Allowed IP (optional)"
        />
        <button type="submit" disabled={creating}>{creating ? 'Creating...' : 'Add Sender'}</button>
      </form>

      {secretNotice && (
        <div style={{
          fontFamily: 'monospace',
          fontSize: '0.8rem',
          background: 'rgba(8, 12, 20, 0.85)',
          border: '1px solid var(--panel-border)',
          borderRadius: '8px',
          padding: '0.75rem',
          color: 'var(--text-primary)',
          wordBreak: 'break-all',
        }}>
          {secretNotice}
        </div>
      )}

      <div className="table-container" style={{ maxHeight: '320px', overflowY: 'auto' }}>
        <table>
          <thead style={{ position: 'sticky', top: 0, background: 'rgba(22, 30, 46, 0.95)', zIndex: 1 }}>
            <tr>
              <th>Name</th>
              <th>Allowed IP</th>
              <th>Status</th>
              <th>Last Seen</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', padding: '1rem' }}>Loading senders...</td>
              </tr>
            ) : senders.length === 0 ? (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', padding: '1rem', color: 'var(--text-muted)' }}>
                  No senders configured.
                </td>
              </tr>
            ) : (
              senders.map((sender) => (
                <tr key={sender.id}>
                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                      <strong>{sender.name}</strong>
                      <span className="text-muted text-sm" style={{ fontSize: '0.75rem' }}>{sender.description || '-'}</span>
                    </div>
                  </td>
                  <td style={{ fontFamily: 'monospace' }}>{sender.allowed_ip || 'Any'}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                      <span className={`badge ${sender.is_active ? 'badge-low' : 'badge-medium'}`}>
                        {sender.is_active ? 'active' : 'inactive'}
                      </span>
                      <span className={`badge ${sender.is_blocked ? 'badge-critical' : 'badge-closed'}`}>
                        {sender.is_blocked ? 'blocked' : 'allowed'}
                      </span>
                    </div>
                  </td>
                  <td className="text-muted text-sm">
                    {sender.last_seen_at ? new Date(sender.last_seen_at).toLocaleString() : 'Never'}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                      <button
                        className="secondary"
                        onClick={() => patchSender(sender.id, 'block', { is_blocked: !sender.is_blocked, reason: sender.is_blocked ? '' : 'Blocked by admin' })}
                      >
                        {sender.is_blocked ? 'Unblock' : 'Block'}
                      </button>
                      <button
                        className="secondary"
                        onClick={() => patchSender(sender.id, 'active', { is_active: !sender.is_active })}
                      >
                        {sender.is_active ? 'Deactivate' : 'Activate'}
                      </button>
                      <button className="secondary" onClick={() => revokeKey(sender.id, sender.name)}>Revoke Key</button>
                      <button onClick={() => deleteSender(sender.id, sender.name)} style={{ background: '#991b1b' }}>Delete</button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default SenderControl;
