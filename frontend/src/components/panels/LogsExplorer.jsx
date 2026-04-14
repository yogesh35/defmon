import React, { useEffect, useState } from 'react';
import { useAuth } from '../../context/AuthContext';

const LogsExplorer = () => {
  const { authFetch } = useAuth();
  const [mode, setMode] = useState('received');
  const [logs, setLogs] = useState([]);
  const [selectedPath, setSelectedPath] = useState('');
  const [content, setContent] = useState('');
  const [receivedRows, setReceivedRows] = useState([]);
  const [senderFilter, setSenderFilter] = useState('all');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (mode !== 'files') {
      return;
    }

    const loadLogs = async () => {
      try {
        const res = await authFetch('/api/logs');
        if (!res.ok) return;
        const data = await res.json();
        setLogs(data);
        if (data.length > 0) {
          setSelectedPath(data[0].path);
        }
      } catch (err) {
        console.error('Failed to load log files', err);
      }
    };

    loadLogs();
  }, [authFetch, mode]);

  useEffect(() => {
    if (mode !== 'files') {
      return;
    }

    if (!selectedPath) {
      setContent('');
      return;
    }

    const loadContent = async () => {
      setLoading(true);
      try {
        const encodedPath = encodeURIComponent(selectedPath);
        const res = await authFetch(`/api/logs/content?path=${encodedPath}&lines=300`);
        if (!res.ok) {
          setContent('Failed to load log content');
          return;
        }
        const data = await res.json();
        setContent(data.content || '');
      } catch (err) {
        console.error('Failed to load log content', err);
        setContent('Failed to load log content');
      } finally {
        setLoading(false);
      }
    };

    loadContent();
  }, [authFetch, selectedPath, mode]);

  useEffect(() => {
    if (mode !== 'received') {
      return;
    }

    const loadReceived = async () => {
      setLoading(true);
      try {
        const query = new URLSearchParams();
        query.set('limit', '300');
        if (senderFilter !== 'all') {
          query.set('sender_id', senderFilter);
        }

        const res = await authFetch(`/api/logs/received?${query.toString()}`);
        if (!res.ok) {
          setReceivedRows([]);
          setContent('Failed to load received log stream');
          return;
        }

        const data = await res.json();
        setReceivedRows(data);

        const ordered = [...data].reverse();
        const merged = ordered
          .map((row) => {
            const ts = row.timestamp ? new Date(row.timestamp).toISOString() : '-';
            const senderLabel = row.sender_name || row.sender_id || 'local-file';
            return `[${ts}] [sender=${senderLabel}] ${row.raw_line}`;
          })
          .join('\n');
        setContent(merged || 'No received logs found.');
      } catch (err) {
        console.error('Failed to load received logs', err);
        setReceivedRows([]);
        setContent('Failed to load received log stream');
      } finally {
        setLoading(false);
      }
    };

    loadReceived();
    const interval = setInterval(loadReceived, 5000);
    return () => clearInterval(interval);
  }, [authFetch, mode, senderFilter]);

  const handleDownload = async () => {
    if (!selectedPath) return;
    try {
      const encodedPath = encodeURIComponent(selectedPath);
      const res = await authFetch(`/api/logs/download?path=${encodedPath}`);
      if (!res.ok) {
        return;
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = selectedPath.split('/').pop() || 'log.txt';
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to download log', err);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
        <select value={mode} onChange={(e) => setMode(e.target.value)} style={{ width: '220px' }}>
          <option value="received">Received Stream</option>
          <option value="files">File Browser</option>
        </select>

        {mode === 'received' && (
          <select value={senderFilter} onChange={(e) => setSenderFilter(e.target.value)} style={{ flex: 1, minWidth: 0 }}>
            <option value="all">All Senders</option>
            {Array.from(new Map(
              receivedRows
                .filter((row) => row.sender_id)
                .map((row) => [row.sender_id, row.sender_name || row.sender_id])
            ).entries()).map(([id, name]) => (
              <option key={id} value={id}>{name}</option>
            ))}
          </select>
        )}

        {mode === 'files' && (
        <select
          value={selectedPath}
          onChange={(e) => setSelectedPath(e.target.value)}
          style={{ flex: 1, minWidth: 0 }}
        >
          {logs.length === 0 && <option value="">No log files found</option>}
          {logs.map((log) => (
            <option key={log.path} value={log.path}>
              {log.path}
            </option>
          ))}
        </select>
        )}

        {mode === 'received' && (
          <span className="badge" style={{ background: 'rgba(59,130,246,0.14)', color: 'var(--accent-blue)' }}>
            Rows: {receivedRows.length}
          </span>
        )}

        <button className="btn btn-secondary" onClick={handleDownload} disabled={mode !== 'files' || !selectedPath}>
          Download
        </button>
      </div>

      <textarea
        value={loading ? 'Loading log content...' : content}
        readOnly
        style={{
          width: '100%',
          minHeight: '220px',
          fontFamily: 'monospace',
          fontSize: '0.8rem',
          lineHeight: 1.35,
          resize: 'vertical',
          background: 'rgba(8, 12, 20, 0.85)',
          border: '1px solid var(--panel-border)',
          color: 'var(--text-primary)',
        }}
      />
    </div>
  );
};

export default LogsExplorer;
