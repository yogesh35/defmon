import React, { createContext, useContext, useState, useEffect, useRef } from 'react';
import { useAuth } from './AuthContext';

const WebSocketContext = createContext(null);

export const WebSocketProvider = ({ children }) => {
  const { token } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const ws = useRef(null);

  useEffect(() => {
    // Only connect if user is authenticated
    if (!token) return;
    let shouldReconnect = true;

    // We connect to the same host using ws:// or wss:// depending on protocol
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Since we proxy /api to the backend in Vite, we can just use the host
    const wsUrl = `${protocol}//${window.location.host}/api/ws/alerts?token=${encodeURIComponent(token)}`;

    const connectWS = () => {
      ws.current = new WebSocket(wsUrl);

      ws.current.onopen = () => {
        console.log('Live Alert Stream Connected');
      };

      ws.current.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          const newAlert = payload?.type === 'alert' && payload?.alert ? payload.alert : payload;
          const normalizedAlert = {
            ...newAlert,
            id: newAlert.id || newAlert.alert_id,
          };
          setAlerts((prevAlerts) => {
            // Keep last 50 alerts in memory
            const updated = [normalizedAlert, ...prevAlerts];
            return updated.slice(0, 50);
          });
        } catch (err) {
          console.error("Failed to parse websocket message", err);
        }
      };

      ws.current.onclose = () => {
        if (shouldReconnect) {
          console.log('WebSocket Connection Closed. Reconnecting in 5s...');
          setTimeout(connectWS, 5000);
        }
      };

      ws.current.onerror = (error) => {
        console.error('WebSocket Error:', error);
      };
    };

    connectWS();

    return () => {
      shouldReconnect = false;
      if (ws.current) {
        // Prevent reconnect loop on unmount
        ws.current.onclose = null; 
        ws.current.close();
      }
    };
  }, [token]);

  // Initial fetch for the last 50 alerts so the table isn't empty upon connection
  useEffect(() => {
    if (!token) return;
    
    // AuthContext's fetch is better here but since we need basic fetch inside effect:
    const fetchHistory = async () => {
      try {
        const res = await fetch('/api/alerts?limit=50', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
          const data = await res.json();
          setAlerts(data);
        }
      } catch (err) {
        console.error('Failed to load initial alert history', err);
      }
    };

    fetchHistory();
  }, [token]);

  return (
    <WebSocketContext.Provider value={{ alerts }}>
      {children}
    </WebSocketContext.Provider>
  );
};

// eslint-disable-next-line react-refresh/only-export-components
export const useWebSocket = () => useContext(WebSocketContext);
