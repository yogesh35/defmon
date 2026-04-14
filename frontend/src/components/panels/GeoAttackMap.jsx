import React, { useMemo } from 'react';
import { MapContainer, TileLayer, CircleMarker, Tooltip } from 'react-leaflet';
import { useWebSocket } from '../../context/WebSocketContext';

// Simple deterministic hash to map an IP string to a Lat/Lon coordinate roughly spread across the globe
const ipToGeo = (ip) => {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return [0, 0];
  
  // Hash logic for mock rendering
  const lat = ((parts[0] * parts[1]) % 160) - 80;    // -80 to 80
  const lon = ((parts[2] * parts[3]) % 360) - 180;   // -180 to 180
  
  return [lat, lon];
};

const getSeverityColor = (severity) => {
  switch (severity) {
    case 'Critical': return '#ef4444';
    case 'High': return '#f97316';
    case 'Medium': return '#facc15';
    default: return '#3b82f6';
  }
};

const GeoAttackMap = () => {
  const { alerts } = useWebSocket();

  // Aggregate alerts by IP to draw markers
  const markers = useMemo(() => {
    const ipMap = new Map();
    
    alerts.forEach(alert => {
      if (!ipMap.has(alert.ip)) {
        ipMap.set(alert.ip, {
          ip: alert.ip,
          count: 1,
          maxSeverity: alert.severity, // Simplification for mock map
          coords: ipToGeo(alert.ip)
        });
      } else {
        const entry = ipMap.get(alert.ip);
        entry.count += 1;
        // Should really do severity weighting, but simple override is ok
        if (alert.severity === 'Critical') entry.maxSeverity = 'Critical';
        else if (alert.severity === 'High' && entry.maxSeverity !== 'Critical') entry.maxSeverity = 'High';
      }
    });

    return Array.from(ipMap.values());
  }, [alerts]);

  return (
    <div style={{ height: '350px', width: '100%', borderRadius: '16px', overflow: 'hidden' }}>
      <MapContainer 
        center={[20, 0]} 
        zoom={2} 
        style={{ height: '100%', width: '100%', zIndex: 1 }}
        scrollWheelZoom={false}
      >
        <TileLayer
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
        />
        
        {markers.map((m) => (
          <CircleMarker
            key={m.ip}
            center={m.coords}
            pathOptions={{ 
              color: getSeverityColor(m.maxSeverity), 
              fillColor: getSeverityColor(m.maxSeverity),
              fillOpacity: 0.6
            }}
            radius={Math.min(Math.max(m.count * 3, 6), 24)}
          >
            <Tooltip>
              <div style={{ padding: '4px', textAlign: 'center' }}>
                <div style={{ fontWeight: 'bold' }}>{m.ip}</div>
                <div>{m.count} events ({m.maxSeverity})</div>
              </div>
            </Tooltip>
          </CircleMarker>
        ))}
      </MapContainer>
    </div>
  );
};

export default GeoAttackMap;
