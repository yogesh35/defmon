import React from 'react';
import { Target, Activity, ShieldAlert, BarChart3, Map as MapIcon, FileText } from 'lucide-react';
import LiveAlertFeed from '../components/panels/LiveAlertFeed';
import SeverityDonut from '../components/panels/SeverityDonut';
import GeoAttackMap from '../components/panels/GeoAttackMap';
import MetricsCards from '../components/panels/MetricsCards';
import TopOffenders from '../components/panels/TopOffenders';
import LogsExplorer from '../components/panels/LogsExplorer';
import IncidentTracker from '../components/panels/IncidentTracker';
import AuditTrail from '../components/panels/AuditTrail';
import ExecutiveOverview from '../components/panels/ExecutiveOverview';
import { WebSocketProvider } from '../context/WebSocketContext';

const Dashboard = () => {
  return (
    <WebSocketProvider>
      <div className="dashboard-grid">

        {/* ROW 0: Executive Overview */}
        <div className="col-span-12">
          <div className="glass-panel">
            <div className="glass-panel-body">
              <ExecutiveOverview />
            </div>
          </div>
        </div>
        
        {/* ROW 1: Metrics & Key Stats */}
        <div className="col-span-12 hero-row">
          <MetricsCards />
          
          <div className="glass-panel col-span-2" style={{ gridColumn: 'span 2' }}>
            <div className="glass-panel-header">
              <div className="glass-panel-title">
                <ShieldAlert size={18} color="var(--accent-blue)" /> Alert Distribution (24h)
              </div>
            </div>
            <div className="glass-panel-body">
              <SeverityDonut />
            </div>
          </div>
        </div>

        {/* ROW 2: Main Content Area */}
        <div className="col-span-12 main-row">
          <div className="glass-panel">
            <div className="glass-panel-header">
              <div className="glass-panel-title">
                <Activity size={18} color="var(--accent-blue)" /> Live Alert Stream
              </div>
              <div className="flex gap-2">
                <span className="badge" style={{ background: 'rgba(59, 130, 246, 0.1)', color: 'var(--accent-blue)' }}>
                  <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--accent-blue)', display: 'inline-block', marginRight: '6px', animation: 'pulse 2s infinite' }}></span>
                  Live
                </span>
              </div>
            </div>
            <div className="glass-panel-body" style={{ padding: 0 }}>
              <LiveAlertFeed />
            </div>
          </div>

          <div className="glass-panel">
            <div className="glass-panel-header">
              <div className="glass-panel-title">
                <BarChart3 size={18} color="var(--accent-blue)" /> Top Attackers (24h)
              </div>
            </div>
            <div className="glass-panel-body">
              <TopOffenders />
            </div>
          </div>
        </div>

        {/* ROW 3: Geography */}
        <div className="col-span-12">
          <div className="glass-panel">
            <div className="glass-panel-header">
              <div className="glass-panel-title">
                <MapIcon size={18} color="var(--accent-blue)" /> Incident Threat Map
              </div>
            </div>
            <div className="glass-panel-body">
              <GeoAttackMap />
            </div>
          </div>
        </div>

        {/* ROW 4: Incident Tracker */}
        <div className="col-span-12">
          <IncidentTracker />
        </div>

        {/* ROW 5: SOAR Actions */}
        <div className="col-span-12">
          <div className="glass-panel">
            <div className="glass-panel-header">
              <div className="glass-panel-title">
                <Target size={18} color="var(--accent-blue)" /> SOAR Actions Taken
              </div>
            </div>
            <div className="glass-panel-body" style={{ padding: 0 }}>
              <AuditTrail />
            </div>
          </div>
        </div>

        {/* ROW 6: Log Explorer */}
        <div className="col-span-12">
          <div className="glass-panel">
            <div className="glass-panel-header">
              <div className="glass-panel-title">
                <FileText size={18} color="var(--accent-blue)" /> Real Log Explorer
              </div>
            </div>
            <div className="glass-panel-body">
              <LogsExplorer />
            </div>
          </div>
        </div>
        
      </div>
    </WebSocketProvider>
  );
};

export default Dashboard;
