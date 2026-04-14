import React from 'react';
import { Navigate } from 'react-router-dom';
import { ShieldAlert } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import SenderControl from '../components/panels/SenderControl';

const AdminSenders = () => {
  const { user } = useAuth();

  if (user?.role !== 'admin') {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="dashboard-grid" style={{ marginTop: 0 }}>
      <div className="col-span-12">
        <div className="glass-panel">
          <div className="glass-panel-header">
            <div className="glass-panel-title">
              <ShieldAlert size={18} color="var(--accent-blue)" /> Sender Access Controls
            </div>
          </div>
          <div className="glass-panel-body">
            <SenderControl />
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminSenders;
