import React from 'react';
import { Navigate, Outlet, Link, useLocation } from 'react-router-dom';
import { ShieldCheck, Activity, LogOut, LayoutDashboard, Database, ShieldAlert } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const Layout = () => {
  const { user, logout } = useAuth();
  const location = useLocation();

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  const navItems = [
    { name: 'Dashboard', path: '/', icon: <LayoutDashboard size={20} /> },
    { name: 'Incident Tracker', path: '/incidents', icon: <Database size={20} /> },
    ...(user.role === 'admin' ? [{ name: 'Admin Senders', path: '/admin/senders', icon: <ShieldAlert size={20} /> }] : []),
  ];

  const pageTitle = (() => {
    if (location.pathname === '/') return 'Security Operations Center';
    if (location.pathname === '/incidents') return 'Incident Tracking';
    if (location.pathname === '/admin/senders') return 'Sender Administration';
    return 'DefMon Console';
  })();

  return (
    <div className="app-container">
      <aside className="sidebar">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '3rem' }}>
          <ShieldCheck size={32} color="var(--accent-blue)" />
          <div>
            <h2 style={{ fontSize: '1.25rem', marginBottom: 0 }}>DefMon</h2>
            <span className="text-secondary text-xs">Enterprise SOC</span>
          </div>
        </div>

        <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', flex: 1 }}>
          <div className="text-muted text-xs font-semibold" style={{ textTransform: 'uppercase', marginBottom: '0.5rem' }}>Menu</div>
          
          {navItems.map((item) => {
            const isActive = item.path === '/'
              ? location.pathname === '/'
              : location.pathname.startsWith(item.path);
            return (
              <Link 
                key={item.path} 
                to={item.path}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.75rem',
                  padding: '0.75rem 1rem',
                  borderRadius: '12px',
                  color: isActive ? 'white' : 'var(--text-secondary)',
                  background: isActive ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                  border: isActive ? '1px solid rgba(59, 130, 246, 0.3)' : '1px solid transparent',
                  textDecoration: 'none',
                  transition: 'all 0.2s',
                  fontWeight: isActive ? '600' : '500'
                }}
              >
                {React.cloneElement(item.icon, { color: isActive ? 'var(--accent-blue)' : 'currentColor' })}
                {item.name}
              </Link>
            );
          })}
        </nav>

        {/* User Card */}
        <div style={{ 
          marginTop: 'auto', 
          padding: '1rem', 
          background: 'rgba(0,0,0,0.2)', 
          borderRadius: '12px',
          border: '1px solid var(--panel-border)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
            <div style={{
              width: '40px', height: '40px', borderRadius: '50%', background: 'var(--accent-blue)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 'bold'
            }}>
              {user.username.charAt(0).toUpperCase()}
            </div>
            <div>
              <div style={{ fontWeight: '600', fontSize: '0.875rem' }}>{user.username}</div>
              <div className="text-xs text-muted" style={{ textTransform: 'capitalize' }}>{user.role} role</div>
            </div>
          </div>
          <button 
            onClick={logout} 
            className="secondary" 
            style={{ width: '100%', padding: '0.5rem', fontSize: '0.875rem' }}
          >
            <LogOut size={16} /> Logout
          </button>
        </div>
      </aside>

      <main className="main-content">
        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
          <div>
            <h1 style={{ fontSize: '1.5rem', marginBottom: '0.25rem' }}>
              {pageTitle}
            </h1>
            <p className="text-secondary text-sm">Real-time threat monitoring and response</p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(34, 197, 94, 0.1)', padding: '0.5rem 1rem', borderRadius: '99px', border: '1px solid rgba(34, 197, 94, 0.2)' }}>
            <Activity size={16} color="var(--closed)" />
            <span style={{ fontSize: '0.875rem', fontWeight: '600', color: 'var(--closed)' }}>System Active</span>
          </div>
        </header>
        
        {/* Child Routes inject here */}
        <Outlet />
      </main>
    </div>
  );
}

export default Layout;
