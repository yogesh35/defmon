import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, KeyRound, UserRound, Loader2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    
    try {
      await login(username, password);
      navigate('/');
    } catch {
      setError('Invalid username or password.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-wrapper">
      <div className="glass-panel auth-card">
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <ShieldAlert size={48} color="var(--critical)" style={{ marginBottom: '1rem' }} />
          <h1>DefMon Enterprise</h1>
          <p className="text-secondary">Security Operations Center</p>
        </div>

        {error && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.1)',
            color: 'var(--critical)',
            padding: '1rem',
            borderRadius: '8px',
            marginBottom: '1rem',
            fontSize: '0.875rem',
            border: '1px solid rgba(239, 68, 68, 0.2)'
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div>
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>
              <UserRound size={18} />
              <label className="text-sm font-medium">Username</label>
            </div>
            <input 
              type="text" 
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username" 
              required 
            />
          </div>

          <div>
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>
              <KeyRound size={18} />
              <label className="text-sm font-medium">Password</label>
            </div>
            <input 
              type="password" 
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password" 
              required 
            />
          </div>

          <button type="submit" style={{ marginTop: '0.5rem' }} disabled={isLoading}>
            {isLoading ? <Loader2 size={18} className="spinner" style={{ width: '18px', height: '18px', border: '2px solid transparent', borderTopColor: 'white' }} /> : 'Authenticate'}
          </button>
        </form>
      </div>
    </div>
  );
};

export default Login;
