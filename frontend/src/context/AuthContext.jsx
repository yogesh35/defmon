import React, { createContext, useContext, useState, useEffect } from 'react';
import { jwtDecode } from 'jwt-decode';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(sessionStorage.getItem('jwt') || null);
  const [user, setUser] = useState(null);

  const logout = () => {
    setToken(null);
  };

  useEffect(() => {
    if (token) {
      try {
        const decoded = jwtDecode(token);
        // Check expiry
        if (decoded.exp * 1000 < Date.now()) {
          // eslint-disable-next-line react-hooks/set-state-in-effect
          logout();
        } else {
          setUser({
            username: decoded.sub,
            role: decoded.role,
          });
          sessionStorage.setItem('jwt', token);
        }
      } catch {
        // eslint-disable-next-line react-hooks/set-state-in-effect
        logout();
      }
    } else {
      setUser(null);
      sessionStorage.removeItem('jwt');
    }
  }, [token]);

  const login = async (username, password) => {
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);

    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: formData.toString(),
    });

    if (!response.ok) {
      throw new Error('Authentication failed');
    }

    const data = await response.json();
    setToken(data.access_token);
  };

  /**
   * Helper fetch that automatically adds Authorization header
   */
  const authFetch = async (url, options = {}) => {
    if (!token) throw new Error('Unauthenticated request');
    
    const headers = new Headers(options.headers || {});
    headers.set('Authorization', `Bearer ${token}`);
    
    // Explicit handling for role blocks. If fetch returns 401/403, we might
    // want to trigger logout or show warnings depending on the app flow.
    const res = await fetch(url, { ...options, headers });
    
    if (res.status === 401) {
      logout();
    }
    
    return res;
  };

  return (
    <AuthContext.Provider value={{ user, token, login, logout, authFetch }}>
      {children}
    </AuthContext.Provider>
  );
};

// eslint-disable-next-line react-refresh/only-export-components
export const useAuth = () => useContext(AuthContext);
