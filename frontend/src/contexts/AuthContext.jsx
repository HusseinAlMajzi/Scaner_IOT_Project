import React, { createContext, useContext, useState, useEffect } from 'react';
import { api, API_BASE_URL } from '../config/api';

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [scanStatus, setScanStatus] = useState({
    is_scanning: false,
    progress: 0,
    current_step: '',
    scan_id: null,
    devices_found: 0,
    vulnerabilities_found: 0
  });

  // Check if user is logged in on mount
  useEffect(() => {
    checkAuth();
  }, []);

  // Poll scan status - starts when scan begins, stops when scan ends
  useEffect(() => {
    if (!isAuthenticated) return;

    const pollScanStatus = async () => {
      try {
        const { data, response } = await api.get('/scan/status');
        if (response.ok) {
          setScanStatus(prevStatus => {
            // If scan just started, begin polling
            // If scan just ended, polling will stop on next cycle
            return data;
          });
        }
      } catch (error) {
        console.error('Failed to fetch scan status:', error);
      }
    };

    // Initial check
    pollScanStatus();

    // Set up interval only if scanning OR we don't know the status yet
    let interval = null;
    if (scanStatus.is_scanning || scanStatus.scan_id) {
      interval = setInterval(pollScanStatus, 2000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isAuthenticated, scanStatus.is_scanning]);

  const checkAuth = async () => {
    try {
      const { data, response } = await api.get('/auth/me');

      if (response.ok) {
        if (data.success) {
          setUser(data.user);
          setIsAuthenticated(true);
        } else {
          setUser(null);
          setIsAuthenticated(false);
        }
      } else {
        setUser(null);
        setIsAuthenticated(false);
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      setUser(null);
      setIsAuthenticated(false);
    } finally {
      setLoading(false);
    }
  };

  const login = async (username, password, remember = false) => {
    try {
      const { data } = await api.post('/auth/login', { username, password, remember });

      if (data.success) {
        setUser(data.user);
        setIsAuthenticated(true);
        return { success: true, message: data.message };
      } else {
        return { success: false, message: data.message };
      }
    } catch (error) {
      console.error('Login failed:', error);
      return { success: false, message: 'خطأ في الاتصال بالخادم' };
    }
  };

  const register = async (username, email, password, confirmPassword) => {
    try {
      const { data } = await api.post('/auth/register', { username, email, password, confirmPassword });

      if (data.success) {
        return { success: true, message: data.message };
      } else {
        return { success: false, message: data.message };
      }
    } catch (error) {
      console.error('Registration failed:', error);
      return { success: false, message: 'خطأ في الاتصال بالخادم' };
    }
  };

  const logout = async () => {
    try {
      const { data } = await api.post('/auth/logout', {});

      if (data.success) {
        setUser(null);
        setIsAuthenticated(false);
        return { success: true, message: data.message };
      }
    } catch (error) {
      console.error('Logout failed:', error);
    }
    
    // Always clear user state even if request fails
    setUser(null);
    setIsAuthenticated(false);
    return { success: true };
  };

  const updateProfile = async (profileData) => {
    try {
      const { data } = await api.put('/auth/profile', profileData);

      if (data.success) {
        setUser(data.user);
        return { success: true, message: data.message };
      } else {
        return { success: false, message: data.message };
      }
    } catch (error) {
      console.error('Profile update failed:', error);
      return { success: false, message: 'خطأ في الاتصال بالخادم' };
    }
  };

  const changePassword = async (currentPassword, newPassword, confirmPassword) => {
    try {
      const { data } = await api.post('/auth/change-password', { currentPassword, newPassword, confirmPassword });

      if (data.success) {
        return { success: true, message: data.message };
      } else {
        return { success: false, message: data.message };
      }
    } catch (error) {
      console.error('Password change failed:', error);
      return { success: false, message: 'خطأ في الاتصال بالخادم' };
    }
  };

  const refreshScanStatus = async () => {
    try {
      const { data, response } = await api.get('/scan/status');
      if (response.ok) {
        setScanStatus(data);
        return data;
      }
    } catch (error) {
      console.error('Failed to refresh scan status:', error);
    }
    return null;
  };

  const value = {
    user,
    loading,
    isAuthenticated,
    login,
    register,
    logout,
    updateProfile,
    changePassword,
    checkAuth,
    scanStatus,
    setScanStatus,
    refreshScanStatus,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
