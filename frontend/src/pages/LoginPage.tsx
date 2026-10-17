import React, { useState } from 'react';
import { Shield, Lock, User, AlertCircle, Loader2 } from 'lucide-react';
import { authApi } from '../api';
import { User as UserType, UserRole } from '../types';

interface LoginPageProps {
  onLoginSuccess: (user: UserType, token: string) => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('admin123');
  const [role, setRole] = useState<UserRole>('ADMIN');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const data = await authApi.login(username, password, role);
      localStorage.setItem('secureshare_token', data.access_token);
      onLoginSuccess(data.user, data.access_token);
    } catch (err: any) {
      setError(
        err.response?.data?.detail || 'Invalid username or password. Please try again.'
      );
    } finally {
      setLoading(false);
    }
  };

  const setDemoAccount = (demoRole: UserRole) => {
    if (demoRole === 'ADMIN') {
      setUsername('admin');
      setPassword('admin123');
      setRole('ADMIN');
    } else if (demoRole === 'RECIPIENT') {
      setUsername('alice');
      setPassword('alice123');
      setRole('RECIPIENT');
    } else if (demoRole === 'INVESTIGATOR') {
      setUsername('investigator');
      setPassword('investigator123');
      setRole('INVESTIGATOR');
    }
    setError(null);
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md text-center">
        <div className="w-14 h-14 bg-blue-600 text-white rounded-2xl flex items-center justify-center mx-auto shadow-md mb-4">
          <Shield className="w-8 h-8" />
        </div>
        <h1 className="text-3xl font-extrabold text-gray-900 tracking-tight">SecureShare</h1>
        <p className="mt-1 text-sm text-gray-600 font-medium">Secure Document Distribution</p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-6 shadow-sm sm:rounded-xl sm:px-10 border border-gray-200">
          <form className="space-y-5" onSubmit={handleLogin}>
            {error && (
              <div className="rounded-lg bg-red-50 p-3.5 flex items-start space-x-2.5 text-sm text-red-700 border border-red-100">
                <AlertCircle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* Role Selector Tabs */}
            <div>
              <label className="block text-xs font-semibold text-gray-700 uppercase tracking-wider mb-2">
                Role
              </label>
              <div className="grid grid-cols-3 gap-1.5 p-1 bg-gray-100 rounded-lg">
                <button
                  type="button"
                  onClick={() => {
                    setRole('ADMIN');
                    if (username === 'alice' || username === 'investigator') {
                      setUsername('admin');
                      setPassword('admin123');
                    }
                  }}
                  className={`py-2 text-xs font-semibold rounded-md transition-all ${
                    role === 'ADMIN'
                      ? 'bg-white text-blue-700 shadow-sm'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  Admin
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setRole('RECIPIENT');
                    if (username === 'admin' || username === 'investigator') {
                      setUsername('alice');
                      setPassword('alice123');
                    }
                  }}
                  className={`py-2 text-xs font-semibold rounded-md transition-all ${
                    role === 'RECIPIENT'
                      ? 'bg-white text-blue-700 shadow-sm'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  Recipient
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setRole('INVESTIGATOR');
                    if (username === 'admin' || username === 'alice') {
                      setUsername('investigator');
                      setPassword('investigator123');
                    }
                  }}
                  className={`py-2 text-xs font-semibold rounded-md transition-all ${
                    role === 'INVESTIGATOR'
                      ? 'bg-white text-blue-700 shadow-sm'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  Investigator
                </button>
              </div>
            </div>

            {/* Username */}
            <div>
              <label className="block text-xs font-semibold text-gray-700 uppercase tracking-wider mb-1.5">
                Username
              </label>
              <div className="relative rounded-md shadow-sm">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <User className="h-4 w-4 text-gray-400" />
                </div>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="block w-full pl-10 pr-3 py-2.5 border border-gray-300 rounded-lg text-sm text-gray-900 focus:ring-2 focus:ring-blue-600 focus:border-blue-600 bg-white"
                  placeholder="Enter username"
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="block text-xs font-semibold text-gray-700 uppercase tracking-wider mb-1.5">
                Password
              </label>
              <div className="relative rounded-md shadow-sm">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-4 w-4 text-gray-400" />
                </div>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="block w-full pl-10 pr-3 py-2.5 border border-gray-300 rounded-lg text-sm text-gray-900 focus:ring-2 focus:ring-blue-600 focus:border-blue-600 bg-white"
                  placeholder="••••••••"
                />
              </div>
            </div>

            {/* Login Button */}
            <div>
              <button
                type="submit"
                disabled={loading}
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors disabled:opacity-75"
              >
                {loading ? (
                  <div className="flex items-center space-x-2">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Signing in...</span>
                  </div>
                ) : (
                  <span>Login</span>
                )}
              </button>
            </div>
          </form>

          {/* Demo Accounts Quick-Fill Helper */}
          <div className="mt-6 pt-6 border-t border-gray-100">
            <p className="text-xs font-medium text-gray-500 mb-2.5 text-center">
              Quick Demo Accounts:
            </p>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setDemoAccount('ADMIN')}
                className="px-2.5 py-2 text-xs bg-gray-50 hover:bg-gray-100 border border-gray-200 rounded-lg text-gray-700 text-left transition-colors"
              >
                <div className="font-semibold text-gray-900 truncate">Admin</div>
                <div className="text-gray-500 text-[10px] truncate">admin</div>
              </button>
              <button
                type="button"
                onClick={() => setDemoAccount('RECIPIENT')}
                className="px-2.5 py-2 text-xs bg-gray-50 hover:bg-gray-100 border border-gray-200 rounded-lg text-gray-700 text-left transition-colors"
              >
                <div className="font-semibold text-gray-900 truncate">Alice</div>
                <div className="text-gray-500 text-[10px] truncate">alice</div>
              </button>
              <button
                type="button"
                onClick={() => setDemoAccount('INVESTIGATOR')}
                className="px-2.5 py-2 text-xs bg-gray-50 hover:bg-gray-100 border border-gray-200 rounded-lg text-gray-700 text-left transition-colors"
              >
                <div className="font-semibold text-gray-900 truncate">Officer</div>
                <div className="text-gray-500 text-[10px] truncate">investigator</div>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
