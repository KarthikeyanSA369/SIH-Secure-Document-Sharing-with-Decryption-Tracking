import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { LoginPage } from './pages/LoginPage';
import { AdminDashboard } from './pages/AdminDashboard';
import { RecipientDashboard } from './pages/RecipientDashboard';
import { InvestigatorDashboard } from './pages/InvestigatorDashboard';
import { authApi } from './api';
import { User } from './types';
import { Loader2 } from 'lucide-react';

export const App: React.FC = () => {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    const token = localStorage.getItem('secureshare_token');
    if (!token) {
      setLoading(false);
      return;
    }

    try {
      const user = await authApi.getMe();
      setCurrentUser(user);
    } catch (e) {
      localStorage.removeItem('secureshare_token');
      setCurrentUser(null);
    } finally {
      setLoading(false);
    }
  };

  const handleLoginSuccess = (user: User, token: string) => {
    localStorage.setItem('secureshare_token', token);
    setCurrentUser(user);
  };

  const handleLogout = () => {
    localStorage.removeItem('secureshare_token');
    setCurrentUser(null);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="w-8 h-8 text-blue-600 animate-spin mx-auto mb-2" />
          <p className="text-xs text-gray-500 font-medium">Initializing SecureShare...</p>
        </div>
      </div>
    );
  }

  if (!currentUser) {
    return <LoginPage onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <Navbar user={currentUser} onLogout={handleLogout} />

      <main className="flex-1">
        {currentUser.role === 'ADMIN' ? (
          <AdminDashboard />
        ) : currentUser.role === 'INVESTIGATOR' ? (
          <InvestigatorDashboard />
        ) : (
          <RecipientDashboard user={currentUser} />
        )}
      </main>

      <footer className="py-6 border-t border-gray-200 bg-white text-center text-xs text-gray-400">
        SecureShare &copy; 2026 &bull; Post-Quantum Document Protection (ML-KEM-768 &bull; AES-256-GCM &bull; ML-DSA-65)
      </footer>
    </div>
  );
};

export default App;
