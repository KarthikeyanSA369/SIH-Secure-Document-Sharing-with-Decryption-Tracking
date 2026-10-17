import React from 'react';
import { Shield, LogOut } from 'lucide-react';
import { User } from '../types';

interface NavbarProps {
  user: User | null;
  onLogout: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ user, onLogout }) => {
  return (
    <header className="bg-white border-b border-gray-200">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 bg-blue-600 rounded-lg flex items-center justify-center text-white shadow-sm">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <span className="text-lg font-bold text-gray-900 tracking-tight">SecureShare</span>
            <span className="hidden sm:inline-block ml-2 text-xs font-medium text-gray-500 bg-gray-100 px-2 py-0.5 rounded">
              Secure Document Distribution
            </span>
          </div>
        </div>

        {user && (
          <div className="flex items-center space-x-4">
            <div className="text-right hidden sm:block">
              <div className="text-sm font-semibold text-gray-800">{user.name}</div>
              <div className="text-xs text-gray-500 font-medium">
                {user.role === 'ADMIN'
                  ? 'Administrator'
                  : user.role === 'INVESTIGATOR'
                  ? 'Investigator'
                  : 'Recipient'}
              </div>
            </div>

            <button
              onClick={onLogout}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 transition-colors shadow-sm"
              title="Logout"
            >
              <LogOut className="w-4 h-4 text-gray-500" />
              <span>Logout</span>
            </button>
          </div>
        )}
      </div>
    </header>
  );
};
