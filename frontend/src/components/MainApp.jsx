import React, { useState } from 'react';
import { Routes, Route, useNavigate, Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { 
  Shield, 
  Wifi, 
  AlertTriangle, 
  FileText,
  Menu,
  X,
  User,
  LogOut,
  Settings
} from 'lucide-react';
import Dashboard from './Dashboard';
import DeviceList from './DeviceList';
import VulnerabilityList from './VulnerabilityList';
import ReportsList from './ReportsList';

function MainApp() {
  const navigate = useNavigate();
  const { user, logout, scanStatus } = useAuth();
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const navigation = [
    {
      id: 'dashboard',
      name: 'لوحة التحكم',
      icon: Shield,
      path: '/dashboard',
      component: Dashboard
    },
    {
      id: 'devices',
      name: 'الأجهزة',
      icon: Wifi,
      path: '/dashboard/devices',
      component: DeviceList
    },
    {
      id: 'vulnerabilities',
      name: 'الثغرات',
      icon: AlertTriangle,
      path: '/dashboard/vulnerabilities',
      component: VulnerabilityList
    },
    {
      id: 'reports',
      name: 'التقارير',
      icon: FileText,
      path: '/dashboard/reports',
      component: ReportsList
    }
  ];

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const handleNavigate = (item) => {
    setActiveTab(item.id);
    navigate(item.path);
    setSidebarOpen(false);
  };

  return (
    <div className="min-h-screen bg-gray-100" dir="rtl">
      {/* Mobile menu button */}
      <div className="lg:hidden fixed top-4 right-4 z-50">
        <Button
          variant="outline"
          size="sm"
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="bg-white shadow-lg"
        >
          {sidebarOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
        </Button>
      </div>

      {/* Sidebar */}
      <div className={`fixed inset-y-0 right-0 z-40 w-64 bg-white shadow-xl transform transition-transform duration-300 ease-in-out lg:translate-x-0 ${
        sidebarOpen ? 'translate-x-0' : 'translate-x-full'
      }`}>
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="flex items-center justify-center h-16 px-4 bg-gradient-to-r from-blue-600 to-purple-600">
            <Shield className="h-8 w-8 text-white ml-2" />
            <h1 className="text-white font-bold text-lg">أداة فحص IoT</h1>
          </div>

          {/* User Info */}
          <div className="p-4 border-b bg-gradient-to-r from-blue-50 to-purple-50">
            <DropdownMenu>
              <DropdownMenuTrigger className="w-full outline-none">
                <div className="flex items-center space-x-3 space-x-reverse p-2 rounded-md hover:bg-white/50 transition-colors cursor-pointer">
                  <div className="w-10 h-10 rounded-full bg-gradient-to-r from-blue-600 to-purple-600 flex items-center justify-center">
                    <User className="h-5 w-5 text-white" />
                  </div>
                  <div className="text-right flex-1">
                    <p className="text-sm font-medium text-gray-900">{user?.username}</p>
                    <p className="text-xs text-gray-500">{user?.email}</p>
                  </div>
                </div>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="w-56" dir="rtl">
                <DropdownMenuLabel>حسابي</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem className="cursor-pointer">
                  <Settings className="ml-2 h-4 w-4" />
                  <span>الإعدادات</span>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={handleLogout} className="text-red-600 cursor-pointer">
                  <LogOut className="ml-2 h-4 w-4" />
                  <span>تسجيل الخروج</span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>

          {/* Scan Status Indicator */}
          {scanStatus.is_scanning && (
            <div className="px-4 py-3 bg-blue-50 border-b border-blue-200">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-blue-900">الفحص جاري...</span>
                  <span className="text-xs text-blue-600">{scanStatus.progress}%</span>
                </div>
                <div className="w-full bg-blue-200 rounded-full h-2">
                  <div 
                    className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${scanStatus.progress}%` }}
                  />
                </div>
                <p className="text-xs text-blue-700">{scanStatus.current_step}</p>
              </div>
            </div>
          )}

          {/* Navigation */}
          <nav className="flex-1 px-4 py-6 space-y-2 overflow-y-auto">
            {navigation.map((item) => {
              const Icon = item.icon;
              return (
                <Button
                  key={item.id}
                  variant={activeTab === item.id ? "default" : "ghost"}
                  className={`w-full justify-start text-right ${
                    activeTab === item.id 
                      ? 'bg-blue-600 text-white hover:bg-blue-700' 
                      : 'text-gray-700 hover:bg-gray-100'
                  }`}
                  onClick={() => handleNavigate(item)}
                >
                  <Icon className="h-5 w-5 ml-3" />
                  {item.name}
                </Button>
              );
            })}
          </nav>

          {/* Footer */}
          <div className="p-4 border-t">
            <Card className="bg-gradient-to-r from-blue-50 to-purple-50">
              <CardContent className="p-4 text-center">
                <Shield className="h-8 w-8 mx-auto mb-2 text-blue-600" />
                <p className="text-sm text-gray-600 mb-2">
                  أداة متقدمة لفحص أمان أجهزة IoT
                </p>
                <p className="text-xs text-gray-500">
                  الإصدار 1.0.0
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>

      {/* Overlay for mobile */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 z-30 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Main content */}
      <div className="lg:mr-64 min-h-screen">
        <main className="w-full">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/devices" element={<DeviceList />} />
            <Route path="/vulnerabilities" element={<VulnerabilityList />} />
            <Route path="/reports" element={<ReportsList />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default MainApp;
