import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { 
  Shield, 
  Wifi, 
  AlertTriangle, 
  FileText, 
  Settings,
  Menu,
  X
} from 'lucide-react';
import Dashboard from './components/Dashboard';
import DeviceList from './components/DeviceList';
import VulnerabilityList from './components/VulnerabilityList';
import ReportsList from './components/ReportsList';
import './App.css';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const navigation = [
    {
      id: 'dashboard',
      name: 'لوحة التحكم',
      icon: Shield,
      component: Dashboard
    },
    {
      id: 'devices',
      name: 'الأجهزة',
      icon: Wifi,
      component: DeviceList
    },
    {
      id: 'vulnerabilities',
      name: 'الثغرات',
      icon: AlertTriangle,
      component: VulnerabilityList
    },
    {
      id: 'reports',
      name: 'التقارير',
      icon: FileText,
      component: ReportsList
    }
  ];

  const ActiveComponent = navigation.find(nav => nav.id === activeTab)?.component || Dashboard;

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
      <div className={`fixed inset-y-0 right-0 z-40 w-64 bg-white shadow-xl transform transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-0 ${
        sidebarOpen ? 'translate-x-0' : 'translate-x-full'
      }`}>
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="flex items-center justify-center h-16 px-4 bg-gradient-to-r from-blue-600 to-purple-600">
            <Shield className="h-8 w-8 text-white ml-2" />
            <h1 className="text-white font-bold text-lg">أداة فحص IoT</h1>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-4 py-6 space-y-2">
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
                  onClick={() => {
                    setActiveTab(item.id);
                    setSidebarOpen(false);
                  }}
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
      <div className="lg:mr-64">
        <ActiveComponent />
      </div>
    </div>
  );
}

export default App;

