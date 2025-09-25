import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Shield, 
  Wifi, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Activity,
  Search,
  FileText,
  Settings
} from 'lucide-react';

const Dashboard = () => {
  const [scanStatus, setScanStatus] = useState({
    is_scanning: false,
    progress: 0,
    current_step: '',
    devices_found: 0,
    vulnerabilities_found: 0
  });
  
  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });
  
  const [devices, setDevices] = useState([]);
  const [isLoading, setIsLoading] = useState(false);

  // Fetch scan status
  const fetchScanStatus = async () => {
    try {
      const response = await fetch('/api/scan/status');
      const data = await response.json();
      setScanStatus(data);
    } catch (error) {
      console.error('Error fetching scan status:', error);
    }
  };

  // Fetch vulnerability stats
  const fetchStats = async () => {
    try {
      const response = await fetch('/api/vulnerabilities/stats');
      const data = await response.json();
      if (data.success) {
        setStats(data.stats);
      }
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  // Fetch devices
  const fetchDevices = async () => {
    try {
      const response = await fetch('/api/devices');
      const data = await response.json();
      if (data.success) {
        setDevices(data.devices);
      }
    } catch (error) {
      console.error('Error fetching devices:', error);
    }
  };

  // Start scan
  const startScan = async () => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/scan/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({})
      });
      
      const data = await response.json();
      if (data.success) {
        // Start polling for status updates
        const interval = setInterval(() => {
          fetchScanStatus();
          if (!scanStatus.is_scanning) {
            clearInterval(interval);
            fetchStats();
            fetchDevices();
          }
        }, 2000);
      }
    } catch (error) {
      console.error('Error starting scan:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // Stop scan
  const stopScan = async () => {
    try {
      const response = await fetch('/api/scan/stop', {
        method: 'POST'
      });
      
      if (response.ok) {
        fetchScanStatus();
      }
    } catch (error) {
      console.error('Error stopping scan:', error);
    }
  };

  // Generate report
  const generateReport = async () => {
    try {
      const response = await fetch('/api/reports/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          title: `تقرير أمان IoT - ${new Date().toLocaleDateString('ar-SA')}`
        })
      });
      
      const data = await response.json();
      if (data.success) {
        alert('تم إنشاء التقرير بنجاح!');
      }
    } catch (error) {
      console.error('Error generating report:', error);
    }
  };

  useEffect(() => {
    fetchScanStatus();
    fetchStats();
    fetchDevices();
  }, []);

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const getSeverityBadgeVariant = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'default';
      case 'low': return 'secondary';
      default: return 'outline';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-6" dir="rtl">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="h-12 w-12 text-blue-600 ml-3" />
            <h1 className="text-4xl font-bold text-gray-900">أداة فحص أمان أجهزة IoT</h1>
          </div>
          <p className="text-lg text-gray-600">
            اكتشف وحلل الثغرات الأمنية في أجهزة إنترنت الأشياء المتصلة بشبكتك
          </p>
        </div>

        {/* Scan Control */}
        <Card className="border-2 border-blue-200 shadow-lg">
          <CardHeader>
            <CardTitle className="flex items-center">
              <Search className="h-6 w-6 ml-2" />
              التحكم في الفحص
            </CardTitle>
            <CardDescription>
              ابدأ فحص شامل لاكتشاف أجهزة IoT والثغرات الأمنية
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {scanStatus.is_scanning ? (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">{scanStatus.current_step}</span>
                    <span className="text-sm text-gray-500">{scanStatus.progress}%</span>
                  </div>
                  <Progress value={scanStatus.progress} className="w-full" />
                  <div className="flex justify-between text-sm text-gray-600">
                    <span>الأجهزة المكتشفة: {scanStatus.devices_found}</span>
                    <span>الثغرات المكتشفة: {scanStatus.vulnerabilities_found}</span>
                  </div>
                  <Button onClick={stopScan} variant="destructive" className="w-full">
                    <XCircle className="h-4 w-4 ml-2" />
                    إيقاف الفحص
                  </Button>
                </div>
              ) : (
                <div className="space-y-4">
                  <Button 
                    onClick={startScan} 
                    disabled={isLoading}
                    className="w-full bg-blue-600 hover:bg-blue-700"
                  >
                    <Activity className="h-4 w-4 ml-2" />
                    {isLoading ? 'جاري البدء...' : 'بدء الفحص'}
                  </Button>
                  {scanStatus.current_step && (
                    <Alert>
                      <AlertDescription>{scanStatus.current_step}</AlertDescription>
                    </Alert>
                  )}
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Statistics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          <Card className="text-center">
            <CardHeader className="pb-2">
              <CardTitle className="text-2xl font-bold text-blue-600">
                {stats.total}
              </CardTitle>
              <CardDescription>إجمالي الثغرات</CardDescription>
            </CardHeader>
          </Card>
          
          <Card className="text-center border-red-200">
            <CardHeader className="pb-2">
              <CardTitle className="text-2xl font-bold text-red-600">
                {stats.critical}
              </CardTitle>
              <CardDescription>ثغرات حرجة</CardDescription>
            </CardHeader>
          </Card>
          
          <Card className="text-center border-orange-200">
            <CardHeader className="pb-2">
              <CardTitle className="text-2xl font-bold text-orange-600">
                {stats.high}
              </CardTitle>
              <CardDescription>ثغرات عالية</CardDescription>
            </CardHeader>
          </Card>
          
          <Card className="text-center border-yellow-200">
            <CardHeader className="pb-2">
              <CardTitle className="text-2xl font-bold text-yellow-600">
                {stats.medium}
              </CardTitle>
              <CardDescription>ثغرات متوسطة</CardDescription>
            </CardHeader>
          </Card>
          
          <Card className="text-center border-green-200">
            <CardHeader className="pb-2">
              <CardTitle className="text-2xl font-bold text-green-600">
                {stats.low}
              </CardTitle>
              <CardDescription>ثغرات منخفضة</CardDescription>
            </CardHeader>
          </Card>
        </div>

        {/* Devices List */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Wifi className="h-6 w-6 ml-2" />
              الأجهزة المكتشفة ({devices.length})
            </CardTitle>
            <CardDescription>
              قائمة بأجهزة IoT المتصلة بالشبكة
            </CardDescription>
          </CardHeader>
          <CardContent>
            {devices.length === 0 ? (
              <div className="text-center py-8 text-gray-500">
                <Wifi className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>لم يتم اكتشاف أي أجهزة بعد. قم ببدء الفحص لاكتشاف الأجهزة.</p>
              </div>
            ) : (
              <div className="grid gap-4">
                {devices.slice(0, 5).map((device) => (
                  <div key={device.id} className="flex items-center justify-between p-4 border rounded-lg hover:bg-gray-50">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 space-x-reverse">
                        <div className="flex-shrink-0">
                          <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                        </div>
                        <div>
                          <p className="font-medium text-gray-900">{device.ip_address}</p>
                          <p className="text-sm text-gray-500">
                            {device.device_type || 'جهاز غير معروف'} • {device.manufacturer || 'شركة غير معروفة'}
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2 space-x-reverse">
                      <Badge variant="outline">
                        {device.open_ports?.length || 0} منفذ مفتوح
                      </Badge>
                      {device.hostname && (
                        <Badge variant="secondary">{device.hostname}</Badge>
                      )}
                    </div>
                  </div>
                ))}
                {devices.length > 5 && (
                  <div className="text-center pt-4">
                    <Button variant="outline">
                      عرض جميع الأجهزة ({devices.length})
                    </Button>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card className="cursor-pointer hover:shadow-lg transition-shadow">
            <CardHeader className="text-center">
              <FileText className="h-8 w-8 mx-auto mb-2 text-blue-600" />
              <CardTitle className="text-lg">إنشاء تقرير</CardTitle>
              <CardDescription>
                إنشاء تقرير مفصل عن الثغرات المكتشفة
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button onClick={generateReport} className="w-full" variant="outline">
                إنشاء تقرير جديد
              </Button>
            </CardContent>
          </Card>

          <Card className="cursor-pointer hover:shadow-lg transition-shadow">
            <CardHeader className="text-center">
              <AlertTriangle className="h-8 w-8 mx-auto mb-2 text-orange-600" />
              <CardTitle className="text-lg">الثغرات الحرجة</CardTitle>
              <CardDescription>
                عرض الثغرات التي تتطلب اهتماماً فورياً
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button className="w-full" variant="outline">
                عرض الثغرات الحرجة
              </Button>
            </CardContent>
          </Card>

          <Card className="cursor-pointer hover:shadow-lg transition-shadow">
            <CardHeader className="text-center">
              <Settings className="h-8 w-8 mx-auto mb-2 text-gray-600" />
              <CardTitle className="text-lg">الإعدادات</CardTitle>
              <CardDescription>
                تخصيص إعدادات الفحص والتقارير
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button className="w-full" variant="outline">
                فتح الإعدادات
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

