import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../config/api';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import NewScanDialog from './NewScanDialog';
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
import { useAuth } from '../contexts/AuthContext';

const Dashboard = () => {
  const navigate = useNavigate();
  const { scanStatus, refreshScanStatus, activeScanSession, setActiveScanSession } = useAuth();
  
  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });
  
  const [devices, setDevices] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [showNewScanDialog, setShowNewScanDialog] = useState(false);

  // Scan status is now handled globally in AuthContext

  // Fetch vulnerability stats
  const fetchStats = async () => {
    try {
      const url = activeScanSession 
        ? `/vulnerabilities/stats?scan_session_id=${activeScanSession}`
        : '/vulnerabilities/stats';
      const { data } = await api.get(url);
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
      const url = activeScanSession
        ? `/devices?scan_session_id=${activeScanSession}`
        : '/devices';
      const { data } = await api.get(url);
      if (data.success) {
        setDevices(data.devices);
      }
    } catch (error) {
      console.error('Error fetching devices:', error);
    }
  };

  // Start scan with name
  const startScanWithName = async (scanName) => {
    const mode = 'comprehensive';
    setIsLoading(true);
    try {
      console.log('[Dashboard] Starting scan:', scanName);
      
      const result = await api.post('/scan/start', {
        scan_name: scanName,
        scan_mode: mode
      });
      
      if (result && result.data && result.data.success) {
        const newScanId = result.data.scan_id;
        setActiveScanSession(newScanId);  // Set new scan as active
        alert(`تم بدء الفحص: ${scanName}`);
        await refreshScanStatus();
        setTimeout(() => {
          fetchStats();
          fetchDevices();
        }, 1000);
      } else if (result && result.data) {
        if (result.data.message && result.data.message.includes('فحص آخر قيد التشغيل')) {
          const stopAndRetry = window.confirm('يوجد فحص قيد التشغيل. هل تريد إيقافه وبدء فحص جديد؟');
          if (stopAndRetry) {
            await stopScan();
            setTimeout(() => setShowNewScanDialog(true), 1000);
            return;
          }
        }
        alert('خطأ: ' + (result.data.message || 'فشل بدء الفحص'));
      }
    } catch (error) {
      console.error('[Dashboard] Error starting scan:', error);
      if (error.message && error.message.includes('400')) {
        const stopAndRetry = window.confirm('يوجد فحص قيد التشغيل. هل تريد إيقافه وبدء فحص جديد؟');
        if (stopAndRetry) {
          await stopScan();
          setTimeout(() => setShowNewScanDialog(true), 1000);
          return;
        }
      }
      alert('خطأ في الاتصال بالخادم: ' + error.message);
    } finally {
      setIsLoading(false);
    }
  };

  // Open new scan dialog
  const startScan = async (mode = 'comprehensive') => {
    setIsLoading(true);
    try {
      console.log('[Dashboard] Starting scan with mode:', mode);
      
      const result = await api.post('/scan/start', {
        scan_mode: mode
      });
      
      console.log('[Dashboard] Scan start result:', result);
      
      if (result && result.data && result.data.success) {
        alert('تم بدء الفحص بنجاح!');
        // Immediately refresh scan status to trigger polling
        await refreshScanStatus();
        // Also refresh data
        setTimeout(() => {
          fetchStats();
          fetchDevices();
        }, 1000);
      } else if (result && result.data) {
        // Check if it's because another scan is running
        if (result.data.message && result.data.message.includes('فحص آخر قيد التشغيل')) {
          const stopAndRetry = window.confirm('يوجد فحص قيد التشغيل. هل تريد إيقافه وبدء فحص جديد؟');
          if (stopAndRetry) {
            await stopScan();
            setTimeout(() => startScan(mode), 1000);
            return;
          }
        }
        alert('خطأ: ' + (result.data.message || 'فشل بدء الفحص'));
      } else {
        alert('خطأ: لم يتم استلام رد من الخادم');
      }
    } catch (error) {
      console.error('[Dashboard] Error starting scan:', error);
      // If it's a 400 error, it might be because a scan is already running
      if (error.message && error.message.includes('400')) {
        const stopAndRetry = window.confirm('يوجد فحص قيد التشغيل. هل تريد إيقافه وبدء فحص جديد؟');
        if (stopAndRetry) {
          await stopScan();
          setTimeout(() => startScan(mode), 1000);
          return;
        }
      }
      alert('خطأ في الاتصال بالخادم: ' + error.message);
    } finally {
      setIsLoading(false);
    }
  };

  // Stop scan
  const stopScan = async () => {
    try {
      const { data } = await api.post('/scan/stop', {});
      
      if (data.success) {
        alert('تم إيقاف الفحص');
        // Scan status will update automatically via global polling
        setTimeout(() => {
          fetchStats();
          fetchDevices();
        }, 500);
      }
    } catch (error) {
      console.error('Error stopping scan:', error);
    }
  };

  // Generate report for active scan session
  const generateReport = async () => {
    if (!activeScanSession) {
      alert('الرجاء اختيار فحص أو إجراء فحص جديد أولاً');
      return;
    }
    
    try {
      const { data } = await api.post('/reports/generate', {
        scan_session_id: activeScanSession,
        title: `تقرير أمان IoT - ${new Date().toLocaleDateString('ar-SA')}`
      });
      if (data.success) {
        alert('تم إنشاء تقرير PDF بنجاح!');
        navigate('/dashboard/reports');
      }
    } catch (error) {
      console.error('Error generating report:', error);
      alert('حدث خطأ في إنشاء التقرير');
    }
  }; 

  useEffect(() => {
    fetchStats();
    fetchDevices();               
    
    // Refresh data when scan completes
    if (!scanStatus.is_scanning && scanStatus.progress === 100) {
      fetchStats();
      fetchDevices();
    }
  }, [scanStatus.is_scanning, activeScanSession]);

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
    <>
      <NewScanDialog
        open={showNewScanDialog}
        onOpenChange={setShowNewScanDialog}
        onStartScan={startScanWithName}
        isScanning={scanStatus.is_scanning}
      />
      
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
                    onClick={() => setShowNewScanDialog(true)} 
                    disabled={isLoading}
                    className="w-full bg-blue-600 hover:bg-blue-700"
                  >
                    <Activity className="h-4 w-4 ml-2" />
                    بدء فحص جديد
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
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card className="cursor-pointer hover:shadow-lg transition-shadow">
            <CardHeader className="text-center">
              <FileText className="h-8 w-8 mx-auto mb-2 text-blue-600" />
              <CardTitle className="text-lg">إنشاء تقرير</CardTitle>
              <CardDescription>
                إنشاء تقرير PDF مفصل عن الثغرات المكتشفة
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button onClick={generateReport} className="w-full" variant="outline">
                إنشاء تقرير PDF
              </Button>
            </CardContent>
          </Card>

          <Card 
            className="cursor-pointer hover:shadow-lg transition-shadow"
            onClick={() => navigate('/dashboard/vulnerabilities')}
          >
            <CardHeader className="text-center">
              <AlertTriangle className="h-8 w-8 mx-auto mb-2 text-orange-600" />
              <CardTitle className="text-lg">الثغرات الحرجة</CardTitle>
              <CardDescription>
                عرض جميع الثغرات المكتشفة
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex justify-center space-x-2 space-x-reverse">
                <Badge className="bg-red-500 text-white">
                  {stats.critical} حرجة
                </Badge>
                <Badge className="bg-orange-500 text-white">
                  {stats.high} عالية
                </Badge>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
    </>
  );
};

export default Dashboard;

