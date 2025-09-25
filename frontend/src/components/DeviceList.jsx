import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { 
  Wifi, 
  Search, 
  Filter, 
  Monitor, 
  Router, 
  Camera, 
  Smartphone,
  AlertTriangle,
  CheckCircle,
  Clock,
  Network
} from 'lucide-react';

const DeviceList = () => {
  const [devices, setDevices] = useState([]);
  const [filteredDevices, setFilteredDevices] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  // Fetch devices
  const fetchDevices = async () => {
    try {
      setIsLoading(true);
      const response = await fetch('/api/devices');
      const data = await response.json();
      if (data.success) {
        setDevices(data.devices);
        setFilteredDevices(data.devices);
      }
    } catch (error) {
      console.error('Error fetching devices:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // Fetch device details
  const fetchDeviceDetails = async (deviceId) => {
    try {
      const response = await fetch(`/api/devices/${deviceId}`);
      const data = await response.json();
      if (data.success) {
        setSelectedDevice(data.device);
      }
    } catch (error) {
      console.error('Error fetching device details:', error);
    }
  };

  // Filter devices based on search term
  useEffect(() => {
    const filtered = devices.filter(device => 
      device.ip_address.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (device.hostname && device.hostname.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (device.manufacturer && device.manufacturer.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (device.device_type && device.device_type.toLowerCase().includes(searchTerm.toLowerCase()))
    );
    setFilteredDevices(filtered);
  }, [searchTerm, devices]);

  useEffect(() => {
    fetchDevices();
  }, []);

  const getDeviceIcon = (deviceType) => {
    const type = deviceType?.toLowerCase() || '';
    if (type.includes('camera')) return Camera;
    if (type.includes('router') || type.includes('gateway')) return Router;
    if (type.includes('phone') || type.includes('mobile')) return Smartphone;
    if (type.includes('tv') || type.includes('monitor')) return Monitor;
    return Network;
  };

  const getDeviceTypeColor = (deviceType) => {
    const type = deviceType?.toLowerCase() || '';
    if (type.includes('camera')) return 'bg-purple-100 text-purple-800';
    if (type.includes('router')) return 'bg-blue-100 text-blue-800';
    if (type.includes('smart')) return 'bg-green-100 text-green-800';
    return 'bg-gray-100 text-gray-800';
  };

  const getRiskLevel = (vulnerabilities) => {
    if (!vulnerabilities || vulnerabilities.length === 0) return { level: 'آمن', color: 'bg-green-500', icon: CheckCircle };
    
    const hasCritical = vulnerabilities.some(v => v.severity === 'Critical');
    const hasHigh = vulnerabilities.some(v => v.severity === 'High');
    
    if (hasCritical) return { level: 'خطر عالي', color: 'bg-red-500', icon: AlertTriangle };
    if (hasHigh) return { level: 'خطر متوسط', color: 'bg-orange-500', icon: AlertTriangle };
    return { level: 'خطر منخفض', color: 'bg-yellow-500', icon: AlertTriangle };
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-6" dir="rtl">
        <div className="max-w-7xl mx-auto">
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
            <p className="mt-4 text-gray-600">جاري تحميل الأجهزة...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-6" dir="rtl">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 flex items-center">
              <Wifi className="h-8 w-8 ml-3 text-blue-600" />
              الأجهزة المكتشفة
            </h1>
            <p className="text-gray-600 mt-2">
              إجمالي {devices.length} جهاز متصل بالشبكة
            </p>
          </div>
          <Button onClick={fetchDevices} className="bg-blue-600 hover:bg-blue-700">
            تحديث القائمة
          </Button>
        </div>

        {/* Search and Filter */}
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center space-x-4 space-x-reverse">
              <div className="flex-1 relative">
                <Search className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
                <Input
                  placeholder="البحث في الأجهزة (عنوان IP، اسم المضيف، الشركة المصنعة...)"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pr-10"
                />
              </div>
              <Button variant="outline">
                <Filter className="h-4 w-4 ml-2" />
                تصفية
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Devices Grid */}
        {filteredDevices.length === 0 ? (
          <Card>
            <CardContent className="text-center py-12">
              <Wifi className="h-16 w-16 mx-auto mb-4 text-gray-400" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">لا توجد أجهزة</h3>
              <p className="text-gray-600">
                {searchTerm ? 'لم يتم العثور على أجهزة تطابق البحث' : 'لم يتم اكتشاف أي أجهزة بعد'}
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
            {filteredDevices.map((device) => {
              const DeviceIcon = getDeviceIcon(device.device_type);
              const riskInfo = getRiskLevel(device.vulnerabilities);
              const RiskIcon = riskInfo.icon;
              
              return (
                <Card 
                  key={device.id} 
                  className="hover:shadow-lg transition-shadow cursor-pointer border-2 hover:border-blue-200"
                  onClick={() => fetchDeviceDetails(device.id)}
                >
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3 space-x-reverse">
                        <div className="p-2 bg-blue-100 rounded-lg">
                          <DeviceIcon className="h-6 w-6 text-blue-600" />
                        </div>
                        <div>
                          <CardTitle className="text-lg">{device.ip_address}</CardTitle>
                          <CardDescription>
                            {device.hostname || 'اسم مضيف غير متوفر'}
                          </CardDescription>
                        </div>
                      </div>
                      <div className={`flex items-center space-x-1 space-x-reverse px-2 py-1 rounded-full ${riskInfo.color}`}>
                        <RiskIcon className="h-3 w-3 text-white" />
                        <span className="text-xs text-white font-medium">{riskInfo.level}</span>
                      </div>
                    </div>
                  </CardHeader>
                  
                  <CardContent className="space-y-4">
                    {/* Device Info */}
                    <div className="space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-gray-600">نوع الجهاز:</span>
                        <Badge className={getDeviceTypeColor(device.device_type)}>
                          {device.device_type || 'غير معروف'}
                        </Badge>
                      </div>
                      
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-gray-600">الشركة المصنعة:</span>
                        <span className="text-sm font-medium">
                          {device.manufacturer || 'غير معروف'}
                        </span>
                      </div>
                      
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-gray-600">المنافذ المفتوحة:</span>
                        <Badge variant="outline">
                          {device.open_ports?.length || 0} منفذ
                        </Badge>
                      </div>
                      
                      {device.last_scanned_at && (
                        <div className="flex justify-between items-center">
                          <span className="text-sm text-gray-600">آخر فحص:</span>
                          <div className="flex items-center space-x-1 space-x-reverse text-sm text-gray-500">
                            <Clock className="h-3 w-3" />
                            <span>{new Date(device.last_scanned_at).toLocaleDateString('ar-SA')}</span>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Vulnerabilities Summary */}
                    {device.vulnerabilities && device.vulnerabilities.length > 0 && (
                      <div className="pt-2 border-t">
                        <div className="flex justify-between items-center mb-2">
                          <span className="text-sm font-medium text-gray-700">الثغرات المكتشفة:</span>
                          <Badge variant="destructive">{device.vulnerabilities.length}</Badge>
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {['Critical', 'High', 'Medium', 'Low'].map(severity => {
                            const count = device.vulnerabilities.filter(v => v.severity === severity).length;
                            if (count === 0) return null;
                            
                            const colors = {
                              Critical: 'bg-red-100 text-red-800',
                              High: 'bg-orange-100 text-orange-800',
                              Medium: 'bg-yellow-100 text-yellow-800',
                              Low: 'bg-green-100 text-green-800'
                            };
                            
                            return (
                              <Badge key={severity} className={`text-xs ${colors[severity]}`}>
                                {count} {severity === 'Critical' ? 'حرجة' : 
                                      severity === 'High' ? 'عالية' :
                                      severity === 'Medium' ? 'متوسطة' : 'منخفضة'}
                              </Badge>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    <Button className="w-full" variant="outline" size="sm">
                      عرض التفاصيل
                    </Button>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}

        {/* Device Details Modal */}
        {selectedDevice && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <Card className="max-w-4xl w-full max-h-[90vh] overflow-y-auto">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-xl">
                    تفاصيل الجهاز: {selectedDevice.ip_address}
                  </CardTitle>
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={() => setSelectedDevice(null)}
                  >
                    إغلاق
                  </Button>
                </div>
              </CardHeader>
              
              <CardContent className="space-y-6">
                {/* Basic Info */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <h4 className="font-medium text-gray-900">معلومات أساسية</h4>
                    <div className="space-y-1 text-sm">
                      <div><strong>عنوان IP:</strong> {selectedDevice.ip_address}</div>
                      <div><strong>عنوان MAC:</strong> {selectedDevice.mac_address || 'غير متوفر'}</div>
                      <div><strong>اسم المضيف:</strong> {selectedDevice.hostname || 'غير متوفر'}</div>
                      <div><strong>نوع الجهاز:</strong> {selectedDevice.device_type || 'غير معروف'}</div>
                      <div><strong>الشركة المصنعة:</strong> {selectedDevice.manufacturer || 'غير معروف'}</div>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <h4 className="font-medium text-gray-900">معلومات تقنية</h4>
                    <div className="space-y-1 text-sm">
                      <div><strong>نظام التشغيل:</strong> {selectedDevice.os_info || 'غير معروف'}</div>
                      <div><strong>إصدار البرنامج الثابت:</strong> {selectedDevice.firmware_version || 'غير معروف'}</div>
                      <div><strong>المنافذ المفتوحة:</strong> {selectedDevice.open_ports?.length || 0}</div>
                      <div><strong>آخر فحص:</strong> {selectedDevice.last_scanned_at ? new Date(selectedDevice.last_scanned_at).toLocaleString('ar-SA') : 'غير متوفر'}</div>
                    </div>
                  </div>
                </div>

                {/* Open Ports */}
                {selectedDevice.open_ports && selectedDevice.open_ports.length > 0 && (
                  <div>
                    <h4 className="font-medium text-gray-900 mb-3">المنافذ المفتوحة</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {selectedDevice.open_ports.map((port, index) => (
                        <div key={index} className="flex justify-between items-center p-2 bg-gray-50 rounded">
                          <span className="font-medium">{port.port}</span>
                          <div className="text-sm text-gray-600">
                            {port.service} {port.version && `(${port.version})`}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Vulnerabilities */}
                {selectedDevice.vulnerabilities && selectedDevice.vulnerabilities.length > 0 && (
                  <div>
                    <h4 className="font-medium text-gray-900 mb-3">
                      الثغرات المكتشفة ({selectedDevice.vulnerabilities.length})
                    </h4>
                    <div className="space-y-3">
                      {selectedDevice.vulnerabilities.map((vuln, index) => (
                        <div key={index} className="border rounded-lg p-4">
                          <div className="flex items-center justify-between mb-2">
                            <h5 className="font-medium">{vuln.cve_id || 'ثغرة مخصصة'}</h5>
                            <Badge 
                              className={
                                vuln.severity === 'Critical' ? 'bg-red-500' :
                                vuln.severity === 'High' ? 'bg-orange-500' :
                                vuln.severity === 'Medium' ? 'bg-yellow-500' : 'bg-green-500'
                              }
                            >
                              {vuln.severity}
                            </Badge>
                          </div>
                          <p className="text-sm text-gray-600 mb-2">{vuln.description}</p>
                          {vuln.recommendation && (
                            <div className="bg-blue-50 p-3 rounded text-sm">
                              <strong>التوصية:</strong> {vuln.recommendation}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
};

export default DeviceList;

