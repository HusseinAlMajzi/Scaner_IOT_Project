import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { 
  FileText, 
  Download, 
  Calendar, 
  BarChart3,
  Plus,
  Search,
  Eye,
  Trash2
} from 'lucide-react';

const ReportsList = () => {
  const [reports, setReports] = useState([]);
  const [filteredReports, setFilteredReports] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [isGenerating, setIsGenerating] = useState(false);

  // Fetch reports
  const fetchReports = async () => {
    try {
      setIsLoading(true);
      const response = await fetch('/api/reports');
      const data = await response.json();
      if (data.success) {
        setReports(data.reports);
        setFilteredReports(data.reports);
      }
    } catch (error) {
      console.error('Error fetching reports:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // Generate new report
  const generateReport = async () => {
    try {
      setIsGenerating(true);
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
        fetchReports(); // Refresh the list
      } else {
        alert('حدث خطأ في إنشاء التقرير: ' + data.message);
      }
    } catch (error) {
      console.error('Error generating report:', error);
      alert('حدث خطأ في إنشاء التقرير');
    } finally {
      setIsGenerating(false);
    }
  };

  // Download report
  const downloadReport = async (reportId) => {
    try {
      const response = await fetch(`/api/reports/${reportId}/download`);
      const data = await response.json();
      
      if (data.success) {
        // Create a temporary link to download the file
        const link = document.createElement('a');
        link.href = data.file_path;
        link.download = data.filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      } else {
        alert('حدث خطأ في تحميل التقرير: ' + data.message);
      }
    } catch (error) {
      console.error('Error downloading report:', error);
      alert('حدث خطأ في تحميل التقرير');
    }
  };

  // Filter reports based on search term
  useEffect(() => {
    const filtered = reports.filter(report => 
      report.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      report.summary.toLowerCase().includes(searchTerm.toLowerCase())
    );
    setFilteredReports(filtered);
  }, [searchTerm, reports]);

  useEffect(() => {
    fetchReports();
  }, []);

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getRiskLevelColor = (critical, high) => {
    if (critical > 0) return 'bg-red-100 text-red-800 border-red-200';
    if (high > 0) return 'bg-orange-100 text-orange-800 border-orange-200';
    return 'bg-green-100 text-green-800 border-green-200';
  };

  const getRiskLevelText = (critical, high) => {
    if (critical > 0) return 'خطر عالي';
    if (high > 0) return 'خطر متوسط';
    return 'خطر منخفض';
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-6" dir="rtl">
        <div className="max-w-7xl mx-auto">
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
            <p className="mt-4 text-gray-600">جاري تحميل التقارير...</p>
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
              <FileText className="h-8 w-8 ml-3 text-blue-600" />
              التقارير الأمنية
            </h1>
            <p className="text-gray-600 mt-2">
              إجمالي {reports.length} تقرير متوفر
            </p>
          </div>
          <div className="flex space-x-3 space-x-reverse">
            <Button onClick={fetchReports} variant="outline">
              تحديث القائمة
            </Button>
            <Button 
              onClick={generateReport} 
              disabled={isGenerating}
              className="bg-blue-600 hover:bg-blue-700"
            >
              <Plus className="h-4 w-4 ml-2" />
              {isGenerating ? 'جاري الإنشاء...' : 'إنشاء تقرير جديد'}
            </Button>
          </div>
        </div>

        {/* Search */}
        <Card>
          <CardContent className="pt-6">
            <div className="relative">
              <Search className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
              <Input
                placeholder="البحث في التقارير (العنوان، الملخص...)"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pr-10"
              />
            </div>
          </CardContent>
        </Card>

        {/* Reports List */}
        {filteredReports.length === 0 ? (
          <Card>
            <CardContent className="text-center py-12">
              <FileText className="h-16 w-16 mx-auto mb-4 text-gray-400" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">لا توجد تقارير</h3>
              <p className="text-gray-600 mb-4">
                {searchTerm ? 'لم يتم العثور على تقارير تطابق البحث' : 'لم يتم إنشاء أي تقارير بعد'}
              </p>
              {!searchTerm && (
                <Button onClick={generateReport} disabled={isGenerating}>
                  <Plus className="h-4 w-4 ml-2" />
                  إنشاء أول تقرير
                </Button>
              )}
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-6">
            {filteredReports.map((report) => (
              <Card key={report.id} className="hover:shadow-lg transition-shadow">
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <CardTitle className="text-xl mb-2">{report.title}</CardTitle>
                      <CardDescription className="text-base">
                        {report.summary}
                      </CardDescription>
                      
                      <div className="flex items-center space-x-4 space-x-reverse mt-3 text-sm text-gray-500">
                        <div className="flex items-center space-x-1 space-x-reverse">
                          <Calendar className="h-4 w-4" />
                          <span>{new Date(report.generated_at).toLocaleDateString('ar-SA')}</span>
                        </div>
                        <div className="flex items-center space-x-1 space-x-reverse">
                          <BarChart3 className="h-4 w-4" />
                          <span>{report.total_devices} جهاز</span>
                        </div>
                        <div className="flex items-center space-x-1 space-x-reverse">
                          <FileText className="h-4 w-4" />
                          <span>{report.total_vulnerabilities} ثغرة</span>
                        </div>
                      </div>
                    </div>
                    
                    <div className="flex flex-col items-end space-y-2">
                      <Badge className={getRiskLevelColor(report.critical_count, report.high_count)}>
                        {getRiskLevelText(report.critical_count, report.high_count)}
                      </Badge>
                      <div className="flex space-x-2 space-x-reverse">
                        <Button 
                          size="sm" 
                          variant="outline"
                          onClick={() => downloadReport(report.id)}
                        >
                          <Download className="h-4 w-4 ml-1" />
                          تحميل
                        </Button>
                        <Button size="sm" variant="outline">
                          <Eye className="h-4 w-4 ml-1" />
                          معاينة
                        </Button>
                      </div>
                    </div>
                  </div>
                </CardHeader>
                
                <CardContent>
                  {/* Statistics Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-4">
                    <div className="text-center p-3 bg-gray-50 rounded-lg">
                      <div className="text-lg font-bold text-gray-900">{report.total_devices}</div>
                      <div className="text-xs text-gray-600">الأجهزة</div>
                    </div>
                    <div className="text-center p-3 bg-red-50 rounded-lg">
                      <div className="text-lg font-bold text-red-600">{report.critical_count}</div>
                      <div className="text-xs text-red-600">حرجة</div>
                    </div>
                    <div className="text-center p-3 bg-orange-50 rounded-lg">
                      <div className="text-lg font-bold text-orange-600">{report.high_count}</div>
                      <div className="text-xs text-orange-600">عالية</div>
                    </div>
                    <div className="text-center p-3 bg-yellow-50 rounded-lg">
                      <div className="text-lg font-bold text-yellow-600">{report.medium_count}</div>
                      <div className="text-xs text-yellow-600">متوسطة</div>
                    </div>
                    <div className="text-center p-3 bg-green-50 rounded-lg">
                      <div className="text-lg font-bold text-green-600">{report.low_count}</div>
                      <div className="text-xs text-green-600">منخفضة</div>
                    </div>
                  </div>

                  {/* Report Details */}
                  <div className="flex items-center justify-between text-sm text-gray-500 pt-4 border-t">
                    <div className="flex items-center space-x-4 space-x-reverse">
                      <span>تم الإنشاء: {new Date(report.generated_at).toLocaleString('ar-SA')}</span>
                      {report.file_size && (
                        <span>الحجم: {formatFileSize(report.file_size)}</span>
                      )}
                    </div>
                    
                    <div className="flex items-center space-x-2 space-x-reverse">
                      <span className="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded">HTML</span>
                      <span className="text-xs bg-gray-100 text-gray-800 px-2 py-1 rounded">PDF</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Quick Stats Card */}
        {reports.length > 0 && (
          <Card className="bg-gradient-to-r from-blue-500 to-purple-600 text-white">
            <CardHeader>
              <CardTitle className="text-white">إحصائيات سريعة</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold">{reports.length}</div>
                  <div className="text-sm opacity-90">إجمالي التقارير</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold">
                    {reports.reduce((sum, report) => sum + report.total_devices, 0)}
                  </div>
                  <div className="text-sm opacity-90">إجمالي الأجهزة</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold">
                    {reports.reduce((sum, report) => sum + report.total_vulnerabilities, 0)}
                  </div>
                  <div className="text-sm opacity-90">إجمالي الثغرات</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold">
                    {reports.reduce((sum, report) => sum + report.critical_count, 0)}
                  </div>
                  <div className="text-sm opacity-90">الثغرات الحرجة</div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
};

export default ReportsList;

