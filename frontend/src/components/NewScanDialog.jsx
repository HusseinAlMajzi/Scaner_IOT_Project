import React, { useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Activity, Loader2 } from 'lucide-react';

const NewScanDialog = ({ open, onOpenChange, onStartScan, isScanning }) => {
  const [scanName, setScanName] = useState('');
  const [isStarting, setIsStarting] = useState(false);

  const handleStart = async () => {
    if (!scanName.trim()) {
      alert('الرجاء إدخال اسم للفحص');
      return;
    }

    setIsStarting(true);
    await onStartScan(scanName.trim());
    setIsStarting(false);
    setScanName('');
    onOpenChange(false);
  };

  const handleCancel = () => {
    setScanName('');
    onOpenChange(false);
  };

  // Auto-generate default name
  const generateDefaultName = () => {
    const now = new Date();
    const date = now.toLocaleDateString('ar-SA');
    const time = now.toLocaleTimeString('ar-SA', { hour: '2-digit', minute: '2-digit' });
    return `فحص ${date} - ${time}`;
  };

  React.useEffect(() => {
    if (open && !scanName) {
      setScanName(generateDefaultName());
    }
  }, [open]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px]" dir="rtl">
        <DialogHeader>
          <DialogTitle className="text-xl">بدء فحص جديد</DialogTitle>
          <DialogDescription>
            أدخل اسماً للفحص لتتمكن من العودة إليه لاحقاً
          </DialogDescription>
        </DialogHeader>
        
        <div className="grid gap-4 py-4">
          <div className="grid gap-2">
            <Label htmlFor="scanName" className="text-right">
              اسم الفحص
            </Label>
            <Input
              id="scanName"
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
              placeholder="مثال: فحص الشبكة المنزلية"
              className="text-right"
              disabled={isStarting}
              autoFocus
            />
            <p className="text-sm text-gray-500">
              سيتم حفظ جميع الأجهزة والثغرات تحت هذا الاسم
            </p>
          </div>
        </div>

        <DialogFooter className="flex-row-reverse gap-2">
          <Button
            onClick={handleStart}
            disabled={isStarting || !scanName.trim()}
            className="bg-blue-600 hover:bg-blue-700"
          >
            {isStarting ? (
              <>
                <Loader2 className="h-4 w-4 ml-2 animate-spin" />
                جاري البدء...
              </>
            ) : (
              <>
                <Activity className="h-4 w-4 ml-2" />
                بدء الفحص
              </>
            )}
          </Button>
          <Button
            variant="outline"
            onClick={handleCancel}
            disabled={isStarting}
          >
            إلغاء
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default NewScanDialog;
