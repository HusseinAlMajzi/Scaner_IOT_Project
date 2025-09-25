
from datetime import datetime
import uuid

from.import db

class ScanResult(db.Model):
    __tablename__ = 'scan_results'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=False)
    vulnerability_id = db.Column(db.String(36), db.ForeignKey('vulnerabilities.id'), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False)  # Detected, Mitigated, False Positive
    details = db.Column(db.Text, nullable=True)
    confidence_level = db.Column(db.String(20), nullable=True)  # High, Medium, Low
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'vulnerability_id': self.vulnerability_id,
            'scan_date': self.scan_date.isoformat() if self.scan_date else None,
            'status': self.status,
            'details': self.details,
            'confidence_level': self.confidence_level
        }
    
    def __repr__(self):
        return f'<ScanResult {self.device_id} - {self.vulnerability_id} - {self.status}>'

