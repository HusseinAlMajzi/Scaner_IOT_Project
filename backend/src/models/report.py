
from datetime import datetime
import uuid

from.import db

class Report(db.Model):
    __tablename__ = 'reports'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(255), nullable=False)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    file_path = db.Column(db.String(255), nullable=True)
    scan_ids = db.Column(db.JSON, nullable=True)  # Store scan result IDs as JSON array
    summary = db.Column(db.Text, nullable=True)
    total_devices = db.Column(db.Integer, default=0)
    total_vulnerabilities = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'generated_at': self.generated_at.isoformat() if self.generated_at else None,
            'file_path': self.file_path,
            'scan_ids': self.scan_ids,
            'summary': self.summary,
            'total_devices': self.total_devices,
            'total_vulnerabilities': self.total_vulnerabilities,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count
        }
    
    def __repr__(self):
        return f'<Report {self.title} - {self.generated_at}>'

