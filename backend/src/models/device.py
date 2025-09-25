
from datetime import datetime
import uuid

from.import db

class Device(db.Model):
    __tablename__ = 'devices'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip_address = db.Column(db.String(45), nullable=False)  # IPv4 or IPv6
    mac_address = db.Column(db.String(17), nullable=True)
    hostname = db.Column(db.String(255), nullable=True)
    manufacturer = db.Column(db.String(255), nullable=True)
    device_type = db.Column(db.String(255), nullable=True)
    os_info = db.Column(db.Text, nullable=True)
    firmware_version = db.Column(db.String(255), nullable=True)
    open_ports = db.Column(db.JSON, nullable=True)  # Store as JSON
    last_scanned_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scan_results = db.relationship('ScanResult', backref='device', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,  
            'ip_address': self.ip_address,   
            'mac_address': self.mac_address,   
            'hostname': self.hostname,   
            'manufacturer': self.manufacturer,    
            'device_type': self.device_type,       
            'os_info': self.os_info,                  
            'firmware_version': self.firmware_version,
            'open_ports': self.open_ports, 
            'last_scanned_at': self.last_scanned_at.isoformat() if self.last_scanned_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f'<Device {self.ip_address} - {self.device_type}>'

