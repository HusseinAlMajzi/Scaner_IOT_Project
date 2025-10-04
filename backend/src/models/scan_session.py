"""
Scan Session Model
Represents a scanning session with its own devices and vulnerabilities
"""

from datetime import datetime
from . import db


class ScanSession(db.Model):
    """Model for scan sessions"""
    __tablename__ = 'scan_sessions'
    
    id = db.Column(db.String(36), primary_key=True)  # UUID
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    scan_mode = db.Column(db.String(50))  # comprehensive, enhanced, standard
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    progress = db.Column(db.Integer, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # Statistics
    devices_found = db.Column(db.Integer, default=0)
    vulnerabilities_found = db.Column(db.Integer, default=0)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('scan_sessions', lazy='dynamic'))
    devices = db.relationship('Device', backref='scan_session', lazy='dynamic', cascade='all, delete-orphan')
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'description': self.description,
            'scan_mode': self.scan_mode,
            'status': self.status,
            'progress': self.progress,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'devices_found': self.devices_found,
            'vulnerabilities_found': self.vulnerabilities_found
        }
    
    def __repr__(self):
        return f'<ScanSession {self.name}>'
