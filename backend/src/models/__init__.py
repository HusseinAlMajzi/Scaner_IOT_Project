# Use the same db instance across all models
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

# استورد الموديلات بعد تعريف db
from .device import Device
from .vulnerability import Vulnerability
from .scan_result import ScanResult
from .report import Report



# Import all models to ensure they are registered with SQLAlchemy
__all__ = ['Device', 'Vulnerability', 'ScanResult', 'Report', 'db']





