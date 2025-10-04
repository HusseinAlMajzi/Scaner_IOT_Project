"""
Database Optimization - Phase 9.3
Implements indexing, query optimization, and connection pooling
"""

import logging
from sqlalchemy import Index, text
from typing import Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseOptimizer:
    """Database optimization and indexing"""
    
    # Indexes to create for optimal performance
    RECOMMENDED_INDEXES = {
        'devices': [
            ('idx_device_user_id', ['user_id']),
            ('idx_device_ip', ['ip_address']),
            ('idx_device_mac', ['mac_address']),
            ('idx_device_type', ['device_type']),
            ('idx_device_last_scanned', ['last_scanned_at']),
            ('idx_device_user_ip', ['user_id', 'ip_address']),  # Composite
        ],
        'vulnerabilities': [
            ('idx_vuln_severity', ['severity']),
            ('idx_vuln_cve', ['cve_id']),
            ('idx_vuln_source', ['source']),
        ],
        'scan_results': [
            ('idx_scan_device', ['device_id']),
            ('idx_scan_vuln', ['vulnerability_id']),
            ('idx_scan_status', ['status']),
            ('idx_scan_device_vuln', ['device_id', 'vulnerability_id']),  # Composite
        ],
        'reports': [
            ('idx_report_user', ['user_id']),
            ('idx_report_date', ['generated_at']),
        ],
        'users': [
            ('idx_user_username', ['username']),
            ('idx_user_email', ['email']),
        ]
    }
    
    def __init__(self, db_session):
        """
        Initialize database optimizer
        
        Args:
            db_session: SQLAlchemy database session
        """
        self.db = db_session
    
    def create_indexes(self) -> Dict:
        """Create recommended indexes"""
        results = {
            'created': [],
            'failed': [],
            'already_exists': []
        }
        
        logger.info("Creating database indexes...")
        
        for table_name, indexes in self.RECOMMENDED_INDEXES.items():
            for index_name, columns in indexes:
                try:
                    # Create index using raw SQL
                    columns_str = ', '.join(columns)
                    create_index_sql = f"""
                        CREATE INDEX IF NOT EXISTS {index_name} 
                        ON {table_name} ({columns_str})
                    """
                    
                    self.db.execute(text(create_index_sql))
                    self.db.commit()
                    
                    results['created'].append(f"{table_name}.{index_name}")
                    logger.info(f"Created index: {index_name} on {table_name}")
                
                except Exception as e:
                    if 'already exists' in str(e).lower():
                        results['already_exists'].append(f"{table_name}.{index_name}")
                    else:
                        results['failed'].append(f"{table_name}.{index_name}: {str(e)}")
                        logger.error(f"Failed to create index {index_name}: {e}")
        
        logger.info(f"Index creation complete: {len(results['created'])} created, "
                   f"{len(results['already_exists'])} already exist, "
                   f"{len(results['failed'])} failed")
        
        return results
    
    def analyze_query_performance(self, query_sql: str) -> Dict:
        """
        Analyze query performance using EXPLAIN
        
        Args:
            query_sql: SQL query to analyze
            
        Returns:
            Query plan analysis
        """
        try:
            explain_sql = f"EXPLAIN ANALYZE {query_sql}"
            result = self.db.execute(text(explain_sql))
            
            plan_lines = [row[0] for row in result]
            
            analysis = {
                'query': query_sql,
                'execution_plan': plan_lines,
                'has_sequential_scan': any('Seq Scan' in line for line in plan_lines),
                'has_index_scan': any('Index Scan' in line for line in plan_lines)
            }
            
            if analysis['has_sequential_scan']:
                logger.warning(f"Query uses sequential scan: {query_sql[:100]}")
            
            return analysis
        
        except Exception as e:
            logger.error(f"Query analysis error: {e}")
            return {'error': str(e)}
    
    def vacuum_database(self) -> bool:
        """Run VACUUM to optimize database"""
        try:
            logger.info("Running database VACUUM...")
            self.db.execute(text("VACUUM ANALYZE"))
            self.db.commit()
            logger.info("VACUUM complete")
            return True
        except Exception as e:
            logger.error(f"VACUUM error: {e}")
            return False
    
    def get_table_statistics(self) -> Dict:
        """Get table statistics"""
        stats = {}
        
        try:
            for table in ['devices', 'vulnerabilities', 'scan_results', 'reports', 'users']:
                count_sql = f"SELECT COUNT(*) FROM {table}"
                result = self.db.execute(text(count_sql))
                count = result.scalar()
                
                stats[table] = {
                    'row_count': count
                }
                
                # Get table size
                size_sql = f"""
                    SELECT pg_size_pretty(pg_total_relation_size('{table}'))
                """
                result = self.db.execute(text(size_sql))
                size = result.scalar()
                stats[table]['size'] = size
        
        except Exception as e:
            logger.error(f"Error getting table statistics: {e}")
        
        return stats
    
    def optimize_all(self) -> Dict:
        """Run all optimization routines"""
        logger.info("Running full database optimization...")
        
        results = {
            'indexes': self.create_indexes(),
            'vacuum': self.vacuum_database(),
            'statistics': self.get_table_statistics()
        }
        
        return results


# Connection pooling configuration
def configure_connection_pool(app_config: Dict) -> Dict:
    """
    Configure SQLAlchemy connection pooling
    
    Args:
        app_config: Flask app configuration
        
    Returns:
        Pool configuration
    """
    pool_config = {
        'pool_size': 10,  # Base pool size
        'max_overflow': 20,  # Additional connections when needed
        'pool_timeout': 30,  # Timeout for getting connection
        'pool_recycle': 3600,  # Recycle connections after 1 hour
        'pool_pre_ping': True,  # Verify connections before use
    }
    
    # Update app config
    app_config.update({
        'SQLALCHEMY_ENGINE_OPTIONS': pool_config
    })
    
    logger.info(f"Connection pool configured: {pool_config['pool_size']} base, "
               f"{pool_config['max_overflow']} overflow")
    
    return pool_config


# Example usage
if __name__ == '__main__':
    print("="*70)
    print("Database Optimization - Phase 9.3")
    print("="*70)
    
    print("\nRecommended Indexes:")
    optimizer = DatabaseOptimizer(None)
    
    for table, indexes in optimizer.RECOMMENDED_INDEXES.items():
        print(f"\n{table}:")
        for idx_name, columns in indexes:
            print(f"  - {idx_name}: {', '.join(columns)}")
    
    print(f"\nConnection Pool Settings:")
    pool_config = configure_connection_pool({})
    for key, value in pool_config.items():
        print(f"  {key}: {value}")
