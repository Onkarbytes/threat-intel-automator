# database.py - Caching Layer for IOC Analysis Pipeline
# Phase 5: Caching Layer Implementation

import sqlite3
import json
from datetime import datetime, timedelta
import os

class IOCDatabase:
    """
    SQLite database for caching IOC analysis results.
    
    Stores IOC data with timestamps to avoid redundant API calls
    and implements 24-hour cache expiration policy.
    """
    
    def __init__(self, db_path='ioc_cache.db'):
        """
        Initialize the IOC database.
        
        Args:
            db_path (str): Path to SQLite database file
        """
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """
        Initialize database tables if they don't exist.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create IOC cache table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ioc_cache (
                    ioc TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    analysis_data TEXT NOT NULL,  -- JSON string
                    risk_score INTEGER,
                    risk_level TEXT,
                    recommendations TEXT,  -- JSON string
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create index for faster lookups
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_ioc_timestamp 
                ON ioc_cache(ioc, timestamp)
            ''')
            
            conn.commit()
    
    def is_cache_valid(self, ioc, max_age_hours=24):
        """
        Check if cached data for an IOC is still valid (not expired).
        
        Args:
            ioc (str): The IOC to check
            max_age_hours (int): Maximum age in hours for cache validity
            
        Returns:
            bool: True if cache is valid and fresh, False otherwise
        """
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT timestamp FROM ioc_cache 
                WHERE ioc = ? AND timestamp > ?
            ''', (ioc, cutoff_time))
            
            result = cursor.fetchone()
            return result is not None
    
    def get_cached_ioc(self, ioc):
        """
        Retrieve cached IOC data if it exists and is valid.
        
        Args:
            ioc (str): The IOC to retrieve
            
        Returns:
            dict or None: Cached IOC data or None if not found/expired
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT category, analysis_data, risk_score, risk_level, 
                       recommendations, timestamp, last_updated
                FROM ioc_cache 
                WHERE ioc = ?
                ORDER BY timestamp DESC
                LIMIT 1
            ''', (ioc,))
            
            result = cursor.fetchone()
            
            if result:
                category, analysis_data, risk_score, risk_level, recommendations, timestamp, last_updated = result
                
                # Parse JSON data
                try:
                    analysis_data = json.loads(analysis_data)
                    recommendations = json.loads(recommendations) if recommendations else []
                except json.JSONDecodeError:
                    return None
                
                return {
                    'ioc': ioc,
                    'category': category,
                    'analysis': analysis_data,
                    'risk_score': risk_score,
                    'risk_level': risk_level,
                    'recommendations': recommendations,
                    'timestamp': timestamp,
                    'last_updated': last_updated,
                    'cached': True
                }
        
        return None
    
    def store_ioc_data(self, ioc, category, analysis_data, risk_score, risk_level, recommendations):
        """
        Store or update IOC data in the cache.
        
        Args:
            ioc (str): The IOC identifier
            category (str): IOC category (ip, domain, hash, url)
            analysis_data (dict): Analysis results from APIs
            risk_score (int): Calculated risk score
            risk_level (str): Risk level (CRITICAL, HIGH, etc.)
            recommendations (list): List of recommendation strings
        """
        now = datetime.now()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Convert data to JSON strings
            analysis_json = json.dumps(analysis_data, default=str)
            recommendations_json = json.dumps(recommendations)
            
            # Insert or replace (UPSERT)
            cursor.execute('''
                INSERT OR REPLACE INTO ioc_cache 
                (ioc, category, analysis_data, risk_score, risk_level, recommendations, timestamp, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (ioc, category, analysis_json, risk_score, risk_level, recommendations_json, now, now))
            
            conn.commit()
    
    def get_cache_stats(self):
        """
        Get statistics about the cache.
        
        Returns:
            dict: Cache statistics
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total entries
            cursor.execute('SELECT COUNT(*) FROM ioc_cache')
            total_entries = cursor.fetchone()[0]
            
            # Fresh entries (last 24 hours)
            cutoff_time = datetime.now() - timedelta(hours=24)
            cursor.execute('SELECT COUNT(*) FROM ioc_cache WHERE timestamp > ?', (cutoff_time,))
            fresh_entries = cursor.fetchone()[0]
            
            # Stale entries
            stale_entries = total_entries - fresh_entries
            
            # Category breakdown
            cursor.execute('''
                SELECT category, COUNT(*) 
                FROM ioc_cache 
                GROUP BY category
            ''')
            category_breakdown = dict(cursor.fetchall())
            
            return {
                'total_entries': total_entries,
                'fresh_entries': fresh_entries,
                'stale_entries': stale_entries,
                'category_breakdown': category_breakdown
            }
    
    def cleanup_stale_entries(self, max_age_hours=168):  # 7 days default
        """
        Remove stale entries older than specified hours.
        
        Args:
            max_age_hours (int): Maximum age in hours before deletion
            
        Returns:
            int: Number of entries deleted
        """
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM ioc_cache WHERE timestamp < ?', (cutoff_time,))
            deleted_count = cursor.rowcount
            conn.commit()
            
            return deleted_count
    
    def clear_cache(self):
        """
        Clear all cached data.
        
        Returns:
            int: Number of entries deleted
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM ioc_cache')
            deleted_count = cursor.rowcount
            conn.commit()
            
            return deleted_count