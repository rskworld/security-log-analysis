"""
Advanced Security Log Analyzer
Additional analysis features for security log analysis

Project by:
- Molla Samser (Founder)
- Rima Khatun (Designer & Tester)
RSK World - https://rskworld.in

Contact:
- Email: help@rskworld.in, support@rskworld.in
- Phone: +91 93305 39277
- Address: Nutanhat, Mongolkote, Purba Burdwan, West Bengal, India, 713147
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import Counter
import warnings
warnings.filterwarnings('ignore')


class AdvancedAnalyzer:
    """
    Advanced analysis features for security logs.
    """
    
    def __init__(self):
        """Initialize the advanced analyzer."""
        pass
    
    def detect_port_scanning(self, df, threshold=10):
        """
        Detect potential port scanning attacks.
        
        Args:
            df (pd.DataFrame): Log data
            threshold (int): Minimum unique ports per source IP to flag
            
        Returns:
            pd.DataFrame: Data with port scanning flags
        """
        df = df.copy()
        
        if 'source_ip' not in df.columns or 'port' not in df.columns:
            return df
        
        # Count unique ports per source IP
        port_counts = df.groupby('source_ip')['port'].nunique()
        scanning_ips = port_counts[port_counts >= threshold].index
        
        df['is_port_scan'] = df['source_ip'].isin(scanning_ips).astype(int)
        
        return df
    
    def detect_brute_force(self, df, failed_attempts_threshold=5):
        """
        Detect potential brute force attacks.
        
        Args:
            df (pd.DataFrame): Log data
            failed_attempts_threshold (int): Minimum failed attempts to flag
            
        Returns:
            pd.DataFrame: Data with brute force flags
        """
        df = df.copy()
        
        if 'source_ip' not in df.columns or 'status_code' not in df.columns:
            return df
        
        # Identify failed authentication attempts (status 401, 403)
        failed_mask = df['status_code'].isin([401, 403])
        
        # Count failed attempts per source IP
        failed_counts = df[failed_mask].groupby('source_ip').size()
        brute_force_ips = failed_counts[failed_counts >= failed_attempts_threshold].index
        
        df['is_brute_force'] = df['source_ip'].isin(brute_force_ips).astype(int)
        
        return df
    
    def detect_ddos_patterns(self, df, time_window_minutes=5, request_threshold=100):
        """
        Detect potential DDoS attack patterns.
        
        Args:
            df (pd.DataFrame): Log data
            time_window_minutes (int): Time window for analysis
            request_threshold (int): Minimum requests in time window to flag
            
        Returns:
            pd.DataFrame: Data with DDoS flags
        """
        df = df.copy()
        
        if 'timestamp' not in df.columns:
            return df
        
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        df['is_ddos'] = 0
        
        # Check requests in time windows
        for idx in range(len(df)):
            time_window = df.iloc[idx]['timestamp'] - pd.Timedelta(minutes=time_window_minutes)
            mask = (df['timestamp'] >= time_window) & (df['timestamp'] <= df.iloc[idx]['timestamp'])
            request_count = mask.sum()
            
            if request_count >= request_threshold:
                df.iloc[idx, df.columns.get_loc('is_ddos')] = 1
        
        return df
    
    def detect_data_exfiltration(self, df, bytes_threshold=1000000):
        """
        Detect potential data exfiltration attempts.
        
        Args:
            df (pd.DataFrame): Log data
            bytes_threshold (int): Minimum bytes sent to flag
            
        Returns:
            pd.DataFrame: Data with exfiltration flags
        """
        df = df.copy()
        
        if 'bytes_sent' not in df.columns:
            return df
        
        # Flag large outbound transfers
        df['is_data_exfiltration'] = (df['bytes_sent'] > bytes_threshold).astype(int)
        
        # Also check for multiple large transfers from same source
        if 'source_ip' in df.columns:
            large_transfers = df[df['bytes_sent'] > bytes_threshold]
            if len(large_transfers) > 0:
                source_counts = large_transfers.groupby('source_ip').size()
                suspicious_sources = source_counts[source_counts >= 3].index
                df.loc[df['source_ip'].isin(suspicious_sources), 'is_data_exfiltration'] = 1
        
        return df
    
    def detect_suspicious_geographic_patterns(self, df):
        """
        Detect suspicious geographic access patterns.
        
        Args:
            df (pd.DataFrame): Log data
            
        Returns:
            pd.DataFrame: Data with geographic anomaly flags
        """
        df = df.copy()
        
        if 'country' not in df.columns or 'source_ip' not in df.columns:
            return df
        
        # Count unique countries per source IP
        country_counts = df.groupby('source_ip')['country'].nunique()
        multi_country_ips = country_counts[country_counts >= 3].index
        
        df['is_geographic_anomaly'] = df['source_ip'].isin(multi_country_ips).astype(int)
        
        return df
    
    def detect_privilege_escalation_attempts(self, df):
        """
        Detect potential privilege escalation attempts.
        
        Args:
            df (pd.DataFrame): Log data
            
        Returns:
            pd.DataFrame: Data with privilege escalation flags
        """
        df = df.copy()
        
        flags = []
        
        # Check for suspicious patterns
        if 'request_method' in df.columns and 'port' in df.columns:
            # Unusual methods on admin ports
            admin_ports = [22, 3389, 1433, 3306, 5432]
            suspicious = (df['request_method'].isin(['PUT', 'DELETE', 'POST'])) & \
                        (df['port'].isin(admin_ports))
            flags.append(suspicious)
        
        if 'status_code' in df.columns:
            # Multiple 403 errors
            failed_auth = (df['status_code'] == 403)
            flags.append(failed_auth)
        
        if flags:
            df['is_privilege_escalation'] = (np.any(flags, axis=0)).astype(int)
        else:
            df['is_privilege_escalation'] = 0
        
        return df
    
    def generate_threat_intelligence(self, df):
        """
        Generate threat intelligence summary.
        
        Args:
            df (pd.DataFrame): Log data with threat flags
            
        Returns:
            dict: Threat intelligence summary
        """
        summary = {
            'total_logs': len(df),
            'threats_detected': {}
        }
        
        threat_columns = ['is_port_scan', 'is_brute_force', 'is_ddos', 
                         'is_data_exfiltration', 'is_geographic_anomaly', 
                         'is_privilege_escalation']
        
        for col in threat_columns:
            if col in df.columns:
                threat_count = df[col].sum()
                threat_percentage = (threat_count / len(df) * 100) if len(df) > 0 else 0
                summary['threats_detected'][col] = {
                    'count': int(threat_count),
                    'percentage': round(threat_percentage, 2)
                }
        
        # Top threat sources
        if 'source_ip' in df.columns:
            threat_sources = []
            for col in threat_columns:
                if col in df.columns:
                    threat_sources.extend(df[df[col] == 1]['source_ip'].tolist())
            
            if threat_sources:
                source_counts = Counter(threat_sources)
                summary['top_threat_sources'] = dict(source_counts.most_common(10))
        
        return summary
    
    def analyze_all_threats(self, df):
        """
        Run all threat detection analyses.
        
        Args:
            df (pd.DataFrame): Log data
            
        Returns:
            pd.DataFrame: Data with all threat flags
        """
        print("Running advanced threat analysis...")
        
        df = self.detect_port_scanning(df)
        print("✓ Port scanning detection complete")
        
        df = self.detect_brute_force(df)
        print("✓ Brute force detection complete")
        
        df = self.detect_ddos_patterns(df)
        print("✓ DDoS pattern detection complete")
        
        df = self.detect_data_exfiltration(df)
        print("✓ Data exfiltration detection complete")
        
        df = self.detect_suspicious_geographic_patterns(df)
        print("✓ Geographic anomaly detection complete")
        
        df = self.detect_privilege_escalation_attempts(df)
        print("✓ Privilege escalation detection complete")
        
        return df

