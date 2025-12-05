"""
Log Parser and Preprocessing Module
Security Log Analysis with ML

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
from datetime import datetime
import re
import os


class LogParser:
    """
    Parse and preprocess security logs from various formats.
    """
    
    def __init__(self):
        """Initialize the log parser."""
        pass
    
    def parse_csv_logs(self, file_path):
        """
        Parse security logs from CSV file.
        
        Args:
            file_path (str): Path to the CSV log file
            
        Returns:
            pd.DataFrame: Parsed log data
        """
        try:
            df = pd.read_csv(file_path)
            return self.preprocess(df)
        except FileNotFoundError:
            print(f"Error: File {file_path} not found.")
            return None
        except Exception as e:
            print(f"Error parsing CSV: {str(e)}")
            return None
    
    def preprocess(self, df):
        """
        Preprocess the log data.
        
        Args:
            df (pd.DataFrame): Raw log data
            
        Returns:
            pd.DataFrame: Preprocessed log data
        """
        # Make a copy to avoid modifying original
        df = df.copy()
        
        # Convert timestamp to datetime if it exists
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        
        # Fill missing values
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        df[numeric_columns] = df[numeric_columns].fillna(df[numeric_columns].median())
        
        # Fill categorical missing values
        categorical_columns = df.select_dtypes(include=['object']).columns
        df[categorical_columns] = df[categorical_columns].fillna('Unknown')
        
        # Remove duplicates
        df = df.drop_duplicates()
        
        # Remove rows with invalid timestamps
        if 'timestamp' in df.columns:
            df = df.dropna(subset=['timestamp'])
        
        return df
    
    def extract_ip_features(self, df, ip_column='source_ip'):
        """
        Extract features from IP addresses.
        
        Args:
            df (pd.DataFrame): Log data
            ip_column (str): Name of IP address column
            
        Returns:
            pd.DataFrame: Data with extracted IP features
        """
        if ip_column not in df.columns:
            return df
        
        df = df.copy()
        
        # Extract IP octets
        def extract_octets(ip):
            try:
                parts = str(ip).split('.')
                if len(parts) == 4:
                    return [int(parts[i]) for i in range(4)]
                return [0, 0, 0, 0]
            except:
                return [0, 0, 0, 0]
        
        octets = df[ip_column].apply(lambda x: pd.Series(extract_octets(x)))
        for i in range(4):
            df[f'{ip_column}_octet_{i+1}'] = octets[i]
        
        return df
    
    def normalize_logs(self, df):
        """
        Normalize log data for machine learning.
        
        Args:
            df (pd.DataFrame): Preprocessed log data
            
        Returns:
            pd.DataFrame: Normalized log data
        """
        df = df.copy()
        
        # Normalize numeric columns
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        for col in numeric_columns:
            if df[col].std() > 0:
                df[col] = (df[col] - df[col].mean()) / df[col].std()
        
        return df


def generate_sample_logs(n_samples=1000, output_path='data/security_logs.csv'):
    """
    Generate enhanced sample security logs for testing with more realistic features.
    
    Args:
        n_samples (int): Number of log entries to generate
        output_path (str): Output file path
    """
    np.random.seed(42)
    
    # Create data directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    
    # Generate timestamps with varying frequencies (more activity during business hours)
    base_timestamps = pd.date_range(start='2024-01-01', periods=n_samples, freq='30min')
    timestamps = []
    for ts in base_timestamps[:n_samples]:
        # Add some randomness
        if np.random.random() < 0.3:  # 30% chance to skip some timestamps
            continue
        timestamps.append(ts)
    
    # Ensure we have enough timestamps
    while len(timestamps) < n_samples:
        timestamps.append(timestamps[-1] + pd.Timedelta(minutes=np.random.randint(1, 60)))
    
    timestamps = timestamps[:n_samples]
    
    # Generate realistic IP addresses (some common, some random)
    def generate_ip(common=False):
        if common and np.random.random() < 0.3:
            # Common internal IP ranges
            return f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
        elif common and np.random.random() < 0.5:
            return f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
        else:
            return f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
    
    # Generate source IPs (some repeat for connection patterns)
    source_ip_pool = [generate_ip(common=True) for _ in range(50)]
    source_ips = np.random.choice(source_ip_pool, n_samples, p=[0.3] + [0.7/49]*49)
    
    # Generate destination IPs
    dest_ips = [generate_ip() for _ in range(n_samples)]
    
    # Generate realistic ports (common ports more frequent)
    common_ports = [80, 443, 22, 21, 25, 53, 3306, 5432, 8080, 3389, 1433, 1521]
    ports = []
    for _ in range(n_samples):
        if np.random.random() < 0.6:  # 60% common ports
            ports.append(np.random.choice(common_ports))
        else:
            ports.append(np.random.randint(1024, 65535))
    
    # Generate protocols with realistic distribution
    protocols = np.random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS', 'SSH', 'FTP', 'SMTP', 'DNS'], 
                                n_samples, p=[0.25, 0.15, 0.20, 0.20, 0.05, 0.05, 0.05, 0.05])
    
    # Generate actions with realistic distribution
    actions = np.random.choice(['ALLOW', 'DENY', 'BLOCK', 'LOG'], n_samples, p=[0.65, 0.15, 0.10, 0.10])
    
    # Generate status codes with realistic HTTP status distribution
    status_codes = np.random.choice([200, 201, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503], 
                                   n_samples, p=[0.50, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.10, 0.02, 0.02, 0.01])
    
    # Generate bytes with realistic patterns (some large transfers, mostly small)
    bytes_sent = []
    bytes_received = []
    for _ in range(n_samples):
        if np.random.random() < 0.1:  # 10% large transfers
            bytes_sent.append(np.random.randint(100000, 10000000))
            bytes_received.append(np.random.randint(100000, 10000000))
        else:  # 90% normal traffic
            bytes_sent.append(np.random.randint(100, 100000))
            bytes_received.append(np.random.randint(100, 100000))
    
    # Generate duration with realistic patterns
    duration = np.random.exponential(2.0, n_samples)  # Exponential distribution
    duration = np.clip(duration, 0.01, 30.0)  # Clip to reasonable range
    
    # Generate additional features
    user_agents = ['Mozilla/5.0', 'Chrome/120.0', 'Firefox/121.0', 'Safari/17.0', 'Bot/1.0', 'API-Client/2.0']
    user_agent = np.random.choice(user_agents, n_samples, p=[0.25, 0.25, 0.20, 0.15, 0.10, 0.05])
    
    # Request methods
    request_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
    request_method = np.random.choice(request_methods, n_samples, p=[0.60, 0.25, 0.05, 0.03, 0.05, 0.02])
    
    # Response times (correlated with status codes)
    response_times = []
    for sc in status_codes:
        if sc >= 500:  # Server errors take longer
            response_times.append(np.random.uniform(1.0, 5.0))
        elif sc >= 400:  # Client errors
            response_times.append(np.random.uniform(0.1, 1.0))
        else:  # Success
            response_times.append(np.random.uniform(0.01, 0.5))
    
    # Geographic data (simplified)
    countries = ['US', 'IN', 'GB', 'DE', 'FR', 'CN', 'JP', 'BR', 'AU', 'CA']
    country = np.random.choice(countries, n_samples, p=[0.30, 0.15, 0.10, 0.08, 0.08, 0.08, 0.05, 0.05, 0.05, 0.06])
    
    # Session IDs (some connections have sessions)
    session_ids = []
    for _ in range(n_samples):
        if np.random.random() < 0.4:  # 40% have session IDs
            session_ids.append(f"SESS{np.random.randint(100000, 999999)}")
        else:
            session_ids.append('')
    
    # Threat level (for testing classification)
    threat_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    threat_level = np.random.choice(threat_levels, n_samples, p=[0.70, 0.20, 0.08, 0.02])
    
    # Create DataFrame
    df = pd.DataFrame({
        'timestamp': timestamps,
        'source_ip': source_ips,
        'destination_ip': dest_ips,
        'port': ports,
        'protocol': protocols,
        'action': actions,
        'status_code': status_codes,
        'bytes_sent': bytes_sent,
        'bytes_received': bytes_received,
        'duration': duration,
        'user_agent': user_agent,
        'request_method': request_method,
        'response_time': response_times,
        'country': country,
        'session_id': session_ids,
        'threat_level': threat_level
    })
    
    # Add some anomalies manually for better testing
    anomaly_indices = np.random.choice(n_samples, size=int(n_samples * 0.1), replace=False)
    for idx in anomaly_indices:
        # Make some entries more suspicious
        if np.random.random() < 0.5:
            df.loc[idx, 'action'] = 'DENY'
            df.loc[idx, 'status_code'] = 403
        else:
            df.loc[idx, 'bytes_sent'] = np.random.randint(1000000, 10000000)
            df.loc[idx, 'threat_level'] = np.random.choice(['HIGH', 'CRITICAL'])
    
    # Save to CSV
    df.to_csv(output_path, index=False)
    print(f"Enhanced sample logs generated: {output_path}")
    print(f"Total entries: {len(df)}")
    print(f"Features: {len(df.columns)}")
    return df


if __name__ == '__main__':
    # Generate sample data
    generate_sample_logs(n_samples=1000)

