"""
Feature Extraction Module
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
from sklearn.preprocessing import LabelEncoder, StandardScaler
from datetime import datetime


class FeatureExtractor:
    """
    Extract meaningful features from security logs for machine learning.
    """
    
    def __init__(self):
        """Initialize the feature extractor."""
        self.label_encoders = {}
        self.scaler = StandardScaler()
        self.feature_columns = []
    
    def extract_time_features(self, df, timestamp_column='timestamp'):
        """
        Extract time-based features from timestamp.
        
        Args:
            df (pd.DataFrame): Log data
            timestamp_column (str): Name of timestamp column
            
        Returns:
            pd.DataFrame: Data with time features
        """
        if timestamp_column not in df.columns:
            return df
        
        df = df.copy()
        df[timestamp_column] = pd.to_datetime(df[timestamp_column])
        
        # Extract time features
        df['hour'] = df[timestamp_column].dt.hour
        df['day_of_week'] = df[timestamp_column].dt.dayofweek
        df['day_of_month'] = df[timestamp_column].dt.day
        df['month'] = df[timestamp_column].dt.month
        df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        df['is_business_hours'] = ((df['hour'] >= 9) & (df['hour'] <= 17)).astype(int)
        
        return df
    
    def extract_statistical_features(self, df, numeric_columns):
        """
        Extract statistical features from numeric columns.
        
        Args:
            df (pd.DataFrame): Log data
            numeric_columns (list): List of numeric column names
            
        Returns:
            pd.DataFrame: Data with statistical features
        """
        df = df.copy()
        
        for col in numeric_columns:
            if col in df.columns:
                # Rolling statistics
                df[f'{col}_rolling_mean'] = df[col].rolling(window=10, min_periods=1).mean()
                df[f'{col}_rolling_std'] = df[col].rolling(window=10, min_periods=1).std()
                
                # Z-score
                mean_val = df[col].mean()
                std_val = df[col].std()
                if std_val > 0:
                    df[f'{col}_zscore'] = (df[col] - mean_val) / std_val
                else:
                    df[f'{col}_zscore'] = 0
        
        return df
    
    def encode_categorical_features(self, df, categorical_columns):
        """
        Encode categorical features using label encoding.
        
        Args:
            df (pd.DataFrame): Log data
            categorical_columns (list): List of categorical column names
            
        Returns:
            pd.DataFrame: Data with encoded features
        """
        df = df.copy()
        
        for col in categorical_columns:
            if col in df.columns:
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder()
                    df[col + '_encoded'] = self.label_encoders[col].fit_transform(df[col].astype(str))
                else:
                    # Handle unseen categories
                    try:
                        df[col + '_encoded'] = self.label_encoders[col].transform(df[col].astype(str))
                    except ValueError:
                        # If new categories found, refit
                        self.label_encoders[col] = LabelEncoder()
                        df[col + '_encoded'] = self.label_encoders[col].fit_transform(df[col].astype(str))
        
        return df
    
    def extract_network_features(self, df):
        """
        Extract network-specific features with enhanced capabilities.
        
        Args:
            df (pd.DataFrame): Log data
            
        Returns:
            pd.DataFrame: Data with network features
        """
        df = df.copy()
        
        # Connection rate features
        if 'source_ip' in df.columns:
            df['connections_per_source'] = df.groupby('source_ip')['source_ip'].transform('count')
            df['unique_destinations_per_source'] = df.groupby('source_ip')['destination_ip'].transform('nunique')
            df['unique_ports_per_source'] = df.groupby('source_ip')['port'].transform('nunique')
        
        if 'destination_ip' in df.columns:
            df['connections_per_destination'] = df.groupby('destination_ip')['destination_ip'].transform('count')
            df['unique_sources_per_destination'] = df.groupby('destination_ip')['source_ip'].transform('nunique')
        
        # Port-based features
        if 'port' in df.columns:
            df['is_common_port'] = df['port'].isin([80, 443, 22, 21, 25, 53, 3306, 5432, 8080, 3389]).astype(int)
            df['is_high_port'] = (df['port'] > 1024).astype(int)
            df['is_privileged_port'] = (df['port'] < 1024).astype(int)
            df['port_category'] = pd.cut(df['port'], bins=[0, 1024, 49152, 65535], labels=[0, 1, 2])
            df['port_category'] = df['port_category'].astype(int)
        
        # Protocol-based features
        if 'protocol' in df.columns:
            df['is_secure_protocol'] = df['protocol'].isin(['HTTPS', 'SSH', 'FTPS']).astype(int)
            df['is_web_protocol'] = df['protocol'].isin(['HTTP', 'HTTPS']).astype(int)
            df['is_application_protocol'] = df['protocol'].isin(['HTTP', 'HTTPS', 'FTP', 'SMTP']).astype(int)
        
        # Traffic features
        if 'bytes_sent' in df.columns and 'bytes_received' in df.columns:
            df['total_bytes'] = df['bytes_sent'] + df['bytes_received']
            df['bytes_ratio'] = df['bytes_sent'] / (df['bytes_received'] + 1)  # +1 to avoid division by zero
            df['bytes_difference'] = abs(df['bytes_sent'] - df['bytes_received'])
            df['is_large_transfer'] = (df['total_bytes'] > 1000000).astype(int)
            df['is_small_transfer'] = (df['total_bytes'] < 1000).astype(int)
        
        # Status code features
        if 'status_code' in df.columns:
            df['is_error_status'] = (df['status_code'] >= 400).astype(int)
            df['is_success_status'] = ((df['status_code'] >= 200) & (df['status_code'] < 300)).astype(int)
            df['is_redirect_status'] = ((df['status_code'] >= 300) & (df['status_code'] < 400)).astype(int)
            df['is_server_error'] = (df['status_code'] >= 500).astype(int)
            df['is_client_error'] = ((df['status_code'] >= 400) & (df['status_code'] < 500)).astype(int)
            df['status_code_category'] = pd.cut(df['status_code'], 
                                               bins=[0, 200, 300, 400, 500, 600], 
                                               labels=[0, 1, 2, 3, 4])
            df['status_code_category'] = df['status_code_category'].astype(int)
        
        # Request method features
        if 'request_method' in df.columns:
            df['is_write_method'] = df['request_method'].isin(['POST', 'PUT', 'DELETE']).astype(int)
            df['is_read_method'] = df['request_method'].isin(['GET', 'HEAD', 'OPTIONS']).astype(int)
        
        # Response time features
        if 'response_time' in df.columns:
            df['is_slow_response'] = (df['response_time'] > 1.0).astype(int)
            df['is_fast_response'] = (df['response_time'] < 0.1).astype(int)
            df['response_time_category'] = pd.cut(df['response_time'], 
                                                bins=[0, 0.1, 0.5, 1.0, 5.0, 100], 
                                                labels=[0, 1, 2, 3, 4])
            df['response_time_category'] = df['response_time_category'].astype(int)
        
        # User agent features
        if 'user_agent' in df.columns:
            df['is_bot'] = df['user_agent'].str.contains('Bot', case=False, na=False).astype(int)
            df['is_browser'] = df['user_agent'].str.contains('Mozilla|Chrome|Firefox|Safari', case=False, na=False).astype(int)
            df['is_api_client'] = df['user_agent'].str.contains('API', case=False, na=False).astype(int)
        
        # Session features
        if 'session_id' in df.columns:
            df['has_session'] = (df['session_id'] != '').astype(int)
            if df['has_session'].sum() > 0:
                df['session_count'] = df.groupby('session_id')['session_id'].transform('count')
            else:
                df['session_count'] = 0
        
        # Geographic features
        if 'country' in df.columns:
            df['connections_per_country'] = df.groupby('country')['country'].transform('count')
        
        # Threat level features
        if 'threat_level' in df.columns:
            threat_mapping = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
            df['threat_level_numeric'] = df['threat_level'].map(threat_mapping).fillna(0)
        
        # Duration features
        if 'duration' in df.columns:
            df['is_long_connection'] = (df['duration'] > 10.0).astype(int)
            df['is_short_connection'] = (df['duration'] < 0.1).astype(int)
            df['duration_category'] = pd.cut(df['duration'], 
                                            bins=[0, 0.1, 1.0, 5.0, 10.0, 100], 
                                            labels=[0, 1, 2, 3, 4])
            df['duration_category'] = df['duration_category'].astype(int)
        
        # Rate-based features (connections per time window)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df = df.sort_values('timestamp')
            
            # Connections in last hour
            df['connections_last_hour'] = 0
            for idx in range(len(df)):
                time_window = df.iloc[idx]['timestamp'] - pd.Timedelta(hours=1)
                mask = (df['timestamp'] >= time_window) & (df['timestamp'] <= df.iloc[idx]['timestamp'])
                df.iloc[idx, df.columns.get_loc('connections_last_hour')] = mask.sum()
            
            # Connections from same source in last hour
            if 'source_ip' in df.columns:
                df['same_source_connections_last_hour'] = 0
                for idx in range(len(df)):
                    source_ip = df.iloc[idx]['source_ip']
                    time_window = df.iloc[idx]['timestamp'] - pd.Timedelta(hours=1)
                    mask = ((df['timestamp'] >= time_window) & 
                           (df['timestamp'] <= df.iloc[idx]['timestamp']) &
                           (df['source_ip'] == source_ip))
                    df.iloc[idx, df.columns.get_loc('same_source_connections_last_hour')] = mask.sum()
        
        return df
    
    def extract_all_features(self, df):
        """
        Extract all features from log data.
        
        Args:
            df (pd.DataFrame): Preprocessed log data
            
        Returns:
            pd.DataFrame: Data with all extracted features
        """
        # Time features
        df = self.extract_time_features(df)
        
        # Network features
        df = self.extract_network_features(df)
        
        # Statistical features for numeric columns
        numeric_cols = ['bytes_sent', 'bytes_received', 'duration', 'port']
        numeric_cols = [col for col in numeric_cols if col in df.columns]
        if numeric_cols:
            df = self.extract_statistical_features(df, numeric_cols)
        
        # Encode categorical features
        categorical_cols = ['protocol', 'action']
        categorical_cols = [col for col in categorical_cols if col in df.columns]
        if categorical_cols:
            df = self.encode_categorical_features(df, categorical_cols)
        
        # Fill NaN values
        df = df.fillna(0)
        
        return df
    
    def prepare_features_for_ml(self, df, target_column=None):
        """
        Prepare features for machine learning models.
        
        Args:
            df (pd.DataFrame): Data with extracted features
            target_column (str): Optional target column name
            
        Returns:
            tuple: (X, y) where X is features and y is target (if provided)
        """
        # Select numeric columns for ML
        feature_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        
        # Remove target column if present
        if target_column and target_column in feature_cols:
            feature_cols.remove(target_column)
        
        # Remove timestamp if present (already extracted time features)
        if 'timestamp' in feature_cols:
            feature_cols.remove('timestamp')
        
        # Store feature columns
        self.feature_columns = feature_cols
        
        X = df[feature_cols].fillna(0)
        
        if target_column and target_column in df.columns:
            y = df[target_column]
            return X, y
        
        return X, None
    
    def scale_features(self, X, fit=True):
        """
        Scale features using StandardScaler.
        
        Args:
            X (pd.DataFrame or np.array): Features
            fit (bool): Whether to fit the scaler
            
        Returns:
            np.array: Scaled features
        """
        if fit:
            return self.scaler.fit_transform(X)
        else:
            return self.scaler.transform(X)

