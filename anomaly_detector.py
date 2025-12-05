"""
Anomaly Detection Module
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

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')


class AnomalyDetector:
    """
    Detect anomalies in security logs using machine learning.
    """
    
    def __init__(self, method='isolation_forest', contamination=0.1):
        """
        Initialize the anomaly detector.
        
        Args:
            method (str): Detection method ('isolation_forest' or 'dbscan')
            contamination (float): Expected proportion of anomalies
        """
        self.method = method
        self.contamination = contamination
        self.model = None
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def fit(self, X):
        """
        Fit the anomaly detection model.
        
        Args:
            X (pd.DataFrame or np.array): Training features
        """
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        if self.method == 'isolation_forest':
            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100
            )
            self.model.fit(X_scaled)
        
        elif self.method == 'dbscan':
            self.model = DBSCAN(eps=0.5, min_samples=5)
            self.model.fit(X_scaled)
        
        self.is_fitted = True
    
    def predict(self, X):
        """
        Predict anomalies in the data.
        
        Args:
            X (pd.DataFrame or np.array): Features to predict
            
        Returns:
            np.array: Anomaly predictions (-1 for anomaly, 1 for normal)
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction.")
        
        X_scaled = self.scaler.transform(X)
        
        if self.method == 'isolation_forest':
            predictions = self.model.predict(X_scaled)
            # Convert to binary: -1 -> 1 (anomaly), 1 -> 0 (normal)
            anomaly_labels = (predictions == -1).astype(int)
        
        elif self.method == 'dbscan':
            predictions = self.model.fit_predict(X_scaled)
            # DBSCAN: -1 is noise/anomaly, others are clusters
            anomaly_labels = (predictions == -1).astype(int)
        
        return anomaly_labels
    
    def predict_proba(self, X):
        """
        Get anomaly scores (higher = more anomalous).
        
        Args:
            X (pd.DataFrame or np.array): Features to predict
            
        Returns:
            np.array: Anomaly scores
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction.")
        
        if self.method != 'isolation_forest':
            # For DBSCAN, use distance to nearest cluster
            X_scaled = self.scaler.transform(X)
            predictions = self.model.fit_predict(X_scaled)
            # Simple scoring: -1 (anomaly) = 1.0, others = 0.0
            scores = (predictions == -1).astype(float)
            return scores
        
        X_scaled = self.scaler.transform(X)
        # Isolation Forest returns negative scores (more negative = more anomalous)
        scores = -self.model.score_samples(X_scaled)
        # Normalize to 0-1 range
        scores = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
        return scores
    
    def detect_anomalies(self, df, feature_columns):
        """
        Detect anomalies in a DataFrame.
        
        Args:
            df (pd.DataFrame): Log data with features
            feature_columns (list): List of feature column names
            
        Returns:
            pd.DataFrame: Data with anomaly labels and scores
        """
        X = df[feature_columns].fillna(0)
        
        # Fit if not already fitted
        if not self.is_fitted:
            self.fit(X)
        
        # Predict anomalies
        anomaly_labels = self.predict(X)
        anomaly_scores = self.predict_proba(X)
        
        # Add to dataframe
        df_result = df.copy()
        df_result['is_anomaly'] = anomaly_labels
        df_result['anomaly_score'] = anomaly_scores
        
        return df_result
    
    def get_anomaly_summary(self, df):
        """
        Get summary statistics of detected anomalies.
        
        Args:
            df (pd.DataFrame): Data with anomaly labels
            
        Returns:
            dict: Summary statistics
        """
        if 'is_anomaly' not in df.columns:
            return {}
        
        total = len(df)
        anomalies = df['is_anomaly'].sum()
        normal = total - anomalies
        
        summary = {
            'total_logs': total,
            'anomalies': int(anomalies),
            'normal': int(normal),
            'anomaly_percentage': (anomalies / total * 100) if total > 0 else 0
        }
        
        if 'anomaly_score' in df.columns:
            summary['avg_anomaly_score'] = float(df['anomaly_score'].mean())
            summary['max_anomaly_score'] = float(df['anomaly_score'].max())
        
        return summary

