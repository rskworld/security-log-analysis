"""
Incident Classification Module
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder
import warnings
warnings.filterwarnings('ignore')


class IncidentClassifier:
    """
    Classify security incidents by type and severity.
    """
    
    def __init__(self):
        """Initialize the incident classifier."""
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.label_encoder = LabelEncoder()
        self.is_fitted = False
        self.feature_names = []
    
    def create_labels(self, df):
        """
        Create incident labels based on log features.
        
        Args:
            df (pd.DataFrame): Log data with features
            
        Returns:
            pd.DataFrame: Data with incident labels
        """
        df = df.copy()
        
        # Initialize incident type
        df['incident_type'] = 'Normal'
        
        # Define rules for incident classification
        # Suspicious activity
        suspicious_mask = (
            (df.get('is_error_status', 0) == 1) |
            (df.get('is_weekend', 0) == 1) & (df.get('is_business_hours', 0) == 0) |
            (df.get('bytes_sent', 0) > df.get('bytes_sent', 0).quantile(0.9))
        )
        df.loc[suspicious_mask, 'incident_type'] = 'Suspicious'
        
        # Malicious activity
        malicious_mask = (
            (df.get('action', '') == 'BLOCK') |
            (df.get('status_code', 0) == 403) |
            (df.get('is_anomaly', 0) == 1)
        )
        df.loc[malicious_mask, 'incident_type'] = 'Malicious'
        
        # Critical activity
        critical_mask = (
            (df.get('action', '') == 'DENY') |
            (df.get('anomaly_score', 0) > 0.8) |
            (df.get('status_code', 0) == 500)
        )
        df.loc[critical_mask, 'incident_type'] = 'Critical'
        
        return df
    
    def train(self, X, y):
        """
        Train the incident classifier.
        
        Args:
            X (pd.DataFrame or np.array): Training features
            y (pd.Series or np.array): Target labels
        """
        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Store feature names
        if isinstance(X, pd.DataFrame):
            self.feature_names = X.columns.tolist()
        
        # Train model
        self.model.fit(X, y_encoded)
        self.is_fitted = True
        
        # Calculate training accuracy
        train_pred = self.model.predict(X)
        train_accuracy = accuracy_score(y_encoded, train_pred)
        print(f"Training Accuracy: {train_accuracy:.4f}")
    
    def predict(self, X):
        """
        Predict incident types.
        
        Args:
            X (pd.DataFrame or np.array): Features to predict
            
        Returns:
            np.array: Predicted incident types
        """
        if not self.is_fitted:
            raise ValueError("Model must be trained before prediction.")
        
        y_pred_encoded = self.model.predict(X)
        y_pred = self.label_encoder.inverse_transform(y_pred_encoded)
        return y_pred
    
    def predict_proba(self, X):
        """
        Predict probabilities for each incident type.
        
        Args:
            X (pd.DataFrame or np.array): Features to predict
            
        Returns:
            np.array: Predicted probabilities
        """
        if not self.is_fitted:
            raise ValueError("Model must be trained before prediction.")
        
        return self.model.predict_proba(X)
    
    def evaluate(self, X_test, y_test):
        """
        Evaluate the classifier on test data.
        
        Args:
            X_test (pd.DataFrame or np.array): Test features
            y_test (pd.Series or np.array): True labels
            
        Returns:
            dict: Evaluation metrics
        """
        y_test_encoded = self.label_encoder.transform(y_test)
        y_pred_encoded = self.model.predict(X_test)
        
        accuracy = accuracy_score(y_test_encoded, y_pred_encoded)
        conf_matrix = confusion_matrix(y_test_encoded, y_pred_encoded)
        
        # Get classification report
        y_pred = self.label_encoder.inverse_transform(y_pred_encoded)
        report = classification_report(y_test, y_pred, output_dict=True)
        
        results = {
            'accuracy': accuracy,
            'confusion_matrix': conf_matrix,
            'classification_report': report
        }
        
        return results
    
    def get_feature_importance(self):
        """
        Get feature importance scores.
        
        Returns:
            pd.DataFrame: Feature importance rankings
        """
        if not self.is_fitted:
            raise ValueError("Model must be trained first.")
        
        importances = self.model.feature_importances_
        
        if self.feature_names:
            importance_df = pd.DataFrame({
                'feature': self.feature_names,
                'importance': importances
            })
        else:
            importance_df = pd.DataFrame({
                'feature': [f'feature_{i}' for i in range(len(importances))],
                'importance': importances
            })
        
        importance_df = importance_df.sort_values('importance', ascending=False)
        return importance_df
    
    def classify_incidents(self, df, feature_columns):
        """
        Classify incidents in a DataFrame.
        
        Args:
            df (pd.DataFrame): Log data with features
            feature_columns (list): List of feature column names
            
        Returns:
            pd.DataFrame: Data with incident classifications
        """
        X = df[feature_columns].fillna(0)
        
        if not self.is_fitted:
            # Create labels and train
            df_labeled = self.create_labels(df)
            y = df_labeled['incident_type']
            self.train(X, y)
        
        # Predict
        predictions = self.predict(X)
        probabilities = self.predict_proba(X)
        
        # Add to dataframe
        df_result = df.copy()
        df_result['predicted_incident_type'] = predictions
        
        # Add probability columns
        for i, class_name in enumerate(self.label_encoder.classes_):
            df_result[f'prob_{class_name}'] = probabilities[:, i]
        
        return df_result
    
    def get_incident_summary(self, df):
        """
        Get summary of classified incidents.
        
        Args:
            df (pd.DataFrame): Data with incident classifications
            
        Returns:
            dict: Incident summary
        """
        if 'predicted_incident_type' not in df.columns:
            return {}
        
        incident_counts = df['predicted_incident_type'].value_counts().to_dict()
        total = len(df)
        
        summary = {
            'total_incidents': total,
            'incident_counts': incident_counts,
            'incident_percentages': {
                k: (v / total * 100) for k, v in incident_counts.items()
            }
        }
        
        return summary

