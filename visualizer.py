"""
Visualization and Reporting Module
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

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import os
from datetime import datetime


class SecurityLogVisualizer:
    """
    Create visualizations and reports for security log analysis.
    """
    
    def __init__(self, output_dir='reports'):
        """
        Initialize the visualizer.
        
        Args:
            output_dir (str): Directory to save visualizations
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Set style
        sns.set_style('whitegrid')
        plt.rcParams['figure.figsize'] = (12, 8)
        plt.rcParams['font.size'] = 10
    
    def plot_anomaly_distribution(self, df, save_path=None):
        """
        Plot anomaly distribution.
        
        Args:
            df (pd.DataFrame): Data with anomaly labels
            save_path (str): Path to save the plot
        """
        if 'is_anomaly' not in df.columns:
            print("No anomaly data found.")
            return
        
        fig, axes = plt.subplots(1, 2, figsize=(14, 6))
        
        # Count plot
        anomaly_counts = df['is_anomaly'].value_counts()
        axes[0].bar(['Normal', 'Anomaly'], 
                   [anomaly_counts.get(0, 0), anomaly_counts.get(1, 0)],
                   color=['green', 'red'])
        axes[0].set_title('Anomaly Distribution', fontsize=14, fontweight='bold')
        axes[0].set_ylabel('Count')
        axes[0].grid(axis='y', alpha=0.3)
        
        # Score distribution
        if 'anomaly_score' in df.columns:
            axes[1].hist(df['anomaly_score'], bins=50, color='orange', alpha=0.7)
            axes[1].axvline(df['anomaly_score'].mean(), color='red', 
                           linestyle='--', label=f'Mean: {df["anomaly_score"].mean():.3f}')
            axes[1].set_title('Anomaly Score Distribution', fontsize=14, fontweight='bold')
            axes[1].set_xlabel('Anomaly Score')
            axes[1].set_ylabel('Frequency')
            axes[1].legend()
            axes[1].grid(alpha=0.3)
        
        plt.tight_layout()
        
        # Add watermark
        fig.text(0.99, 0.01, 'RSK World - rskworld.in', 
                ha='right', va='bottom', fontsize=8, alpha=0.5)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Anomaly distribution plot saved: {save_path}")
        else:
            plt.savefig(os.path.join(self.output_dir, 'anomaly_distribution.png'), 
                       dpi=300, bbox_inches='tight')
        
        plt.close()
    
    def plot_incident_classification(self, df, save_path=None):
        """
        Plot incident classification results.
        
        Args:
            df (pd.DataFrame): Data with incident classifications
            save_path (str): Path to save the plot
        """
        if 'predicted_incident_type' not in df.columns:
            print("No incident classification data found.")
            return
        
        fig, axes = plt.subplots(1, 2, figsize=(14, 6))
        
        # Pie chart
        incident_counts = df['predicted_incident_type'].value_counts()
        colors = ['green', 'yellow', 'orange', 'red']
        axes[0].pie(incident_counts.values, labels=incident_counts.index, 
                   autopct='%1.1f%%', colors=colors[:len(incident_counts)],
                   startangle=90)
        axes[0].set_title('Incident Type Distribution', fontsize=14, fontweight='bold')
        
        # Bar chart
        incident_counts.plot(kind='bar', ax=axes[1], color=colors[:len(incident_counts)])
        axes[1].set_title('Incident Counts by Type', fontsize=14, fontweight='bold')
        axes[1].set_xlabel('Incident Type')
        axes[1].set_ylabel('Count')
        axes[1].tick_params(axis='x', rotation=45)
        axes[1].grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        
        # Add watermark
        fig.text(0.99, 0.01, 'RSK World - rskworld.in', 
                ha='right', va='bottom', fontsize=8, alpha=0.5)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Incident classification plot saved: {save_path}")
        else:
            plt.savefig(os.path.join(self.output_dir, 'incident_classification.png'), 
                       dpi=300, bbox_inches='tight')
        
        plt.close()
    
    def plot_time_series_analysis(self, df, save_path=None):
        """
        Plot time series analysis of security events.
        
        Args:
            df (pd.DataFrame): Data with timestamp
            save_path (str): Path to save the plot
        """
        if 'timestamp' not in df.columns:
            print("No timestamp data found.")
            return
        
        df = df.copy()
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        fig, axes = plt.subplots(2, 1, figsize=(14, 10))
        
        # Events over time
        df_hourly = df.set_index('timestamp').resample('1H').size()
        axes[0].plot(df_hourly.index, df_hourly.values, linewidth=2, color='blue')
        axes[0].set_title('Security Events Over Time', fontsize=14, fontweight='bold')
        axes[0].set_xlabel('Time')
        axes[0].set_ylabel('Number of Events')
        axes[0].grid(alpha=0.3)
        
        # Anomalies over time
        if 'is_anomaly' in df.columns:
            df_anomalies = df[df['is_anomaly'] == 1].set_index('timestamp').resample('1H').size()
            axes[1].plot(df_anomalies.index, df_anomalies.values, 
                        linewidth=2, color='red', label='Anomalies')
            axes[1].set_title('Anomalies Over Time', fontsize=14, fontweight='bold')
            axes[1].set_xlabel('Time')
            axes[1].set_ylabel('Number of Anomalies')
            axes[1].legend()
            axes[1].grid(alpha=0.3)
        
        plt.tight_layout()
        
        # Add watermark
        fig.text(0.99, 0.01, 'RSK World - rskworld.in', 
                ha='right', va='bottom', fontsize=8, alpha=0.5)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Time series plot saved: {save_path}")
        else:
            plt.savefig(os.path.join(self.output_dir, 'time_series_analysis.png'), 
                       dpi=300, bbox_inches='tight')
        
        plt.close()
    
    def plot_feature_importance(self, importance_df, save_path=None, top_n=15):
        """
        Plot feature importance.
        
        Args:
            importance_df (pd.DataFrame): Feature importance data
            save_path (str): Path to save the plot
            top_n (int): Number of top features to display
        """
        fig, ax = plt.subplots(figsize=(10, 8))
        
        top_features = importance_df.head(top_n)
        ax.barh(range(len(top_features)), top_features['importance'].values, color='steelblue')
        ax.set_yticks(range(len(top_features)))
        ax.set_yticklabels(top_features['feature'].values)
        ax.set_xlabel('Importance Score')
        ax.set_title(f'Top {top_n} Feature Importance', fontsize=14, fontweight='bold')
        ax.grid(axis='x', alpha=0.3)
        
        # Invert y-axis so most important is on top
        ax.invert_yaxis()
        
        plt.tight_layout()
        
        # Add watermark
        fig.text(0.99, 0.01, 'RSK World - rskworld.in', 
                ha='right', va='bottom', fontsize=8, alpha=0.5)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Feature importance plot saved: {save_path}")
        else:
            plt.savefig(os.path.join(self.output_dir, 'feature_importance.png'), 
                       dpi=300, bbox_inches='tight')
        
        plt.close()
    
    def plot_network_analysis(self, df, save_path=None):
        """
        Plot network traffic analysis.
        
        Args:
            df (pd.DataFrame): Data with network features
            save_path (str): Path to save the plot
        """
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        
        # Protocol distribution
        if 'protocol' in df.columns:
            protocol_counts = df['protocol'].value_counts()
            axes[0, 0].bar(protocol_counts.index, protocol_counts.values, color='teal')
            axes[0, 0].set_title('Protocol Distribution', fontsize=12, fontweight='bold')
            axes[0, 0].set_xlabel('Protocol')
            axes[0, 0].set_ylabel('Count')
            axes[0, 0].tick_params(axis='x', rotation=45)
            axes[0, 0].grid(axis='y', alpha=0.3)
        
        # Port distribution (top 10)
        if 'port' in df.columns:
            port_counts = df['port'].value_counts().head(10)
            axes[0, 1].bar(range(len(port_counts)), port_counts.values, color='coral')
            axes[0, 1].set_xticks(range(len(port_counts)))
            axes[0, 1].set_xticklabels(port_counts.index, rotation=45)
            axes[0, 1].set_title('Top 10 Ports', fontsize=12, fontweight='bold')
            axes[0, 1].set_xlabel('Port')
            axes[0, 1].set_ylabel('Count')
            axes[0, 1].grid(axis='y', alpha=0.3)
        
        # Bytes sent vs received
        if 'bytes_sent' in df.columns and 'bytes_received' in df.columns:
            axes[1, 0].scatter(df['bytes_sent'], df['bytes_received'], 
                             alpha=0.5, s=10, color='purple')
            axes[1, 0].set_title('Bytes Sent vs Received', fontsize=12, fontweight='bold')
            axes[1, 0].set_xlabel('Bytes Sent')
            axes[1, 0].set_ylabel('Bytes Received')
            axes[1, 0].grid(alpha=0.3)
        
        # Status code distribution
        if 'status_code' in df.columns:
            status_counts = df['status_code'].value_counts()
            axes[1, 1].bar(status_counts.index.astype(str), status_counts.values, color='gold')
            axes[1, 1].set_title('Status Code Distribution', fontsize=12, fontweight='bold')
            axes[1, 1].set_xlabel('Status Code')
            axes[1, 1].set_ylabel('Count')
            axes[1, 1].tick_params(axis='x', rotation=45)
            axes[1, 1].grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        
        # Add watermark
        fig.text(0.99, 0.01, 'RSK World - rskworld.in', 
                ha='right', va='bottom', fontsize=8, alpha=0.5)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Network analysis plot saved: {save_path}")
        else:
            plt.savefig(os.path.join(self.output_dir, 'network_analysis.png'), 
                       dpi=300, bbox_inches='tight')
        
        plt.close()
    
    def plot_threat_analysis(self, df, save_path=None):
        """
        Plot threat analysis results.
        
        Args:
            df (pd.DataFrame): Data with threat flags
            save_path (str): Path to save the plot
        """
        threat_columns = ['is_port_scan', 'is_brute_force', 'is_ddos', 
                         'is_data_exfiltration', 'is_geographic_anomaly', 
                         'is_privilege_escalation']
        
        available_threats = [col for col in threat_columns if col in df.columns]
        
        if not available_threats:
            print("No threat analysis data found.")
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        
        # Threat counts
        threat_counts = {col: df[col].sum() for col in available_threats}
        axes[0, 0].bar(range(len(threat_counts)), list(threat_counts.values()), color='crimson')
        axes[0, 0].set_xticks(range(len(threat_counts)))
        axes[0, 0].set_xticklabels([col.replace('is_', '').replace('_', ' ').title() 
                                    for col in threat_counts.keys()], rotation=45, ha='right')
        axes[0, 0].set_title('Threat Detection Summary', fontsize=12, fontweight='bold')
        axes[0, 0].set_ylabel('Count')
        axes[0, 0].grid(axis='y', alpha=0.3)
        
        # Threat percentages
        threat_percentages = {col: (df[col].sum() / len(df) * 100) for col in available_threats}
        axes[0, 1].bar(range(len(threat_percentages)), list(threat_percentages.values()), color='orange')
        axes[0, 1].set_xticks(range(len(threat_percentages)))
        axes[0, 1].set_xticklabels([col.replace('is_', '').replace('_', ' ').title() 
                                    for col in threat_percentages.keys()], rotation=45, ha='right')
        axes[0, 1].set_title('Threat Percentage Distribution', fontsize=12, fontweight='bold')
        axes[0, 1].set_ylabel('Percentage (%)')
        axes[0, 1].grid(axis='y', alpha=0.3)
        
        # Combined threat score
        if len(available_threats) > 0:
            df['total_threats'] = df[available_threats].sum(axis=1)
            threat_score_dist = df['total_threats'].value_counts().sort_index()
            axes[1, 0].bar(threat_score_dist.index, threat_score_dist.values, color='purple')
            axes[1, 0].set_title('Combined Threat Score Distribution', fontsize=12, fontweight='bold')
            axes[1, 0].set_xlabel('Number of Threat Types')
            axes[1, 0].set_ylabel('Count')
            axes[1, 0].grid(axis='y', alpha=0.3)
        
        # Top threat sources
        if 'source_ip' in df.columns:
            threat_sources = []
            for col in available_threats:
                threat_sources.extend(df[df[col] == 1]['source_ip'].tolist())
            
            if threat_sources:
                from collections import Counter
                source_counts = Counter(threat_sources)
                top_sources = dict(source_counts.most_common(10))
                axes[1, 1].bar(range(len(top_sources)), list(top_sources.values()), color='darkred')
                axes[1, 1].set_xticks(range(len(top_sources)))
                axes[1, 1].set_xticklabels(list(top_sources.keys()), rotation=45, ha='right')
                axes[1, 1].set_title('Top 10 Threat Sources', fontsize=12, fontweight='bold')
                axes[1, 1].set_ylabel('Threat Count')
                axes[1, 1].grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        
        # Add watermark
        fig.text(0.99, 0.01, 'RSK World - rskworld.in', 
                ha='right', va='bottom', fontsize=8, alpha=0.5)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Threat analysis plot saved: {save_path}")
        else:
            plt.savefig(os.path.join(self.output_dir, 'threat_analysis.png'), 
                       dpi=300, bbox_inches='tight')
        
        plt.close()
    
    def generate_summary_report(self, df, anomaly_summary, incident_summary, threat_intel=None, save_path=None):
        """
        Generate a text summary report.
        
        Args:
            df (pd.DataFrame): Analyzed data
            anomaly_summary (dict): Anomaly detection summary
            incident_summary (dict): Incident classification summary
            save_path (str): Path to save the report
        """
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("SECURITY LOG ANALYSIS REPORT")
        report_lines.append("=" * 80)
        report_lines.append("")
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Total Logs Analyzed: {len(df)}")
        report_lines.append("")
        report_lines.append("-" * 80)
        report_lines.append("ANOMALY DETECTION SUMMARY")
        report_lines.append("-" * 80)
        
        if anomaly_summary:
            for key, value in anomaly_summary.items():
                if isinstance(value, float):
                    report_lines.append(f"{key}: {value:.2f}")
                else:
                    report_lines.append(f"{key}: {value}")
        
        report_lines.append("")
        report_lines.append("-" * 80)
        report_lines.append("INCIDENT CLASSIFICATION SUMMARY")
        report_lines.append("-" * 80)
        
        if incident_summary:
            report_lines.append(f"Total Incidents: {incident_summary.get('total_incidents', 0)}")
            report_lines.append("")
            report_lines.append("Incident Counts:")
            for incident_type, count in incident_summary.get('incident_counts', {}).items():
                percentage = incident_summary.get('incident_percentages', {}).get(incident_type, 0)
                report_lines.append(f"  {incident_type}: {count} ({percentage:.2f}%)")
        
        report_lines.append("")
        report_lines.append("-" * 80)
        report_lines.append("ADVANCED THREAT ANALYSIS")
        report_lines.append("-" * 80)
        
        if threat_intel:
            report_lines.append(f"Total Threats Detected: {sum([v['count'] for v in threat_intel.get('threats_detected', {}).values()])}")
            report_lines.append("")
            report_lines.append("Threat Breakdown:")
            for threat_type, data in threat_intel.get('threats_detected', {}).items():
                report_lines.append(f"  {threat_type}: {data['count']} ({data['percentage']:.2f}%)")
            
            if 'top_threat_sources' in threat_intel:
                report_lines.append("")
                report_lines.append("Top Threat Sources:")
                for ip, count in list(threat_intel['top_threat_sources'].items())[:10]:
                    report_lines.append(f"  {ip}: {count} threats")
        
        report_lines.append("")
        report_lines.append("=" * 80)
        report_lines.append("Project by: Molla Samser (Founder) & Rima Khatun (Designer & Tester)")
        report_lines.append("Organization: RSK World")
        report_lines.append("Website: https://rskworld.in")
        report_lines.append("Contact: help@rskworld.in | +91 93305 39277")
        report_lines.append("=" * 80)
        
        report_text = "\n".join(report_lines)
        
        if save_path:
            with open(save_path, 'w') as f:
                f.write(report_text)
            print(f"Summary report saved: {save_path}")
        else:
            report_path = os.path.join(self.output_dir, 'analysis_summary.txt')
            with open(report_path, 'w') as f:
                f.write(report_text)
            print(f"Summary report saved: {report_path}")
        
        return report_text

