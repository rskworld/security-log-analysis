"""
Security Log Analysis with Machine Learning
Main Entry Point

Project by:
- Molla Samser (Founder)
- Rima Khatun (Designer & Tester)
RSK World - https://rskworld.in

Contact:
- Email: help@rskworld.in, support@rskworld.in
- Phone: +91 93305 39277
- Address: Nutanhat, Mongolkote, Purba Burdwan, West Bengal, India, 713147

Description:
This system analyzes security logs using machine learning to detect anomalies
and classify security incidents automatically.
"""

import pandas as pd
import numpy as np
import os
from datetime import datetime

# Import project modules
from log_parser import LogParser, generate_sample_logs
from feature_extractor import FeatureExtractor
from anomaly_detector import AnomalyDetector
from incident_classifier import IncidentClassifier
from visualizer import SecurityLogVisualizer
from advanced_analyzer import AdvancedAnalyzer
import config


def print_header():
    """Print application header."""
    print("=" * 80)
    print("SECURITY LOG ANALYSIS WITH MACHINE LEARNING")
    print("=" * 80)
    print("Project by: Molla Samser (Founder) & Rima Khatun (Designer & Tester)")
    print("Organization: RSK World")
    print("Website: https://rskworld.in")
    print("Contact: help@rskworld.in | +91 93305 39277")
    print("=" * 80)
    print()


def main():
    """Main function to run the security log analysis."""
    print_header()
    
    # Create necessary directories
    os.makedirs('data', exist_ok=True)
    os.makedirs('output', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    
    # Step 1: Generate or load sample data
    print("Step 1: Loading Security Logs...")
    print("-" * 80)
    
    # Check for main log file, then sample file, then generate new one
    if os.path.exists(config.LOG_FILE_PATH):
        log_file = config.LOG_FILE_PATH
        print(f"Using log file: {log_file}")
    elif os.path.exists(config.SAMPLE_LOG_FILE):
        log_file = config.SAMPLE_LOG_FILE
        print(f"Using sample data file: {log_file}")
    else:
        print(f"Sample data not found. Generating {config.LOG_FILE_PATH}...")
        generate_sample_logs(n_samples=1000, output_path=config.LOG_FILE_PATH)
        log_file = config.LOG_FILE_PATH
    
    # Initialize parser
    parser = LogParser()
    df = parser.parse_csv_logs(log_file)
    
    if df is None:
        print("Error: Failed to load log data.")
        return
    
    print(f"✓ Loaded {len(df)} log entries")
    print()
    
    # Step 2: Feature Extraction
    print("Step 2: Extracting Features...")
    print("-" * 80)
    
    extractor = FeatureExtractor()
    df = extractor.extract_all_features(df)
    X, _ = extractor.prepare_features_for_ml(df)
    
    print(f"✓ Extracted {len(X.columns)} features")
    print(f"  Features: {', '.join(X.columns[:5].tolist())}...")
    print()
    
    # Step 3: Anomaly Detection
    print("Step 3: Detecting Anomalies...")
    print("-" * 80)
    
    detector = AnomalyDetector(method='isolation_forest', contamination=config.ANOMALY_THRESHOLD)
    df = detector.detect_anomalies(df, X.columns.tolist())
    anomaly_summary = detector.get_anomaly_summary(df)
    
    print(f"✓ Anomaly Detection Complete")
    print(f"  Total Logs: {anomaly_summary.get('total_logs', 0)}")
    print(f"  Anomalies Detected: {anomaly_summary.get('anomalies', 0)}")
    print(f"  Anomaly Rate: {anomaly_summary.get('anomaly_percentage', 0):.2f}%")
    print()
    
    # Step 4: Incident Classification
    print("Step 4: Classifying Incidents...")
    print("-" * 80)
    
    classifier = IncidentClassifier()
    df = classifier.classify_incidents(df, X.columns.tolist())
    incident_summary = classifier.get_incident_summary(df)
    
    print(f"✓ Incident Classification Complete")
    print(f"  Total Incidents: {incident_summary.get('total_incidents', 0)}")
    for incident_type, count in incident_summary.get('incident_counts', {}).items():
        percentage = incident_summary.get('incident_percentages', {}).get(incident_type, 0)
        print(f"  {incident_type}: {count} ({percentage:.2f}%)")
    print()
    
    # Step 5: Advanced Threat Analysis
    print("Step 5: Running Advanced Threat Analysis...")
    print("-" * 80)
    
    advanced_analyzer = AdvancedAnalyzer()
    df = advanced_analyzer.analyze_all_threats(df)
    threat_intel = advanced_analyzer.generate_threat_intelligence(df)
    
    print("\n✓ Advanced Threat Analysis Complete")
    print("\nThreat Summary:")
    for threat_type, data in threat_intel.get('threats_detected', {}).items():
        print(f"  {threat_type}: {data['count']} ({data['percentage']:.2f}%)")
    
    if 'top_threat_sources' in threat_intel:
        print("\nTop Threat Sources:")
        for ip, count in list(threat_intel['top_threat_sources'].items())[:5]:
            print(f"  {ip}: {count} threats")
    print()
    
    # Step 6: Get Feature Importance
    print("Step 6: Analyzing Feature Importance...")
    print("-" * 80)
    
    importance_df = classifier.get_feature_importance()
    print("✓ Top 5 Most Important Features:")
    for idx, row in importance_df.head(5).iterrows():
        print(f"  {row['feature']}: {row['importance']:.4f}")
    print()
    
    # Step 7: Visualization and Reporting
    print("Step 7: Generating Visualizations and Reports...")
    print("-" * 80)
    
    visualizer = SecurityLogVisualizer(output_dir=config.REPORTS_DIR)
    
    # Generate all visualizations
    visualizer.plot_anomaly_distribution(df)
    visualizer.plot_incident_classification(df)
    visualizer.plot_time_series_analysis(df)
    visualizer.plot_feature_importance(importance_df)
    visualizer.plot_network_analysis(df)
    visualizer.plot_threat_analysis(df)
    
    # Generate summary report
    report_text = visualizer.generate_summary_report(df, anomaly_summary, incident_summary, threat_intel)
    
    print("✓ All visualizations saved to:", config.REPORTS_DIR)
    print()
    
    # Step 8: Save processed data
    print("Step 8: Saving Results...")
    print("-" * 80)
    
    output_file = os.path.join(config.OUTPUT_DIR, 'analyzed_logs.csv')
    df.to_csv(output_file, index=False)
    print(f"✓ Analyzed data saved to: {output_file}")
    
    # Save top anomalies
    if 'is_anomaly' in df.columns:
        anomalies = df[df['is_anomaly'] == 1].sort_values('anomaly_score', ascending=False)
        anomaly_file = os.path.join(config.OUTPUT_DIR, 'detected_anomalies.csv')
        anomalies.to_csv(anomaly_file, index=False)
        print(f"✓ Detected anomalies saved to: {anomaly_file}")
    
    # Save critical incidents
    if 'predicted_incident_type' in df.columns:
        critical = df[df['predicted_incident_type'] == 'Critical']
        critical_file = os.path.join(config.OUTPUT_DIR, 'critical_incidents.csv')
        critical.to_csv(critical_file, index=False)
        print(f"✓ Critical incidents saved to: {critical_file}")
    
    print()
    print("=" * 80)
    print("ANALYSIS COMPLETE!")
    print("=" * 80)
    print()
    print("Summary Report:")
    print(report_text)
    print()
    print("Thank you for using RSK World Security Log Analysis System!")
    print("For support: help@rskworld.in | +91 93305 39277")
    print("Visit us: https://rskworld.in")
    print("=" * 80)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user.")
    except Exception as e:
        print(f"\n\nError: {str(e)}")
        print("For support, contact: help@rskworld.in")

