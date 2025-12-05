"""
Configuration file for Security Log Analysis with ML
Project by Molla Samser (Founder) & Rima Khatun (Designer & Tester)
RSK World - https://rskworld.in
Contact: help@rskworld.in, support@rskworld.in
Phone: +91 93305 39277
Address: Nutanhat, Mongolkote, Purba Burdwan, West Bengal, India, 713147
"""

# Log file paths
# Use sample file if main file doesn't exist
LOG_FILE_PATH = 'data/security_logs.csv'
SAMPLE_LOG_FILE = 'data/security_logs_sample.csv'  # Small sample for quick testing
OUTPUT_DIR = 'output'
REPORTS_DIR = 'reports'

# Feature extraction settings
FEATURE_COLUMNS = [
    'timestamp',
    'source_ip',
    'destination_ip',
    'port',
    'protocol',
    'action',
    'status_code',
    'bytes_sent',
    'bytes_received',
    'duration',
    'user_agent',
    'request_method',
    'response_time',
    'country',
    'session_id',
    'threat_level'
]

# Anomaly detection settings
ANOMALY_THRESHOLD = 0.1  # 10% of data considered anomalous
RANDOM_STATE = 42

# Classification settings
INCIDENT_TYPES = [
    'Normal',
    'Suspicious',
    'Malicious',
    'Critical'
]

# Visualization settings
FIGURE_SIZE = (12, 8)
DPI = 100

# Model settings
TRAIN_TEST_SPLIT = 0.2
CROSS_VALIDATION_FOLDS = 5

