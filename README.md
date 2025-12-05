# Security Log Analysis with ML

Machine learning system to analyze security logs and identify security incidents automatically.

## Project Description

This project develops an automated security log analysis system that processes security event logs, identifies patterns, and detects security incidents using machine learning. It helps security analysts prioritize threats and respond quickly.

## Features

- **Log Parsing and Preprocessing**: Parse various security log formats and clean the data
- **Enhanced Feature Extraction**: Extract 50+ features including time-based, network, statistical, and behavioral features
- **Anomaly Detection**: Identify unusual patterns and potential security threats using Isolation Forest
- **Incident Classification**: Classify security incidents by type and severity (Normal, Suspicious, Malicious, Critical)
- **Advanced Threat Detection**: 
  - Port scanning detection
  - Brute force attack detection
  - DDoS pattern detection
  - Data exfiltration detection
  - Geographic anomaly detection
  - Privilege escalation attempt detection
- **Comprehensive Visualization**: Generate visual reports, dashboards, and threat analysis charts
- **Rich Sample Data**: Enhanced sample data generation with realistic security log patterns

## Technologies

- Python 3.8+
- Scikit-learn
- Pandas
- NumPy
- Matplotlib
- Jupyter Notebook

## Installation

1. Clone or download this repository
2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Running the Analysis

```bash
python main.py
```

### Using Jupyter Notebook

```bash
jupyter notebook security_log_analysis.ipynb
```

## Project Structure

```
security-log-analysis/
├── main.py                 # Main entry point
├── log_parser.py           # Log parsing and preprocessing with enhanced sample data
├── feature_extractor.py    # Advanced feature extraction module (50+ features)
├── anomaly_detector.py     # Anomaly detection using ML
├── incident_classifier.py # Incident classification
├── advanced_analyzer.py   # Advanced threat detection (port scan, DDoS, etc.)
├── visualizer.py          # Visualization and reporting
├── config.py              # Configuration settings
├── security_log_analysis.ipynb  # Jupyter notebook
├── requirements.txt       # Python dependencies
├── index.html             # Demo page
└── README.md             # This file
```

## Sample Data

The project includes sample data files in the `data/` directory:

- `security_logs_sample.csv` - Small sample file with 20 entries (ready to use)
- `security_logs.csv` - Full sample dataset (generated automatically)

### Generate More Sample Data

To generate additional sample data, run:

```bash
python generate_sample_data.py
```

This will create a file with 2000 entries in `data/security_logs.csv`.

### Sample Data Features

The project includes enhanced sample log data generation with realistic features:
- Timestamps with varying frequencies
- Realistic IP address patterns (internal/external)
- Common and uncommon port distributions
- Multiple protocols (TCP, UDP, HTTP, HTTPS, SSH, FTP, SMTP, DNS)
- HTTP status codes with realistic distributions
- User agents, request methods, response times
- Geographic data, session IDs, threat levels
- Pre-injected anomalies for testing

You can replace this with your own security logs by modifying the `LOG_FILE_PATH` in `config.py`.

## License

This project is provided for educational purposes.

---

## Contact Information

**Project Developer**: Molla Samser  
**Designer & Tester**: Rima Khatun  
**Organization**: RSK World

**Email**: 
- help@rskworld.in
- support@rskworld.in
- info@rskworld.com

**Phone**: +91 93305 39277

**Address**:  
Nutanhat, Mongolkote  
Purba Burdwan, West Bengal  
India, 713147

**Website**: https://rskworld.in

© 2025 RSK World. All rights reserved.

