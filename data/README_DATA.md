# Sample Security Log Data

This directory contains sample security log data for testing the Security Log Analysis system.

## Files

- `security_logs.csv` - Main sample security log file (generated automatically)

## Generating Sample Data

To generate sample data, run:

```bash
python generate_sample_data.py
```

Or use the function directly:

```python
from log_parser import generate_sample_logs
generate_sample_logs(n_samples=2000, output_path='data/security_logs.csv')
```

## Data Format

The sample data includes the following fields:

- **timestamp**: Event timestamp
- **source_ip**: Source IP address
- **destination_ip**: Destination IP address
- **port**: Port number
- **protocol**: Network protocol (TCP, UDP, HTTP, HTTPS, SSH, FTP, SMTP, DNS)
- **action**: Action taken (ALLOW, DENY, BLOCK, LOG)
- **status_code**: HTTP status code
- **bytes_sent**: Bytes sent
- **bytes_received**: Bytes received
- **duration**: Connection duration
- **user_agent**: User agent string
- **request_method**: HTTP request method (GET, POST, PUT, DELETE, HEAD, OPTIONS)
- **response_time**: Response time in seconds
- **country**: Country code
- **session_id**: Session identifier
- **threat_level**: Threat level (LOW, MEDIUM, HIGH, CRITICAL)

## Using Your Own Data

To use your own security logs:

1. Place your CSV file in this directory
2. Update `LOG_FILE_PATH` in `config.py` to point to your file
3. Ensure your CSV has at least these columns: timestamp, source_ip, destination_ip, port, protocol, action, status_code

---

**Project by:** Molla Samser (Founder) & Rima Khatun (Designer & Tester)  
**Organization:** RSK World  
**Website:** https://rskworld.in  
**Contact:** help@rskworld.in | +91 93305 39277

