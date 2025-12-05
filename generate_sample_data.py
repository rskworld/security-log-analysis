"""
Generate Sample Security Log Data
This script creates sample security log data for testing

Project by:
- Molla Samser (Founder)
- Rima Khatun (Designer & Tester)
RSK World - https://rskworld.in

Contact:
- Email: help@rskworld.in, support@rskworld.in
- Phone: +91 93305 39277
- Address: Nutanhat, Mongolkote, Purba Burdwan, West Bengal, India, 713147
"""

from log_parser import generate_sample_logs
import os

if __name__ == '__main__':
    print("=" * 80)
    print("Generating Sample Security Log Data")
    print("RSK World - Security Log Analysis System")
    print("=" * 80)
    print()
    
    # Create data directory
    os.makedirs('data', exist_ok=True)
    
    # Generate sample data
    print("Generating 2000 sample log entries...")
    df = generate_sample_logs(n_samples=2000, output_path='data/security_logs.csv')
    
    print()
    print("=" * 80)
    print("Sample data generation complete!")
    print("=" * 80)
    print(f"File location: data/security_logs.csv")
    print(f"Total entries: {len(df)}")
    print(f"Columns: {len(df.columns)}")
    print()
    print("Sample columns:", ', '.join(df.columns.tolist()[:10]))
    print()
    print("You can now run: python main.py")
    print("=" * 80)

