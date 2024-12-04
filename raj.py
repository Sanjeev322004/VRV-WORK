import re
import csv
from collections import defaultdict

def parse_log(file_path):
    with open(file_path, 'r') as f:
        logs = f.readlines()
    return logs

# Function to count requests per IP address
def count_requests_per_ip(logs):
    ip_counts = defaultdict(int)
    for log in logs:
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log)
        if match:
            ip_counts[match.group(1)] += 1
    return ip_counts

# Function to find the most frequently accessed endpoint
def most_frequented_endpoint(logs):
    endpoint_counts = defaultdict(int)
    for log in logs:
        match = re.search(r'\"[A-Z]+\s([^\s]+)\s', log)
        if match:
            endpoint_counts[match.group(1)] += 1
    most_accessed = max(endpoint_counts, key=endpoint_counts.get)
    return most_accessed, endpoint_counts[most_accessed]

# Function to detect suspicious activity based on failed login attempts
def detect_suspicious_activity(logs, threshold=10):
    failed_logins = defaultdict(int)
    for log in logs:
        if "401" in log or "Invalid credentials" in log:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log)
            if match:
                ip = match.group(1)
                failed_logins[ip] += 1
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
    return suspicious_ips

# Function to save the results to a CSV file
def save_to_csv(ip_counts, most_accessed, suspicious_ips):
    with open('log_analysis_results.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Write "Requests per IP"
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        
        # Write "Most Accessed Endpoint"
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow([most_accessed[0], most_accessed[1]])
        
        # Write "Suspicious Activity"
        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Main function to execute the analysis
def main():
    logs = parse_log('sample.log')

    # Task 1: Count requests per IP address
    ip_counts = count_requests_per_ip(logs)

    # Task 2: Identify the most frequently accessed endpoint
    most_accessed = most_frequented_endpoint(logs)

    # Task 3: Detect suspicious activity
    suspicious_ips = detect_suspicious_activity(logs)

    # Display results in the terminal
    print("Requests per IP Address")
    print("IP Address           Request Count")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")

    # Save results to CSV file
    save_to_csv(ip_counts, most_accessed, suspicious_ips)

# Run the main function
if __name__ == "__main__":
    main()
