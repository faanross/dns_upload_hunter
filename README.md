
# DNS Upload Hunter

A comprehensive DNS analysis tool for detecting various DNS abuse techniques including TXT record abuse, NULL record detection, subdomain encoding, and beaconing behavior.

## Installation

1. **Install Go** (version 1.21 or later):
   ```bash
   # Check if Go is installed
   go version
   ```

2. **Clone and build the tool**:
   ```bash
   # Create project directory
    git clone https://github.com/faanross/dns_upload_hunter.git
   
   # Install dependencies
   go mod tidy
   
   # Run Application 
   go run ./cmd

   ```

3. **Install required system dependencies**:
   ```bash
   # On Ubuntu/Debian
   sudo apt-get install libpcap-dev
   
   # On macOS
   brew install libpcap
   
   # On RHEL/CentOS/Fedora
   sudo yum install libpcap-devel
   ```

## Usage

### Basic Commands

```bash
# Show help
go run ./cmd --help

# Analyze TXT records for encoded data
go run ./cmd txt-analysis -p capture.pcap

# Detect NULL records (high confidence malicious)
go run ./cmd null-detect -p capture.pcap

# Detect subdomain encoding
go run ./cmd subdomain-encoding -p capture.pcap

# Detect DNS beaconing behavior
go run ./cmd beacon-detect -p capture.pcap

# Run all detection methods
go run ./cmd full-analysis -p capture.pcap

# Monitor live DNS traffic (requires root/admin)
go run ./cmd live-monitor
```

### Advanced Options

```bash
# Save results to file
go run ./cmd full-analysis -p capture.pcap -o results.txt

# Verbose output with additional details
go run ./cmd txt-analysis -p capture.pcap -v

# Custom entropy threshold (default: 4.0)
go run ./cmd txt-analysis -p capture.pcap -t 3.5

# Combine options
go run ./cmd full-analysis -p capture.pcap -o report.txt -v -t 4.5
```

## Detection Methods

### 1. TXT Record Analysis (`txt-analysis`)
Detects:
- High entropy content (possible encoding)
- Base64 encoded data
- Unusually long TXT records (>100 bytes)
- High frequency queries to same domain

### 2. NULL Record Detection (`null-detect`)
Detects:
- Any NULL record usage (Type 10)
- Extremely rare in legitimate traffic
- High confidence indicator of malicious activity

### 3. Subdomain Encoding Detection (`subdomain-encoding`)
Detects:
- Excessive subdomain depth (>3 levels)
- High entropy in subdomain labels
- Base64/hex patterns in subdomains
- Unusually long subdomain labels (>50 chars)
- Multiple suspicious labels in single domain

### 4. Beaconing Detection (`beacon-detect`)
Detects:
- Regular interval DNS queries
- Automated C2 communication patterns
- Requires at least 10 queries to same domain
- Identifies consistent timing patterns (low standard deviation)

### 5. Live Monitoring (`live-monitor`)
Features:
- Real-time DNS traffic analysis
- Automatic interface selection
- Instant alerts for suspicious patterns
- Requires root/administrator privileges

## Output Format

The tool provides structured output with:
- **Type**: Detection category (TXT_RECORD, NULL_RECORD, SUBDOMAIN_ENCODING, BEACONING)
- **Confidence**: CRITICAL, HIGH, MEDIUM
- **Domain**: Affected domain name
- **Reason**: Specific detection trigger
- **Timestamp**: When the activity occurred
- **Additional Data**: Context-specific details (with -v flag)

## Example Workflow

1. **Capture DNS traffic**:
   ```bash
   sudo tcpdump -i eth0 -w dns_capture.pcap port 53
   # Let it run for a while, then stop with Ctrl+C
   ```

2. **Run full analysis**:
   ```bash
   go run ./cmd full-analysis -p dns_capture.pcap -o report.txt -v
   ```

3. **Investigate specific indicators**:
   ```bash
   # If TXT abuse was detected, deep dive:
   go run ./cmd txt-analysis -p dns_capture.pcap -v
   ```

4. **Set up continuous monitoring**:
   ```bash
   # In a screen/tmux session:
   sudo go run ./cmd live-monitor
   ```

## Integration Examples

### With tcpdump
```bash
# Capture only DNS traffic for analysis
sudo tcpdump -i any -w dns_only.pcap -c 10000 port 53
go run ./cmd full-analysis -p dns_only.pcap
```

### With tshark
```bash
# Extract DNS from existing capture
tshark -r full_capture.pcap -Y "dns" -w dns_filtered.pcap
go run ./cmd full-analysis -p dns_filtered.pcap
```

### Automated Analysis Script
```bash
#!/bin/bash
# Automated hourly DNS analysis

CAPTURE_DIR="/var/log/dns_captures"
REPORT_DIR="/var/log/dns_reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Rotate capture
sudo pkill tcpdump
sudo tcpdump -i any -w "$CAPTURE_DIR/dns_$TIMESTAMP.pcap" port 53 &

# Analyze previous hour's capture
if [ -f "$CAPTURE_DIR/dns_previous.pcap" ]; then
    ./dns-threat-hunter full-analysis \
        -p "$CAPTURE_DIR/dns_previous.pcap" \
        -o "$REPORT_DIR/report_$TIMESTAMP.txt" \
        -v
fi

# Rotate files
mv "$CAPTURE_DIR/dns_current.pcap" "$CAPTURE_DIR/dns_previous.pcap" 2>/dev/null
sleep 3600
mv "$CAPTURE_DIR/dns_$TIMESTAMP.pcap" "$CAPTURE_DIR/dns_current.pcap"
```

## Performance Considerations

- **Large PCAP files**: The tool loads the entire PCAP into memory. For files >1GB, consider splitting:
  ```bash
  tcpdump -r large.pcap -w split.pcap -C 100
  ```

- **Live monitoring**: Processes packets in real-time. High-volume networks may need filtering:
  ```bash
  # Filter by specific subnet
  sudo go run ./cmd live-monitor --filter "src net 192.168.1.0/24"
  ```

## Troubleshooting

### Permission Denied (Live Monitoring)
```bash
# Must run as root for packet capture
sudo go run ./cmd live-monitor
```

### No Network Devices Found
```bash
# Check available interfaces
ip addr show
# or
ifconfig

# Verify libpcap installation
ldconfig -p | grep pcap
```

### Build Errors
```bash
# Update dependencies
go mod download
go mod tidy

# Clean build
go clean -cache
go build -o dns-threat-hunter main.go
```

## Security Notes

1. **PCAP files may contain sensitive data** - Handle with appropriate security controls
2. **Live monitoring requires root** - Use with caution in production
3. **Detection is probabilistic** - Always verify findings before taking action
4. **Consider privacy regulations** when capturing DNS traffic

## Contributing

To add new detection methods:
1. Add a new command in the `init()` function
2. Implement the detection logic
3. Use the `SuspiciousIndicator` struct for results
4. Call `printResults()` to display findings

## License

MIT License - Feel free to modify and distribute as needed.