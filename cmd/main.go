package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
	"golang.org/x/net/publicsuffix"
)

// Detection thresholds
const (
	EntropyThreshold      = 4.0
	TXTLengthThreshold    = 100
	SubdomainDepthLimit   = 3
	BeaconStdDevThreshold = 5.0
	DomainAgeThreshold    = 30
)

// DNSRecord represents a parsed DNS record
type DNSRecord struct {
	Timestamp    time.Time
	QueryName    string
	RecordType   string
	RecordData   string
	ResponseCode int
	TTL          uint32
}

// SuspiciousIndicator represents a detection result
type SuspiciousIndicator struct {
	Type       string
	Domain     string
	Reason     string
	Confidence string
	Data       map[string]interface{}
	Timestamp  time.Time
}

var (
	pcapFile   string
	outputFile string
	verbose    bool
	threshold  float64
)

var rootCmd = &cobra.Command{
	Use:   "dns-threat-hunter",
	Short: "DNS Threat Hunter - Detect DNS-based data exfiltration and C2 communication",
	Long: `A comprehensive DNS analysis tool for detecting various DNS abuse techniques including:
- TXT record abuse for data smuggling
- NULL record detection
- Subdomain encoding detection
- DNS beaconing behavior
- Domain reputation analysis`,
}

var txtCmd = &cobra.Command{
	Use:   "txt-analysis",
	Short: "Analyze TXT records for encoded data",
	Run:   runTXTAnalysis,
}

var nullCmd = &cobra.Command{
	Use:   "null-detect",
	Short: "Detect NULL record usage",
	Run:   runNULLDetection,
}

var subdomainCmd = &cobra.Command{
	Use:   "subdomain-encoding",
	Short: "Detect encoded data in subdomains",
	Run:   runSubdomainAnalysis,
}

var beaconCmd = &cobra.Command{
	Use:   "beacon-detect",
	Short: "Detect DNS beaconing behavior",
	Run:   runBeaconDetection,
}

var fullCmd = &cobra.Command{
	Use:   "full-analysis",
	Short: "Run all detection methods",
	Run:   runFullAnalysis,
}

var liveCmd = &cobra.Command{
	Use:   "live-monitor",
	Short: "Monitor live DNS traffic",
	Run:   runLiveMonitor,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&pcapFile, "pcap", "p", "", "PCAP file to analyze")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Output file for results")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().Float64VarP(&threshold, "threshold", "t", EntropyThreshold, "Entropy threshold for detection")

	rootCmd.AddCommand(txtCmd)
	rootCmd.AddCommand(nullCmd)
	rootCmd.AddCommand(subdomainCmd)
	rootCmd.AddCommand(beaconCmd)
	rootCmd.AddCommand(fullCmd)
	rootCmd.AddCommand(liveCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// calculateEntropy calculates Shannon entropy of a string
func calculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	frequency := make(map[rune]float64)
	for _, char := range data {
		frequency[char]++
	}

	var entropy float64
	dataLen := float64(len(data))
	for _, count := range frequency {
		probability := count / dataLen
		if probability > 0 {
			entropy -= probability * math.Log2(probability)
		}
	}
	return entropy
}

// isBase64 checks if a string appears to be base64 encoded
func isBase64(s string) bool {
	if len(s)%4 != 0 {
		return false
	}
	base64Regex := regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
	if !base64Regex.MatchString(s) {
		return false
	}

	// Try to decode
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// isHex checks if a string appears to be hex encoded
func isHex(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// extractDNSRecords extracts DNS records from a PCAP file
func extractDNSRecords(pcapPath string) ([]DNSRecord, error) {
	handle, err := pcap.OpenOffline(pcapPath)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	var records []DNSRecord
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)

			for _, answer := range dns.Answers {
				record := DNSRecord{
					Timestamp: packet.Metadata().Timestamp,
					QueryName: string(answer.Name),
					TTL:       answer.TTL,
				}

				switch answer.Type {
				case layers.DNSTypeA:
					record.RecordType = "A"
					record.RecordData = answer.IP.String()
				case layers.DNSTypeAAAA:
					record.RecordType = "AAAA"
					record.RecordData = answer.IP.String()
				case layers.DNSTypeTXT:
					record.RecordType = "TXT"
					for _, txt := range answer.TXTs {
						record.RecordData += string(txt) + " "
					}
				case layers.DNSTypeCNAME:
					record.RecordType = "CNAME"
					record.RecordData = string(answer.CNAME)
				case layers.DNSTypeMX:
					record.RecordType = "MX"
					record.RecordData = string(answer.MX.Name)
				case layers.DNSTypeNS:
					record.RecordType = "NS"
					record.RecordData = string(answer.NS)
				case layers.DNSTypeNULL:
					record.RecordType = "NULL"
					record.RecordData = "NULL Record Detected"
				}

				records = append(records, record)
			}
		}
	}

	return records, nil
}

// runTXTAnalysis analyzes TXT records for suspicious patterns
func runTXTAnalysis(cmd *cobra.Command, args []string) {
	if pcapFile == "" {
		log.Fatal("Please provide a PCAP file with -p flag")
	}

	fmt.Println("🔍 Analyzing TXT Records for Encoded Data...")
	records, err := extractDNSRecords(pcapFile)
	if err != nil {
		log.Fatal(err)
	}

	var suspicious []SuspiciousIndicator
	txtCount := make(map[string]int)

	for _, record := range records {
		if record.RecordType != "TXT" {
			continue
		}

		txtCount[record.QueryName]++
		entropy := calculateEntropy(record.RecordData)

		indicator := SuspiciousIndicator{
			Type:      "TXT_RECORD",
			Domain:    record.QueryName,
			Timestamp: record.Timestamp,
			Data:      make(map[string]interface{}),
		}

		indicator.Data["entropy"] = entropy
		indicator.Data["length"] = len(record.RecordData)
		indicator.Data["content"] = record.RecordData

		// Check for high entropy
		if entropy > threshold {
			indicator.Reason = fmt.Sprintf("High entropy detected: %.2f", entropy)
			indicator.Confidence = "HIGH"
			suspicious = append(suspicious, indicator)
		}

		// Check for base64 encoding
		if isBase64(strings.TrimSpace(record.RecordData)) {
			decoded, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(record.RecordData))
			if len(decoded) > 20 {
				indicator.Reason = "Base64 encoded content detected"
				indicator.Confidence = "HIGH"
				indicator.Data["decoded_length"] = len(decoded)
				suspicious = append(suspicious, indicator)
			}
		}

		// Check for suspicious length
		if len(record.RecordData) > TXTLengthThreshold {
			if indicator.Reason == "" {
				indicator.Reason = fmt.Sprintf("Unusually long TXT record: %d bytes", len(record.RecordData))
				indicator.Confidence = "MEDIUM"
				suspicious = append(suspicious, indicator)
			}
		}
	}

	// Check for high frequency queries
	for domain, count := range txtCount {
		if count > 10 {
			indicator := SuspiciousIndicator{
				Type:       "TXT_RECORD",
				Domain:     domain,
				Reason:     fmt.Sprintf("High frequency TXT queries: %d requests", count),
				Confidence: "MEDIUM",
				Data:       map[string]interface{}{"query_count": count},
			}
			suspicious = append(suspicious, indicator)
		}
	}

	printResults(suspicious)
}

// runNULLDetection detects NULL record usage
func runNULLDetection(cmd *cobra.Command, args []string) {
	if pcapFile == "" {
		log.Fatal("Please provide a PCAP file with -p flag")
	}

	fmt.Println("🔍 Detecting NULL Records...")
	records, err := extractDNSRecords(pcapFile)
	if err != nil {
		log.Fatal(err)
	}

	var suspicious []SuspiciousIndicator

	for _, record := range records {
		if record.RecordType == "NULL" {
			indicator := SuspiciousIndicator{
				Type:       "NULL_RECORD",
				Domain:     record.QueryName,
				Reason:     "NULL record detected - extremely rare in legitimate traffic",
				Confidence: "CRITICAL",
				Timestamp:  record.Timestamp,
				Data: map[string]interface{}{
					"record_type": "NULL (Type 10)",
					"ttl":         record.TTL,
				},
			}
			suspicious = append(suspicious, indicator)
		}
	}

	if len(suspicious) == 0 {
		fmt.Println("✅ No NULL records detected")
	} else {
		fmt.Printf("⚠️  Found %d NULL record(s)!\n", len(suspicious))
		printResults(suspicious)
	}
}

// runSubdomainAnalysis detects encoded data in subdomains
func runSubdomainAnalysis(cmd *cobra.Command, args []string) {
	if pcapFile == "" {
		log.Fatal("Please provide a PCAP file with -p flag")
	}

	fmt.Println("🔍 Analyzing Subdomains for Encoding...")
	records, err := extractDNSRecords(pcapFile)
	if err != nil {
		log.Fatal(err)
	}

	var suspicious []SuspiciousIndicator
	domainPattern := make(map[string]int)

	for _, record := range records {
		parts := strings.Split(record.QueryName, ".")
		if len(parts) < 2 {
			continue
		}

		// Extract subdomain parts (everything except TLD and domain)
		domain, err := publicsuffix.EffectiveTLDPlusOne(record.QueryName)
		if err != nil {
			continue
		}

		subdomain := strings.TrimSuffix(record.QueryName, "."+domain)
		if subdomain == "" || subdomain == record.QueryName {
			continue
		}

		labels := strings.Split(subdomain, ".")
		domainPattern[domain]++

		indicator := SuspiciousIndicator{
			Type:      "SUBDOMAIN_ENCODING",
			Domain:    record.QueryName,
			Timestamp: record.Timestamp,
			Data:      make(map[string]interface{}),
		}

		indicator.Data["subdomain_depth"] = len(labels)
		indicator.Data["parent_domain"] = domain

		var suspiciousLabels []string
		highEntropyCount := 0
		base64Count := 0
		hexCount := 0
		maxLabelLength := 0

		for _, label := range labels {
			if len(label) > maxLabelLength {
				maxLabelLength = len(label)
			}

			entropy := calculateEntropy(label)
			if entropy > 4.0 {
				highEntropyCount++
				suspiciousLabels = append(suspiciousLabels, label)
			}

			if isBase64(label) {
				base64Count++
			}

			if isHex(label) {
				hexCount++
			}
		}

		indicator.Data["max_label_length"] = maxLabelLength
		indicator.Data["high_entropy_labels"] = highEntropyCount
		indicator.Data["suspicious_labels"] = suspiciousLabels

		// Decision logic
		if len(labels) > SubdomainDepthLimit {
			indicator.Reason = fmt.Sprintf("Excessive subdomain depth: %d levels", len(labels))
			indicator.Confidence = "HIGH"
			suspicious = append(suspicious, indicator)
		} else if maxLabelLength > 50 {
			indicator.Reason = fmt.Sprintf("Unusually long subdomain label: %d chars", maxLabelLength)
			indicator.Confidence = "HIGH"
			suspicious = append(suspicious, indicator)
		} else if highEntropyCount >= 2 {
			indicator.Reason = fmt.Sprintf("Multiple high-entropy labels detected: %d", highEntropyCount)
			indicator.Confidence = "HIGH"
			suspicious = append(suspicious, indicator)
		} else if base64Count >= 2 {
			indicator.Reason = "Multiple base64-encoded labels detected"
			indicator.Confidence = "HIGH"
			suspicious = append(suspicious, indicator)
		} else if hexCount >= 2 {
			indicator.Reason = "Multiple hex-encoded labels detected"
			indicator.Confidence = "MEDIUM"
			suspicious = append(suspicious, indicator)
		}
	}

	// Check for domains with many subdomains (potential DGA or tunneling)
	for domain, count := range domainPattern {
		if count > 20 {
			indicator := SuspiciousIndicator{
				Type:       "SUBDOMAIN_ENCODING",
				Domain:     domain,
				Reason:     fmt.Sprintf("High number of unique subdomains: %d", count),
				Confidence: "HIGH",
				Data:       map[string]interface{}{"unique_subdomains": count},
			}
			suspicious = append(suspicious, indicator)
		}
	}

	printResults(suspicious)
}

// runBeaconDetection detects DNS beaconing behavior
func runBeaconDetection(cmd *cobra.Command, args []string) {
	if pcapFile == "" {
		log.Fatal("Please provide a PCAP file with -p flag")
	}

	fmt.Println("🔍 Detecting DNS Beaconing Behavior...")
	records, err := extractDNSRecords(pcapFile)
	if err != nil {
		log.Fatal(err)
	}

	// Group queries by domain
	domainQueries := make(map[string][]time.Time)
	for _, record := range records {
		domainQueries[record.QueryName] = append(domainQueries[record.QueryName], record.Timestamp)
	}

	var suspicious []SuspiciousIndicator

	for domain, timestamps := range domainQueries {
		if len(timestamps) < 10 {
			continue // Need sufficient data points
		}

		// Sort timestamps
		sort.Slice(timestamps, func(i, j int) bool {
			return timestamps[i].Before(timestamps[j])
		})

		// Calculate time deltas
		var deltas []float64
		for i := 1; i < len(timestamps); i++ {
			delta := timestamps[i].Sub(timestamps[i-1]).Seconds()
			if delta > 0 && delta < 3600 { // Ignore gaps > 1 hour
				deltas = append(deltas, delta)
			}
		}

		if len(deltas) < 5 {
			continue
		}

		// Calculate statistics
		mean := calculateMean(deltas)
		stdDev := calculateStdDev(deltas, mean)

		// Check for beaconing pattern (consistent intervals)
		if stdDev < BeaconStdDevThreshold && mean > 10 && mean < 3600 {
			indicator := SuspiciousIndicator{
				Type:       "BEACONING",
				Domain:     domain,
				Reason:     fmt.Sprintf("Potential beaconing detected - Average interval: %.2f seconds, StdDev: %.2f", mean, stdDev),
				Confidence: "HIGH",
				Data: map[string]interface{}{
					"query_count":      len(timestamps),
					"average_interval": mean,
					"std_deviation":    stdDev,
					"first_seen":       timestamps[0],
					"last_seen":        timestamps[len(timestamps)-1],
				},
			}
			suspicious = append(suspicious, indicator)
		}
	}

	printResults(suspicious)
}

// runFullAnalysis runs all detection methods
func runFullAnalysis(cmd *cobra.Command, args []string) {
	if pcapFile == "" {
		log.Fatal("Please provide a PCAP file with -p flag")
	}

	fmt.Println("🔍 Running Full DNS Threat Analysis...")
	fmt.Println("=" + strings.Repeat("=", 50))

	// Run each analysis
	fmt.Println("\n📋 TXT Record Analysis:")
	runTXTAnalysis(cmd, args)

	fmt.Println("\n📋 NULL Record Detection:")
	runNULLDetection(cmd, args)

	fmt.Println("\n📋 Subdomain Encoding Detection:")
	runSubdomainAnalysis(cmd, args)

	fmt.Println("\n📋 Beaconing Detection:")
	runBeaconDetection(cmd, args)

	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("✅ Full analysis complete!")
}

// runLiveMonitor monitors live DNS traffic
func runLiveMonitor(cmd *cobra.Command, args []string) {
	fmt.Println("🔍 Starting Live DNS Monitoring...")
	fmt.Println("Press Ctrl+C to stop")

	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	if len(devices) == 0 {
		log.Fatal("No network devices found")
	}

	// Select first non-loopback device
	var device string
	for _, d := range devices {
		if len(d.Addresses) > 0 {
			for _, addr := range d.Addresses {
				if addr.IP.String() != "127.0.0.1" && addr.IP.To4() != nil {
					device = d.Name
					break
				}
			}
			if device != "" {
				break
			}
		}
	}

	if device == "" {
		device = devices[0].Name
	}

	fmt.Printf("Monitoring on device: %s\n", device)

	// Open device for live capture
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter for DNS traffic
	err = handle.SetBPFFilter("port 53")
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)

			// Check for suspicious patterns in real-time
			for _, answer := range dns.Answers {
				checkRealTimeRecord(answer, packet.Metadata().Timestamp)
			}
		}
	}
}

// checkRealTimeRecord checks a DNS record in real-time for suspicious patterns
func checkRealTimeRecord(answer layers.DNSResourceRecord, timestamp time.Time) {
	domain := string(answer.Name)

	switch answer.Type {
	case layers.DNSTypeNULL:
		fmt.Printf("⚠️  [%s] NULL RECORD DETECTED: %s\n",
			timestamp.Format("15:04:05"), domain)

	case layers.DNSTypeTXT:
		var txtData string
		for _, txt := range answer.TXTs {
			txtData += string(txt)
		}
		entropy := calculateEntropy(txtData)
		if entropy > threshold {
			fmt.Printf("⚠️  [%s] High entropy TXT record (%.2f): %s\n",
				timestamp.Format("15:04:05"), entropy, domain)
		}
		if len(txtData) > TXTLengthThreshold {
			fmt.Printf("⚠️  [%s] Large TXT record (%d bytes): %s\n",
				timestamp.Format("15:04:05"), len(txtData), domain)
		}

	case layers.DNSTypeCNAME, layers.DNSTypeNS:
		labels := strings.Split(domain, ".")
		if len(labels) > SubdomainDepthLimit+2 { // +2 for domain and TLD
			fmt.Printf("⚠️  [%s] Deep subdomain (%d levels): %s\n",
				timestamp.Format("15:04:05"), len(labels)-2, domain)
		}

		// Check for high entropy in labels
		for _, label := range labels {
			if len(label) > 20 && calculateEntropy(label) > 4.0 {
				fmt.Printf("⚠️  [%s] High entropy subdomain: %s\n",
					timestamp.Format("15:04:05"), domain)
				break
			}
		}
	}
}

// calculateMean calculates the mean of a slice of floats
func calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// calculateStdDev calculates the standard deviation
func calculateStdDev(values []float64, mean float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var variance float64
	for _, v := range values {
		variance += math.Pow(v-mean, 2)
	}
	variance /= float64(len(values))
	return math.Sqrt(variance)
}

// printResults prints the detection results
func printResults(indicators []SuspiciousIndicator) {
	if len(indicators) == 0 {
		fmt.Println("✅ No suspicious activity detected")
		return
	}

	fmt.Printf("\n⚠️  Found %d suspicious indicator(s):\n", len(indicators))
	fmt.Println(strings.Repeat("-", 80))

	for i, ind := range indicators {
		fmt.Printf("\n[%d] Type: %s | Confidence: %s\n", i+1, ind.Type, ind.Confidence)
		fmt.Printf("    Domain: %s\n", ind.Domain)
		fmt.Printf("    Reason: %s\n", ind.Reason)

		if ind.Timestamp.Unix() > 0 {
			fmt.Printf("    Time: %s\n", ind.Timestamp.Format("2006-01-02 15:04:05"))
		}

		if verbose && len(ind.Data) > 0 {
			fmt.Println("    Additional Data:")
			for key, value := range ind.Data {
				fmt.Printf("      - %s: %v\n", key, value)
			}
		}
	}

	fmt.Println(strings.Repeat("-", 80))

	// Save to file if specified
	if outputFile != "" {
		saveResults(indicators)
	}
}

// saveResults saves results to a file
func saveResults(indicators []SuspiciousIndicator) {
	file, err := os.Create(outputFile)
	if err != nil {
		log.Printf("Error creating output file: %v", err)
		return
	}
	defer file.Close()

	fmt.Fprintf(file, "DNS Threat Hunting Report\n")
	fmt.Fprintf(file, "Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "PCAP File: %s\n", pcapFile)
	fmt.Fprintf(file, "%s\n\n", strings.Repeat("=", 80))

	for _, ind := range indicators {
		fmt.Fprintf(file, "Type: %s\n", ind.Type)
		fmt.Fprintf(file, "Confidence: %s\n", ind.Confidence)
		fmt.Fprintf(file, "Domain: %s\n", ind.Domain)
		fmt.Fprintf(file, "Reason: %s\n", ind.Reason)
		if ind.Timestamp.Unix() > 0 {
			fmt.Fprintf(file, "Timestamp: %s\n", ind.Timestamp.Format("2006-01-02 15:04:05"))
		}
		for key, value := range ind.Data {
			fmt.Fprintf(file, "%s: %v\n", key, value)
		}
		fmt.Fprintf(file, "%s\n", strings.Repeat("-", 40))
	}

	fmt.Printf("✅ Results saved to %s\n", outputFile)
}
