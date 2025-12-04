import ipaddress
import shodan
import csv
import json
import time
import sys
import argparse
from shodan.exception import APIError

# --- Configuration ---
# Hardcoded API Key (Will be used IF no API key is provided via command line)
# Note: Use a secured method (like environment variables) for production secrets.
# shodan_hardcoded_key = "YOUR_HARDCODED_API_KEY_HERE" 
shodan_hardcoded_key = "" # Leave blank or comment out if you prefer no hardcoded key

# Rate limiting delay (seconds) to prevent hitting API limits
SLEEP_TIME = 0.5 

def expand_ips(input_list):
    """
    Expands a mixed list of individual IPs and CIDR ranges into a unique set
    of individual IP addresses (including network and broadcast addresses).
    """
    print("🚀 Expanding IP ranges...")
    target_ips = set()
    for entry in input_list:
        entry = entry.strip()
        if not entry:
            continue
            
        try:
            # Tries to parse as a network (CIDR). strict=False allows host IPs to be used.
            network = ipaddress.ip_network(entry, strict=False)
            # Iterates over all addresses in the network
            for ip in network:
                target_ips.add(ip.compressed)
        except ValueError:
            # If not a valid network, assume it's an individual IP address
            try:
                ipaddress.ip_address(entry)
                target_ips.add(entry)
            except ValueError:
                print(f"⚠️ Skipping invalid entry: {entry}")
    
    print(f"✅ Total unique IPs to check: {len(target_ips)}")
    return target_ips

def get_shodan_data(ip_list, api_key, output_prefix="shodan_report"):
    """
    Looks up Shodan data for each IP and saves results to a full JSON file
    and a concise CSV summary.
    """
    if not api_key:
        print("\n❌ Error: No Shodan API Key provided. Cannot proceed with API lookups.")
        return

    try:
        api = shodan.Shodan(api_key)
    except Exception as e:
        print(f"\n❌ Error initializing Shodan API: {e}")
        return

    # 1. Output Files
    json_filename = f"{output_prefix}_full_dump.jsonl" 
    csv_filename = f"{output_prefix}_summary.csv"
    
    # CSV headers for the concise report
    csv_headers = ["IP", "FQDN_Hostnames", "Country", "Organization", "Open_Ports_Services"]
    
    successful_lookups = 0

    with open(json_filename, 'w') as json_file, open(csv_filename, 'w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(csv_headers)
        
        for i, ip in enumerate(ip_list):
            print(f"🔎 [{i+1}/{len(ip_list)}] Looking up: {ip}...", end='\r') # Print on the same line
            
            try:
                # The api.host() call retrieves all host data
                host_info = api.host(ip)
                successful_lookups += 1

                # --- A. Full JSON Dump ---
                json_file.write(json.dumps(host_info) + '\n')
                
                # --- B. Concise CSV Summary ---
                
                # Extract FQDNs
                hostnames = "; ".join(host_info.get('hostnames', []))
                
                # Format Ports & Services (Port:Service/Product)
                ports_services = []
                # Iterate through the 'data' array, which contains service banners
                for service in host_info.get('data', []):
                    port = service.get('port')
                    # Use the 'product' field (e.g., Apache, nginx) or 'transport' if product is missing
                    product = service.get('product') or service.get('transport', 'unknown')
                    ports_services.append(f"{port}:{product}")
                
                ports_services_str = "; ".join(ports_services)
                
                csv_row = [
                    ip,
                    hostnames,
                    host_info.get('country_name', 'N/A'),
                    host_info.get('org', 'N/A'),
                    ports_services_str
                ]
                csv_writer.writerow(csv_row)
                
            except APIError as e:
                # Handle common Shodan API errors (e.g., No information found)
                if "No information available for that IP" in str(e):
                    # Clear the line before printing the status
                    sys.stdout.write(' ' * 80 + '\r')
                    print(f"   [--] {ip}: No Shodan data found.")
                else:
                    sys.stdout.write(' ' * 80 + '\r')
                    print(f"   [--] API Error for {ip}: {e}")
            
            # Pause to respect rate limits
            time.sleep(SLEEP_TIME) 
            
    # Clear the last line and print summary
    sys.stdout.write(' ' * 80 + '\r')
    print("\n\n--- RESULTS ---")
    print(f"✅ Completed lookups for {successful_lookups} hosts with data.")
    print(f"   - Full JSON Dump (JSON Lines): {json_filename}")
    print(f"   - Concise CSV Summary: {csv_filename}")

def main():
    parser = argparse.ArgumentParser(
        description="Expand IP/CIDR list and query Shodan API for host information."
    )
    
    # Optional API Key argument
    parser.add_argument(
        '-k', '--key', 
        type=str, 
        help="Your Shodan API Key. Overrides any hardcoded key.", 
        default=None
    )
    
    # Required Input File argument
    parser.add_argument(
        'ip_file', 
        type=str, 
        help="Path to the file containing IP addresses and/or CIDR ranges (one per line)."
    )
    
    args = parser.parse_args()
    
    # 1. Determine the API Key (Priority: Command Line > Hardcoded)
    shodan_api_key = args.key
    if not shodan_api_key and shodan_hardcoded_key:
        shodan_api_key = shodan_hardcoded_key
        print("🔑 Using hardcoded API key.")
    elif not shodan_api_key:
        print("\n❌ Error: No Shodan API Key provided via argument (-k/--key) or hardcoded.")
        sys.exit(1)

    # 2. Read the input file
    try:
        with open(args.ip_file, 'r') as f:
            ip_cidr_list = f.readlines()
    except FileNotFoundError:
        print(f"❌ Error: Input file not found at {args.ip_file}")
        sys.exit(1)

    # 3. Expand the list
    expanded_ips = expand_ips(ip_cidr_list)
    
    # 4. Get Shodan data and write files
    get_shodan_data(expanded_ips, shodan_api_key)

if __name__ == "__main__":
    main()
