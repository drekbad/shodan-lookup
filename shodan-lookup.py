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
# shodan_hardcoded_key = "YOUR_HARDCODED_API_KEY_HERE" 
shodan_hardcoded_key = "" 

# Rate limiting delay (seconds) to prevent hitting API limits
SLEEP_TIME = 0.5 

def expand_ips(input_list):
    """
    Expands a mixed list of individual IPs and CIDR ranges into a unique set
    of public individual IP addresses (excluding RFC 1918 and other private IPs).
    """
    print("🚀 Starting IP list processing...")
    
    # Trackers for the reporting
    total_original_lines = len(input_list)
    private_lines_found = set()  # Store original line entries that contain private IPs/CIDRs
    total_expanded_private_ips = 0
    total_expanded_ips = 0
    
    # Set to hold the final unique public IPs for scanning
    target_public_ips = set()

    for entry in input_list:
        entry = entry.strip()
        if not entry:
            continue
            
        try:
            # First, try to parse it as a network/CIDR (e.g., 192.168.1.0/24)
            network = ipaddress.ip_network(entry, strict=False)
            
            # Use the .is_private property on the network object itself
            if network.is_private:
                private_lines_found.add(entry)
                total_expanded_private_ips += network.num_addresses
                total_expanded_ips += network.num_addresses
            else:
                # If it's a public network, iterate and add all IPs to the public set
                for ip in network:
                    target_public_ips.add(ip.compressed)
                    total_expanded_ips += 1

        except ValueError:
            # If it failed as a network, try to parse it as an individual IP
            try:
                ip_addr = ipaddress.ip_address(entry)
                total_expanded_ips += 1
                
                if ip_addr.is_private:
                    private_lines_found.add(entry)
                    total_expanded_private_ips += 1
                else:
                    target_public_ips.add(ip_addr.compressed)
                    
            except ValueError:
                print(f"⚠️ Skipping invalid entry: {entry}")

    # --- Reporting ---
    
    # Dump Private IP entries to file
    private_list_filename = "private_ips_original_entries.txt"
    if private_lines_found:
        with open(private_list_filename, 'w') as f:
            f.write('\n'.join(sorted(list(private_lines_found))) + '\n')
        print(f"\n📢 Found Private IPs/CIDRs in {len(private_lines_found)} original line item(s).")
        print(f"   (Written to {private_list_filename})")
    else:
        print("\n📢 No private IPs or CIDR ranges found in the input list.")

    
    print("\n--- Summary of IP Processing ---")
    print(f"1. Total initial lines read: {total_original_lines}")
    print(f"2. Total theoretical expanded IPs: {total_expanded_ips}")
    print(f"3. Total expanded private IPs (Excluded): {total_expanded_private_ips}")
    print(f"4. Total unique IPs to check (Public): {len(target_public_ips)}")
    
    return target_public_ips


# --- (The rest of the script remains the same) ---
# The 'get_shodan_data' and 'main' functions are unchanged, 
# as they accept the filtered list of public IPs from 'expand_ips'.
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
            print(f"🔎 [{i+1}/{len(ip_list)}] Looking up: {ip}...", end='\r') 
            
            try:
                host_info = api.host(ip)
                successful_lookups += 1

                # --- A. Full JSON Dump ---
                json_file.write(json.dumps(host_info) + '\n')
                
                # --- B. Concise CSV Summary ---
                hostnames = "; ".join(host_info.get('hostnames', []))
                
                ports_services = []
                for service in host_info.get('data', []):
                    port = service.get('port')
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
                if "No information available for that IP" in str(e):
                    sys.stdout.write(' ' * 80 + '\r')
                    print(f"   [--] {ip}: No Shodan data found.")
                else:
                    sys.stdout.write(' ' * 80 + '\r')
                    print(f"   [--] API Error for {ip}: {e}")
            
            time.sleep(SLEEP_TIME) 
            
    sys.stdout.write(' ' * 80 + '\r')
    print("\n\n--- FINAL RESULTS ---")
    print(f"✅ Completed lookups for {successful_lookups} hosts with data.")
    print(f"   - Full JSON Dump (JSON Lines): {json_filename}")
    print(f"   - Concise CSV Summary: {csv_filename}")

def main():
    parser = argparse.ArgumentParser(
        description="Expand IP/CIDR list, filter private IPs, and query Shodan API for host information."
    )
    
    parser.add_argument(
        '-k', '--key', 
        type=str, 
        help="Your Shodan API Key. Overrides any hardcoded key.", 
        default=None
    )
    
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

    # 3. Filter and Expand the list (now removes private IPs)
    expanded_public_ips = expand_ips(ip_cidr_list)
    
    if not expanded_public_ips:
        print("\n🛑 No public IP addresses remaining after filtering. Exiting.")
        sys.exit(0)
        
    # 4. Get Shodan data and write files
    get_shodan_data(expanded_public_ips, shodan_api_key)

if __name__ == "__main__":
    main()
