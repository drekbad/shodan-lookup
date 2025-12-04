import ipaddress
import shodan
import csv
import json
import time
import sys
import argparse
import socket # Added for DNS resolution
from shodan.exception import APIError

# --- Configuration ---
# Hardcoded API Key (Will be used IF no API key is provided via command line)
# shodan_hardcoded_key = "YOUR_HARDCODED_API_KEY_HERE" 
shodan_hardcoded_key = "" 

# Rate limiting delay (seconds) to prevent hitting API limits
SLEEP_TIME = 0.5 

# --- New Function: DNS Resolver ---
def resolve_fqdn(target):
    """
    Attempts to resolve an FQDN to a list of public IPv4 addresses.
    Returns (resolved_ips, is_resolved_from_fqdn)
    """
    try:
        # Check if the target is already an IP address
        ipaddress.ip_address(target)
        # If it's an IP, return it as a list of one IP, not resolved from FQDN
        return [target], False
    except ValueError:
        # It's not an IP, so attempt to resolve it as an FQDN
        pass
        
    resolved_ips = []
    
    try:
        # socket.gethostbyname_ex returns (hostname, aliases, ipaddrlist)
        # We only care about the ipaddrlist (index 2)
        _, _, ip_list = socket.gethostbyname_ex(target)
        
        for ip in ip_list:
            # Re-use ipaddress logic to ensure we only proceed with public IPs
            ip_addr = ipaddress.ip_address(ip)
            if not ip_addr.is_private:
                resolved_ips.append(ip)
            else:
                print(f"⚠️ Resolved IP {ip} for {target} is private and will be ignored.")

        return resolved_ips, True
    
    except socket.gaierror:
        # Name or service not known (DNS failure)
        return [], True # is_resolved_from_fqdn is True because we tried to resolve an FQDN
    except Exception as e:
        # Catch other errors, e.g., invalid input characters
        print(f"⚠️ Error during DNS resolution for {target}: {e}")
        return [], True


# --- Existing Function: IP Expander (Modified to handle FQDNs) ---
def expand_ips(input_list):
    """
    Expands a mixed list of individual IPs, CIDR ranges, and FQDNs into a
    dictionary of unique public IPs, tagged with their source (IP, CIDR, or FQDN).
    Returns: { 'ip_str': 'source_tag', ... }
    """
    print("🚀 Starting IP list processing...")
    
    # Trackers for the reporting
    total_original_lines = len(input_list)
    private_lines_found = set()
    total_expanded_private_ips = 0
    total_expanded_ips = 0
    
    # Dictionary to hold the final unique public IPs and their source tag
    # { '1.1.1.1': 'IP', '2.2.2.2': 'FQDN:example.com' }
    target_public_ips = {} 

    for entry in input_list:
        entry = entry.strip()
        if not entry:
            continue
            
        is_ip_or_cidr = False

        try:
            # 1. Try to parse as a network/CIDR (e.g., 192.168.1.0/24 or 8.8.8.8/32)
            network = ipaddress.ip_network(entry, strict=False)
            is_ip_or_cidr = True
            
            if network.is_private:
                private_lines_found.add(entry)
                total_expanded_private_ips += network.num_addresses
                total_expanded_ips += network.num_addresses
            else:
                for ip in network:
                    ip_str = ip.compressed
                    target_public_ips[ip_str] = 'CIDR'
                    total_expanded_ips += 1

        except ValueError:
            # 2. If it's not a valid IP/CIDR, assume it's an FQDN
            if not is_ip_or_cidr:
                # Attempt DNS resolution
                resolved_ips, is_fqdn = resolve_fqdn(entry)
                
                if is_fqdn and resolved_ips:
                    print(f"   [+] Resolved {entry} to {', '.join(resolved_ips)}")
                    for ip in resolved_ips:
                        target_public_ips[ip] = f"FQDN:{entry}"
                        total_expanded_ips += 1
                elif is_fqdn and not resolved_ips:
                    print(f"   [--] Failed to resolve FQDN: {entry} (or resolved to only private IP).")
                elif not is_fqdn and resolved_ips:
                    # This case should cover single IPs that were not parsed as /32 CIDR
                    ip_addr = ipaddress.ip_address(entry)
                    if ip_addr.is_private:
                        private_lines_found.add(entry)
                        total_expanded_private_ips += 1
                        total_expanded_ips += 1
                    else:
                        target_public_ips[entry] = 'IP'
                        total_expanded_ips += 1
                else:
                    print(f"⚠️ Skipping unknown entry format: {entry}")

    # --- Reporting ---
    private_list_filename = "private_ips_original_entries.txt"
    if private_lines_found:
        with open(private_list_filename, 'w') as f:
            f.write('\n'.join(sorted(list(private_lines_found))) + '\n')
        print(f"\n📢 Found Private IPs/CIDRs in {len(private_lines_found)} original line item(s). (Written to {private_list_filename})")
    else:
        print("\n📢 No private IPs or CIDR ranges found in the input list.")

    
    print("\n--- Summary of IP Processing ---")
    print(f"1. Total initial lines read: {total_original_lines}")
    print(f"2. Total theoretical expanded IPs: {total_expanded_ips}")
    print(f"3. Total expanded private IPs (Excluded): {total_expanded_private_ips}")
    print(f"4. Total unique Public IPs to check: {len(target_public_ips)}")
    
    return target_public_ips # Returns dictionary of IPs and their source tags


# --- Existing Function: Shodan Data Getter (Modified to accept IP/Source Dict) ---
def get_shodan_data(ip_dict, api_key, output_prefix="shodan_report"):
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
    
    # Added "Source_Tag" to the CSV headers
    csv_headers = ["IP", "Source_Tag", "FQDN_Hostnames", "Country", "Organization", "Open_Ports_Services"]
    
    successful_lookups = 0
    ip_list = list(ip_dict.keys()) # Get a list of IPs for iteration/counting

    with open(json_filename, 'w') as json_file, open(csv_filename, 'w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(csv_headers)
        
        for i, ip in enumerate(ip_list):
            source_tag = ip_dict.get(ip, 'Unknown') # Get the source tag for this IP
            print(f"🔎 [{i+1}/{len(ip_list)}] Looking up: {ip} ({source_tag[:12]}...)...", end='\r') 
            
            try:
                host_info = api.host(ip)
                successful_lookups += 1

                # --- A. Full JSON Dump ---
                # Add the source tag to the JSON for clarity
                host_info['__source_tag'] = source_tag 
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
                    source_tag, # New column for the source tag
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


# --- Main Function (Modified for Single Target Mode) ---
def main():
    parser = argparse.ArgumentParser(
        description="Expand IP/CIDR list or resolve FQDNs and query Shodan API for host information."
    )
    
    parser.add_argument(
        '-k', '--key', 
        type=str, 
        help="Your Shodan API Key. Overrides any hardcoded key.", 
        default=None
    )
    
    # New argument for single target
    parser.add_argument(
        '-t', '--target',
        type=str,
        help="Single IP or FQDN to scan (e.g., 8.8.8.8 or google.com). This takes precedence over the input file.",
        default=None
    )

    # Input file is now optional/positional
    parser.add_argument(
        'ip_file', 
        type=str, 
        nargs='?', # Makes the argument optional
        help="Path to the file containing IP addresses and/or CIDR ranges (one per line). Ignored if --target is used.",
    )
    
    args = parser.parse_args()
    
    # 1. Determine the API Key
    shodan_api_key = args.key
    if not shodan_api_key and shodan_hardcoded_key:
        shodan_api_key = shodan_hardcoded_key
        print("🔑 Using hardcoded API key.")
    elif not shodan_api_key:
        print("\n❌ Error: No Shodan API Key provided via argument (-k/--key) or hardcoded.")
        sys.exit(1)

    # 2. Determine Targets (Target argument takes precedence)
    target_ips_dict = {}

    if args.target:
        # Single Target Mode
        print(f"🎯 Single target mode active: {args.target}")
        resolved_ips, is_fqdn = resolve_fqdn(args.target)
        
        if resolved_ips:
            for ip in resolved_ips:
                # Tag the IP based on whether the input was an FQDN or IP
                source_tag = f"FQDN:{args.target}" if is_fqdn else "IP"
                target_ips_dict[ip] = source_tag
        else:
            print(f"🛑 Could not resolve target {args.target} to a public IP. Exiting.")
            sys.exit(0)
            
    elif args.ip_file:
        # File List Mode
        try:
            with open(args.ip_file, 'r') as f:
                ip_cidr_list = f.readlines()
        except FileNotFoundError:
            print(f"❌ Error: Input file not found at {args.ip_file}")
            sys.exit(1)
            
        target_ips_dict = expand_ips(ip_cidr_list)
        
    else:
        print("\n🛑 Error: Must provide either a single target (--target) or an input file path.")
        sys.exit(1)

    # 3. Final Check and Execution
    if not target_ips_dict:
        print("\n🛑 No public IP addresses remaining after processing and filtering. Exiting.")
        sys.exit(0)
        
    get_shodan_data(target_ips_dict, shodan_api_key)

if __name__ == "__main__":
    main()
