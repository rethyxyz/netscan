import ipaddress
import socket
import threading
import time
import json
import os
from queue import Queue
from datetime import datetime, timedelta

#
# Global Variables
#
THREAD_COUNT = 50
SCAN_TIMEOUT = 1.0
OUTPUT_FILE = "scan_results.txt"
DATABASE_FILE = "scan_database.json"
# Process IPs in blocks to save memory. Otherwise, we'd need a lot of data type
# optimization or RAM.
IP_BLOCK_SIZE = 1000
# Days after which entries are considered stale
ENTRY_EXPIRE_DAYS = 30

# Common ports to check
TARGET_PORTS = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    445: 'smb',
    # Web services
    80: 'http',
    443: 'https',
    8080: 'http-alt',
    8443: 'https-alt',
    8000: 'http-dev',
    3000: 'http-dev',
    # Database services
    3306: 'mysql',
    5432: 'postgresql',
    1433: 'mssql',
    1521: 'oracle',
    27017: 'mongodb',
    6379: 'redis',
    5984: 'couchdb',
    9200: 'elasticsearch',
    # Remote access
    3389: 'rdp',
    5900: 'vnc',
    5901: 'vnc',
    4899: 'radmin',
    # Email services
    25: 'smtp',
    110: 'pop3',
    143: 'imap',
    993: 'imaps',
    995: 'pop3s',
    # File sharing
    139: 'netbios',
    135: 'rpc',
    2049: 'nfs',
    111: 'rpcbind',
    # Network services
    53: 'dns',
    161: 'snmp',
    162: 'snmp-trap',
    69: 'tftp',
    514: 'syslog',
    123: 'ntp',
    # Messaging/Communication
    1883: 'mqtt',
    5672: 'amqp',
    61613: 'stomp',
    # Development/Debug
    9000: 'dev',
    5000: 'dev',
    4000: 'dev',
    3001: 'dev',
    # Industrial/IoT
    502: 'modbus',
    102: 'iso-tsap',
    44818: 'opcua',
    20000: 'dnp3',
    # Backup/Sync
    873: 'rsync',
    22000: 'syncthing',
    # Virtualization
    2376: 'docker',
    8006: 'proxmox',
    902: 'vmware',
    # Misc vulnerable services
    1900: 'upnp',
    5060: 'sip',
    1723: 'pptp',
    500: 'ipsec',
    4500: 'ipsec-nat'
}

database_lock = threading.Lock()
results_lock = threading.Lock()
database_data = {}
results = []
scanned_ips = 0
start_time = time.time()
current_block = 0
running = True

def load_database():
    """
    Load existing database or create new one.
    """
    global database_data
    if os.path.exists(DATABASE_FILE):
        try:
            with open(DATABASE_FILE, 'r') as f:
                database_data = json.load(f)
        except (json.JSONDecodeError, IOError):
            print(f"Warning: Could not load {DATABASE_FILE}, starting with empty database")
            database_data = {}
    else:
        database_data = {}

def save_database():
    """
    Save database to file.
    """
    with database_lock:
        try:
            with open(DATABASE_FILE, 'w') as f:
                json.dump(database_data, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save database: {e}")

def get_ip_data(ip):
    """
    Get stored data for an IP.
    """
    with database_lock:
        return database_data.get(str(ip), {})

def update_ip_data(ip, port, service, status, banner="", force_update=False):
    """
    Update IP data in database.
    """
    ip_str = str(ip)
    current_time = datetime.now().isoformat()
    
    with database_lock:
        if ip_str not in database_data:
            database_data[ip_str] = {
                'first_seen': current_time,
                'last_updated': current_time,
                'ports': {}
            }
        
        port_key = f"{port}/{service}"
        existing_port_data = database_data[ip_str]['ports'].get(port_key, {})
        
        new_port_data = {
            'status': status,
            'banner': banner,
            'last_seen': current_time
        }
        
        # Check if data has changed
        data_changed = (
            existing_port_data.get('status') != status or
            existing_port_data.get('banner') != banner or
            force_update
        )
        
        if data_changed:
            database_data[ip_str]['ports'][port_key] = new_port_data
            database_data[ip_str]['last_updated'] = current_time
            return True  # Data was updated
        
        return False  # No changes

def remove_stale_ports(ip, current_open_ports):
    """
    Remove ports that are no longer open.
    """
    ip_str = str(ip)
    current_time = datetime.now().isoformat()
    
    with database_lock:
        if ip_str not in database_data:
            return
        
        existing_ports = list(database_data[ip_str]['ports'].keys())
        ports_to_remove = []
        
        for port_key in existing_ports:
            port_num = int(port_key.split('/')[0])
            if port_num not in current_open_ports and database_data[ip_str]['ports'][port_key]['status'] == 'open':
                ports_to_remove.append(port_key)
        
        if ports_to_remove:
            for port_key in ports_to_remove:
                # Mark as closed instead of removing completely
                database_data[ip_str]['ports'][port_key]['status'] = 'closed'
                database_data[ip_str]['ports'][port_key]['last_seen'] = current_time
            
            database_data[ip_str]['last_updated'] = current_time

def cleanup_old_entries(days_old=ENTRY_EXPIRE_DAYS):
    """
    Remove entries older than specified days
    """
    cutoff_date = datetime.now() - timedelta(days=days_old)
    
    with database_lock:
        ips_to_remove = []
        
        for ip, data in database_data.items():
            try:
                last_updated = datetime.fromisoformat(data['last_updated'])
                if last_updated < cutoff_date:
                    ips_to_remove.append(ip)
            except (ValueError, KeyError):
                # Invalid date format, mark for removal
                ips_to_remove.append(ip)
        
        for ip in ips_to_remove:
            del database_data[ip]
        
        if ips_to_remove:
            print(f"Cleaned up {len(ips_to_remove)} old entries from database")

def scan_port(ip, port, service, queue):
    """
    Scan a single port on an IP"""
    try:
        # Print the IP being scanned
        with results_lock:
            print(f"Scanning {ip} (Block {current_block})", end='\r')
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SCAN_TIMEOUT)
            result = s.connect_ex((str(ip), port))
            if result == 0:  # Port is open
                banner = ""
                try:
                    banner = s.recv(1024).decode('utf-8', 'ignore').strip()
                except:
                    pass
                
                # Check if this is new or changed information
                data_changed = update_ip_data(ip, port, service, 'open', banner)
                
                with results_lock:
                    result_line = f"{ip}:{port} ({service}) - Open - {banner[:50]}"
                    results.append(result_line)
                    
                    if data_changed:
                        print(f"\n[+] Found open {service} on {ip}:{port} - {banner[:50]}... [NEW/UPDATED]")
                    else:
                        print(f"\n[+] Found open {service} on {ip}:{port} - {banner[:50]}... [KNOWN]")
            else:
                # Port is closed, update database if it was previously open
                existing_data = get_ip_data(ip)
                port_key = f"{port}/{service}"
                if existing_data.get('ports', {}).get(port_key, {}).get('status') == 'open':
                    update_ip_data(ip, port, service, 'closed')

    except Exception as e:
        pass
    finally:
        queue.task_done()

def worker(queue):
    """
    Worker thread function.
    """
    global running
    while running:
        item = queue.get()
        if item is None:
            break
        ip, port, service = item
        scan_port(ip, port, service, queue)

def generate_public_ips():
    """
    Generator that yields public IPs in blocks.
    """
    current_block = []
    for int_addr in range(2**32):
        ip = ipaddress.IPv4Address(int_addr)
        if ip.is_global:
            current_block.append(ip)
            if len(current_block) >= IP_BLOCK_SIZE:
                yield current_block
                current_block = []
    if current_block:  # Yield any remaining IPs
        yield current_block

def save_results():
    """
    Save current results and clear memory.
    """
    global results
    if results:
        with open(OUTPUT_FILE, 'a') as f:  # Append mode
            f.write("\n".join(results) + "\n")
        results = []

def progress_monitor():
    """
    Monitor and display scanning progress.
    """
    global running, scanned_ips, start_time, current_block
    while running:
        with results_lock:
            elapsed = time.time() - start_time
            ips_per_sec = scanned_ips / elapsed if elapsed > 0 else 0
            print(f"Block {current_block} | IPs: {scanned_ips} | {ips_per_sec:.1f} IPs/sec", end='\r')
        time.sleep(1)

def main():
    """
    Main scanning function.
    """
    global running, scanned_ips, current_block

    load_database()
    cleanup_old_entries()
    
    queue = Queue()
    threads = []
    for _ in range(THREAD_COUNT):
        t = threading.Thread(target=worker, args=(queue,))
        t.start()
        threads.append(t)

    # Start progress monitoring thread
    monitor_thread = threading.Thread(target=progress_monitor)
    monitor_thread.start()

    # Infinite scanning loop
    scan_cycle = 0
    try:
        while True:
            scan_cycle += 1
            print(f"\n=== Starting scan cycle {scan_cycle} ===")
            
            # Reset block counter for each cycle
            current_block = 0
            cycle_start_time = time.time()
            cycle_scanned_ips = 0
            
            # Process IPs in blocks
            for block in generate_public_ips():
                current_block += 1
                
                # Add current block to queue
                for ip in block:
                    for port, service in TARGET_PORTS.items():
                        queue.put((ip, port, service))
                
                # Wait for current block to complete
                queue.join()

                with results_lock:
                    scanned_ips += len(block)
                    cycle_scanned_ips += len(block)
                    
                # Save results and database after each block
                save_results()
                save_database()
                
                # Optional: Check if we should stop (for graceful shutdown)
                if not running:
                    break
            
            # Cycle completion stats
            cycle_elapsed = time.time() - cycle_start_time
            cycle_ips_per_sec = cycle_scanned_ips / cycle_elapsed if cycle_elapsed > 0 else 0
            
            print(f"\n=== Completed scan cycle {scan_cycle} ===")
            print(f"Cycle stats: {cycle_scanned_ips} IPs in {cycle_elapsed:.1f}s ({cycle_ips_per_sec:.1f} IPs/sec)")
            print(f"Total scanned: {scanned_ips} IPs")
            
            # Cleanup old entries after each full cycle
            cleanup_old_entries()
            
            # Brief pause between cycles to prevent overwhelming the system
            print("Starting next cycle in 10 seconds...")
            time.sleep(10)
            
    except KeyboardInterrupt:
        print("\n\nReceived interrupt signal. Shutting down gracefully...")
        running = False
    
    # Cleanup
    running = False
    for _ in range(THREAD_COUNT):
        queue.put(None)
    for t in threads:
        t.join()
    
    monitor_thread.join()
    
    # Final save
    save_results()
    save_database()

    print(f"\n\nScan stopped. Total scanned: {scanned_ips} IPs across {scan_cycle} cycles.")
    print(f"Results saved to {OUTPUT_FILE}.")
    print(f"Database saved to {DATABASE_FILE}.")

if __name__ == "__main__":
    print("\nnetscan: IPv4 public address space scanner.")
    print("<https://articles.rethy.xyz/articles/netscan/>")
    print("Press Ctrl+C to stop gracefully")
    print(f"Database file: {DATABASE_FILE}")
    main()
