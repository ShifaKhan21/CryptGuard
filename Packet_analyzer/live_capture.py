import subprocess
import os
import sys
import time
import re
import platform

# Constants
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe" if platform.system() == "Windows" else "tshark"
DPI_ENGINE_PATH = "dpi_engine.exe" if platform.system() == "Windows" else "./dpi_engine"
TEMP_PCAP = "live_temp_capture.pcap"
TEMP_OUT = "live_temp_output.pcap"
CAPTURE_DURATION = 1  # seconds (Faster updates)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def get_interfaces():
    """Returns a list of available network interfaces from tshark."""
    try:
        if platform.system() == "Windows":
             # Provide full path to tshark if on Windows
             cmd = [TSHARK_PATH, "-D"]
        else:
             cmd = ["tshark", "-D"]
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        interfaces = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if line:
                interfaces.append(line)
        return interfaces
    except FileNotFoundError:
        print("Error: tshark is not installed or not found in your PATH.")
        print(f"I tried looking for it at: {TSHARK_PATH}")
        print("Please install Wireshark and ensure tshark is available.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
         print(f"Error fetching interfaces: {e}")
         sys.exit(1)


def capture_traffic(interface_id, duration):
    """Captures traffic using tshark to a temporary PCAP file."""
    try:
        cmd = [TSHARK_PATH, "-i", str(interface_id), "-a", f"duration:{duration}", "-w", TEMP_PCAP, "-F", "pcap", "-q"]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error during packet capture: {e}")
        return False
    return True


def run_dpi_engine():
    """Runs the DPI engine on the captured PCAP and returns its output."""
    if not os.path.exists(TEMP_PCAP):
        return ""
        
    try:
        # We need to run the DPI engine using MSYS2 bash because it's compiled with MSYS2 environment
        # and depends on MSYS DLLs (libgcc_s_seh-1.dll, libstdc++-6.dll, libwinpthread-1.dll)
        
        dpi_cmd = [
            r"C:\msys64\usr\bin\bash.exe", "-lc",
            f"export PATH=/mingw64/bin:$PATH && ./{DPI_ENGINE_PATH} {TEMP_PCAP} {TEMP_OUT}"
        ]
        
        result = subprocess.run(dpi_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
        return result.stdout
    except Exception as e:
        print(f"Error running DPI engine: {e}")
        return ""

def parse_and_display_live_traffic(dpi_output, total_stats):
    """Parses output from the DPI engine and continuously aggregates/displays stats."""
    
    # 1. Extract SNIs 
    sni_section = False
    new_snis = 0
    for line in dpi_output.split("\n"):
        line = line.strip()
        if "[Detected Domains/SNIs]" in line:
            sni_section = True
            continue
            
        if sni_section:
            if not line:
                break # End of section
            
            # Format is usually: "- www.example.com -> Category"
            if line.startswith("- "):
                parts = line[2:].split(" -> ")
                domain = parts[0]
                category = parts[1] if len(parts) > 1 else "Unknown"
                
                # Update aggregated stats
                if domain not in total_stats['domains']:
                    total_stats['domains'][domain] = {'count': 0, 'category': category}
                    new_snis += 1
                total_stats['domains'][domain]['count'] += 1
                
    # 2. Render Dashboard
    clear_screen()
    print("=" * 60)
    print(" 📡 CRYPTGUARD DPI: REAL-TIME TRAFFIC MONITOR ".center(60))
    print("=" * 60)
    print("Press Ctrl+C to stop.".center(60))
    print(f"Status: Listening... (updating every {CAPTURE_DURATION} seconds)")
    print("-" * 60)
    
    print(f"\n[Live Feed] {new_snis} new domain(s) detected this interval.")
    print("\n🔥 **Top Network Destinations Discovered** 🔥")
    print(f"{'Domain / SNI':<40} | {'Category':<15} | {'Hits'}")
    print("-" * 60)
    
    # Sort by hits descending
    sorted_domains = sorted(total_stats['domains'].items(), key=lambda x: x[1]['count'], reverse=True)
    
    for domain, data in sorted_domains[:15]: # Show top 15
        print(f"{domain[:38]:<40} | {data['category'][:13]:<15} | {data['count']}")
        
    print("\n" + "=" * 60)

def main():
    print("Initializing Real-Time DPI Monitor...")
    
    # Pre-flight checks
    if not os.path.exists("C:\\msys64\\usr\\bin\\bash.exe"):
        print("Error: Could not find MSYS2 bash environment. Please ensure MSYS2 is installed at C:\\msys64")
        sys.exit(1)
        
    interfaces = get_interfaces()
    if not interfaces:
        print("No network interfaces found!")
        sys.exit(1)
        
    print("\nAvailable Network Interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"  {iface}")
        
    # Get user interface selection
    while True:
        try:
            choice = input("\nEnter the index number of the interface to monitor (e.g. 1, 2...): ")
            interface_idx = int(choice)
            break
        except ValueError:
            print("Please enter a valid number.")
    
    print("\nStarting live capture... Setting up streams.")
    time.sleep(1)
    
    # Data aggregation state
    total_stats = {
        'domains': {}
    }
    
    try:
        while True:
            # 1. Capture chunk of traffic
            success = capture_traffic(interface_idx, CAPTURE_DURATION)
            
            if success:
                # 2. Process chunk through C++ DPI engine
                dpi_output = run_dpi_engine()
                
                # 3. Aggregate data & render dashboard
                parse_and_display_live_traffic(dpi_output, total_stats)
                
            # Cleanup temp files for next iteration
            if os.path.exists(TEMP_PCAP): os.remove(TEMP_PCAP)
            if os.path.exists(TEMP_OUT): os.remove(TEMP_OUT)
            
    except KeyboardInterrupt:
        print("\n\nStopping real-time monitor.")
        if os.path.exists(TEMP_PCAP): os.remove(TEMP_PCAP)
        if os.path.exists(TEMP_OUT): os.remove(TEMP_OUT)
        sys.exit(0)

if __name__ == "__main__":
    main()
