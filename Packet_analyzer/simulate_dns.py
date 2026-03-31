import subprocess
import time
import random
import string

def run_nslookup(domain):
    print(f"[*] Querying: {domain}")
    try:
        # We use a non-existent or real domain, either way a Query packet is sent
        subprocess.run(['nslookup', domain], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[!] Error querying {domain}: {e}")

def generate_random_domain(length=20):
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length)) + ".cryptguard-sim.test"

def main():
    print("="*60)
    print("   CryptGuard DNS Intelligence Simulation")
    print("   This script triggers real DNS packets to verify heuristics.")
    print("="*60)
    print("\n[STEP 1] Normal DNS Query")
    run_nslookup("google.com")
    time.sleep(1)

    print("\n[STEP 2] LONG_DOMAIN Heuristic (>30 chars)")
    # Triggering a very long domain query (common in tunneling)
    long_domain = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0" + ".malicious-tunnel.com"
    run_nslookup(long_domain)
    time.sleep(1)

    print("\n[STEP 3] LOW_READABILITY / ENTROPY Heuristic")
    # Triggering high-entropy random domains (common in DGAs)
    for _ in range(3):
        random_dom = generate_random_domain(25)
        run_nslookup(random_dom)
        time.sleep(0.5)

    print("\n[STEP 4] Mixed DNS Types (MX/TXT)")
    try:
        print("[*] Querying MX for gmail.com")
        subprocess.run(['nslookup', '-type=mx', 'gmail.com'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except: pass

    print("\n" + "="*60)
    print("   Simulation Complete!")
    print("   1. Ensure CryptGuard API Server is running.")
    print("   2. Ensure 'Live Traffic' scan is ACTIVE in the dashboard.")
    print("   3. Check the '🔎 DNS Intelligence' tab for results.")
    print("="*60)

if __name__ == "__main__":
    main()
