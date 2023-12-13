"""
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

"""

from req_imports import *
from help_func import check_internet_connection

# Function to check DMARC Compliance
def check_spf(sender_domain, return_path):
    try:
        spf_query = dns.resolver.resolve(sender_domain, 'TXT')
        spf_records = [txt_record.to_text() for txt_record in spf_query]

        if not check_internet_connection():
            return "\n[-] Unable to connect to the internet. Skipping SPF check."

        for spf_text in spf_records:
            if "v=spf1" in spf_text:
                mechanisms = ("all", "include", "a", "mx", "redirect")
                if any(mechanism in spf_text for mechanism in mechanisms):
                    if return_path.endswith(sender_domain):
                        return f"[+] SPF Passed: Sender is authorized and aligned ({sender_domain})"
                    else:
                        return f"[-] SPF Failed: Sender is authorized but not aligned ({sender_domain})"

        return "[-] SPF Failed: No SPF record found"

    except dns.resolver.NXDOMAIN:
        return f"[-] DNS record not found for {sender_domain}"
    except dns.resolver.NoAnswer:
        return f"[-] No DNS answer for {sender_domain}"
    except dns.resolver.Timeout:
        return f"[-] DNS resolution timeout for {sender_domain}"
    except Exception as e:
        return f"[-] SPF Failed: {str(e)}"

def verify_dkim_signature_from_headers(headers):
    
    if not check_internet_connection():
        return "\n[-] Unable to connect to the internet. Skipping DKIM check."
    
    try:
        # Encode the header with UTF-8
        email_msg_headers = b"\r\n".join([f"{name}: {value}".encode('utf-8') for name, value in headers])

        # Verify the DKIM signature
        result = dkim.verify(email_msg_headers, logger=None)
        
        # Extract the 'from' and 'd=' values from the DKIM signature
        from_header = next((value for name, value in headers if name.lower() == 'from'), '')
        from_domain = re.search(r'@([^\s>]+)', from_header).group(1) if from_header else ''
        
        dkim_signature = next((value for name, value in headers if name.lower() == 'dkim-signature'), '')
        d_value_match = re.search(r'd=([^\s;]+)', dkim_signature)
        d_value = d_value_match.group(1) if d_value_match else None
        
        # Check DKIM alignment
        alignment_result = ""
        if from_domain and d_value:
            if from_domain == d_value:
                alignment_result = f"[+] DKIM alignment is aligned ({from_domain})."
            else:
                alignment_result = f"[-] DKIM alignment is not aligned. From: {from_domain}, d=: {d_value}"
        
        return result, alignment_result + "\n[+] DKIM signature is valid. " if result else alignment_result + "\n[-] DKIM signature is invalid. " 

    except Exception as e:
        return False, f"[-] Error: {str(e)}"

def print_dkim_verification_details_from_headers(headers):
    if not check_internet_connection():
        return "\n[-] Unable to connect to the internet. Skipping DKIM (details) check."

    try:
        # Create a fake email message with the extracted headers
        email_msg_headers = b"\r\n".join([f"{name}: {value}".encode('utf-8') for name, value in headers])

        # Perform DKIM verification and print details
        verifier = dkim.DKIM(email_msg_headers)
        verification_result = verifier.verify()
        for key, value in verification_result.items():
            print(f"{key}: {value}")

    except dkim.ValidationError as ve:
        error_message = str(ve)
        if "x= value is past" in error_message:
            timestamp_match = re.search(r"b'(\d+)'", error_message)
            if timestamp_match:
                timestamp_value = int(timestamp_match.group(1))
                timestamp = datetime.datetime.fromtimestamp(timestamp_value).strftime('%Y-%m-%d %H:%M:%S (local_time)')
                print(f"[-] DKIM signature has expired. Expiration timestamp: {timestamp}")
        else:
            print(f"[-] DKIM validation error: {error_message}")
    except Exception as e:
        print(f"[-] Error during verification: {str(e)}")

# Function to extract and verify DKIM signature
def extract_and_verify_dkim_signature_raw(email_message):
    def get_signature_components(dkim_signature):
        return {key.strip(): value.strip() for key, value in (component.split("=", 1) for component in dkim_signature.split(";"))}

    def compute_email_body_hash(email_body):
        return base64.b64encode(hashlib.sha256(email_body.encode()).digest()).decode()

    try:
        # Define a regular expression pattern to search for the DKIM signature
        dkim_signature_match = re.search(r'DKIM-Signature:(.*?)(?=\n\S+:|$)', email_message, re.DOTALL)
        if not dkim_signature_match:
            return "[-] No DKIM signature found"

        dkim_signature = re.sub(r'\s+', '', dkim_signature_match.group(1).strip())
        signature_components = get_signature_components(dkim_signature)

        v = signature_components.get("v")
        a = signature_components.get("a")
        s = signature_components.get("s")
        d = signature_components.get("d")
        h = signature_components.get("h")
        bh = signature_components.get("bh")
        b = signature_components.get("b")

        # Use DNS to automatically retrieve the DKIM selector, domain, and public key
        selector = s
        domain = d

        # Get the "From" domain from the email's header
        from_domain_match = re.search(r'From:\s.*?@([^>]+)', email_message)
        if not from_domain_match:
            return "[-] No 'From' domain found in the email header"

        from_domain = from_domain_match.group(1).strip()

        if v != "1" or a != "rsa-sha256":
            return f"[-] Invalid DKIM version or algorithm: v={v}, a={a}"

        # Check strict alignment between the DKIM domain and the "From" domain
        if d != from_domain:
            print("[-] DKIM signature is not strictly aligned.")
            print(f"[-] DKIM domain ({d}) does not match 'From' domain ({from_domain})")
        else:
            print(f"[+] DKIM is aligned. DKIM domain ({d}), 'From' domain ({from_domain})")

        # Query DNS for the public key record (TXT record)
        txt_records = dns.resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
        public_key_pem = "".join(str(txt_record) for txt_record in txt_records)

        # Get the header fields specified in the 'h' tag
        header_fields = {field: email_message[email_message.find(field):].split("\n")[0] for field in h}

        # Prepare the email body for hashing (remove leading empty lines)
        email_body = email_message[email_message.find("\n\n") + 2:]
        computed_bh = compute_email_body_hash(email_body)

        if bh != computed_bh:
            return f"[-] DKIM signature is invalid. \n[-] Body hash didn't match: bh={bh}, computed_bh={computed_bh}"

        # Perform RSA signature verification using the retrieved public key
        public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        signature = base64.b64decode(b)

        try:
            public_key.verify(signature, email_body.encode(), padding.PKCS1v15(), hashes.SHA256())
            # If verification is successful, return True
            return "[+] DKIM signature is valid and authorized."
        except ValueError as ve:
            return f"[-] DKIM signature is invalid. \n[-] RSA signature verification failed: {ve}"
        except Exception as e:
            return f"[-] DKIM signature is invalid. \n[-] Error during RSA signature verification: {e}"

    except dns.resolver.NXDOMAIN as nxdomain:
        return f"[-] DNS query failed (NXDOMAIN): {nxdomain}"
    except dns.resolver.NoAnswer as noanswer:
        return f"[-] DNS query failed (NoAnswer): {noanswer}"
    except Exception as e:
        return f"[-] Error retrieving DKIM information from DNS: {e}"

# Function to check DMARC policy
def check_dmarc_policy(domain):
    if not check_internet_connection():
        return "\n[-] Unable to connect to the internet. Skipping DMARC policy check."

    try:
        # Query DNS for DMARC TXT record
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')

        for answer in answers:
            # Check for DMARC policy in the TXT record
            dmarc_policy = answer.to_text()

            # Validate DMARC policy
            if 'v=DMARC1' not in dmarc_policy:
                return "\n[-] Invalid DMARC policy found in DNS"

            # Extract policy value from DMARC policy
            policy_value = None
            policy_parts = dmarc_policy.split(';')
            for part in policy_parts:
                if part.strip().startswith('p='):
                    policy_value = part.strip().split('=')[1]
                    break

            if policy_value is None:
                return "\n[-] No DMARC policy found in DNS"

            # Perform comprehensive policy checks
            if policy_value == 'reject':
                return f"\n[+] DMARC policy is 'reject' ({domain})"
            elif policy_value == 'quarantine':
                return f"\n[+] DMARC policy is 'quarantine' ({domain})"
            elif policy_value == 'none':
                return f"\n[+] DMARC policy is 'none' ({domain})"
            else:
                return "\n[-] Unknown DMARC policy found in DNS"

        return "\n[-] No DMARC policy found in DNS"
    except dns.resolver.NXDOMAIN:
        return "\n[-] No DMARC record found in DNS"