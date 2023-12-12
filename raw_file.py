"""
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

"""

from req_imports import *
from time_adj import *
from dmarc_compliance import *
from qr_proc import extract_qr_codes_from_image
from help_func import remove_equals_and_newlines, clear_temp_folder, extract_domains_and_print_links

# Function to parse email headers from raw files        
def decode_header_str(header_str):
    # Decode the raw email header
    decoded = email.header.decode_header(header_str)
    result = []
    for text, charset in decoded:
        if charset is not None:
            try:
                text = text.decode(charset)
            except UnicodeDecodeError:
                pass
        result.append(text)
    return ' '.join(result)

def extract_urls_raw(text):
    # Remove newlines from the text
    text = text.replace("\n", "")

    # Regular expression pattern to match URLs
    url_pattern = r'(http[s]?://(?:[^\s<>"]+|www\.[^\s<>"]+))'

    # Extract URLs using regex
    urls = re.findall(url_pattern, text)

    # Create a set to store unique URLs
    unique_urls = set(urls)

    # Convert the set back to a list
    unique_urls = list(unique_urls)

    return unique_urls

def extract_email_addresses(text, img_extensions, doc_extensions):
    # Regular expression to match email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    addresses = set(re.findall(email_pattern, text))

    # Filter out email addresses with the specified extensions
    filtered_addresses = [address for address in addresses if not any(address.endswith(ext) for ext in img_extensions or doc_extensions)]

    return filtered_addresses

def extract_domain_from_email(email_address):
    # Extract the domain from an email address
    return email_address.split('@')[-1] if '@' in email_address else None

def extract_ips(text):
    # Regular expression to match IPv4 and IPv6 addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    ips = re.findall(ip_pattern, text)
    
    unique_ips = set(ips)  # Keep only unique IP addresses
    return list(unique_ips)

def extract_smtp_mailfrom(text):
    # Extract SMTP mailfrom value when mentioned
    smtp_mailfrom_pattern = r'\bsmtp\.mailfrom\s*=\s*([^\s;]+)'
    match = re.search(smtp_mailfrom_pattern, text, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    return None

def extract_qr_codes_from_folder(folder_path):
    # Extract QR codes from image along with file names
    qr_codes = []

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)

            # Loop through files in a directory
            if any(file.lower().endswith(ext) for ext in img_extensions):
                try:
                    extracted_qr_codes = extract_qr_codes_from_image(file_path)
                    for qr_code_data in extracted_qr_codes:
                        qr_codes.append((qr_code_data, file))
                except Exception:
                    pass

    return qr_codes

def analyze_raw_headers(raw_email_file):
    try:
        with open(raw_email_file, 'r', encoding='utf-8') as email_file:
            email_text = email_file.read()

        # Parse the raw email
        msg = email.message_from_string(email_text)

        # Extract email content
        subject = decode_header_str(msg['Subject'])
        from_address = decode_header_str(msg['From'])
        to_addresses = [decode_header_str(addr) for addr in msg.get_all('To', [])]

        # Extract the necessary info
        mime_version = msg.get('MIME-Version')
        content_type = msg.get('Content-Type')
        message_id = msg.get('Message-ID')
        return_path = msg.get('Return-Path')

        # Adjust the time to the local (machine) time
        time_adjuster = TimeAdjuster()

        # Extract the desired format using regex
        date_received_match = re.search(r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{1,2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2}", email_text)
        if date_received_match:
            date_received = date_received_match.group()
            received_time = datetime.datetime.strptime(date_received, "%a, %d %b %Y %H:%M:%S")
            adjusted_time = time_adjuster.adjust_time_raw_email(received_time)  # Adjust the received time to the machine's local time

        # Extract all "received from" and "received by" servers using regex
        received_from_matches = re.findall(r"from\s+(\S+)\s+\((.*?)\)\s+by", email_text)
        received_by_matches = re.findall(r"by\s+(\S+)\s+(?:with|for)", email_text)
        time_matches = re.search(r"(\w+,\s+\d+\s+\w+\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[-+]\d{4}(?:\s+\(\w+\))?)", email_text)

        # Extract the server names
        received_from_servers = received_from_matches if received_from_matches else ["Unknown"]
        received_by_servers = received_by_matches if received_by_matches else ["Unknown"]
        servers_time = time_matches.group(1)

        # Print the results
        print(f"\nSubject       : {subject}")
        print(f"From          : {from_address}")
        print(f"To            : {', '.join(to_addresses)}")
        print(f"Date          : {adjusted_time}")
        print(f"Return-Path   : {return_path}")
        print(f"MIME-Version  : {mime_version}")
        print(f"Content-Type  : {content_type}")
        print(f"Message-ID    : {message_id}")
        print("\n(Received From) :")
        for server in received_from_servers:
            print(f"                - {server} ({servers_time})")

        print("\n(Received By)   :")
        for server in received_by_servers:
            print(f"                - {server} ({servers_time})")

        # Removing all "=" and newlines from email_text
        email_text = remove_equals_and_newlines(email_text)

        # Extract and print email domains and IP addresses
        all_text = email_text + subject + from_address + ' '.join(to_addresses)
        domains = set(extract_domain_from_email(addr) for addr in extract_email_addresses(all_text, img_extensions, doc_extensions))
        ips = extract_ips(all_text)

        if domains:
            print("\n\n ###########")
            print(" | Domains |")
            print(" ###########")
            for domain in domains:
                print("\n[+] ", domain)

        if ips:
            print("\n\n ###########################")
            print(" | IP Addresses (POSSIBLE) |")
            print(" ###########################")
            for ip in ips:
                print("\n[+]", ip)

        # Extract and print SMTP mailfrom value when mentioned
        smtp_mailfrom = extract_smtp_mailfrom(all_text)
        if smtp_mailfrom:
            print("\n\n ###################")
            print(" | SMTP (mailfrom) |")
            print(" ###################")
            print(f"\n[+] {smtp_mailfrom}")

        # Extract domains from email addresses
        from_domain = from_address.split()[-1].strip('<>').split('@')[-1]
        return_path_domain = return_path.split()[-1].strip('<>').split('@')[-1]

        # Extract and print DMARC value when mentioned
        dmarc_value = check_dmarc_policy(from_domain)
        spf_check = check_spf(from_domain, return_path_domain)

        if dmarc_value:
            print("\n\n ####################")
            print(" | DMARC compliance |")
            print(" ####################")
            print(dmarc_value)
            print(spf_check)
            with open(raw_email_file, 'r') as f:
                raw_email_message = f.read()
                result_message = extract_and_verify_dkim_signature_raw(raw_email_message)
                print(result_message)
        
        clear_temp_folder(TEMP_FOLDER)  # Clear the TEMP_FOLDER before processing

        # Extract and print all links in the email
        links = extract_urls_raw(email_text)
        if links:
            print("\n\n\n\n<=========================================>\n")
            print("||\t\t\t\t\t||")
            print("||\t\tEMAIL_BODY\t\t||")
            print("||\t\t (links) \t\t||")
            print("\n<=========================================>\n\n")
            for link in links:
                print(link)

        extract_domains_and_print_links(email_text, img_extensions, doc_extensions)

        # Extract QR codes from the raw email file
        print("\n\n\n\n<=========================================>\n")
        print("||\t\t\t\t\t||")
        print("||\t\tQR_CODES\t\t||")
        print("||\t\t\t\t\t||")
        print("\n<=========================================>\n\n")
        qr_codes = extract_qr_codes_from_folder(TEMP_FOLDER)

        # Print the extracted QR codes
        if qr_codes:
            print("\n[!] QR found!  <[ QR Data ]>  \n")
            for qr_code, file_name in qr_codes:
                print(f"[+] {file_name} :: {qr_code} ")

        else:
            print("\n[-] No QR code found in the email.")

        # Extract and print unique email addresses mentioned in the email
        email_addresses = extract_email_addresses(email_text, img_extensions, doc_extensions)

        # Remove smtp_mailfrom and message-id from the list of email addresses if they exist
        if message_id and message_id.startswith('<') and message_id.endswith('>'):
            message_id = message_id[1:-1]

        email_addresses = [addr for addr in email_addresses if addr not in (smtp_mailfrom, message_id)]

        # Print the filtered list of email addresses
        if email_addresses:
            print("\n\n\n\n<=========================================>\n")
            print("||\t\t\t\t\t||")
            print("||\t     EMAIL_ADDRESSES\t\t||")
            print("||\t\t\t\t\t||")
            print("\n<=========================================>\n\n")
            for email_address in email_addresses:
                print("[+] ", email_address)
            print("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> [end]\n")

    except Exception as e:
        print(f"\n[-] Error: {str(e)}")

    sys.exit(0)