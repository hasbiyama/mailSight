"""
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

"""

from print_result import *
from time_adj import *
from constants import *
from req_imports import *
from dmarc_compliance import *
from content_proc import extract_email_contents
from qr_proc import extract_qr_codes_from_email

# Function to parse email headers from .eml files
def analyze_eml_headers(eml_file, all_emails):
    headers_for_dkim = []

    try:
        with open(eml_file, 'rb') as eml_binary:
            msg_for_dkim = BytesParser(policy=policy.default).parse(eml_binary)
            headers_for_dkim = list(msg_for_dkim.items())
    except FileNotFoundError:
        print(f"\n[-] Binary file {eml_file} not found.")

    is_valid, result_message = verify_dkim_signature_from_headers(headers_for_dkim)

    try:
        with open(eml_file, "r", encoding="utf-8") as eml_text:
            msg = Parser(policy=policy.default).parse(eml_text)

            # Check DMARC compliance for the sender's domain
            from_email = msg.get("From", "").strip("<>").lower()
            sender_domain = from_email.split('@')[-1]
            dmarc_compliance = check_dmarc_policy(sender_domain)

            # Extract email addresses from "To," "CC," and "BCC" fields in headers
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}'
            email_fields = ["To", "CC", "BCC", "From"]
            unique_emails_set = set()

            for field in email_fields:
                if field in msg:
                    email_matches = re.findall(email_pattern, msg[field])
                    unique_emails_set.update(email_matches)

            all_emails.extend(unique_emails_set)

            # Variables to store the Return-Path, MIME-Version and Content-Type
            return_path = msg.get("Return-Path", "")
            mime_version = msg.get("MIME-Version", "")
            content_type = msg.get("Content-Type", "")

            received_froms = []
            ips = []
            received_bys = []
            senders = []
            domains_set = set()
            recipients = []
            timestamps = []
            message_ids = []

            for key, value in msg.items():
                key_lower = key.lower()
                if key_lower == "received":
                    match = re.search(r'from\s+(\S+)\s+\(([^)]+)\)', value)
                    if match:
                        server = match.group(1)
                        received_froms.append(server)
                        ip = match.group(2)
                        ips.append(ip)
                        smtp_match = re.search(r'by\s+([^\s;]+)', value)
                        if smtp_match:
                            smtp_server = smtp_match.group(1)
                            received_bys.append(smtp_server)
                        time_adjuster = TimeAdjuster()
                        date_match = re.search(r'(\d+\s+[A-Za-z]+\s+\d+)\s+(\d+:\d+:\d+)', value)
                        if date_match:
                            date = date_match.group(1)
                            hour_min_sec = date_match.group(2)
                            timestamp = f"{date} {hour_min_sec}"
                            adjusted_timestamp = time_adjuster.adjust_time_to_pdt(timestamp)
                            timestamps.append(adjusted_timestamp)
                elif key_lower == "from":
                    email_matches = re.findall(email_pattern, value)
                    senders.extend(email_matches)
                    domains_set.update([match.split('@')[1] for match in email_matches])
                elif key_lower == "to":
                    email_matches = re.findall(email_pattern, value)
                    unique_emails_set = set(email_matches)
                    recipients.extend(unique_emails_set)
                    domains_set.update([match.split('@')[1] for match in unique_emails_set])
                elif key_lower == "message-id":
                    message_ids.append(value.strip())

            # Convert the set of unique domains back to a list for printing
            domains = list(domains_set)

            # Print the results including the MIME-Version, Content-Type, DKIM signature, and Return-Path
            print_results(
                domains, ips, senders, received_froms, recipients, received_bys,
                message_ids, dmarc_compliance, timestamps, mime_version, content_type, 
                sender_domain, return_path, eml_file, result_message, is_valid, headers_for_dkim)

    except FileNotFoundError:
        print(f"\n[-] Text file {eml_file} not found.")