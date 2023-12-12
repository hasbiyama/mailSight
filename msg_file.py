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

# Function to analyze email headers from .msg files
def analyze_msg_headers(msg_file, all_emails):
    msg = Message(msg_file)

    headers = msg.header

    msg_for_dkim = Message(open(msg_file, 'rb').read())
    headers_for_dkim = list(msg_for_dkim.header.items())

    # Verify DKIM signature and print details using extracted headers
    is_valid, result_message = verify_dkim_signature_from_headers(headers_for_dkim)

    # Check DMARC compliance for the sender's domain
    from_email = headers.get("from", "").strip("<>").lower()
    sender_domain = from_email.split('@')[-1]
    dmarc_compliance = check_dmarc_policy(sender_domain)

    # Updated regular expression pattern to match email addresses
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}'

    # Variables to store the MIME-Version, Content-Type, DKIM signature, and Return-Path
    mime_version = None
    content_type = None
    dkim_signature = None
    return_path = None

    for key, value in headers.items():
        # Extract email addresses from "To," "CC," "BCC," and "From" fields in headers
        if key.lower() in ["to", "cc", "bcc", "from"]:
            email_matches = re.findall(email_pattern, value)
            if email_matches:
                unique_emails = set(email_matches)
                all_emails.extend(unique_emails)

        # Extract domains, IPs, and received_froms from headers
        if key.lower() == "received":
            # Extract IPs and received_froms from the "Received" header
            match = re.search(r'from\s+(\S+)\s+\(([^)]+)\)', value)
            if match:
                server = match.group(1)
                received_froms.append(server)
                ip = match.group(2)
                ips.append(ip)
                # Extract the SMTP server from the "Received" header (assuming it appears after "by" keyword)
                smtp_match = re.search(r'by\s+([^\s;]+)', value)
                if smtp_match:
                    smtp_server = smtp_match.group(1)
                    received_bys.append(smtp_server)
                # Extract the date, hours, minutes, and seconds from the "Received" header
                time_adjuster = TimeAdjuster()
                date_match = re.search(r'(\d+\s+[A-Za-z]+\s+\d+)\s+(\d+:\d+:\d+)', value)
                if date_match:
                    date = date_match.group(1)
                    hour_min_sec = date_match.group(2)
                    timestamp = f"{date} {hour_min_sec}"

                    # Adjust the time to the local (machine) time
                    timestamp = timestamp.translate(str.maketrans("", "", "\r\n\t"))
                    adjusted_timestamp = time_adjuster.adjust_time_to_gmt(timestamp)
                    timestamps.append(adjusted_timestamp)

        elif key.lower() == "from":
            # Extract the sender's email address and domain using the updated email pattern
            email_matches = re.findall(email_pattern, value)
            if email_matches:
                senders.extend(email_matches)
                domains_set.update([match.split('@')[1] for match in email_matches])

        elif key.lower() == "to":
            # Extract recipient email addresses and domains using the updated email pattern
            email_matches = re.findall(email_pattern, value)
            if email_matches:
                unique_emails = set(email_matches)
                recipients.extend(unique_emails)
                domains_set.update([match.split('@')[1] for match in unique_emails])

        elif key.lower() == "mime-version":
            mime_version = value
        elif key.lower() == "content-type":
            content_type = value
        elif key.lower() == "return-path":
            return_path = value
        elif key.lower() == "message-id":
            # Extract the Message-ID header value
            message_id = value.strip()
            message_ids.append(message_id)

    # Convert the set of unique domains back to a list for printing
    domains = list(domains_set)

    # Print the results including the MIME-Version, Content-Type, DKIM signature, and Return-Path
    print_results(
        domains, ips, senders, received_froms, recipients, received_bys,
        message_ids, dmarc_compliance, timestamps, mime_version, content_type, 
        sender_domain, return_path, msg_file, result_message, is_valid, headers_for_dkim)