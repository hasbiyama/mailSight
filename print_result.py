"""
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

"""

from dmarc_compliance import check_spf, print_dkim_verification_details_from_headers

# Function to Print the results (for .msg and .eml)
def print_results(domains, ips, senders, received_froms, recipients, 
                  receive_bys, message_ids, dmarc_compliance, dates, 
                  mime_version, content_type, sender_domain, return_path,
                  msg_file, dkim_result, is_valid, headers_for_dkim):
    
    def print_section(title, items):
        print("\n ::::::::::::::::::::::")
        print(f"  {title} ")
        print(" ::::::::::::::::::::::\n")
        for item in items:
            print(f'[+] {item}')

    print_section("Domains", domains)
    print_section("Senders", senders)
    print_section("Recipients", recipients)
    print_section("Return-Path", [''.join(return_path)])
    print_section("Message-ID", message_ids)
    
    print("\n ::::::::::::::::::::::")
    print("  IP addresses ( POSSIBLE )")
    print(" ::::::::::::::::::::::\n")
    for ip in ips:
        print(f'[+] {ip}')
    
    print_section("Time", dates)
    print_section("(Received from)", received_froms)
    print_section("(Received by)", receive_bys)
    
    print("\n ::::::::::::::::::::::")
    print("  DMARC Compliant")
    print(" ::::::::::::::::::::::")
    print(dmarc_compliance)
    
    spf_result = check_spf(sender_domain, return_path)
    print(spf_result)
    print(dkim_result)
    
    if not is_valid:
        print_dkim_verification_details_from_headers(headers_for_dkim)
    
    print("\n ::::::::::::::::::::::")
    print("  MIME-Version")
    print(" ::::::::::::::::::::::\n")
    print("[+] ", mime_version)

    print("\n ::::::::::::::::::::::")
    print("  Content-Type")
    print(" ::::::::::::::::::::::\n")
    print("[+] ", content_type)