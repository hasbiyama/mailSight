"""
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

"""

from msg_file import *
from eml_file import *
from raw_file import *
from content_proc import extract_attachments_from_eml
from help_func import clear_temp_folder, extract_domains_and_print_links

banner = """
               .__.__    _________.__       .__     __    
  _____ _____  |__|  |  /   _____/|__| ____ |  |___/  |_  
 /     \\__   \\ |  |  |  \\_____  \\ |  |/ ___\\|  |  \\   __\\ 
|  Y Y  \\/ __ \\|  |  |__/        \\|  / /_/  >   Y  \\  |   
|__|_|  (____  /__|____/_______  /|__\\___  /|___|  /__|   
      \\/     \\/                \\/   /_____/      \\/       
   
                <( github.com/hasbiyama )>
"""

def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    file_path = sys.argv[1]
    safelink_option = "-orgurl" in sys.argv[2:]

    _, file_extension = os.path.splitext(file_path)
    file_extension = file_extension.lower()

    if file_extension in (".msg", ".eml", ".txt"):
        print_headers()
        if file_extension == ".msg":
            analyze_msg_headers(file_path, all_emails)
        elif file_extension == ".eml":
            analyze_eml_headers(file_path, all_emails)
        else:
            analyze_raw_headers(file_path)

        print_listOf_attachments(file_path)
        print_email_body(file_path, safelink_option)
        print_qr_codes(file_path)

    else:
        print("\n[-] Invalid file format. Supported formats: .msg, .eml, and .txt")

    print_email_addresses()

def print_usage():
    print("\n>> Usage: " + sys.argv[0] + " <.msg/.eml/.txt path> [-orgurl] <outputFolder>\n")

def print_headers():
    print("\n<=========================================>\n")
    print("||\t\t\t\t\t||")
    print("||\t\t HEADERS\t\t||")
    print("||\t\t\t\t\t||")
    print("\n<=========================================>\n\n")

def print_listOf_attachments(email_file_path):
    print("\n\n\n\n<=========================================>\n")
    print("||\t\t\t\t\t||")
    print("||\t\t ATTACHMENTS\t\t||")
    print("||\t\t\t\t\t||")
    print("\n<=========================================>\n\n")

    clear_temp_folder(TEMP_FOLDER)  # Clear the TEMP_FOLDER before processing

    file_extension = os.path.splitext(email_file_path)[-1]
    attachments_saved = []

    if file_extension.lower() == ".msg":
        msg = Message(email_file_path)
        attachments_saved = msg.saveAttachments(customPath=TEMP_FOLDER)
    elif file_extension.lower() == ".eml":
        attachments_saved = extract_attachments_from_eml(email_file_path)

    for attachment_filename in os.listdir(TEMP_FOLDER):
        print(f"[+] {attachment_filename}")

def print_email_body(file_path, safelink_option):
    print("\n\n\n\n<=========================================>\n")
    print("||\t\t\t\t\t||")
    print("||\t\tEMAIL_BODY\t\t||")
    print("||\t\t (links) \t\t||")
    print("\n<=========================================>\n\n")

    extracted_data = extract_email_contents(file_path, safelink_option)
    json_data = json.dumps(extracted_data, indent=4)
    print("\n" + json_data + "\n")
    if not isinstance(extracted_data, str):
        extracted_data = str(extracted_data)
    extract_domains_and_print_links(extracted_data, img_extensions, doc_extensions)

def print_qr_codes(file_path):
    print("\n\n\n\n<=========================================>\n")
    print("||\t\t\t\t\t||")
    print("||\t\tQR_CODES\t\t||")
    print("||\t\t\t\t\t||")
    print("\n<=========================================>\n\n")

    qr_codes = extract_qr_codes_from_email(file_path)
    if qr_codes:
        print("\n[!] QR found!  <[ QR Data ]>  \n")
        for qr_code, file_name in qr_codes:
            file_name = str(file_name)  # Convert to string if it's not already
            filename_without_numbers = re.sub(r'\s*\(\d+\)', '', file_name)
            print(f"[+] {filename_without_numbers} :: {qr_code} ")

    else:
        print("\n[-] No QR code found in the email.")

def print_email_addresses():
    if all_emails:
        print("\n\n\n\n<=========================================>\n")
        print("||\t\t\t\t\t||")
        print("||\t     EMAIL_ADDRESSES\t\t||")
        print("||\t\t\t\t\t||")
        print("\n<=========================================>\n\n")
        for email in all_emails:
            print("[+] ", email)
        print("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> [end]\n")

if __name__ == "__main__":
    print(banner)  # Print the banner when the script is executed
    main()