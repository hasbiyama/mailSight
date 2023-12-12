"""
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

"""

from constants import *
from req_imports import *
from help_func import remove_equals_and_newlines

def extract_urls(text, safelink_option):

    # Regular expression pattern to match URLs
    url_pattern = r'(http[s]?://(?:[^\s<>"]+|www\.[^\s<>"]+))'

    # Extract URLs using regex
    urls = re.findall(url_pattern, text)

    # Process URLs
    processed_urls = []
    seen_urls = set()

    for url in urls:
        if safelink_option:
            original_url = remove_safelink(url)
            if original_url not in seen_urls:
                processed_urls.append(original_url)
                seen_urls.add(original_url)
        else:
            if url not in seen_urls:
                processed_urls.append(url)
                seen_urls.add(url)

    return processed_urls

# Function to extract attachments from .eml file
def extract_attachments_from_eml(eml_file_path):
    attachments_saved = []
    with open(eml_file_path, "rb") as eml_file:
        msg = email.message_from_binary_file(eml_file)
        for part in msg.walk():
            if part.get_content_disposition() and part.get_filename():
                attachment_filename = part.get_filename()
                attachment_path = os.path.join(TEMP_FOLDER, attachment_filename)
                with open(attachment_path, "wb") as attachment_file:
                    attachment_file.write(part.get_payload(decode=True))
                attachments_saved.append(attachment_filename)
    return attachments_saved

# Function to extract the subject from .eml content
def extract_subject(eml_content):
    subject = re.search(r"Subject: (.+?)(?=Received: from )", eml_content)
    return subject.group(1).strip() if subject else ""

# Function to extract contents from .eml file
def extract_eml_contents(eml_content, safelink_option):
    eml_data = {}
    # Extract the subject
    eml_data['subject'] = extract_subject(eml_content)

    # Extract the body
    eml_data['body'] = extract_urls(eml_content, safelink_option)

    return eml_data

# Function to extract message contents from .msg or .eml file
def extract_email_contents(file_path, safelink_option):
    # Check the file extension to determine the email format
    _, file_extension = os.path.splitext(file_path)

    if file_extension.lower() == ".msg":
        msg = Message(file_path)
        msg_data = {}

        # Extract the subject
        msg_data['subject'] = msg.subject

        # Extract the body if it exists
        if msg.body:
            msg_data['body'] = extract_urls(msg.body, safelink_option)
        else:
            msg_data['body'] = ""

        return msg_data
    elif file_extension.lower() == ".eml":
        with open(file_path, "r", encoding="utf-8") as eml_file:
            eml_content = eml_file.read()
            eml_content = remove_equals_and_newlines(eml_content)  # Removing all "=" and newlines after being read
            eml_data = extract_eml_contents(eml_content, safelink_option)
            return eml_data