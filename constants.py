"""
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

"""
from req_imports import *

if len(sys.argv) >= 3:
    if sys.argv[2] == "-orgurl":
        print("\n[!] Please input the target folder first.")
        sys.exit(1)
    TEMP_FOLDER = sys.argv[2]
else:
    TEMP_FOLDER = "temp"

# List to store all email addresses
all_emails = []

# Initialize variables to store domain, IPs, received_from, senders, recipients, received_by, and Message ID
domains_set = set()  # Use a set to store unique domains
ips = []
senders = []
recipients = []
received_froms = []
received_bys = []
message_ids = []
timestamps = []

# Define a list of image extensions
img_extensions = [
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tif', '.tiff', '.webp',
    '.svg', '.ico', '.exif', '.raw', '.heif', '.heic',
    # Add more image extensions as needed
]

# Define a list of documents extensions
doc_extensions = [
    '.txt', '.docx', '.odt', '.csv', '.xlsx', '.ods', 
    '.pptx', '.odp', '.pdf', '.epub', '.exe',
    # Add more documents extensions as needed 
]

# Define a dictionary of months
month_dict = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}