"""
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

"""

from constants import *

# Function to check for internet connectivity
def check_internet_connection():
    try:
        response = requests.get("https://www.google.com", timeout=3)
        return True
    except requests.exceptions.RequestException:
        return False

# Function to create the TEMP_FOLDER if it doesn't exist
def create_temp_folder(temp_folder):
    try:
        if not os.path.exists(temp_folder):
            os.makedirs(temp_folder)
    except Exception as e:
        print(f"[-] Error creating folder {temp_folder}: {str(e)}")

# Function to clear anything from TEMP_FOLDER
def clear_temp_folder(temp_folder):
    try:
        create_temp_folder(temp_folder)  # Create folder if it doesn't exist

        for filename in os.listdir(temp_folder):
            file_path = os.path.join(temp_folder, filename)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
            except Exception as e:
                print(f"[-] Error deleting file {file_path}: {str(e)}")
    except Exception as e:
        print(f"[-] Error clearing TEMP_FOLDER: {str(e)}")

# Function to remove all "=" and newlines
def remove_equals_and_newlines(email_text):
    lines = email_text.split("\n")
    cleaned_lines = []
    
    for line in lines:
        if "smtp.mailfrom=" in line or "header.i=" in line:
            cleaned_lines.append(line)
        else:
            cleaned_lines.append(line.replace("=", ""))

    cleaned_text = "".join(cleaned_lines)
    return cleaned_text

# Function to remove anything after imgs/docs extensions
def remove_extension(link):
    return re.sub(r'(.*\/)([^/]+\.[a-zA-Z0-9]{2,6}).*$', r'\1\2', link)

# Function to extract domains and clean_links from the email
def extract_domains_and_print_links(text, img_extensions, doc_extensions):
    domain_regex = r'https?://([^/\s]+)'
    link_regex = r'(https?://[^\s]+)'

    domains_count = defaultdict(int)
    img_links = set()
    doc_links = set()
    links = re.findall(link_regex, text)

    img_link_checker = lambda link: any(ext in link for ext in img_extensions)
    doc_link_checker = lambda link: any(ext in link for ext in doc_extensions)

    for link in links:
        if img_link_checker(link):
            img_links.add(remove_extension(link))
        elif doc_link_checker(link):
            doc_links.add(remove_extension(link))
        else:
            domain_match = re.search(domain_regex, link)
            
            if domain_match:
                domain = domain_match.group(1)
                domain = re.sub(r'[^a-zA-Z0-9.-]', '', domain)
                domains_count[domain] += 1

    print("\n\n\n----------> [ EMAIL_BODY: Domains ]\n")
    for domain, count in domains_count.items():
        print(f"{domain} ({count})")

    internet_connected = check_internet_connection()

    print("\n----------> [ EMAIL_BODY: Images ]\n")
    for link in img_links:
        if internet_connected:
            download_and_save(link, TEMP_FOLDER, "img")
        else: 
            print(link)

    print("\n----------> [ EMAIL_BODY: Documents ]\n")
    for link in doc_links:
        if internet_connected:
            download_and_save(link, TEMP_FOLDER, "doc")
        else:
            print(link)

    if not internet_connected:
        print("\n[-] Unable to connect to the internet. Skipping file download.")

    return domains_count, img_links, doc_links

# Function to download and save the imgs/docs
def download_and_save(url, directory, file_type):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)

        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx and 5xx status codes)

        file_name = url.split("/")[-1]
        file_path = os.path.join(directory, file_name)

        with open(file_path, "wb") as file:
            file.write(response.content)

        print(f"[✓] {url}")
        print(f"    Download successful!")

    except requests.exceptions.RequestException as e:
        if response.status_code == 403:
            print(f"[x] {url}")
            print("    Error 403: Access Forbidden - Please try to download manually.\n")
        elif response.status_code >= 400 and response.status_code < 600:
            print(f"[x] {url}")
            print(f"    Error {response.status_code}: {response.reason}\n")
        else:
            print(f"[x] {url}")
            print(f"    Error: Failed to download the file: {e}\n")
    except Exception as e:
        print(f"[x] {url}")
        print(f"    Error: An unexpected error occurred: {e}")

# Function to compute the hash of a file
def file_hash(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Function to remove safelink URL redirection
def remove_safelink(url):
    parsed_url = urlparse(url)
    query_params = parsed_url.query.split('&')

    for param in query_params:
        if param.startswith('url='):
            original_url = unquote(param[4:])
            return original_url

    return url