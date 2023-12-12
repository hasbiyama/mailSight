"""
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

"""

from req_imports import *
from help_func import *

# Function to decode a QR code from an image
def decode_qr_code(image_path):
    # Read the QR code image
    image = cv2.imread(image_path)

    # Create a QR code detector object
    qr_code_detector = cv2.QRCodeDetector()

    # Detect and decode the QR code
    #  _, _ used to ignore and discard 
    # additional information returned by 
    # the detectAndDecode function
    decoded_text, _, _ = qr_code_detector.detectAndDecode(image)

    return decoded_text

# Function to extract QR codes from an image
def extract_qr_codes_from_image(image_path):
    qr_codes = []

    # Decode the QR code in the image
    qr_code_data = decode_qr_code(image_path)

    if qr_code_data:
        qr_codes.append(qr_code_data)

    return qr_codes

# Function to extract QR codes from .msg or .eml files
def extract_qr_codes_from_email(email_file_path):
    def process_email_file(file_path):
        existing_hashes = set()
        file_hash_to_filename = {}

        # Create the 'temp' folder if it doesn't exist
        os.makedirs(TEMP_FOLDER, exist_ok=True)

        qr_codes = []

        processed_hashes = set()

        for root, dirs, files in os.walk(TEMP_FOLDER):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash_value = file_hash(file_path)

                if file_hash_value in existing_hashes:
                    # File with the same hash already exists
                    existing_file_path = file_hash_to_filename[file_hash_value]
                    os.remove(file_path)
                    try:
                        shutil.move(existing_file_path, file_path)
                    except Exception:
                        pass
                else:
                    # New file, add its hash to the set
                    existing_hashes.add(file_hash_value)
                    file_hash_to_filename[file_hash_value] = file_path

                if any(file.lower().endswith(ext) for ext in img_extensions):
                    try:
                        if file_hash_value not in processed_hashes:
                            extracted_qr_codes = extract_qr_codes_from_image(file_path)
                            if extracted_qr_codes:
                                qr_codes.append((extracted_qr_codes, file_path))
                            processed_hashes.add(file_hash_value)
                    except Exception:
                        pass

        return qr_codes

    _, file_extension = os.path.splitext(email_file_path)

    if file_extension.lower() == ".msg":
        return process_email_file(email_file_path)
    elif file_extension.lower() == ".eml":
        with open(email_file_path, "rb") as eml_file:
            msg = email.message_from_binary_file(eml_file)
        return process_email_file(msg)

    return []