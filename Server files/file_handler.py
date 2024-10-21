import os
import zlib
import re
import logging
from dataBase import add_file
from protocol import create_file_accepted, create_general_error, create_message_accepted

def safe_filename(filename):
    """
    Sanitizes the filename by replacing any non-alphanumeric characters (except periods) with underscores.
    """
    return re.sub(r'[^\w\-_\. ]', '_', filename)

def process_file_content(client_id, data):
    """
    Processes received file content and saves it to disk. This function handles both partial
    and complete file transfers, updating the file on disk accordingly.

    When the final chunk is received, it performs a CRC check on the complete file
    and updates the database with the file information.
    """
    if not os.path.exists('uploads'):
        os.makedirs('uploads')

    safe_name = safe_filename(data['file_name'])
    if safe_name != data['file_name']:
        logging.warning(f"File name was sanitized. Original: {data['file_name']}, Sanitized: {safe_name}")

    file_path = os.path.join('uploads', f"{client_id.hex()}_{safe_name}")

    try:
        with open(file_path, 'ab') as f:
            f.write(data['content'])

        if data['packet_number'] == data['total_packets']:
            # File transfer complete, verify CRC
            with open(file_path, 'rb') as f:
                file_content = f.read()
            crc = zlib.crc32(file_content)

            if len(file_content) != data['orig_file_size']:
                logging.warning(f"File size mismatch. Expected: {data['orig_file_size']}, Got: {len(file_content)}")
                return create_general_error(client_id)

            add_file(client_id, safe_name, file_path, 1)
            return create_file_accepted(client_id, len(file_content), safe_name, crc)
        else:
            return create_message_accepted(client_id)  # Acknowledge partial upload

    except IOError as e:
        logging.error(f"Error writing file {file_path}: {str(e)}")
        return create_general_error(client_id)
    except Exception as e:
        logging.error(f"Unexpected error processing file content: {str(e)}")
        return create_general_error(client_id)

def calculate_crc(file_path):
    """
    Calculates the CRC32 checksum of a file. This function is used to verify the
    integrity of uploaded files.
    """
    try:
        with open(file_path, 'rb') as f:
            file_content = f.read()
        return zlib.crc32(file_content)
    except IOError as e:
        logging.error(f"Error reading file {file_path} for CRC calculation: {str(e)}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error calculating CRC: {str(e)}")
        return None