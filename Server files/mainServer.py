import selectors
import socket
import logging
import binascii
import os
import uuid
import types
from dataBase import setup_database, get_client, add_client, update_client_key, get_client_aes_key, get_client_by_name
from file_handler import process_file_content, calculate_crc
from crypt import generate_aes_key, encrypt_aes_key, decrypt_aes
from protocol import *

# Constants for server configuration
HOST = '127.0.0.1'
DEFAULT_PORT = 1256
DATABASE_NAME = 'defensive.db'

# Set up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def read_port():
    """
    Read the port number from 'port.info' file or use the default port.
    """
    try:
        with open('port.info', 'r') as f:
            return int(f.read().strip())
    except FileNotFoundError:
        logging.warning("port.info not found. Using default port 1256.")
        return DEFAULT_PORT
    except ValueError:
        logging.warning("Invalid port in port.info. Using default port 1256.")
        return DEFAULT_PORT


PORT = read_port()
# Initialize the selector for non-blocking I/O
selector = selectors.DefaultSelector()
file_data = {}

def get_client_info(client_id):
    """
    get client info and decoding it for representing
    """
    client = get_client(client_id)
    client_id_hex = binascii.hexlify(client_id).decode()
    username = client[1] if client else "Unknown"
    return f"Client ID: {client_id_hex} (Username: {username})"

def handle_client(key, mask):
    """
    Handle client connections and process their requests.
    """
    sock = key.fileobj
    data = key.data
    if not hasattr(data, 'file_data'):
        data.file_data = {}  # Initialize file_data if it doesn't exist
    if mask & selectors.EVENT_READ:
        try:
            # Read the header of the incoming message
            header = sock.recv(23)
            if not header:
                logging.info(f"Client {data.addr} closed the connection")
                selector.unregister(sock)
                sock.close()
                return
            client_id, version, code, payload_size = parse_request_header(header)
            payload = sock.recv(payload_size)
            parsed_data = parse_request_payload(code, payload, data.file_data)
            client_info = get_client_info(client_id)

            # Handle different types of requests based on the code
            if code == 825:  # Client registration
                logging.info(f"Received client registration request from {client_info}")
                if get_client_by_name(parsed_data['name']):
                    logging.warning(f"Registration failed: Username {parsed_data['name']} already exists")
                    response = create_registration_failed()
                else:
                    new_client_id = uuid.uuid4().bytes
                    aes_key = generate_aes_key()
                    add_client(new_client_id, parsed_data['name'], aes_key)
                    logging.info(f"{client_info} registered successfully")
                    response = create_registration_success(new_client_id)
            elif code == 826:  # Public key update
                logging.info(f"Received public key update from {client_info}")
                update_client_key(client_id, parsed_data['public_key'])
                aes_key = get_client_aes_key(client_id)
                encrypted_aes_key = encrypt_aes_key(aes_key, parsed_data['public_key'])
                logging.info(f"Public key updated for {client_info}. Sending encrypted AES key.")
                response = create_public_key_accepted(client_id, encrypted_aes_key)
            elif code == 827:  # Reconnect
                client = get_client(client_id)
                if client and client[1] == parsed_data['name']:  # Check if client exists and name matches
                    username = parsed_data['name']
                    logging.info(f"Received reconnection request from {client_info}")
                    aes_key = get_client_aes_key(client_id)
                    encrypted_aes_key = encrypt_aes_key(aes_key, client[2])  # Encrypt with stored public key
                    logging.info(f"{client_info} reconnected successfully")
                    response = create_reconnect_confirm(client_id, encrypted_aes_key)
                else:
                    logging.warning(f"Reconnection failed for client {client_id}")
                    response = create_reconnect_denied(client_id)
            elif code == 828:  # File content
                try:
                    parsed_data = parse_request_payload(code, payload, data.file_data)
                    if 'packet_number' in parsed_data:
                        logging.info(f"Received file chunk {parsed_data['packet_number']}/{parsed_data['total_packets']} from {client_info}")
                    if parsed_data['is_complete']:
                        logging.info(f"File transfer complete for {parsed_data['file_name']} from {client_info}")
                        aes_key = get_client_aes_key(client_id)
                        decrypted_content = decrypt_aes(parsed_data['content'], aes_key)
                        # Check if the decrypted size matches the expected size
                        if len(decrypted_content) != parsed_data['orig_file_size']:
                            logging.warning(f"Size mismatch: expected {parsed_data['orig_file_size']}, got {len(decrypted_content)}")
                        file_path = process_file_content(client_id, parsed_data['file_name'], decrypted_content)
                        if file_path:
                            crc = calculate_crc(file_path)
                            logging.info(f"File received and CRC calculated for client {client_info}")
                            response = create_file_accepted(client_id, parsed_data['orig_file_size'],
                                                            parsed_data['file_name'], crc)
                        else:
                            logging.warning(f"File processing failed for client {client_info}")
                            response = create_general_error(client_id)

                        # Clear the file data after processing
                        del data.file_data[parsed_data['file_name']]
                    else:
                        # Acknowledge receipt of the chunk
                        response = create_message_accepted(client_id)

                except ValueError as e:
                    logging.error(f"Error processing file content: {str(e)}")
                    response = create_general_error(client_id)

            elif code == 900:  # CRC correct
                logging.info(f"CRC correct for file from client {client_info}")
                response = create_message_accepted(client_id)
            elif code == 901:  # CRC incorrect, client will retry
                logging.info(f"CRC incorrect for file from client {client_info}, client will retry")
                response = create_message_accepted(client_id)
            elif code == 902:  # CRC incorrect, final failure
                logging.warning(f"File transfer failed after multiple attempts for client {client_info}")
                response = create_message_accepted(client_id)
            else:
                logging.warning(f"Unknown command {code} from client {client_id}")
                response = create_general_error(client_id)

            data.outb += response
        except Exception as e:
            logging.error(f"Error handling client {data.addr}: {e}")
            selector.unregister(sock)
            sock.close()

    if mask & selectors.EVENT_WRITE:
        if data.outb:
            try:
                sent = sock.send(data.outb)
                data.outb = data.outb[sent:]
            except Exception as e:
                logging.error(f"Error sending data to client {data.addr}: {e}")
                selector.unregister(sock)
                sock.close()


def accept_connection(sock):
    """
    Accept a new client connection and register it with the selector.
    """
    conn, addr = sock.accept()
    logging.info(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    selector.register(conn, events, data=data)


def start_server():
    """
    Start the server and enter the main event loop.
    """
    setup_database()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    server_socket.setblocking(False)
    selector.register(server_socket, selectors.EVENT_READ, data=None)
    logging.info(f"Server listening on {HOST}:{PORT}")

    while True:
        # Main event loop: continuously check for new connections and client events
        events = selector.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_connection(key.fileobj)
            else:
                handle_client(key, mask)


if __name__ == "__main__":
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    start_server()