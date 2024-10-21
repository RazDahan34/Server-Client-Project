import struct

def parse_request_header(data):
    """
    Parses the header of an incoming request. The header contains crucial information
    about the client and the type of request being made. This function extracts the
    client ID, protocol version, request code, and payload size from the binary header data.
    """
    return struct.unpack('<16sBHI', data)


def parse_request_payload(code, payload, file_data):
    """
    Parses the payload of an incoming request based on its code. Different request types
    (e.g., registration, key updates, file transfers) have different payload structures.
    This function interprets the payload according to the request type and returns the
    relevant data in a dictionary format.
    """
    if code == 825:  # Client registration
        name = payload[:255].decode('utf-8', errors='replace').rstrip('\0')
        return {'name': name}
    elif code == 826:  # Public key update
        name = payload[:255].decode('utf-8', errors='replace').rstrip('\0')
        public_key = payload[255:415]
        return {'name': name, 'public_key': public_key}
    elif code == 827:  # Reconnect
        name = payload[:255].decode('utf-8', errors='replace').rstrip('\0')
        return {'name': name}
    elif code == 828:  # File content
        if len(payload) < 267:
            raise ValueError("Payload too short for file content.")
        content_size, orig_file_size = struct.unpack('<II', payload[:8])
        packet_number, total_packets = struct.unpack('<HH', payload[8:12])

        file_name = payload[12:267].decode('utf-8', errors='replace').rstrip('\0')

        content = payload[267:]

        if file_name not in file_data:
            file_data[file_name] = {
                'content': bytearray(),
                'total_packets': total_packets,
                'received_packets': 0,
                'content_size': content_size,
                'orig_file_size': orig_file_size
            }

        file_data[file_name]['content'].extend(content)

        is_complete = file_data[file_name]['received_packets'] == total_packets
        if is_complete:
            file_content = file_data[file_name]['content']
            if len(file_content) != content_size:
                raise ValueError(f"Expected {content_size} bytes of content, got {len(file_content)}.")

        return {
            'file_name': file_name,
            'content': content,
            'is_complete': is_complete,
            'packet_number': packet_number,
            'total_packets': total_packets,
            'content_size': content_size,
            'orig_file_size': orig_file_size
        }
    elif code in [900, 901, 902]:  # CRC requests
        file_name = payload.decode('utf-8', errors='replace').rstrip('\0')
        return {'file_name': file_name}
    return {}


def create_response_header(code, payload_size):
    """
    Creates a header for outgoing responses. The header includes the protocol version,
    response code, and payload size. This standardized header format allows the client
    to properly interpret the incoming response data.
    """
    return struct.pack('<BHI', 3, code, payload_size)  # Version is always 3


def create_registration_success(client_id):
    """
    Creates a response for successful client registration. This response includes
    the newly assigned client ID, which the client will use for future communications.
    """
    payload = client_id
    return create_response_header(1600, len(payload)) + payload


def create_registration_failed():
    """
    Creates a response for failed client registration. This might occur if the
    requested username is already taken or if there's an internal server error.
    """
    return create_response_header(1601, 0)


def create_public_key_accepted(client_id, encrypted_aes_key):
    """
    Creates a response indicating that the client's public key has been accepted.
    This response includes an encrypted AES key that the client will use for
    future secure communications.
    """
    payload = client_id + encrypted_aes_key
    return create_response_header(1602, len(payload)) + payload


def create_file_accepted(client_id, content_size, file_name, cksum):
    """
    Creates a response indicating that a file has been successfully received and processed.
    This response includes details about the file and its checksum for verification.
    """
    file_name_bytes = file_name.encode('ascii').ljust(255, b'\0')
    payload = client_id + struct.pack('<I', content_size) + file_name_bytes + struct.pack('<I', cksum)
    return create_response_header(1603, len(payload)) + payload


def create_message_accepted(client_id):
    """
    Creates a general response indicating that a message or action has been accepted.
    This is used for various confirmations in the protocol.
    """
    return create_response_header(1604, 16) + client_id


def create_reconnect_confirm(client_id, encrypted_aes_key):
    """
    Creates a response confirming successful client reconnection. This includes
    a new encrypted AES key for the reconnected session.
    """
    payload = client_id + encrypted_aes_key
    return create_response_header(1605, len(payload)) + payload


def create_reconnect_denied(client_id):
    """
    Creates a response indicating that a reconnection attempt has been denied.
    This might occur if the client's credentials are no longer valid.
    """
    return create_response_header(1606, 16) + client_id


def create_general_error(client_id):
    """
    Creates a general error response. This is used for various error conditions
    that don't have more specific error responses.
    """
    return create_response_header(1607, 16) + client_id