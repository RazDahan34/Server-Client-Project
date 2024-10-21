# Secure File Transfer Project

## Project Overview

This project implements a secure file transfer system using a custom protocol. It allows for encrypted file transmission between a client and a server, ensuring the confidentiality and integrity of the transferred data. The project is unique in its hybrid architecture, featuring a Python-based server and a C++ client.

### Purpose

The main purpose of this project is to demonstrate a secure method of transferring files over a potentially insecure network. It incorporates various cryptographic techniques to protect against common security threats while also showcasing interoperability between different programming languages.

## Architecture

### Server (Python)
The server component is implemented in Python, leveraging its simplicity and rich ecosystem for networking and cryptographic operations. Python's high-level abstractions allow for rapid development and easy maintenance of the server-side logic.

Key aspects of the Python server:
- Utilizes asyncio for efficient handling of multiple client connections
- Implements the server-side protocol logic
- Manages client registrations and authentications
- Handles file reception and integrity verification

### Client (C++)
The client is implemented in C++, chosen for its performance characteristics and low-level control, which are beneficial for file handling and network operations on the client side.

Key aspects of the C++ client:
- Provides a command-line interface for file selection and transfer initiation
- Implements client-side encryption of files before transmission
- Manages the chunking of large files for efficient transfer
- Handles the client-side protocol logic, including key exchange and file integrity verification

### Interoperability
The use of a well-defined protocol ensures seamless communication between the Python server and C++ client. This architecture demonstrates how different languages can be leveraged for their strengths in a single system:
- Python's ease of use and extensive libraries for the server's complex logic
- C++'s performance and system-level access for efficient client-side operations

## Features

- Cross-language secure communication (Python server, C++ client)
- RSA-based key exchange for secure key distribution
- AES encryption for file content confidentiality
- CRC32 checksum for file integrity verification
- Support for large file transfers through chunking
- Asynchronous handling of multiple clients on the server side
- Command-line interface for easy client operation

## Protocol Description

The secure file transfer protocol follows these steps:

1. **Client Registration:**
   - Client sends a registration request with a username.
   - Server responds with a unique client ID.

2. **Key Exchange:**
   - Client generates RSA key pair.
   - Client sends its public key to the server.
   - Server generates an AES key, encrypts it with the client's public key, and sends it back.

3. **File Transfer:**
   - Client encrypts the file content using AES in CBC mode.
   - File is split into chunks and sent sequentially.
   - Each chunk contains metadata (file name, chunk number, total chunks).
   - Server acknowledges each received chunk.

4. **File Integrity Check:**
   - After all chunks are sent, client sends CRC32 checksum of the original file.
   - Server calculates CRC32 of the received file and compares it with the client's checksum.

5. **Transfer Completion:**
   - Server confirms successful transfer or reports an error.

## Installation

### Prerequisites
- C++ Compiler with C++11 support (e.g., GCC, Clang)
- PyCharm IDE (recommended) or any Python IDE
- Boost library (version 1.66 or higher)
- Crypto++ library (version 8.2 or higher)

### Building the Project

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/secure-file-transfer.git
   cd secure-file-transfer
   ```

2. Create a build directory:
   ```
   mkdir build && cd build
   ```

3. Configure the project with CMake:
   ```
   cmake ..
   ```

4. Build the project:
   ```
   cmake --build .
   ```

This will create two executables: `client` and `server`.

## Usage

1. Start the server:
   ```
   ./server
   ```

2. In a separate terminal, run the client:
   ```
   ./client <file_to_transfer>
   ```

3. Follow the on-screen prompts to complete the file transfer.
