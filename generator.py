import struct
import time

# Define global header for PCAP file (24 bytes)
def create_global_header():
    global_header = struct.pack(
        'IHHiIII', 
        0xa1b2c3d4,  # Magic number
        2,           # Major version
        4,           # Minor version
        0,           # GMT to local correction
        0,           # Accuracy of timestamps
        262144,       # Snapshot length
        1            # Link-layer type (Ethernet)
    )
    return global_header

# Define packet header (16 bytes)
def create_packet_header(data_length):
    ts_sec, ts_usec = int(time.time()), 0  # Use current time as the timestamp
    return struct.pack(
        'IIII', 
        ts_sec,     # Timestamp seconds
        ts_usec,    # Timestamp microseconds
        data_length, # Number of bytes captured
        data_length  # Original length of the packet
    )

# Example Ethernet/IP/UDP packet (mock)
def create_packet_data():
    return b'\x00\x0c\x29\x6d\x4c\x5f\x00\x0c\x29\x3e\x1b\x37\x81\x00\x12\x34\x08\x00\x45\x00' \
           b'\x00\x34\x12\x34\x40\x00\x40\x11\x72\xb2\xc0\xa8\x01\x68\xc0\xa8' \
           b'\x01\x01\x04\x00\x04\x00\x00\x20\x43\x91\xA8\xB4\x6c\x6c\x6f\x2c' \
           b'\x20\x57\x6f\x72\x6c\x64\x21\x44\x6c\x64\x21\x44\x6c\x64\x21\x44\x99'

# Write the global header and packet into a file
def write_pcap(filename):
    with open(filename, 'wb') as f:
        # Write the global header (once)
        f.write(create_global_header())
        
        # Create a mock packet
        packet_data = create_packet_data()
        
        # Write the packet header and packet data
        f.write(create_packet_header(len(packet_data)))
        f.write(packet_data)

# Add a new packet to an existing pcap file
def append_to_pcap(filename):
    with open(filename, 'ab') as f:  # Append to the file
        packet_data = create_packet_data()
        
        # Write the packet header and packet data
        f.write(create_packet_header(len(packet_data)))
        f.write(packet_data)

# Example usage: Create a new PCAP file
write_pcap('example.pcap')

# Example usage: Append a new packet to the existing PCAP file
append_to_pcap('example.pcap')
append_to_pcap('example.pcap')
append_to_pcap('example.pcap')
append_to_pcap('example.pcap')
append_to_pcap('example.pcap')

append_to_pcap('example.pcap')
append_to_pcap('example.pcap')
append_to_pcap('example.pcap')
