import struct

# PCAP global header format: 'IHHiIII' -> 1x 32-bit, 2x 16-bit, 4x 32-bit
global_header_format = 'IHHiIII'

def read_global_header(file_path):
    with open(file_path, 'rb') as f:
        # Read the first 24 bytes (PCAP global header)
        global_header = f.read(24)

        if len(global_header) != 24:
            raise Exception("Not enough data for a valid global header")

        # Unpack the global header according to the PCAP format
        (
            magic_number,      # 4 bytes
            version_major,     # 2 bytes
            version_minor,     # 2 bytes
            timezone_offset,   # 4 bytes
            timestamp_accuracy, # 4 bytes
            snap_length,       # 4 bytes
            link_layer_type    # 4 bytes
        ) = struct.unpack(global_header_format, global_header)

        print(f"Magic Number: {hex(magic_number)}")
        print(f"Version: {version_major}.{version_minor}")
        print(f"Timezone Offset: {timezone_offset}")
        print(f"Timestamp Accuracy: {timestamp_accuracy}")
        print(f"Snapshot Length: {snap_length}")
        print(f"Link Layer Type: {link_layer_type}")

# Replace with the path to your pcap file
file_path = "../pcap/sample_v1.pcap"

# Read and display the global header
read_global_header(file_path)
