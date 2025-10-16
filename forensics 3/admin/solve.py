import struct
import os


IMAGE_FILE = "cat_drive.img"
OUTPUT_DIR = "carved_files"

MAGIC_NUMBER = 0x0D007FCA
BLOCK_SIZE = 1024
HEADER_SIZE = 28
DATA_AREA_SIZE = 996


def xor_data(data, key):
    # XORs data with a repeating key. This is the de-obfuscation logic
    key_bytes = key.encode('utf-8')
    if not key_bytes:
        return data
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])

def carve_pawfs():
    # Scans the disk image, parses PawFS, and carves the files.
    print("--- PawFS Carver ---")
    
    if not os.path.exists(IMAGE_FILE):
        print(f"[!] Error: '{IMAGE_FILE}' not found. Make sure it's in the same directory.")
        return

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"[*] Created output directory: '{OUTPUT_DIR}'")

    with open(IMAGE_FILE, 'rb') as f:
        img_data = f.read()

    blocks = {}
    print("[*] Scanning for PawFS blocks by magic number...")

    for i in range(0, len(img_data), BLOCK_SIZE):
        if i + 4 > len(img_data):
            break
        potential_magic = struct.unpack('<I', img_data[i:i+4])[0]
        if potential_magic == MAGIC_NUMBER:
            if i + HEADER_SIZE > len(img_data):
                continue
            header_format = '<I16sII'
            magic, fname_bytes, size, next_ptr = struct.unpack(header_format, img_data[i:i+HEADER_SIZE])

            if i + HEADER_SIZE + size > len(img_data):
                continue

            filename = fname_bytes.split(b'\x00', 1)[0].decode('utf-8')
            data_chunk = img_data[i+HEADER_SIZE : i+HEADER_SIZE+size]
            
            blocks[i] = {
                "filename": filename,
                "size": size,
                "next_ptr": next_ptr,
                "data": data_chunk
            }


    carved_files = {}
    processed_blocks = set()

    for offset, block in blocks.items():
        if offset in processed_blocks:
            continue

        full_file_data = bytearray()
        current_block = block
        current_offset = offset

        while True:
            processed_blocks.add(current_offset)
            deobfuscated_chunk = xor_data(current_block['data'], current_block['filename'])
            full_file_data.extend(deobfuscated_chunk)

            if current_block['next_ptr'] == 0:
                break
            
            next_offset = current_block['next_ptr']
            if next_offset in blocks:
                current_block = blocks[next_offset]
                current_offset = next_offset
            else:
                print(f"[!] Warning: Broken file chain for '{current_block['filename']}' at offset {current_offset}.")
                break
        
        carved_files[block['filename']] = full_file_data

    for filename, content in carved_files.items():
        output_path = os.path.join(OUTPUT_DIR, filename)
        with open(output_path, 'wb') as f:
            f.write(content)
        print(f"    -> Carved '{filename}' ({len(content)} bytes)")


if __name__ == "__main__":
    carve_pawfs()

