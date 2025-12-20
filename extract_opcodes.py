#!/usr/bin/env python3
import subprocess
import sys
import re

COLORS_ENABLED = False

class Colors:
    if COLORS_ENABLED:
        RESET = '\033[0m'
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        BOLD = '\033[1m'
    else:
        RESET = ''
        RED = ''
        GREEN = ''
        YELLOW = ''
        BLUE = ''
        MAGENTA = ''
        CYAN = ''
        BOLD = ''

def get_labels_from_nm(binary_path):
    try:
        result = subprocess.run(['nm', binary_path], capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    labels = set()
    for line in result.stdout.split('\n'):
        parts = line.split()
        if len(parts) >= 3:
            labels.add(parts[2])
        elif len(parts) == 2:
            labels.add(parts[1])
    return labels

def extract_opcodes(binary_path, requested_labels):
    try:
        result = subprocess.run(['objdump', '-d', binary_path], capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    labels_dict = {label: [] for label in requested_labels}
    current_label = None
    for line in result.stdout.split('\n'):
        label_match = re.search(r'<([^>]+)>:', line)
        if label_match:
            label_name = label_match.group(1)
            current_label = label_name if label_name in requested_labels else None
            continue
        if current_label:
            match = re.search(r':\s+((?:[0-9a-f]{2}\s+)+)', line)
            if match:
                hex_bytes = match.group(1).strip().split()
                labels_dict[current_label].extend(hex_bytes)
    return labels_dict

def format_as_c_array(opcodes):
    if not opcodes:
        return None
    result = 'unsigned char sc[] = \n    "'
    for i, byte in enumerate(opcodes):
        if i > 0 and i % 16 == 0:
            result += '"\n    "'
        result += f'\\x{byte}'
    result += '";'
    return result

def format_as_python_bytes(opcodes):
    if not opcodes:
        return None
    result = "sc = b'"
    for i, byte in enumerate(opcodes):
        if i > 0 and i % 16 == 0:
            result += "\\\n    "
        result += f'\\x{byte}'
    result += "'"
    return result

def format_array_literal(opcodes):
    if not opcodes:
        return None
    result = "unsigned char sc[] =\n\t{ "
    for i, byte in enumerate(opcodes):
        if i > 0:
            result += ",\n\t" if i % 8 == 0 else ", "
        result += f"0x{byte.upper()}"
    result += " };"
    return result

def check_null_bytes(opcodes):
    null_count = sum(1 for b in opcodes if b == '00')
    if null_count > 0:
        print(f"{Colors.YELLOW}WARNING: {null_count} null byte(s) found{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}No null bytes{Colors.RESET}")

def main():
    if len(sys.argv) < 3:
        print("Usage: extract_opcodes.py <binary> <label1> [label2] ...")
        sys.exit(1)

    binary_path = sys.argv[1]
    requested_labels = sys.argv[2:]
    all_labels = get_labels_from_nm(binary_path)
    if all_labels is None:
        print(f"{Colors.RED}Error: Failed to read binary labels{Colors.RESET}")
        sys.exit(1)
    valid_labels = [l for l in requested_labels if l in all_labels]
    invalid_labels = [l for l in requested_labels if l not in all_labels]
    if invalid_labels:
        print(f"{Colors.YELLOW}Invalid labels: {', '.join(invalid_labels)}{Colors.RESET}")
        print(f"{Colors.CYAN}Available: {', '.join(sorted(all_labels))}{Colors.RESET}")
    if not valid_labels:
        print(f"{Colors.RED}Error: No valid labels to process{Colors.RESET}")
        sys.exit(1)
    labels_opcodes = extract_opcodes(binary_path, valid_labels)
    if not labels_opcodes:
        print(f"{Colors.RED}Error: Failed to extract opcodes{Colors.RESET}")
        sys.exit(1)
    for label_name in valid_labels:
        opcodes = labels_opcodes[label_name]
        print(f"\n{Colors.BOLD}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}Label: {label_name}{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 60}{Colors.RESET}")
        if not opcodes:
            print(f"{Colors.YELLOW}No opcodes found (data symbol){Colors.RESET}")
            continue
        print(f"{Colors.CYAN}{len(opcodes)} bytes{Colors.RESET}")
        check_null_bytes(opcodes)
        print(f"\n{Colors.BOLD}// C ARRAY LITERAL:{Colors.RESET}")
        print(format_array_literal(opcodes))
        print(f"\n{Colors.BOLD}// C ARRAY FORMAT:{Colors.RESET}")
        print(format_as_c_array(opcodes))
        # print(f"\n{Colors.BOLD}PYTHON BYTES:{Colors.RESET}")
        # print("-" * 60)
        # print(format_as_python_bytes(opcodes))
        # print()

if __name__ == '__main__':
    main()
