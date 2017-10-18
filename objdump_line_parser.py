"""
parse source lines in objdump -dl output.
"""

import argparse
import os
import sys

def isaddr(s):
    num_len = 0
    for c in s:
        if not c.isalnum():
            break
        if (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F'):
            num_len += 1
        else:
            return False
    return num_len > 0

def getaddr(s):
    end = 0
    while end < len(s):
        if not s[end].isalnum():
            break
        end += 1
    return int(s[:end], 16)

def parse_file(input_file, output_file, start_addr, end_addr):
    input_fd = open(input_file, 'r')
    output_fd = output_file and open(output_file, 'w') or sys.stdout
    force_line = False
    in_addr_range = False
    for raw_line in input_fd.readlines():
        line = raw_line.strip()
        if not line:
            continue
        strs = line.split()
        if strs and isaddr(strs[0]):
            addr = getaddr(strs[0])
            if addr >= start_addr and addr <= end_addr:
                in_addr_range = True
            else:
                in_addr_range = False
        if not in_addr_range:
            continue
        if len(strs) == 2 and isaddr(strs[0]) and strs[1][-1] == ':':
            # a function definition, show it.
            output_fd.write(raw_line)
        elif len(strs) == 1:
            items = line.split(':')
            if len(items) == 2 and items[1].isdigit():
                # a source line
                output_fd.write(raw_line)
                force_line = True
        elif force_line:
            force_line = False
            output_fd.write(raw_line)

def parse_file2(input_file, output_file, start_addr, end_addr):
    input_fd = open(input_file, 'r')
    output_fd = output_file and open(output_file, 'w') or sys.stdout
    file_name = None
    line_number = None
    force_line = False
    in_addr_range = False
    for raw_line in input_fd.readlines():
        line = raw_line.strip()
        if not line:
            continue
        strs = line.split()
        if strs and isaddr(strs[0]):
            addr = getaddr(strs[0])
            if addr >= start_addr and addr <= end_addr:
                in_addr_range = True
            else:
                in_addr_range = False
        if not in_addr_range:
            continue
        if len(strs) == 2 and isaddr(strs[0]) and strs[1][-1] == ':':
            # a function definition, show it.
            #output_fd.write(raw_line)
            pass
        elif len(strs) == 1:
            items = line.split(':')
            if len(items) == 2 and items[1].isdigit():
                # a source line
                #output_fd.write(raw_line)
                file_name = items[0].split('/')[-1]
                line_number = int(items[1])
                force_line = True
        elif force_line and isaddr(strs[0]):
            force_line = False
            addr = getaddr(strs[0])
            output_fd.write('%20s  %11d  0x%-9x\n' % (file_name, line_number, addr))
            #output_fd.write(raw_line)


def main():
    parser = argparse.ArgumentParser(description='parse source lines in objdump.')
    parser.add_argument('-i', nargs=1, required=True, help='input file.')
    parser.add_argument('-o', nargs=1, help='Set output file. If not set, use stdout.')
    parser.add_argument('--start-addr', nargs=1, help='set start address.')
    parser.add_argument('--end-addr', nargs=1, help='set end address.')
    args = parser.parse_args()
    print('args = %s' % args)
    input_file = args.i
    output_file = args.o and args.o[0] or None
    if args.start_addr:
        start_addr = int(args.start_addr[0], 16)
    else:
        start_addr = 0
    if args.end_addr:
        end_addr = int(args.end_addr[0], 16)
    else:
        end_addr = (1 << 64) - 1
    
    parse_file2(args.i[0], output_file, start_addr, end_addr)


if __name__ == '__main__':
    main()