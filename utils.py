
import logging
import string
import sys

def log_debug(msg):
    logging.debug(msg)


def log_info(msg):
    logging.info(msg)


def log_warning(msg):
    logging.warning(msg)


def log_fatal(msg):
    raise Exception(msg)

def log_exit(msg):
    sys.exit(msg)


def get_hex_string(s, chars_per_row=16):
    i = 0
    res = []
    while i < len(s):
        print_line = ''
        for j in range(0, chars_per_row):
            k = i + j
            if j > 0:
                print_line += ' '
            if k >= len(s):
                print_line += '  '
            else:
                print_line += '%02X' % ord(s[k])
        print_line += ' ' * 4
        for j in range(0, chars_per_row):
            k = i + j
            if k < len(s):
                print_line += s[k] if s[k] in string.printable else '.'
        res.append(print_line)
        i += chars_per_row
    return '\n'.join(res)

logging.getLogger().setLevel(logging.DEBUG)

