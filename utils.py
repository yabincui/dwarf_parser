
import logging
import string
import sys
from struct import unpack

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


class DataParser(object):
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def getValue(self, unpack_key, size):
        assert self.offset + size <= len(self.data)
        value = unpack(unpack_key, self.data[self.offset : self.offset + size])[0]
        self.offset += size
        return value

    def getUint(self, size):
        if size == 1:
            c = 'B'
        elif size == 2:
            c = 'H'
        elif size == 4:
            c = 'I'
        elif size == 8:
            c = 'Q'
        else:
            return None
        return self.getValue(c, size)

    def getInt(self, size):
        if size == 1:
            c = 'b'
        elif size == 2:
            c = 'h'
        elif size == 4:
            c = 'i'
        elif size == 8:
            c = 'q'
        else:
            return None
        return self.getValue(c, size)

    def getUleb128(self):
        value = 0
        shift = 0
        while self.offset < len(self.data):
            c = ord(self.data[self.offset])
            value |= (c & 0x7f) << shift
            self.offset += 1
            shift += 7
            if (c & 0x80) == 0:
                break
        return value

    def getSleb128(self):
        value = 0
        shift = 0
        while self.offset < len(self.data):
            c = ord(self.data[self.offset])
            value |= (c & 0x7f) << shift
            self.offset += 1
            shift += 7
            if (c & 0x80) == 0:
                break
        if c & 0x40:
            value |= -1 << shift
        return value

    def getBytes(self, length):
        assert self.offset + length <= len(self.data)
        value = self.data[self.offset : self.offset + length]
        self.offset += length
        return value

    def getCString(self):
        end = self.data.index('\0', self.offset)
        value = self.data[self.offset : end]
        self.offset = end + 1
        return value


    def move(self, offset):
        self.offset += offset
    
    def isEnd(self):
        return self.offset >= len(self.data)

    def remainLen(self):
        return len(self.data) - self.offset


class BinaryFileReader(object):
    def __init__(self, file_path):
        self.fh = open(file_path, 'rb')
        self.where = 0
        self.fh.seek(0, 2)
        self.file_size = self.fh.tell()
        self.fh.seek(0, 0)

    def close(self):
        self.fh.close()

    def pread(self, pos, size):
        if self.where != pos:
            self.fh.seek(pos, 0)
        data = self.fh.read(size)
        if len(data) != size:
            log_fatal('read at offset %d, expect size %d, real size %d\ndata = %s' % (
                self.where, size, len(data), get_hex_string(data)))
        self.where += size
        return data

    def seek(self, pos):
        if self.where != pos:
            self.fh.seek(pos, 0)
            self.where = pos

    def read(self, size):
        return self.pread(self.where, size)
