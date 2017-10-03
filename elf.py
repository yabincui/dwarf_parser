#!/usr/bin/env python

"""
elf.py: a library used to read from elf files.

"""

from utils import *


class ElfHeader(object):
    def __init__(self):
        self.e_ident = None
        self.e_type = None
        self.e_machine = None
        self.e_version = None
        self.e_entry = None
        self.e_phoff = None
        self.e_shoff = None
        self.e_flags = None
        self.e_ehsize = None
        self.e_phentsize = None
        self.e_phnum = None
        self.e_shentsize = None
        self.e_shnum = None
        self.e_shstrndx = None


class ElfSection(object):
    pass


class ElfProgramHeader(object):
    pass


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
            self.fh.seek(0, pos)
        data = self.fh.read(size)
        self.where += size
        return data

    def read(self, size):
        return self.pread(self.where, size)


class Elf(object):
    def __init__(self, file_path):
        self.file_path = file_path
        self.fh = BinaryFileReader(file_path)
        self.header = ElfHeader()
        self.is32 = None
        self.load_elf_header()
        self.load_section_headers()
        self.load_program_headers()

    def close(self):
        self.fh.close()

    def error(self, msg):
        log_fatal("Elf %s: %s" % (self.file_path, msg))

    def load_elf_header(self):
        magic = self.fh.read(16)
        if magic[0:4] != '\x7fELF':
            self.error("magic doesn't match\n%s" % get_hex_string(magic))
        self.is32 = ord(magic[4]) == 1
        is_lsb = ord(magic[5]) == 1
        if not is_lsb:
            self.error("doesn't support MSB file.")
        if ord(magic[6]) != 1:
            self.error("unsupported version")
        



    def load_section_headers(self):
        pass
    


    def load_program_headers(self):
        pass


    def load_section_data(self, section_name):
        pass


def test_elf():
    elf = Elf("examples/exp1")



if __name__ == '__main__':
    test_elf()