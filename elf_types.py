
from const import *
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

    def __str__(self):
        strs = []
        strs.append('e_ident: %s' % get_hex_string(self.e_ident))
        strs.append('is32: %d' % self.is32())
        strs.append('e_type: %d (%s)' % (self.e_type, self.get_file_type()))
        strs.append('e_machine: %d (%s)' % (self.e_machine, self.get_machine()))
        strs.append('e_version: %d' % self.e_version)
        strs.append('e_entry: 0X%X' % self.e_entry)
        strs.append('e_phoff: 0X%X' % self.e_phoff)
        strs.append('e_shoff: 0X%X' % self.e_shoff)
        strs.append('e_flags: 0X%X' % self.e_flags)
        strs.append('e_ehsize: %d (0X%X)' % (self.e_ehsize, self.e_ehsize))
        strs.append('e_phentsize: %d (0X%X)' % (self.e_phentsize, self.e_phentsize))
        strs.append('e_phnum: %d (0X%X)' % (self.e_phnum, self.e_phnum))
        strs.append('e_shentsize: %d (0X%X)' % (self.e_shentsize, self.e_shentsize))
        strs.append('e_shnum: %d (0X%X)' % (self.e_shnum, self.e_shnum))
        strs.append('e_shstrndx: %d' % self.e_shstrndx)
        return '\n'.join(strs)
    
    def is32(self):
        return self.e_ident[4] == '\x01'

    def get_file_type(self):
        if self.e_type == 1:
            return "Relocatable file"
        if self.e_type == 2:
            return "Executable file"
        if self.e_type == 3:
            return "Shared object file"
        if self.e_type == 4:
            return "Core file"
        return "Unknown"

    def get_machine(self):
        if self.e_machine == 3:
            return "EM_386"
        if self.e_machine == 62:
            return "EM_X86_64"
        return "Unknown"


class ElfSection(object):
    def __init__(self, elf, section_index):
        self.elf = elf
        self.section_index = section_index
        self.sh_name = None
        self.sh_type = None
        self.sh_flags = None
        self.sh_addr = None
        self.sh_offset = None
        self.sh_size = None
        self.sh_link = None
        self.sh_info = None
        self.sh_addralign = None
        self.sh_entsize = None
        self.data = None

    def __str__(self):
        strs = []
        strs.append('Section %d' % self.section_index)
        strs.append('sh_name: %d (%s)' % (self.sh_name, self.get_name()))
        strs.append('sh_type: 0X%X (%s)' % (self.sh_type, self.get_type()))
        strs.append('sh_flags: 0X%X (%s)' % (self.sh_flags, self.get_flags()))
        strs.append('sh_addr: 0X%X' % self.sh_addr)
        strs.append('sh_offset: 0X%X' % self.sh_offset)
        strs.append('sh_size: %d (0X%X)' % (self.sh_size, self.sh_size))
        strs.append('sh_link: %d' % self.sh_link)
        strs.append('sh_info: %d' % self.sh_info)
        strs.append('sh_addralign: %d' % self.sh_addralign)
        strs.append('sh_entsize: %d' % self.sh_entsize)
        return '\n'.join(strs)

    def get_name(self):
        return self.elf.get_section_name(self.sh_name)

    def get_type(self):
        if self.sh_type in section_type_map:
            return section_type_map[self.sh_type]
        return 'Unknown'        

    def get_flags(self):
        res = []
        for item in section_flags_array:
            if self.sh_flags & item[0]:
                res.append(item[1])
        return ' '.join(res)

    def get_data(self):
        if self.data is None:
            self.elf.load_section_data(self)
        return self.data

class ElfProgramHeader(object):
    pass


class ElfSymbol(object):
    def __init__(self):
        self.st_name = None
        self.st_value = None
        self.st_size = None
        self.st_info = None
        self.st_other = None
        self.st_shndx = None

    def get_type(self):
        return symbol_type_map[self.st_info & 0xf]

    def get_bind(self):
        return symbol_bind_map[self.st_info >> 4]

class AbbrevNode(object):
    def __init__(self):
        self.tag = None
        self.has_children = None
        self.attr_names = []
        self.attr_forms = []

class AbbrevTable(object):
    def __init__(self):
        self.abbrevs = {}  # map from abbrev_number to AbbrevNode

class DebugInfoEntry(object):
    def __init__(self):
        self.abbrev_number = None
        self.attr_values = []
        self.children = []

class CompileUnit(object):
    def __init__(self):
        self.offset_size = None
        self.length = None
        self.version = None
        self.debug_abbrev_offset = None
        self.abbrev_table = None
        self.addr_size = None
        self.code_ranges = []  # list of (low_pc, high_pc) pairs
        self.die = None


class DwarfLineHeader(object):
    def __init__(self):
        self.endof_sequence = None
        self.unit_length = None
        self.version = None
        self.header_length = None
        self.minimum_instruction_length = None
        self.default_is_stmt = None
        self.line_base = None
        self.line_range = None
        self.opcode_base = None
        self.standard_opcode_lengths = []
        self.include_directories = []
        self.files = []  # list of pair (file_name, dir_index, time, file_length)
        self.opcodes = [] # list of pair (opcode, optional args)

class DwarfLineState(object):
    def __init__(self, is_stmt):
        self.addr = 0
        self.file = 1
        self.line = 1
        self.column = 0
        self.is_stmt = is_stmt
        self.basic_block = 0
        self.end_sequence = 0
