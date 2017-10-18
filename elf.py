#!/usr/bin/env python

"""
elf.py: a library used to read from elf files.

"""

import argparse
import os
from struct import unpack
import subprocess

from const import *
from elf_types import *
from utils import *

class Elf(object):
    def __init__(self, file_path):
        self.file_path = file_path
        self.fh = BinaryFileReader(file_path)
        self.header = ElfHeader()
        self.addr_size = None
        self.addr_unpack_c = None
        self.sections = {}  # map from section id to ElfSection.
        self.section_names = {} # map from section name to ElfSection.
        self.shstr_section = None
        self.load_elf_header()
        self.load_section_headers()
        self.load_program_headers()

        self.abbrev_tables = {}  # map from offset in .debug_abbrev to AbbrevTable


    def close(self):
        self.fh.close()

    def error(self, msg):
        log_fatal("Elf %s: %s" % (self.file_path, msg))

    def load_elf_header(self):
        magic = self.fh.read(16)
        if magic[0:4] != '\x7fELF':
            self.error("magic doesn't match\n%s" % get_hex_string(magic))
        self.addr_size = 4 if ord(magic[4]) == 1 else 8
        self.addr_unpack_c = 'I' if self.addr_size == 4 else 'Q'
        is_lsb = ord(magic[5]) == 1
        if not is_lsb:
            self.error("doesn't support MSB file.")
        if ord(magic[6]) != 1:
            self.error("unsupported version")
        self.header.e_ident = magic
        data = self.fh.read(8)
        (self.header.e_type, self.header.e_machine, self.header.e_version) = unpack('HHI', data)
        data = self.fh.read(self.addr_size * 3)
        (self.header.e_entry, self.header.e_phoff, self.header.e_shoff) = unpack(self.addr_unpack_c * 3, data)
        self.header.e_flags = unpack('I', self.fh.read(4))
        data = self.fh.read(6 * 2)
        (self.header.e_ehsize, self.header.e_phentsize, self.header.e_phnum, self.header.e_shentsize,
         self.header.e_shnum, self.header.e_shstrndx) = unpack('H' * 6, data)

    def load_section_headers(self):
        if self.header.e_shstrndx:
            self._load_section_header(self.header.e_shstrndx)
        self.shstr_section = self.sections[self.header.e_shstrndx]
        self.load_section_data(self.shstr_section)
        for i in range(self.header.e_shnum):
            self._load_section_header(i)
        for section in self.sections.values():
            self.section_names[section.get_name()] = section
    
    def _load_section_header(self, section_index):
        if section_index in self.sections:
            return
        section = ElfSection(self, section_index)
        self.fh.seek(self.header.e_shoff + section_index * self.header.e_shentsize)
        data = self.fh.read(8 + self.addr_size)
        (section.sh_name, section.sh_type, section.sh_flags) = unpack('II' + self.addr_unpack_c, data)
        data = self.fh.read(self.addr_size * 2)
        (section.sh_addr, section.sh_offset) = unpack(self.addr_unpack_c * 2, data)
        data = self.fh.read(4 * 2 + self.addr_size * 3)
        (section.sh_size, section.sh_link, section.sh_info, section.sh_addralign, section.sh_entsize
            ) = unpack(self.addr_unpack_c +  'II' + self.addr_unpack_c * 2, data)
        self.sections[section_index] = section


    def load_program_headers(self):
        pass


    def load_section_data(self, section):
        section.data = self.fh.pread(section.sh_offset, section.sh_size)

    def get_section_name(self, sh_name):
        if self.shstr_section:
            end = self.shstr_section.data.index('\0', sh_name)
            return self.shstr_section.data[sh_name : end]

    def read_attr_value(self, compile_unit, data, attr_form):
        value = None
        if attr_form == DW_FORM_strp:
            offset = data.getUint(compile_unit.offset_size)
            value = self.read_string_in_debug_str(offset)
        elif attr_form == DW_FORM_data1:
            value = data.getUint(1)
        elif attr_form == DW_FORM_data2:
            value = data.getUint(2)
        elif attr_form == DW_FORM_data4:
            value = data.getUint(4)
        elif attr_form == DW_FORM_data8:
            value = data.getUint(8)
        elif attr_form == DW_FORM_udata:
            value = data.getUleb128()
        elif attr_form == DW_FORM_sdata:
            value = data.getSleb128()
        elif attr_form == DW_FORM_flag_present:
            value = 1
        elif attr_form == DW_FORM_flag:
            value = data.getUint(1)
        elif attr_form == DW_FORM_addr:
            value = data.getUint(compile_unit.addr_size)
        elif attr_form == DW_FORM_ref1:
            value = data.getUint(1)
        elif attr_form == DW_FORM_ref2:
            value = data.getUint(2)
        elif attr_form == DW_FORM_ref4:
            value = data.getUint(4)
        elif attr_form == DW_FORM_ref8:
            value = data.getUint(8)
        elif attr_form == DW_FORM_ref_udata:
            value = data.getUleb128()
        elif attr_form == DW_FORM_ref_addr:
            value = data.getUint(compile_unit.offset_size)
        elif attr_form == DW_FORM_ref_sig8:
            value = data.getUint(8)
        elif attr_form == DW_FORM_exprloc:
            length = data.getUleb128()
            value = data.getBytes(length)
        elif attr_form == DW_FORM_sec_offset:
            value = data.getUint(compile_unit.offset_size)
        elif attr_form == DW_FORM_string:
            value = data.getCString()
        return value

    def read_string_in_debug_str(self, offset):
        debug_str_section = self.section_names.get('.debug_str')
        if not debug_str_section:
            return None
        data = debug_str_section.get_data()
        if offset >= len(data):
            return None
        end = data.index('\0', offset)
        return data[offset:end]

    def load_debug_abbrev(self):
        if self.abbrev_tables:
            return
        debug_abbrev_section = self.section_names.get('.debug_abbrev')
        if not debug_abbrev_section:
            return
        data = debug_abbrev_section.get_data()
        data = DataParser(data)
        abbrev_table = self.abbrev_tables[0] = AbbrevTable()
        while not data.isEnd():
            abbrev_number = data.getUleb128()
            if abbrev_number == 0:
                abbrev_table = self.abbrev_tables[data.offset] = AbbrevTable()
                continue
            node = abbrev_table.abbrevs[abbrev_number] = AbbrevNode()
            node.tag = data.getUleb128()
            node.has_children = data.getUint(1)
            while True:
                attr_name = data.getUleb128()
                attr_form = data.getUleb128()
                if attr_name == 0:
                    break
                node.attr_names.append(attr_name)
                node.attr_forms.append(attr_form)


    def read_symbol(self, data):
        sym = ElfSymbol()
        if self.addr_size == 4:
            sym.st_name = data.getUint(4)
            sym.st_value = data.getUint(4)
            sym.st_size = data.getUint(4)
            sym.st_info = data.getUint(1)
            sym.st_other = data.getUint(1)
            sym.st_shndx = data.getUint(2)
        else:
            sym.st_name = data.getUint(4)
            sym.st_info = data.getUint(1)
            sym.st_other = data.getUint(1)
            sym.st_shndx = data.getUint(2)
            sym.st_value = data.getUint(8)
            sym.st_size = data.getUint(8)
        return sym

    def read_dwarf_line(self, data):
        header = DwarfLineHeader()
        header.unit_length = data.getUint(4)
        offset_size = 4
        if header.unit_length == 0xFFFFFFFF:
            header.unit_length = data.getUint(8)
            offset_size = 8
        header.endof_sequence = data.offset + header.unit_length
        header.version = data.getUint(2)
        assert header.version == 2
        header.header_length = data.getUint(offset_size)
        stmt_prog_offset = data.offset + header.header_length
        header.minimum_instruction_length = data.getUint(1)
        header.default_is_stmt = data.getUint(1)
        header.line_base = data.getInt(1)
        header.line_range = data.getUint(1)
        header.opcode_base = data.getUint(1)
        for _ in range(1, header.opcode_base):
            header.standard_opcode_lengths.append(data.getUint(1))
        while True:
            s = data.getCString()
            if not s: break
            header.include_directories.append(s)
        while True:
            s = data.getCString()
            if not s: break
            dir_index = data.getUleb128()
            time = data.getUleb128()
            file_length = data.getUleb128()
            header.files.append((s, dir_index, time, file_length))
        data.offset = stmt_prog_offset

        while data.offset < header.endof_sequence:
            opcode = data.getUint(1)
            if opcode == 0:
                length = data.getUleb128()
                extended_opcode = data.getUint(1)
                if length > 1:
                    arg = data.getBytes(length - 1)
                    header.opcodes.append((opcode, extended_opcode, arg))
                else:
                    header.opcodes.append((opcode, extended_opcode))
            elif opcode < header.opcode_base:
                args = [opcode]
                if opcode == DW_LNS_advance_line:
                    args.append(data.getSleb128())
                elif opcode == DW_LNS_fixed_advance_pc:
                    args.append(data.getUint(2))
                else:
                    for _ in range(header.standard_opcode_lengths[opcode - 1]):
                        args.append(data.getUleb128())
                header.opcodes.append(args)
            else:
                header.opcodes.append((opcode,))
        return header

    def read_compile_unit(self, data):
        compile_unit = CompileUnit()
        length = data.getUint(4)
        compile_unit.offset_size = 4
        if length == 0xFFFFFFFF:
            length = data.getUint(8)
            compile_unit.offset_size = 8
        compile_unit.length = length
        next_offset = data.offset + length
        compile_unit.version = data.getUint(2)
        compile_unit.debug_abbrev_offset = data.getUint(compile_unit.offset_size)
        self.load_debug_abbrev()
        compile_unit.abbrev_table = self.abbrev_tables[compile_unit.debug_abbrev_offset]
        compile_unit.addr_size = data.getUint(1)
        die_stack = []
        while data.offset < next_offset:
            die_offset = data.offset
            abbrev_number = data.getUleb128()
            if abbrev_number == 0:
                die_stack.pop()
                continue
            abbrev_node = compile_unit.abbrev_table.abbrevs[abbrev_number]
            die = DebugInfoEntry()
            if compile_unit.die is None:
                compile_unit.die = die
            die.abbrev_number = abbrev_number
            for i in range(len(abbrev_node.attr_forms)):
                form = abbrev_node.attr_forms[i]
                value = self.read_attr_value(compile_unit, data, form)
                die.attr_values.append(value)
            if abbrev_node.has_children:
                die_stack.append(die)
        return compile_unit
            




files = ['examples/exp1_32', 'examples/exp1_64']


def write(msg):
    print(msg)

def dump_wrapper(callback, args):
    file_list = args.i
    if not file_list:
        file_list = files
    for file in file_list:
        elf = Elf(file)
        write('file %s' % elf.file_path)
        callback(elf)
        write('\n\n')

def dump_section_names(elf):
        for sec_index in sorted(elf.sections):
            write('\t[%02d]  %s' % (sec_index, elf.sections[sec_index].get_name()))

def dump_section_headers(elf):
    for sec_index in sorted(elf.sections):
        section = elf.sections[sec_index]
        write('%s\n' % section)


def dump_debug_info(elf):
    debug_info_section = elf.section_names.get('.debug_info')
    if not debug_info_section: return
    data = DataParser(debug_info_section.get_data())
    write('section %s' % debug_info_section.get_name())
    while not data.isEnd():
        offset = data.offset
        compile_unit = elf.read_compile_unit(data)
        write('Compile unit (offset 0x%x)' % offset)
        write('Length:         0x%x  (%d-bit)' % (compile_unit.length, compile_unit.offset_size * 8))
        write('Version:        %d' % compile_unit.version)
        write('Abbrev Offset:  0x%x' % compile_unit.debug_abbrev_offset)
        write('Address size:   %d' % compile_unit.addr_size)
        
        def print_die_recur(die, level):
            abbrev_node = compile_unit.abbrev_table.abbrevs[die.abbrev_number]
            tag_name = dwarf_tag_map.get(abbrev_node.tag)
            write('  <%d>: Abbrev Number: %d (%s)' % (level, die.abbrev_number, tag_name))
            for i in range(len(abbrev_node.attr_names)):
                name = dwarf_attr_map.get(abbrev_node.attr_names[i])
                value = die.attr_values[i]
                write('    %-18s:  %s' % (name, value))
            for child in die.children:
                print_die_recur(child, level + 1)

        print_die_recur(compile_unit.die, 0)



def dump_debug_abbrev(elf):
    debug_abbrev_section = elf.section_names.get('.debug_abbrev')
    if not debug_abbrev_section:
        return
    data = DataParser(debug_abbrev_section.get_data())
    write('section %s' % debug_abbrev_section.get_name())
    while not data.isEnd():
        write('  Number TAG (0x%x)' % data.offset)
        while not data.isEnd():
            abbrev_number = data.getUleb128()
            if abbrev_number == 0:
                break
            tag = data.getUleb128()
            has_children = data.getUint(1)            
            write('   %d     %s     [%s]' % (abbrev_number, dwarf_tag_map[tag],
                                             has_children and 'has children' or 'no children'))
            while True:
                attr_name = data.getUleb128()
                attr_form = data.getUleb128()
                if attr_name == 0:
                    break
                write('    %-18s %s' % (dwarf_attr_map.get(attr_name), dwarf_attr_form_map.get(attr_form)))

class AddrDiff(object):
    def __init__(self):
        self.addr_diff = -1
        self.addr = 0

def dump_debug_line(elf):
    section = elf.section_names.get('.debug_line')
    if not section: return
    data = DataParser(section.get_data())
    write('section %s' % section.get_name())
    addr_diff = AddrDiff()
    while not data.isEnd():
        offset = data.offset
        header = elf.read_dwarf_line(data)
        write('Offset:                      0x%x' % offset)
        write('Length:                      %d' % header.unit_length)
        write('Dwarf Version:               %d' % header.version)
        write('Prologue Length:             %d' % header.header_length)
        write('Minimum Instruction Length:  %d' % header.minimum_instruction_length)
        write('Default is_stmt:             %d' % header.default_is_stmt)
        write('Line Base:                   %d' % header.line_base)
        write('Line Range:                  %d' % header.line_range)
        write('Opcode Base:                 %d' % header.opcode_base)
        write('Opcodes:')
        for i in range(1, header.opcode_base):
            write('  Opcode %d has %d args' % (i, header.standard_opcode_lengths[i-1]))
        if not header.include_directories:
            write('The Directory Table is empty.')
        else:
            write('The Directory Table:')
            for i in range(len(header.include_directories)):
                write('  %d\t%s' % (i + 1, header.include_directories[i]))
        if not header.files:
            write('The File Name Table is empty.')
        else:
            write('The File Name Table:')
            write('  Entry\tDir\tTime\tSize\tName')
            for i in range(len(header.files)):
                (name, dir_index, time, file_length) = header.files[i]
                write('  %d\t%x\t%x\t%x\t%s' % (i + 1, dir_index, time, file_length, name))

        if not header.opcodes:
            write('No Line number statements.')
        else:
            write('Line number statements:')
            state = DwarfLineState(header.default_is_stmt)
            for args in header.opcodes:
                opcode = args[0]
                if opcode >= header.opcode_base:
                    opcode -= header.opcode_base
                    add_addr = opcode / header.line_range * header.minimum_instruction_length
                    add_line = opcode % header.line_range + header.line_base
                    state.addr += add_addr
                    state.line += add_line
                    write('  Special opcode %d: advance address by 0x%x to 0x%x, and line by %d to %d' % (
                        args[0], add_addr, state.addr, add_line, state.line))
                elif opcode == 0:
                    extended_opcode = args[1]
                    s = '  Extended opcode %d (%s)' % (extended_opcode, dwarf_line_extend_code_map.get(extended_opcode))
                    if extended_opcode == DW_LNE_end_sequence:
                        write('%s: End of sequence' % s)
                        state = DwarfLineState(header.default_is_stmt)
                    elif extended_opcode == DW_LNE_set_address:
                        state.addr = DataParser(args[2]).getUint(elf.addr_size)
                        write('%s: Set address to 0x%x' % (s, state.addr))
                    elif extended_opcode == DW_LNE_set_discriminator:
                        write('%s' % s)
                    else:
                        write('%s' % s)
                        log_exit('unhandled instruction')
                else:
                    s = '  Standard opcode %d (%s)' % (opcode, dwarf_line_stdcode_map.get(opcode))
                    if opcode == DW_LNS_advance_pc:
                        add_addr = args[1] * header.minimum_instruction_length
                        state.addr += add_addr
                        write('%s: Advance pc by 0x%x to 0x%x' % (s, add_addr, state.addr))
                    elif opcode == DW_LNS_advance_line:
                        add_line = args[1]
                        state.line += add_line
                        write('%s: Advance line by %d to %d' % (s, add_line, state.line))
                    elif opcode == DW_LNS_set_column:
                        state.column = args[1]
                        write('%s: Set column to %d' % (s, state.column))
                    elif opcode == DW_LNS_const_add_pc or opcode == DW_LNS_fixed_advance_pc:
                        add_addr = (255 - header.opcode_base) / header.line_range * header.minimum_instruction_length
                        state.addr += add_addr
                        write('%s: Advance pc by 0x%x to 0x%x' % (s, add_addr, state.addr))
                    elif opcode == DW_LNS_set_file:
                        file_id = args[1]
                        write('%s: Set file to %s' % (s, header.files[file_id-1][0]))
                    elif opcode == DW_LNS_copy or opcode == DW_LNS_set_prologue_end or opcode == DW_LNS_negate_stmt:
                        write('%s' % s)
                    else:
                        write('%s' % s)
                        log_exit('unhandled instruction')
            write('')
            write('Decoded line table:')
            write('%20s  %11s  %11s' % ('File name', 'Line number', 'Start address'))
            state = DwarfLineState(header.default_is_stmt)
            old_file_line = [None, None]
            force_dump = False
            force_reset = False
            last_addr = None
            last_addr_is_zero = False
            for args in header.opcodes:
                opcode = args[0]
                if opcode >= header.opcode_base:
                    opcode -= header.opcode_base
                    add_addr = opcode / header.line_range * header.minimum_instruction_length
                    add_line = opcode % header.line_range + header.line_base
                    state.addr += add_addr
                    state.line += add_line
                    force_dump = True
                elif opcode == 0:
                    extended_opcode = args[1]
                    if extended_opcode == DW_LNE_set_address:
                        state.addr = DataParser(args[2]).getUint(elf.addr_size)
                    elif extended_opcode == DW_LNE_end_sequence:
                        force_dump = True
                        force_reset = True
                else:
                    if opcode == DW_LNS_advance_pc:
                        state.addr += args[1] * header.minimum_instruction_length
                    elif opcode == DW_LNS_advance_line:
                        state.line += args[1]
                    elif opcode == DW_LNS_const_add_pc or opcode == DW_LNS_fixed_advance_pc:
                        state.addr += (255 - header.opcode_base) / header.line_range * header.minimum_instruction_length
                    elif opcode == DW_LNS_set_file:
                        state.file = args[1]
                    elif opcode == DW_LNS_copy:
                        force_dump = True
                if force_dump:
                    force_dump = False
                    if old_file_line[0] != state.file or old_file_line[1] != state.line:
                        write('%20s  %11d  0x%-9x' % (header.files[state.file-1][0], state.line, state.addr))
                        old_file_line[0] = state.file
                        old_file_line[1] = state.line
                    if (state.line == 0 or last_addr_is_zero) and last_addr >= 0x4001c0:
                        diff = state.addr - last_addr
                        if diff > addr_diff.addr_diff:
                            addr_diff.addr_diff = diff
                            addr_diff.addr = state.addr
                            write('%20s  %11d  0x%-9x mark' % (header.files[state.file-1][0], state.line, state.addr))
                    last_addr_is_zero = state.line == 0
                    last_addr = state.addr

                if force_reset:
                    force_reset = False
                    state = DwarfLineState(header.default_is_stmt)
                    last_addr_is_zero = False
                    last_addr = 0

        data.offset = header.endof_sequence
    log_debug('addr_diff max_diff = 0x%x, addr = 0x%x' % (addr_diff.addr_diff, addr_diff.addr))


def dump_symbol_table(elf):
    for sec_index in sorted(elf.sections.keys()):
        section = elf.sections[sec_index]
        if section.sh_type != SHT_SYMTAB and section.sh_type != SHT_DYNSYM:
            continue
        str_sec = elf.sections[section.sh_link]
        str_data = DataParser(str_sec.get_data())
        data = DataParser(section.get_data())
        log_info('section %s' % section.get_name())
        log_info('%8s: %8s %8s %8s %8s %8s %8s %s' % ('Num', 'Value', 'Size', 'Type',
                                                      'Bind', 'Vis', 'Ndx', 'Name'))
        number = 0
        while not data.isEnd():
            sym = elf.read_symbol(data)
            str_data.offset = sym.st_name
            name = str_data.getCString()
            log_info('%8d: %08x %8d %8s %8s %8s %8s %s' % (number, sym.st_value, sym.st_size,
                    sym.get_type()[4:], sym.get_bind()[4:], "", sym.st_shndx, name))
            number += 1
        log_info('\n')

def dump_strings(elf):
    for sec_index in sorted(elf.sections.keys()):
        section = elf.sections[sec_index]
        if section.sh_type != SHT_STRTAB:
            continue
        log_info('section %s' % section.get_name())
        data = DataParser(section.get_data())
        pos = 0
        while not data.isEnd():
            line = data.getBytes(min(data.remainLen(), 16))
            log_info('0x%05x  %s' % (pos, get_hex_string(line)))
            pos += len(line)
        log_info('\n')


def extract_gnu_debugdata(file_path):
    elf = Elf(file_path)
    gnu_debugdata_section = elf.section_names.get('.gnu_debugdata')
    if not gnu_debugdata_section:
        log_exit('no .debug_gnudebugdata')
    data = gnu_debugdata_section.get_data()
    out_file = 'gnu_debugdata.xz'
    with open(out_file, 'wb') as f:
        f.write(data)
    if os.path.isfile(out_file[:-3]):
        os.remove(out_file[:-3])
    subprocess.check_call(['xz', '-d', out_file])
    log_info('write .debug_gnudebugdata to %s' % out_file[:-3])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='parse dwarf sections')
    parser.add_argument('--dump-sec-names', action='store_true', help='dump section names')
    parser.add_argument('--dump-sec-headers', action='store_true', help='dump section headers.')
    parser.add_argument('--dump-debug-info', action='store_true', help='dump .debug_info section.')
    parser.add_argument('--dump-debug-abbrev', action='store_true', help='dump .debug_abbrev section.')
    parser.add_argument('--dump-debug-line', action='store_true', help='dump .debug_line section.')
    parser.add_argument('--dump-symbols', action='store_true', help='dump .symtab section.')
    parser.add_argument('--dump-strings', action='store_true', help='dump string sections: .shstrtab, .dynstr, .strtab')
    parser.add_argument('--extract-gnu-debugdata', action='store_true', help='extract .gnudebugdata.')
    parser.add_argument('-i', nargs=1, help='Set input elf file.')
    args = parser.parse_args()
    print('%s' % args)

    if args.dump_sec_names:
        dump_wrapper(dump_section_names, args)
    if args.dump_sec_headers:
        dump_wrapper(dump_section_headers, args)
    if args.dump_debug_info:
        dump_wrapper(dump_debug_info, args)
    if args.dump_debug_abbrev:
        dump_wrapper(dump_debug_abbrev, args)
    if args.dump_debug_line:
        dump_wrapper(dump_debug_line, args)
    if args.dump_symbols:
        dump_wrapper(dump_symbol_table, args)
    if args.dump_strings:
        dump_wrapper(dump_strings, args)
    if args.extract_gnu_debugdata:
        extract_gnu_debugdata(args.i[0])
