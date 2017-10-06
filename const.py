

section_type_map = {
    0: 'SHT_NULL',
    1: 'SHT_PROGBITS',
    2: 'SHT_SYMTAB',
    3: 'SHT_STRTAB',
    4: 'SHT_RELA',
    5: 'SHT_HASH',
    6: 'SHT_DYNAMIC',
    7: 'SHT_NOTE',
    8: 'SHT_NOBITS',
    9: 'SHT_REL',
    10: 'SHT_SHLIB',
    11: 'SHT_DYNSYM',
    0x70000000: 'SHT_LOPROC',
    0x7fffffff: 'SHT_HIPROC',
    0x80000000: 'SHT_LOUSER',
    0xffffffff: 'SHT_HIUSER',
}

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11
SHT_LOPROC = 0x70000000
SHT_HIPROC = 0x7fffffff
SHT_LOUSER = 0x80000000
SHT_HIUSER = 0xffffffff



section_flags_array = [
    (0x1, 'SHF_WRITE'),
    (0x2, 'SHF_ALLOC'),
    (0x4, 'SHF_EXECINSTR'),
    (0xf0000000, 'SHF_MASKPROC'),
]

symbol_type_map = {
    0 : 'STT_NOTYPE',
    1 : 'STT_OBJECT',
    2 : 'STT_FUNC',
    3 : 'STT_SECTION',
    4 : 'STT_FILE',
    file : 'object',
    10 : 'STT_LOOS',
    12 : 'STT_HIOS',
    13 : 'STT_LOPROC',
    15 : 'STT_HIPROC',
}

symbol_bind_map = {
    0 : 'STB_LOCAL',
    1 : 'STB_GLOBAL',
    2 : 'STB_WEAK',
    10 : 'STB_LOOS',
    12 : 'STB_HIOS',
    13 : 'STB_LOPROC',
    15 : 'STB_HIPROC',
}

dwarf_tag_map = {
    0x01: 'DW_TAG_array_type',
    0x02: 'DW_TAG_class_type',
    0x03: 'DW_TAG_entry_point',
    0x04: 'DW_TAG_enumeration_type',
    0x05: 'DW_TAG_formal_parameter',
    0x08: 'DW_TAG_imported_declaration',
    0x0a: 'DW_TAG_label',
    0x0b: 'DW_TAG_lexical_block',
    0x0d: 'DW_TAG_member',
    0x0f: 'DW_TAG_pointer_type',
    0x10: 'DW_TAG_reference_type',
    0x11: 'DW_TAG_compile_unit',
    0x12: 'DW_TAG_string_type',
    0x13: 'DW_TAG_structure_type',
    0x15: 'DW_TAG_subroutine_type',
    0x16: 'DW_TAG_typedef',
    0x17: 'DW_TAG_union_type',
    0x18: 'DW_TAG_unspecified_parameters',
    0x19: 'DW_TAG_variant',
    0x1a: 'DW_TAG_common_block',
    0x1b: 'DW_TAG_common_inclusion',
    0x1c: 'DW_TAG_inheritance',
    0x1d: 'DW_TAG_inlined_subroutine',
    0x1e: 'DW_TAG_module',
    0x1f: 'DW_TAG_ptr_to_member_type',
    0x20: 'DW_TAG_set_type',
    0x21: 'DW_TAG_subrange_type',
    0x22: 'DW_TAG_with_stmt',
    0x23: 'DW_TAG_access_declaration',
    0x24: 'DW_TAG_base_type',
    0x25: 'DW_TAG_catch_block',
    0x26: 'DW_TAG_const_type',
    0x27: 'DW_TAG_constant',
    0x28: 'DW_TAG_enumerator',
    0x29: 'DW_TAG_file_type',
    0x2a: 'DW_TAG_friend',
    0x2b: 'DW_TAG_namelist',
    0x2c: 'DW_TAG_namelist_item',
    0x2d: 'DW_TAG_packed_type',
    0x2e: 'DW_TAG_subprogram',
    0x2f: 'DW_TAG_template_type_parameter',
    0x30: 'DW_TAG_template_value_parameter',
    0x31: 'DW_TAG_thrown_type',
    0x32: 'DW_TAG_try_block',
    0x33: 'DW_TAG_variant_part',
    0x34: 'DW_TAG_variable',
    0x35: 'DW_TAG_volatile_type',
    0x36: 'DW_TAG_dwarf_procedure',
    0x37: 'DW_TAG_restrict_type',
    0x38: 'DW_TAG_interface_type',
    0x39: 'DW_TAG_namespace',
    0x3a: 'DW_TAG_imported_module',
    0x3b: 'DW_TAG_unspecified_type',
    0x3c: 'DW_TAG_partial_unit',
    0x3d: 'DW_TAG_imported_unit',
    0x3f: 'DW_TAG_condition',
    0x40: 'DW_TAG_shared_type',
    0x41: 'DW_TAG_type_unit',
    0x42: 'DW_TAG_rvalue_reference_type',
    0x43: 'DW_TAG_template_alias',
}



dwarf_attr_map = {
    0x01: 'DW_AT_sibling',
    0x02: 'DW_AT_location',
    0x03: 'DW_AT_name',
    0x09: 'DW_AT_ordering',
    0x0b: 'DW_AT_byte_size',
    0x0c: 'DW_AT_bit_offset',
    0x0d: 'DW_AT_bit_size',
    0x10: 'DW_AT_stmt_list',
    0x11: 'DW_AT_low_pc',
    0x12: 'DW_AT_high_pc',
    0x13: 'DW_AT_language',
    0x15: 'DW_AT_discr',
    0x16: 'DW_AT_discr_value',
    0x17: 'DW_AT_visibility',
    0x18: 'DW_AT_import',
    0x19: 'DW_AT_string_length',
    0x1a: 'DW_AT_common_reference',
    0x1b: 'DW_AT_comp_dir',
    0x1c: 'DW_AT_const_value',
    0x1d: 'DW_AT_containing_type',
    0x1e: 'DW_AT_default_value',
    0x20: 'DW_AT_inline',
    0x21: 'DW_AT_is_optional',
    0x22: 'DW_AT_lower_bound',
    0x25: 'DW_AT_producer',
    0x27: 'DW_AT_prototyped',
    0x2a: 'DW_AT_return_addr',
    0x2c: 'DW_AT_start_scope',
    0x2e: 'DW_AT_bit_stride',
    0x2f: 'DW_AT_upper_bound',
    0x31: 'DW_AT_abstract_origin',
    0x32: 'DW_AT_accessibility',
    0x33: 'DW_AT_address_class',
    0x34: 'DW_AT_artificial',
    0x35: 'DW_AT_base_types',
    0x36: 'DW_AT_calling_convention',
    0x37: 'DW_AT_count',
    0x38: 'DW_AT_data_member_location',
    0x39: 'DW_AT_decl_column',
    0x3a: 'DW_AT_decl_file',
    0x3b: 'DW_AT_decl_line',
    0x3c: 'DW_AT_declaration',
    0x3d: 'DW_AT_discr_list',
    0x3e: 'DW_AT_encoding',
    0x3f: 'DW_AT_external',
    0x40: 'DW_AT_frame_base',
    0x41: 'DW_AT_friend',
    0x42: 'DW_AT_identifier_case',
    0x43: 'DW_AT_macro_info',
    0x44: 'DW_AT_namelist_item',
    0x45: 'DW_AT_priority',
    0x46: 'DW_AT_segment',
    0x47: 'DW_AT_specification',
    0x48: 'DW_AT_static_link',
    0x49: 'DW_AT_type',
    0x4a: 'DW_AT_use_location',
    0x4b: 'DW_AT_variable_parameter',
    0x4c: 'DW_AT_virtuality',
    0x4d: 'DW_AT_vtable_elem_location',
    0x4e: 'DW_AT_allocated',
    0x4f: 'DW_AT_associated',
    0x50: 'DW_AT_data_location',
    0x51: 'DW_AT_byte_stride',
    0x52: 'DW_AT_entry_pc',
    0x53: 'DW_AT_use_UTF8',
    0x54: 'DW_AT_extension',
    0x55: 'DW_AT_ranges',
    0x56: 'DW_AT_trampoline',
    0x57: 'DW_AT_call_column',
    0x58: 'DW_AT_call_file',
    0x59: 'DW_AT_call_line',
    0x5a: 'DW_AT_description',
    0x5b: 'DW_AT_binary_scale',
    0x5c: 'DW_AT_decimal_scale',
    0x5d: 'DW_AT_small',
    0x5e: 'DW_AT_decimal_sign',
    0x5f: 'DW_AT_digit_count',
    0x60: 'DW_AT_picture_string',
    0x61: 'DW_AT_mutable',
    0x62: 'DW_AT_threads_scaled',
    0x63: 'DW_AT_explicit',
    0x64: 'DW_AT_object_pointer',
    0x65: 'DW_AT_endianity',
    0x66: 'DW_AT_elemental',
    0x67: 'DW_AT_pure',
    0x68: 'DW_AT_recursive',
    0x69: 'DW_AT_signature',
    0x6a: 'DW_AT_main_subprogram',
    0x6b: 'DW_AT_data_bit_offset',
    0x6c: 'DW_AT_const_expr',
    0x6d: 'DW_AT_enum_class',
    0x6e: 'DW_AT_linkage_name',
}

DW_AT_sibling = 0x01
DW_AT_location = 0x02
DW_AT_name = 0x03
DW_AT_ordering = 0x09
DW_AT_byte_size = 0x0b
DW_AT_bit_offset = 0x0c
DW_AT_bit_size = 0x0d
DW_AT_stmt_list = 0x10
DW_AT_low_pc = 0x11
DW_AT_high_pc = 0x12
DW_AT_language = 0x13
DW_AT_discr = 0x15
DW_AT_discr_value = 0x16
DW_AT_visibility = 0x17
DW_AT_import = 0x18
DW_AT_string_length = 0x19
DW_AT_common_reference = 0x1a
DW_AT_comp_dir = 0x1b
DW_AT_const_value = 0x1c
DW_AT_containing_type = 0x1d
DW_AT_default_value = 0x1e
DW_AT_inline = 0x20
DW_AT_is_optional = 0x21
DW_AT_lower_bound = 0x22
DW_AT_producer = 0x25
DW_AT_prototyped = 0x27
DW_AT_return_addr = 0x2a
DW_AT_start_scope = 0x2c
DW_AT_bit_stride = 0x2e
DW_AT_upper_bound = 0x2f
DW_AT_abstract_origin = 0x31
DW_AT_accessibility = 0x32
DW_AT_address_class = 0x33
DW_AT_artificial = 0x34
DW_AT_base_types = 0x35
DW_AT_calling_convention = 0x36
DW_AT_count = 0x37
DW_AT_data_member_location = 0x38
DW_AT_decl_column = 0x39
DW_AT_decl_file = 0x3a
DW_AT_decl_line = 0x3b
DW_AT_declaration = 0x3c
DW_AT_discr_list = 0x3d
DW_AT_encoding = 0x3e
DW_AT_external = 0x3f
DW_AT_frame_base = 0x40
DW_AT_friend = 0x41
DW_AT_identifier_case = 0x42
DW_AT_macro_info = 0x43
DW_AT_namelist_item = 0x44
DW_AT_priority = 0x45
DW_AT_segment = 0x46
DW_AT_specification = 0x47
DW_AT_static_link = 0x48
DW_AT_type = 0x49
DW_AT_use_location = 0x4a
DW_AT_variable_parameter = 0x4b
DW_AT_virtuality = 0x4c
DW_AT_vtable_elem_location = 0x4d
DW_AT_allocated = 0x4e
DW_AT_associated = 0x4f
DW_AT_data_location = 0x50
DW_AT_byte_stride = 0x51
DW_AT_entry_pc = 0x52
DW_AT_use_UTF8 = 0x53
DW_AT_extension = 0x54
DW_AT_ranges = 0x55
DW_AT_trampoline = 0x56
DW_AT_call_column = 0x57
DW_AT_call_file = 0x58
DW_AT_call_line = 0x59
DW_AT_description = 0x5a
DW_AT_binary_scale = 0x5b
DW_AT_decimal_scale = 0x5c
DW_AT_small = 0x5d
DW_AT_decimal_sign = 0x5e
DW_AT_digit_count = 0x5f
DW_AT_picture_string = 0x60
DW_AT_mutable = 0x61
DW_AT_threads_scaled = 0x62
DW_AT_explicit = 0x63
DW_AT_object_pointer = 0x64
DW_AT_endianity = 0x65
DW_AT_elemental = 0x66
DW_AT_pure = 0x67
DW_AT_recursive = 0x68
DW_AT_signature = 0x69
DW_AT_main_subprogram = 0x6a
DW_AT_data_bit_offset = 0x6b
DW_AT_const_expr = 0x6c
DW_AT_enum_class = 0x6d
DW_AT_linkage_name = 0x6e

dwarf_attr_form_map = {
    0x01: 'DW_FORM_addr',
    0x03: 'DW_FORM_block2',
    0x04: 'DW_FORM_block4',
    0x05: 'DW_FORM_data2',
    0x06: 'DW_FORM_data4',
    0x07: 'DW_FORM_data8',
    0x08: 'DW_FORM_string',
    0x09: 'DW_FORM_block',
    0x0a: 'DW_FORM_block1',
    0x0b: 'DW_FORM_data1',
    0x0c: 'DW_FORM_flag',
    0x0d: 'DW_FORM_sdata',
    0x0e: 'DW_FORM_strp',
    0x0f: 'DW_FORM_udata',
    0x10: 'DW_FORM_ref_addr',
    0x11: 'DW_FORM_ref1',
    0x12: 'DW_FORM_ref2',
    0x13: 'DW_FORM_ref4',
    0x14: 'DW_FORM_ref8',
    0x15: 'DW_FORM_ref_udata',
    0x16: 'DW_FORM_indirect',
    0x17: 'DW_FORM_sec_offset',
    0x18: 'DW_FORM_exprloc',
    0x19: 'DW_FORM_flag_present',
    0x20: 'DW_FORM_ref_sig8',
}

DW_FORM_addr = 0x01
DW_FORM_block2 = 0x03
DW_FORM_block4 = 0x04
DW_FORM_data2 = 0x05
DW_FORM_data4 = 0x06
DW_FORM_data8 = 0x07
DW_FORM_string = 0x08
DW_FORM_block = 0x09
DW_FORM_block1 = 0x0a
DW_FORM_data1 = 0x0b
DW_FORM_flag = 0x0c
DW_FORM_sdata = 0x0d
DW_FORM_strp = 0x0e
DW_FORM_udata = 0x0f
DW_FORM_ref_addr = 0x10
DW_FORM_ref1 = 0x11
DW_FORM_ref2 = 0x12
DW_FORM_ref4 = 0x13
DW_FORM_ref8 = 0x14
DW_FORM_ref_udata = 0x15
DW_FORM_indirect = 0x16
DW_FORM_sec_offset = 0x17
DW_FORM_exprloc = 0x18
DW_FORM_flag_present = 0x19
DW_FORM_ref_sig8 = 0x20


DW_LNS_copy = 0x01
DW_LNS_advance_pc = 0x02
DW_LNS_advance_line = 0x03
DW_LNS_set_file = 0x04
DW_LNS_set_column = 0x05
DW_LNS_negate_stmt = 0x06
DW_LNS_set_basic_block = 0x07
DW_LNS_const_add_pc = 0x08
DW_LNS_fixed_advance_pc = 0x09
DW_LNS_set_prologue_end = 0x0a
DW_LNS_set_epilogue_begin = 0x0b
DW_LNS_set_isa = 0x0c
DW_LNE_end_sequence = 0x01
DW_LNE_set_address = 0x02
DW_LNE_define_file = 0x03
DW_LNE_set_discriminator = 0x04

dwarf_line_stdcode_map = {
    0x01 : 'DW_LNS_copy',
    0x02 : 'DW_LNS_advance_pc',
    0x03 : 'DW_LNS_advance_line',
    0x04 : 'DW_LNS_set_file',
    0x05 : 'DW_LNS_set_column',
    0x06 : 'DW_LNS_negate_stmt',
    0x07 : 'DW_LNS_set_basic_block',
    0x08 : 'DW_LNS_const_add_pc',
    0x09 : 'DW_LNS_fixed_advance_pc',
    0x0a : 'DW_LNS_set_prologue_end',
    0x0b : 'DW_LNS_set_epilogue_begin',
    0x0c : 'DW_LNS_set_isa',
}

dwarf_line_extend_code_map = {
    0x01 : 'DW_LNE_end_sequence',
    0x02 : 'DW_LNE_set_address',
    0x03 : 'DW_LNE_define_file',
    0x04 : 'DW_LNE_set_discriminator',
}

