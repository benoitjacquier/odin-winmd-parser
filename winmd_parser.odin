package main

import "core:os"
import "core:strings"
import "core:fmt"
import "core:mem"
import "core:slice"
import "intrinsics"
import win32 "core:sys/windows"
import c "core:c"

Image_Dos_Header :: struct {
	e_signature: u16,
	e_cblp:      u16,
	e_cp:        u16,
	e_crlc:      u16,
	e_cparhdr:   u16,
	e_minalloc:  u16,
	e_maxalloc:  u16,
	e_ss:        u16,
	e_sp:        u16,
	e_csum:      u16,
	e_ip:        u16,
	e_cs:        u16,
	e_lfarlc:    u16,
	e_ovno:      u16,
	e_res:       [4]u16,
	e_oemid:     u16,
	e_oeminfo:   u16,
	e_res2:      [10]u16,
	e_lfanew:    i32,
};

Image_File_Header :: struct {
	Machine:              u16,
	NumberOfSections:     u16,
	TimeDateStamp:        u32,
	PointerToSymbolTable: u32,
	NumberOfSymbols:      u32,
	SizeOfOptionalHeader: u16,
	Characteristics:      u16,
};

Image_Data_Directory :: struct {
	VirtualAddress: u32,
	Size:           u32,
};

Image_Optional_Header32 :: struct {
	Magic:                       u16,
	MajorLinkerVersion:          u8,
	MinorLinkerVersion:          u8,
	SizeOfCode:                  u32,
	SizeOfInitializedData:       u32,
	SizeOfUninitializedData:     u32,
	AddressOfEntryPoint:         u32,
	BaseOfCode:                  u32,
	BaseOfData:                  u32,
	ImageBase:                   u32,
	SectionAlignment:            u32,
	FileAlignment:               u32,
	MajorOperatingSystemVersion: u16,
	MinorOperatingSystemVersion: u16,
	MajorImageVersion:           u16,
	MinorImageVersion:           u16,
	MajorSubsystemVersion:       u16,
	MinorSubsystemVersion:       u16,
	Win32VersionValue:           u32,
	SizeOfImage:                 u32,
	SizeOfHeaders:               u32,
	CheckSum:                    u32,
	Subsystem:                   u16,
	DllCharacteristics:          u16,
	SizeOfStackReserve:          u32,
	SizeOfStackCommit:           u32,
	SizeOfHeapReserve:           u32,
	SizeOfHeapCommit:            u32,
	LoaderFlags:                 u32,
	NumberOfRvaAndSizes:         u32,
	DataDirectory:               [16]Image_Data_Directory,
};

Image_Nt_Headers32 :: struct {
	Signature:      u32,
	FileHeader:     Image_File_Header,
	OptionalHeader: Image_Optional_Header32,
};

Image_Optional_Header32plus :: struct {
	Magic:                       u16,
	MajorLinkerVersion:          u8,
	MinorLinkerVersion:          u8,
	SizeOfCode:                  u32,
	SizeOfInitializedData:       u32,
	SizeOfUninitializedData:     u32,
	AddressOfEntryPoint:         u32,
	BaseOfCode:                  u32,
	ImageBase:                   u64,
	SectionAlignment:            u32,
	FileAlignment:               u32,
	MajorOperatingSystemVersion: u16,
	MinorOperatingSystemVersion: u16,
	MajorImageVersion:           u16,
	MinorImageVersion:           u16,
	MajorSubsystemVersion:       u16,
	MinorSubsystemVersion:       u16,
	Win32VersionValue:           u32,
	SizeOfImage:                 u32,
	SizeOfHeaders:               u32,
	CheckSum:                    u32,
	Subsystem:                   u16,
	DllCharacteristics:          u16,
	SizeOfStackReserve:          u64,
	SizeOfStackCommit:           u64,
	SizeOfHeapReserve:           u64,
	SizeOfHeapCommit:            u64,
	LoaderFlags:                 u32,
	NumberOfRvaAndSizes:         u32,
	DataDirectory:               [16]Image_Data_Directory,
};

Image_Nt_Headers32plus :: struct {
	Signature:      u32,
	FileHeader:     Image_File_Header,
	OptionalHeader: Image_Optional_Header32plus,
};

Image_Section_Header :: struct {
	Name: [8]u8, // IMAGE_SIZEOF_SHORT_NAME
	Misc: struct #raw_union {
		PhysicalAddress: u32,
		VirtualSize:     u32,
	},
	VirtualAddress:       u32,
	SizeOfRawData:        u32,
	PointerToRawData:     u32,
	PointerToRelocations: u32,
	PointerToLinenumbers: u32,
	NumberOfRelocations:  u16,
	NumberOfLinenumbers:  u16,
	Characteristics:      u32,
};

Image_Cor20_Header :: struct {
	cb:                  u32,
	MajorRuntimeVersion: u16,
	MinorRuntimeVersion: u16,
	MetaData:            Image_Data_Directory,
	Flags:               u32,
	dummyunionname: struct #raw_union {
		EntryPointToken: u32,
		EntryPointRVA:   u32,
	},
	Resources:               Image_Data_Directory,
	StrongNameSignature:     Image_Data_Directory,
	CodeManagerTable:        Image_Data_Directory,
	VTableFixups:            Image_Data_Directory,
	ExportAddressTableJumps: Image_Data_Directory,
	ManagedNativeHeader:     Image_Data_Directory,
};

section_from_rva :: proc(sections: []Image_Section_Header, rva: u32) -> ^Image_Section_Header {
	for _, i in sections {
		s := &sections[i];
		if rva >= s.VirtualAddress && rva < s.VirtualAddress + s.Misc.VirtualSize {
			return s;
		}
	}
	return nil;
}

offset_from_rva :: proc(section: Image_Section_Header, rva: u32) -> uintptr {
	return uintptr(rva - section.VirtualAddress + section.PointerToRawData);
}

to_string :: proc(s: []byte) -> string {
	n := 0;
	for c in s {
		if c == 0 {
			break;
		}
		n += 1;
	}
	return string(s[:n]);
}

read_compressed_cond :: proc($T: typeid, cursor: ^[]byte, cond: T) -> bool {
	val, length := peek_compressed( T, cursor^ );
	if val==cond {
		cursor^ = cursor[length:];
		return true;
	}
	return false;
}

peek_compressed :: proc($T: typeid, cursor: []byte) -> (T, u32) {
	data := uintptr(raw_data(cursor));
	value: u32;
	length: u32;
    switch x := (^u8)(data)^; {
	case x & 0x80 == 0x00:
		length = 1;
		value = u32(x);
	case x & 0xc0 == 0x80:
		length = 2;
		value = u32(x & 0x3f) << 8;
		data += 1;
		value |= u32((^u8)(data)^);
	case x & 0xe0 == 0xc0:
		length = 4;
		value = u32(x & 0x1f) << 24;
		data += 1;
		value |= u32((^u8)(data)^) << 16;
		data += 1;
		value |= u32((^u8)(data)^) << 8;
		data += 1;
		value |= u32((^u8)(data)^);
	case:
		panic("invalid compressed integer in blob");
	}
	return cast(T)value, length;
}

read_compressed :: proc($T: typeid, cursor: ^[]byte) -> T {
	val, length := peek_compressed( T, cursor^ );
	cursor^ = cursor[length:];
	return val;

}

read_data :: proc($T: typeid, cursor: ^[]byte) -> T {
	res := (^T)(raw_data(cursor^))^;
	cursor^ = cursor[size_of(T):];
	return res;
}

Database :: struct {
	data: []byte,
	ptr: uintptr,

	strings: []byte,
	blobs:   []byte,
	guids:   []byte,
	tables:  []byte,

	module:                   Table,
	type_ref:                 Table,
	type_def:                 Table,
	field:                    Table,
	method_def:               Table,
	param:                    Table,
	interface_impl:           Table,
	member_ref:               Table,
	constant:                 Table,
	custom_attribute:         Table,
	field_marshal:            Table,
	decl_security:            Table,
	class_layout:             Table,
	field_layout:             Table,
	stand_alone_sig:          Table,
	event_map:                Table,
	event:                    Table,
	property_map:             Table,
	property:                 Table,
	method_semantics:         Table,
	method_impl:              Table,
	module_ref:               Table,
	type_spec:                Table,
	impl_map:                 Table,
	field_rva:                Table,
	assembly:                 Table,
	assembly_processor:       Table,
	assembly_os:              Table,
	assembly_ref:             Table,
	assembly_ref_processor:   Table,
	assembly_ref_os:          Table,
	file:                     Table,
	exported_type:            Table,
	manifest_resource:        Table,
	nested_class:             Table,
	generic_param:            Table,
	method_spec:              Table,
	generic_param_constraint: Table,


	typedef_map_pername: map[string]u32

}

Table_Column :: struct {
	offset, size: u32,
}
Table :: struct {
	ptr:       uintptr,
	row_count: u32,
	row_size:  u32,
	columns:   [6]Table_Column,
}

table_set_columns :: proc(t: ^Table, table_ptr: ^uintptr, a: u8, b := u8(0), c := u8(0), d := u8(0), e := u8(0), f := u8(0)) {
	assert(a != 0);
	assert(a <= 8);
	assert(b <= 8);
	assert(c <= 8);
	assert(d <= 8);
	assert(e <= 8);
	assert(f <= 8);

	assert(t.row_size == 0);
	t.row_size = u32(a + b + c + d + e + f);

	t.columns[0] = {0, u32(a)};
	if b != 0 { t.columns[1] = {u32(a), u32(b)}; }
	if c != 0 { t.columns[2] = {u32(a+b), u32(c)}; }
	if d != 0 { t.columns[3] = {u32(a+b+c), u32(d)}; }
	if e != 0 { t.columns[4] = {u32(a+b+c+d), u32(e)}; }
	if f != 0 { t.columns[5] = {u32(a+b+c+d+e), u32(f)}; }

	t.ptr = table_ptr^;
	table_ptr^ += uintptr(t.row_count) * uintptr(t.row_size);
}

table_index_size :: proc(t: Table) -> u8 {
	return 2 if t.row_count < 1<<16 else 4;
}

table_get_value :: proc (t: ^Table, $T: typeid, row, column: u32) -> T {
	#assert(size_of(T)==4 || size_of(T)==2);
	column_table := &t.columns[column];
	assert(column_table.size<=size_of(T) && row<=t.row_count);

	ptr := t.ptr + uintptr(row*t.row_size + column_table.offset);
	switch column_table.size {
	case 1: return T((^ u8)(ptr)^);
	case 2: return T((^u16)(ptr)^);
	case 4: return T((^u32)(ptr)^);
	case 8: return T((^u64)(ptr)^);
	}
	return T((^u64)(ptr)^);
}

bits_needed :: proc(value: u32) -> u8 {
	value := value;
	value -= 1;
	bits := u8(1);
	for {
		value >>= 1;
		if value == 0 {
			break;
		}
		bits += 1;
	}
	return bits;
}

is_composite_index_size :: proc(row_count: u32, bits: u8) -> bool {
	return row_count < (u32(1) << (16-bits));
}

composite_index_size :: proc(tables: ..Table) -> u8 {
	assert(len(tables) > 0);
	n := bits_needed(u32(len(tables)));
	for table in tables {
		if !is_composite_index_size(table.row_count, n) {
			return 4;
		}
	}
	return 2;
}

database_get_blob :: proc(db: ^Database, index: u32) -> []byte {
	data := db.blobs[index:];
	initial_byte := data[0];
	blob_size_bytes: u32;

	switch initial_byte>>5 {
	case 0, 1, 2, 3:
		blob_size_bytes = 1;
		initial_byte &= 0x7f;
	case 4, 5:
		blob_size_bytes = 2;
		initial_byte &= 0x3f;
	case 6:
		blob_size_bytes = 4;
		initial_byte &= 0x1f;
	case:
		panic("invalid blob encoding");
	}

	blob_size := u32(initial_byte);

	for b in data[1:blob_size_bytes-1] {
		blob_size = (blob_size << 8) + u32(b);
	}

	return data[blob_size_bytes:][:blob_size];
}


database_get_string :: proc (db: ^Database, index: u32) -> (string, bool) {
	if index >= u32(len(db.strings)) {
		return "OUT OF BOUND", false;
	}
	s := db.strings[index:];
	if i, ok := slice.linear_search(s[:], 0); ok {
		return string(s[:i]), true;
	}
	return "NO END", false;
}

table_get_string :: proc (db: ^Database, table: ^Table, row, column: u32) -> (string, bool) {
	index := table_get_value(table, u32, row, column);
	return database_get_string(db, index);
}


parse_database :: proc(db: ^Database) -> bool {
	if len(db.data) < size_of(Image_Dos_Header) {
		return false;
	}
	db.ptr = uintptr(raw_data(db.data));
	ptr := db.ptr;

	dos := (^Image_Dos_Header)(ptr);
	if dos.e_signature != 0x5a4d {
		return false;
	}

	if len(db.data) < int(dos.e_lfanew) + size_of(Image_Nt_Headers32) {
		return false;
	}

	pe := (^Image_Nt_Headers32)(ptr + uintptr(dos.e_lfanew));
	if pe.FileHeader.NumberOfSections == 0 || pe.FileHeader.NumberOfSections > 100 {
		return false;
	}

	sections_ptr: ^Image_Section_Header;
	com_virtual_address: u32;

	switch pe.OptionalHeader.Magic {
	case 0x10b: // PE32
		com_virtual_address = pe.OptionalHeader.DataDirectory[14].VirtualAddress;
		sections_ptr = (^Image_Section_Header)(ptr + uintptr(dos.e_lfanew) + size_of(Image_Nt_Headers32));
	case 0x20b: // PE32+
		pe_plus := (^Image_Nt_Headers32plus)(ptr + uintptr(dos.e_lfanew));
		com_virtual_address = pe_plus.OptionalHeader.DataDirectory[14].VirtualAddress;
		sections_ptr = (^Image_Section_Header)(ptr + uintptr(dos.e_lfanew) + size_of(Image_Nt_Headers32plus));
	case:
		return false;
	}
	sections := mem.slice_ptr(sections_ptr, int(pe.FileHeader.NumberOfSections));
	section := section_from_rva(sections, com_virtual_address);
	if section == nil {
		return false;
	}

	offset := offset_from_rva(section^, com_virtual_address);

	cli := (^Image_Cor20_Header)(ptr + offset);

	if cli.cb != size_of(Image_Cor20_Header) {
		return false;
	}

	section = section_from_rva(sections, cli.MetaData.VirtualAddress);
	if section == nil {
		return false;
	}

	offset = offset_from_rva(section^, cli.MetaData.VirtualAddress);
	if (^u32)(ptr + offset)^ != 0x424a5342 {
		return false;
	}

	version_length := (^u32)(ptr + offset + 12)^;
	stream_count := (^u16)(ptr + offset + uintptr(version_length) + 18)^;
	stream_ptr := ptr + offset + uintptr(version_length) + 20;

	Stream_Range :: struct {
		offset: u32,
		size:   u32,
	};

	for i in 0..<stream_count {
		stream := (^Stream_Range)(stream_ptr);
		name := to_string((^[12]byte)(stream_ptr + 8)[:]);

		table_offset := offset+uintptr(stream.offset);

		switch name {
		case "#Strings":
			db.strings = db.data[table_offset:][:stream.size];
			//printf("string table offset %v\n", table_offset );
		case "#Blob":
			db.blobs   = db.data[table_offset:][:stream.size];
		case "#GUID":
			db.guids   = db.data[table_offset:][:stream.size];
		case "#~":
			db.tables  = db.data[table_offset:][:stream.size];
			//printf("tables offset %v\n", table_offset );
		case "#US":
			// ignore
		case:
			return false;
		}

		{
			n := uintptr(len(name));
			padding := 4 - n%4;
			if padding == 0 {
				padding = 4;
			}
			stream_ptr += 8 + n + padding;
		}
	}

    start := 0;
    for r, idx in db.strings {
        if r==0 && idx>start {
            str : string = cast(string)db.strings[start:idx];
            start = idx+1;
        }
    }

	heap_sizes := (^bit_set[0..<8; u8])(&db.tables[6])^;
	string_index_size: u8 = 4 if (0 in heap_sizes) else 2;
	guid_index_size:   u8 = 4 if (1 in heap_sizes) else 2;
	blob_index_size:   u8 = 4 if (2 in heap_sizes) else 2;

	valid_bits := (^bit_set[0..<64; u64])(&db.tables[8])^;
	table_ptr := uintptr(&db.tables[24]);

	for i in 0..<64 {
		if i not_in valid_bits {
			continue;
		}

		row_count := (^u32)(table_ptr)^;
		table_ptr += 4;
		switch i {
                case 0x00: db.module.row_count                    = row_count;
                case 0x01: db.type_ref.row_count                  = row_count;
                case 0x02: db.type_def.row_count                  = row_count;
                case 0x04: db.field.row_count                     = row_count;
                case 0x06: db.method_def.row_count                = row_count;
                case 0x08: db.param.row_count                     = row_count;
                case 0x09: db.interface_impl.row_count            = row_count;
                case 0x0a: db.member_ref.row_count                = row_count;
                case 0x0b: db.constant.row_count                  = row_count;
                case 0x0c: db.custom_attribute.row_count          = row_count;
                case 0x0d: db.field_marshal.row_count             = row_count;
                case 0x0e: db.decl_security.row_count             = row_count;
                case 0x0f: db.class_layout.row_count              = row_count;
                case 0x10: db.field_layout.row_count              = row_count;
                case 0x11: db.stand_alone_sig.row_count           = row_count;
                case 0x12: db.event_map.row_count                 = row_count;
                case 0x14: db.event.row_count                     = row_count;
                case 0x15: db.property_map.row_count              = row_count;
                case 0x17: db.property.row_count                  = row_count;
                case 0x18: db.method_semantics.row_count          = row_count;
                case 0x19: db.method_impl.row_count               = row_count;
                case 0x1a: db.module_ref.row_count                = row_count;
                case 0x1b: db.type_spec.row_count                 = row_count;
                case 0x1c: db.impl_map.row_count                  = row_count;
                case 0x1d: db.field_rva.row_count                 = row_count;
                case 0x20: db.assembly.row_count                  = row_count;
                case 0x21: db.assembly_processor.row_count        = row_count;
                case 0x22: db.assembly_os.row_count               = row_count;
                case 0x23: db.assembly_ref.row_count              = row_count;
                case 0x24: db.assembly_ref_processor.row_count    = row_count;
                case 0x25: db.assembly_ref_os.row_count           = row_count;
                case 0x26: db.file.row_count                      = row_count;
                case 0x27: db.exported_type.row_count             = row_count;
                case 0x28: db.manifest_resource.row_count         = row_count;
                case 0x29: db.nested_class.row_count              = row_count;
                case 0x2a: db.generic_param.row_count             = row_count;
                case 0x2b: db.method_spec.row_count               = row_count;
                case 0x2c: db.generic_param_constraint.row_count  = row_count;
                case:
			println("unknown metadata table", i);
                	return false;
                };
	}


	empty_table := Table{};

	type_def_or_ref, has_constant, has_custom_attribute, has_field_marshal, has_decl_security: u8;
	member_ref_parent, has_semantics, method_def_or_ref, member_forwarded, implementation: u8;
	custom_attribute_type, resolution_scope, type_or_method_def: u8;

	{
		using db;
		type_def_or_ref       = composite_index_size(type_def, type_ref, type_spec);
		has_constant          = composite_index_size(field, param, property);
		has_custom_attribute  = composite_index_size(method_def, field, type_ref, type_def, param, interface_impl, member_ref, module, property, event, stand_alone_sig, module_ref, type_spec, assembly, assembly_ref, file, exported_type, manifest_resource, generic_param, generic_param_constraint, method_spec);
		has_field_marshal     = composite_index_size(field, param);
		has_decl_security     = composite_index_size(type_def, method_def, assembly);
		member_ref_parent     = composite_index_size(type_def, type_ref, module_ref, method_def, type_spec);
		has_semantics         = composite_index_size(event, property);
		method_def_or_ref     = composite_index_size(method_def, member_ref);
		member_forwarded      = composite_index_size(field, method_def);
		implementation        = composite_index_size(file, assembly_ref, exported_type);
		custom_attribute_type = composite_index_size(method_def, member_ref, empty_table, empty_table, empty_table);
		resolution_scope      = composite_index_size(module, module_ref, assembly_ref, type_ref);
		type_or_method_def    = composite_index_size(type_def, method_def);

		// table order declaration is important due to ^table_ptr
		table_set_columns(&module, &table_ptr,         2, string_index_size, guid_index_size, guid_index_size, guid_index_size);
		table_set_columns(&type_ref, &table_ptr,        resolution_scope, string_index_size, string_index_size);
		table_set_columns(&type_def, &table_ptr,        4, string_index_size, string_index_size, type_def_or_ref, table_index_size(field), table_index_size(method_def));
		table_set_columns(&field, &table_ptr,            2, string_index_size, blob_index_size);
		table_set_columns(&method_def, &table_ptr,        4, 2, 2, string_index_size, blob_index_size, table_index_size(param));
		table_set_columns(&param, &table_ptr,         2, 2, string_index_size);
		table_set_columns(&interface_impl, &table_ptr,       table_index_size(type_def), type_def_or_ref);
		table_set_columns(&member_ref, &table_ptr,        member_ref_parent, string_index_size, blob_index_size);
		table_set_columns(&constant, &table_ptr,                2, has_constant, blob_index_size);
		table_set_columns(&custom_attribute, &table_ptr,        has_custom_attribute, custom_attribute_type, blob_index_size);
		table_set_columns(&field_marshal, &table_ptr,          has_field_marshal, blob_index_size);
		table_set_columns(&decl_security, &table_ptr,          2, has_decl_security, blob_index_size);
		table_set_columns(&class_layout, &table_ptr,          2, 4, table_index_size(type_def));
		table_set_columns(&field_layout, &table_ptr,           4, table_index_size(field));
		table_set_columns(&stand_alone_sig, &table_ptr,        blob_index_size);
		table_set_columns(&event_map, &table_ptr,              table_index_size(type_def), table_index_size(event));
		table_set_columns(&event, &table_ptr,            2, string_index_size, type_def_or_ref);
		table_set_columns(&property_map,       &table_ptr,        table_index_size(type_def), table_index_size(property));
		table_set_columns(&property,           &table_ptr,        2, string_index_size, blob_index_size);
		table_set_columns(&method_semantics,     &table_ptr,      2, table_index_size(method_def), has_semantics);
		table_set_columns(&method_impl,        &table_ptr,        table_index_size(type_def), method_def_or_ref, method_def_or_ref);
		table_set_columns(&module_ref,        &table_ptr,         string_index_size);
		table_set_columns(&type_spec,          &table_ptr,        blob_index_size);
		table_set_columns(&impl_map,           &table_ptr,        2, member_forwarded, string_index_size, table_index_size(module_ref));
		table_set_columns(&field_rva, &table_ptr,            4, table_index_size(field));
		table_set_columns(&assembly, &table_ptr,                 4, 8, 4, blob_index_size, string_index_size, string_index_size);
		table_set_columns(&assembly_processor, &table_ptr,        4);
		table_set_columns(&assembly_os, &table_ptr,               4, 4, 4);
		table_set_columns(&assembly_ref, &table_ptr,              8, 4, blob_index_size, string_index_size, string_index_size, blob_index_size);
		table_set_columns(&assembly_ref_processor, &table_ptr,     4, table_index_size(assembly_ref));
		table_set_columns(&assembly_ref_os,&table_ptr,           4, 4, 4, table_index_size(assembly_ref));
		table_set_columns(&file, &table_ptr,             4, string_index_size, blob_index_size);
		table_set_columns(&exported_type, &table_ptr,         4, 4, string_index_size, string_index_size, implementation);
		table_set_columns(&manifest_resource,    &table_ptr,      4, 4, string_index_size, implementation);
		table_set_columns(&nested_class,      &table_ptr,        table_index_size(type_def), table_index_size(type_def));
		table_set_columns(&generic_param,&table_ptr,            2, 2, type_or_method_def, string_index_size);

		table_set_columns(&method_spec,        &table_ptr,        method_def_or_ref, blob_index_size);
		table_set_columns(&generic_param_constraint, &table_ptr,   table_index_size(generic_param), type_def_or_ref);
	}

	return true;
}

Base_Type :: struct {
	name: string,
	namespace: string
}


Element_Type :: enum u8 {
    end             = 0x00, 
    void_           = 0x01,
    boolean         = 0x02,
    char_           = 0x03,
    i1              = 0x04,
    u1              = 0x05,
    i2              = 0x06,
    u2              = 0x07,
    i4              = 0x08,
    u4              = 0x09,
    i8              = 0x0a,
    u8              = 0x0b,
    r4              = 0x0c,
    r8              = 0x0d,
    string          = 0x0e,
    ptr             = 0x0f, 
    byRef           = 0x10, 
    valueType       = 0x11, 
    class_          = 0x12, 
    var             = 0x13, 
    array           = 0x14,
    genericInst     = 0x15,
    typedByRef      = 0x16,
    i               = 0x18, 
    u               = 0x19, 
    fnPtr           = 0x1b, 
    object          = 0x1c, 
    szArray         = 0x1d,
    mVar            = 0x1e, 
    cModReqd        = 0x1f, 
    cModOpt         = 0x20, 
    internal        = 0x21,
    modifier        = 0x40, 
    sentinel        = 0x41, 
    pinned          = 0x45,
    type            = 0x50, 
    taggedObject    = 0x51, 
    field           = 0x53, 
    property        = 0x54, 
    enum_           = 0x55, 
}

Calling_Convention :: enum u8 {
    Default         = 0x00,
    Var_Arg         = 0x05,
    Field           = 0x06,
    Local_Sig     	= 0x07,
    Property        = 0x08,
    Generic_Inst    = 0x10,
    Mask            = 0x0f,
    HasThis         = 0x20,
    ExplicitThis    = 0x40,
    Generic         = 0x10,
}

// 5 bits.
Has_Custom_Attribute :: enum u8 {
    methodDef,
    field,
    typeRef,
    typeDef,
    param,
    interfaceImpl,
    memberRef,
    module_,
    permission,
    property,
    event,
    standAloneSig,
    moduleRef,
    typeSpec,
    assembly,
    assemblyRef,
    file,
    exportedType,
    manifestResource,
    genericParam,
    genericParamConstraint,
    methodSpec,
}

Field_Sig :: struct {
	call_conv: Calling_Convention,
	custommod_sig: []CustomMod_Sig,
	type_sig: Type_Sig
	//call convention
	//custom mod

}

Type_Sig :: struct {
	isSZArray: bool,
	isArray: bool,
	arrayRank: u32,
	arraySizes: []u32,
	ptrCount: i32,
	custommod_sig: []CustomMod_Sig,
	element_type: Element_Type,
	value_type: Base_Type
}

read_type_sig :: proc( db: ^Database, cursor: ^[]byte ) -> Type_Sig {
	res := Type_Sig{};
	res.isSZArray = read_compressed_cond( Element_Type, cursor, Element_Type.szArray );
    res.isArray = read_compressed_cond( Element_Type, cursor, Element_Type.array );
	// custom mods
	for {
		if read_compressed_cond( Element_Type, cursor, Element_Type.ptr ) {
			res.ptrCount += 1;
		} else {
			break;
		}
	}
	res.custommod_sig = read_custom_mods( cursor );
	// type
	res.element_type = read_compressed( Element_Type, cursor );
	if res.element_type==.valueType {
		res.value_type = base_type_get( db, read_compressed_type_def_or_ref( cursor ) );
	}
	if res.element_type==.class_ {
		res.value_type = base_type_get( db, read_compressed_type_def_or_ref( cursor ) );
	}
	// array
	if res.isArray {
		res.arrayRank = read_compressed(u32, cursor);
		arraySizes: [dynamic]u32;
		length := read_compressed(u32, cursor);
		for i:u32=0; i<length; i+=1 {
			append(&arraySizes, read_compressed(u32, cursor));
		}
		res.arraySizes = arraySizes[:];
	}
	return res;
}

base_type_to_odin :: proc(b: ^Base_Type) -> string {
	/*
	switch b.name {
		case "BOOL": return "b32";
		case "HRESULT": return "win32.HRESULT";
		case "Guid": return "win32.GUID";
		case: return b.name;
	}*/
	return b.name;
}

type_sig_to_odin :: proc(t: ^Type_Sig) -> string {
	res := "";

	//assert( t.ptrCount<2 );
	if t.element_type==.void_ {
		assert( t.ptrCount>=1 );
		for i : i32 = 0; i < t.ptrCount-1; i += 1 {
			res = strings.concatenate( {res,"^"} );
		}
		return strings.concatenate( {res,"rawptr"} );
	}

	for i : i32 = 0; i < t.ptrCount; i += 1 {
		res = strings.concatenate( {res,"^"} );
	}
	if t.isArray {
		assert( t.arrayRank==1 );
		res = strings.concatenate( {res, fmt.aprintf("[%d]", t.arraySizes[0] )});
	}
	base_type : string;
	if t.element_type==.valueType {
		base_type = base_type_to_odin(&t.value_type);
	} else if t.element_type==.class_ {
		base_type = base_type_to_odin(&t.value_type);
		base_type = strings.concatenate( {"^",base_type} );
	} else {
		base_type =  element_type_to_odin(t.element_type);
	}
	res = strings.concatenate( {res,base_type} );
	return res;
}

element_type_to_odin :: proc( et: Element_Type ) -> string {
	#partial switch et {
		case .boolean: return "b8";
		case .i1: return "i8";
		case .u1: return "u8";
		case .i2: return "i16";
		case .u2: return "u16";
		case .i4: return "i32";
		case .u4: return "u32";
		case .i8: return "i64";
		case .u8: return "u64";
		case .r4: return "f32";
		case .r8: return "f64";
		case .u: return "size_t";
		case .i: return "intptr_t";
		case .valueType: assert(false); return "error!";
		case: assert(false); return "error!";
	}
}

CustomMod_Sig :: struct {
	element_type : Element_Type
}

read_custom_mods :: proc( cursor: ^[]byte ) -> []CustomMod_Sig {
	res: [dynamic]CustomMod_Sig;
	element_type, _ := peek_compressed( Element_Type, cursor^ );
	assert( element_type!=Element_Type.cModOpt );
	assert( element_type!=Element_Type.cModReqd );
	return res[:];
}

field_sig_read :: proc( db: ^Database, cursor: ^[]byte ) -> Field_Sig {
	res := Field_Sig{};
	res.call_conv = read_data( Calling_Convention, cursor );
	assert( res.call_conv==.Field );
	res.custommod_sig = read_custom_mods( cursor );
	res.type_sig = read_type_sig( db, cursor );
	return res;
}

Param_Sig :: struct {
	custommod_sigs: []CustomMod_Sig,
	is_by_ref: bool,
	type_sig: Type_Sig
}

param_sig_read :: proc( db: ^Database, cursor: ^[]byte ) -> (res: Param_Sig) {
	res.custommod_sigs = read_custom_mods( cursor );
	res.is_by_ref = read_compressed_cond( Element_Type, cursor, Element_Type.byRef );
	res.type_sig = read_type_sig( db, cursor );
	return;
}

RetType_Sig :: struct {
	custommod_sigs: []CustomMod_Sig,
	is_by_ref: bool,
	is_void: bool,
	type_sig: Type_Sig
}

rettype_sig_read :: proc( db: ^Database, cursor: ^[]byte ) -> RetType_Sig {
	res := RetType_Sig{};
	res.custommod_sigs = read_custom_mods( cursor );
	res.is_by_ref = read_compressed_cond( Element_Type, cursor, Element_Type.byRef );
	res.is_void = read_compressed_cond( Element_Type, cursor, Element_Type.void_ );
	if res.is_void==false {
		res.type_sig = read_type_sig( db, cursor );
	}
	
	return res;
}

MethodDef_Sig :: struct {
	call_conv: Calling_Convention,
	generic_param_count: u32,
	rettype_sig: RetType_Sig,
	params: []Param_Sig
}

methoddef_sig_read :: proc( db: ^Database, cursor: ^[]byte ) -> MethodDef_Sig {
	res := MethodDef_Sig{};
	res.call_conv = read_compressed( Calling_Convention, cursor );
	assert( res.call_conv!=.Generic );
	params_length := read_compressed( u32, cursor );
	res.rettype_sig = rettype_sig_read( db, cursor );
	params: [dynamic]Param_Sig;
	for i:u32=0; i<params_length; i+=1 {
		ps := param_sig_read( db, cursor );
		append( &params, ps );
	}
	res.params = params[:];
	return res;
}

Type_Def_Or_Ref :: struct {
	type: u32,	// TODO: enum?
	index: u32,
	valid: bool
}

read_compressed_type_def_or_ref :: proc( cursor: ^[]byte ) -> Type_Def_Or_Ref {
	res := Type_Def_Or_Ref{};
	val := read_compressed( u32, cursor );
	if val != 0 {
		res.type = (val & ((1 << 2) - 1));
		res.index = (val>>2)-1;
		res.valid = true;
	}
	return res;
}

type_def_or_ref_from_table :: proc ( t: ^Table, row, column: u32 ) -> Type_Def_Or_Ref {
	res := Type_Def_Or_Ref{};
	val := table_get_value( t, u32, row, column );
	if val != 0 {
		res.type = (val & ((1 << 2) - 1));
		res.index = (val>>2)-1;
		res.valid = true;
	}
	return res;
}

base_type_get :: proc( db: ^Database, idx: Type_Def_Or_Ref ) -> Base_Type {
	res : Base_Type;
	if idx.valid {
		assert( idx.type==0 || idx.type==1 );
		if idx.type==1 {
			res.name,_ = table_get_string(db, &db.type_ref, idx.index, 1);
			res.namespace,_ = table_get_string(db, &db.type_ref, idx.index, 2);
		} else {
			res.name,_ = table_get_string(db, &db.type_def, idx.index, TYPEDEF_NAME_COLUMN);
			res.namespace ,_= table_get_string(db, &db.type_def, idx.index, TYPEDEF_NAMESPACE_COLUMN);
		}
	}
	return res;
}

// Field row
Field_Row :: struct {
	attr: u32,
	name: string,
	sig: u32,
}

field_row_get :: proc(db: ^Database, row_idx: u32) -> (res:Field_Row) {
	
	FIELD_ATTR_COLUMN :: 0;
	FIELD_NAME_COLUMN :: 1;
	FIELD_SIG_COLUMN :: 2;
	
	res.attr = table_get_value(&db.field, u32, row_idx, FIELD_ATTR_COLUMN);
	res.name, _ = table_get_string(db, &db.field, row_idx, FIELD_NAME_COLUMN);
	res.sig = table_get_value(&db.field, u32, row_idx, FIELD_SIG_COLUMN);
	return;
}

// Method Def row
Methoddef_Row :: struct {
	rva: u32,
	name: string,
	sig_blob: []byte,
	param_start_idx: u32
}

methoddef_row_get :: proc(db: ^Database, row_idx: u32) -> (res:Methoddef_Row) {
	METHOD_RVA_COLUMN :: 0;
	METHOD_NAME_COLUMN :: 3;
	METHOD_SIGNATURE_COLUMN :: 4;
	METHOD_PARAM_COLUMN :: 5;

	res.rva = table_get_value(&db.method_def, u32, row_idx, METHOD_RVA_COLUMN);
	res.name, _ = table_get_string(db, &db.method_def, row_idx, METHOD_NAME_COLUMN);
	sig := table_get_value(&db.method_def, u32, row_idx, METHOD_SIGNATURE_COLUMN);
	res.sig_blob = db.blobs[sig+1:];
	res.param_start_idx = table_get_value(&db.method_def, u32, row_idx, METHOD_PARAM_COLUMN)-1;
	return;
}

// Param row
Param_Row :: struct {
	name: string,
	attr: u16,
	rank: u16,
	row_idx: u32
}

param_row_get :: proc(db: ^Database, row_idx: u32) -> (res:Param_Row) {
	PARAM_ATTR_COLUMN :: 0;
	PARAM_RANK_COLUMN :: 1;
	PARAM_NAME_COLUMN :: 2;
	
	res.attr = table_get_value(&db.param, u16, row_idx, PARAM_ATTR_COLUMN);
	res.name, _ = table_get_string(db, &db.param, row_idx, PARAM_NAME_COLUMN);
	res.name = export_variable_name(res.name);
	res.rank = table_get_value(&db.param, u16, row_idx, PARAM_RANK_COLUMN);
	res.row_idx = row_idx;
	return;
}

TYPEDEF_ATTR_COLUMN :: 0;
TYPEDEF_NAME_COLUMN :: 1;
TYPEDEF_NAMESPACE_COLUMN :: 2;
TYPEDEF_FIELD_COLUMN :: 4;
TYPEDEF_METHOD_COLUMN :: 5;

// Type Def row
Typedef_Row :: struct {
	attr: u32,
	name: string,
	namespace: string,
	field_start_idx: u32,
	field_end_idx: u32,
	method_start_idx: u32,
	method_end_idx: u32,
	row_idx: u32
}

typedef_row_get :: proc(db: ^Database, row_idx: u32) -> (res:Typedef_Row) {
	res.attr = table_get_value(&db.type_def, u32, row_idx, TYPEDEF_ATTR_COLUMN);
	res.name, _ = table_get_string(db, &db.type_def, row_idx, TYPEDEF_NAME_COLUMN);
	res.namespace, _ = table_get_string(db, &db.type_def, row_idx, TYPEDEF_NAMESPACE_COLUMN);
	// Todo: check last row
	res.field_start_idx = table_get_value(&db.type_def, u32, row_idx, TYPEDEF_FIELD_COLUMN)-1;
	res.field_end_idx = table_get_value(&db.type_def, u32, row_idx+1, TYPEDEF_FIELD_COLUMN)-1;
	res.method_start_idx = table_get_value(&db.type_def, u32, row_idx, TYPEDEF_METHOD_COLUMN)-1;
	res.method_end_idx = table_get_value(&db.type_def, u32, row_idx+1, TYPEDEF_METHOD_COLUMN)-1;
	res.row_idx = row_idx;
	return;
}

composite_index_get :: inline proc(val: u32, $BITS: u32) -> (type, index: u32) {
	type = (val & ((1<<BITS) - 1));
	index = (val>>BITS)-1;
	return;
}

Custom_Attribute_Type :: enum {
	Method_Def = 2,
	Member_Ref = 3
}

MemberRefParent_Enum :: enum {
	Type_Def = 0,
	Type_Ref = 1,
	Module_Ref = 2,
	Method_Def = 3,
	Type_Spec = 4
}
MemberRefParent :: struct {
	type: MemberRefParent_Enum,
	index: u32
}
MEMBER_REF_PARENT_ENCODE_BITS :: 3;
member_ref_parent_make :: proc(val: u32) -> MemberRefParent {
	res := MemberRefParent{};
	tmp : u32;
	tmp, res.index = composite_index_get(val, MEMBER_REF_PARENT_ENCODE_BITS);
	res.type = cast(MemberRefParent_Enum)tmp;
	return res;
}

Custom_Attribute :: enum {
	Const,
	NativeTypeInfo	
}

Custom_Attribute_Set :: bit_set[Custom_Attribute];

// TODO: move custom attributes to database
Params_Custom_Attributes := make(map[u32]Custom_Attribute_Set);
Fields_Custom_Attributes := make(map[u32]Custom_Attribute_Set);


param_promote_cstring :: proc(param_idx: u32, odin_type: string) -> string {
	if odin_type=="^i8" {
		ca, ok := Params_Custom_Attributes[param_idx];
		if ok && .Const in ca && .NativeTypeInfo in ca {
			return "cstring";
		}
	}
	return odin_type;
}

field_promote_cstring :: proc(param_idx: u32, odin_type: string) -> string {
	if odin_type=="^i8" {
		ca, ok := Fields_Custom_Attributes[param_idx];
		if ok && .Const in ca && .NativeTypeInfo in ca {
			return "cstring";
		}
	}
	return odin_type;
}

parse_custom_attributes :: proc(db: ^Database) {
	res := Custom_Attribute_Set{};
	HAS_CUSTOM_ATTRIB_BIT_INDEX :: 5;
	CUSTOM_ATTRIBUTE_TYPE_BIT_INDEX :: 3;
	for i :u32=0; i<db.custom_attribute.row_count; i+=1 {
		parent_val := table_get_value(&db.custom_attribute, u32, i, 0);
		parent_type, parent_idx := composite_index_get(parent_val, HAS_CUSTOM_ATTRIB_BIT_INDEX);
		hca := cast(Has_Custom_Attribute)parent_type;

		dest_map : ^map[u32]Custom_Attribute_Set;
		#partial switch hca {
			case .field: dest_map = &Fields_Custom_Attributes;
			case .param: dest_map = &Params_Custom_Attributes;
		}
		if dest_map!=nil {
			ctor_val := table_get_value(&db.custom_attribute, u32, i, 1);
			ctor_type, ctor_idx := composite_index_get(ctor_val, CUSTOM_ATTRIBUTE_TYPE_BIT_INDEX);
			//printf("Found param CA: %v ref: %v, name: %v, ctor %v %v", i, parent_idx, param_name, ctor_type, ctor_idx);
			if ctor_type==cast(u32)Custom_Attribute_Type.Member_Ref {
				member_ref_parent_val := table_get_value(&db.member_ref, u32, ctor_idx, 0);
				ctor_name, _ := table_get_string(db, &db.member_ref, ctor_idx, 1);
				member_ref_parent := member_ref_parent_make(member_ref_parent_val);
				if member_ref_parent.type==.Type_Ref {
					type_ref_name, _ := table_get_string(db, &db.type_ref, member_ref_parent.index, 1);
					attribs := dest_map[parent_idx];
					switch type_ref_name {
						case "ConstAttribute": incl(&attribs, Custom_Attribute.Const);
						case "NativeTypeInfoAttribute": incl(&attribs, Custom_Attribute.NativeTypeInfo);
						case: 
					}
					dest_map[parent_idx] = attribs;
				}
				//printf("ctor name %v %v\n", ctor_name, member_ref_parent);
			}	
		}
	}
}

// =========================
// Export functions
// =========================

Export_Function_Type :: enum {
	Global,
	Interface,
	Delegate
}

export_function :: proc(db: ^Database, function_row_idx: u32, func_type: Export_Function_Type, parent_name: string) {
	function_row := methoddef_row_get(db, function_row_idx);
	if func_type==.Delegate && function_row.name!="Invoke" { return; }
	methoddef_sig := methoddef_sig_read( db, &function_row.sig_blob );

	switch func_type {
		case .Global: printf("\t%v :: proc(", function_row.name);
		case .Interface: printf("\t%v : proc(", function_row.name);
		case .Delegate: printf("%v :: proc \"std\" (", parent_name);
	}
	// params
	has_return := methoddef_sig.rettype_sig.is_void==false;
	param_count := len(methoddef_sig.params);
	if has_return { param_count +=1 ;}
	param_by_ranks := make([]Param_Row, param_count);
	{
		param_idx := function_row.param_start_idx;
		for i:=0;i<param_count; i+=1 {
			p := param_row_get(db, param_idx);
			// skip the return param
			if p.rank>0 {
				p.rank -= 1;	
				param_by_ranks[p.rank] = p;
			}
			param_idx += 1;
		}
	}
	
	need_comma := false;
	if func_type==.Interface {
		printf( "this: ^%v", parent_name );	
		need_comma = true;
	}
	for _, param_sig_idx in methoddef_sig.params {
		if need_comma {
			printf(", ");	
		}
		param_sig := &methoddef_sig.params[param_sig_idx];
		param_type_name := type_sig_to_odin(&param_sig.type_sig);
		p := param_by_ranks[param_sig_idx];
		param_type_name = param_promote_cstring(p.row_idx, param_type_name);
		printf("%v: %v", p.name, param_type_name);
		need_comma = true;
	}

	if has_return {
		printf(") -> %v",  type_sig_to_odin(&methoddef_sig.rettype_sig.type_sig) );
	} else {
		printf(")" );
	}

	switch func_type {
		case .Global: printf("---;");
		case .Interface: printf(",");
		case .Delegate: printf(";");
	}
	if DEBUG_OUTPUT {
		printf("// methoddef_row_idx %v", function_row_idx);
	}
	printf("\n");
}

find_typedef_from_typeref :: proc( db: ^Database, typeref_row_id: u32) -> (bool,u32) {
	name, _ := table_get_string( db, &db.type_ref, typeref_row_id, 1 );
	namespace, _ := table_get_string( db, &db.type_ref, typeref_row_id, 2 );
	fullname := strings.concatenate({namespace, ".", name}, context.temp_allocator);
	elem, ok := db.typedef_map_pername[fullname];
	return ok, elem;
}

find_interface_impl :: proc(db: ^Database, class: u32) -> (bool,Type_Def_Or_Ref) {
	INTERFACE_CLASS_COLUMN :: 0;
	INTERFACE_INTERFACE_COLUMN :: 1;
	for i in 0..db.interface_impl.row_count {
		parent_val := cast(u32)table_get_value( &db.interface_impl, u16, i, INTERFACE_CLASS_COLUMN );
		if parent_val==class {
			return true, type_def_or_ref_from_table( &db.interface_impl, i, INTERFACE_INTERFACE_COLUMN );
		}
	}
	return false, Type_Def_Or_Ref{};
}

export_interface_parent_methods :: proc(db: ^Database, typedef_row_idx: u32, interface_name: string) {
	has_parent_interface, parent_type_def_or_ref := find_interface_impl(db, typedef_row_idx+1);
	if has_parent_interface == false { return; }

	assert(parent_type_def_or_ref.type==1);
	// TODO: check resolution scope?
	found, parent_type_def_idx :=find_typedef_from_typeref(db, parent_type_def_or_ref.index);
	assert( found );
	// recursive fonction
	export_interface_parent_methods(db, parent_type_def_idx, interface_name);

	export_typedef_functions(db, parent_type_def_idx, .Interface, interface_name);
	printf( "\n" );
}

export_interface :: proc(db: ^Database, typedef_row_idx: u32) {
	interface_row := typedef_row_get(db, typedef_row_idx);

	// if interface_name!="ID3D11Resource" {
	// 	return;//interface_name="ID3D11Resource";
	// }

	println(interface_row.name, ":: struct {");
	printf( "\tusing vtbl: ^%v_Vtbl,\n", interface_row.name);
	println("}");
	println("");

	printf( "%v_Vtbl", interface_row.name);
	println(" :: struct {");
	export_interface_parent_methods(db, typedef_row_idx, interface_row.name);

	export_typedef_functions(db, typedef_row_idx, .Interface, interface_row.name);
	println("}");
	println("");
}

export_field_val :: proc(db: ^Database, field_owner_idx: u32) -> string {
	// TODO: check enum is u32
	t := &db.constant;
	row_idx : u32 = 0;
	for {
		parent_val := table_get_value(t, u32, row_idx, 1);
		parent_idx := (parent_val>>2)-1;
		
		if parent_idx==field_owner_idx {
			// TODO: to clean
			et := Element_Type(table_get_value(t, u32, row_idx, 0));
			blob_idx := table_get_value(t, u32, row_idx, 2);
			if et==.string {
				len := int(db.blobs[blob_idx]);
				blob_idx += 1;
				builder := strings.make_builder();
				strings.write_string(&builder, "\"");
				for i:=0; i<len; i+=2 {
					b := cast(byte)db.blobs[u32(i)+blob_idx];
					if b==0 { break; }
					strings.write_byte(&builder, b);
				}
				strings.write_string(&builder, "\"");
				return strings.to_string(builder);
			} else {
				a : u32 = cast(u32)db.blobs[blob_idx+1];
				b : u32 = cast(u32)db.blobs[blob_idx+2];
				c : u32 = cast(u32)db.blobs[blob_idx+3];
				return fmt.aprintf("%d", a | (b<<8) | (c<<8));
			}


		}
		row_idx += 1;
		if row_idx>=t.row_count { break; }
	}
	return "";
}

Export_Field_Type :: enum {
	Global,
	Enum
}

export_typedef_fields :: proc(db: ^Database, typedef_row_idx: u32, field_type: Export_Field_Type) {
	typedef_row := typedef_row_get(db, typedef_row_idx);
	field_idx := typedef_row.field_start_idx;
	if field_type==.Enum {
		println(typedef_row.name, ":: enum {");
		field_idx += 1; // not sure...
	}
	for {
		field_row := field_row_get(db, field_idx);
		if field_row.attr != 32854 { // TODO: clean
			break;
		}
		field_val := export_field_val(db, field_idx);
		switch field_type {
			case .Enum: printf("\t%v = %v,\n", field_row.name, field_val);
			case .Global: printf("%v :: %v;\n", field_row.name, field_val);
		}
		field_idx += 1;
	}
	if field_type==.Enum {
		println("}");
	}
}

export_typedef_functions :: proc(db: ^Database, typedef_row_idx: u32, func_type: Export_Function_Type, parent_name: string = "") {
	typedef_row := typedef_row_get(db, typedef_row_idx);

	if DEBUG_OUTPUT {
		printf( "\t// typedef:%v row:%v field:%v method:%v\n", typedef_row.name, typedef_row_idx, typedef_row.field_start_idx, typedef_row.method_start_idx);
	}

	if func_type==.Interface {
		printf( "\t//  %v\n", typedef_row.name );
	}

	method_idx := typedef_row.method_start_idx;
	for {
		if method_idx>=typedef_row.method_end_idx {
			break;
		}
		method_row := methoddef_row_get(db, method_idx);
		export_function(db, method_idx, func_type, len(parent_name)==0?typedef_row.name:parent_name);
		method_idx += 1;
	}
}

print_tab :: proc(count: int) {
	for i in 0.. count {
		printf("\t");
	}
}

export_variable_uid := 0;
export_variable_name :: proc(name: string) -> string {
	switch(name) {
		case "in": return "in_";
		case "defer": return "defer_";
		case "proc": return "proc_";
		case "context": return "context_";
		case "_bitfield": 
			export_variable_uid += 1;
			return fmt.aprintf("_bitfield_%v", export_variable_uid);

		case: return name;
	}
}

export_struct_members :: proc(db: ^Database, tab: int, struct_idx: u32) -> u32 {
	struct_row := typedef_row_get(db, struct_idx);
	union_idx : u32 = 0;
	member_row_idx := struct_row.field_start_idx;
	for {
		member := field_row_get(db, member_row_idx);
		if member.attr!=6 || member_row_idx>=struct_row.field_end_idx {
			break;
		}
		
		blob_data := db.blobs[member.sig+1:];
		field_sig := field_sig_read( db, &blob_data );
		odin_type := type_sig_to_odin(&field_sig.type_sig);
		odin_type = field_promote_cstring(member_row_idx, odin_type);

		// union detection, not very clean...
		is_anonymous := strings.has_prefix(odin_type, "_Anonymous");
		is_struct := strings.has_suffix(odin_type, "_e__Struct");
		is_union := strings.has_suffix(odin_type, "_e__Union");
		if is_anonymous || is_struct || is_union {
			if DEBUG_OUTPUT {
				print_tab(tab);
				printf("// anonymous union field %v referencing typedef %v\n", member_row_idx, union_idx);
			}
			print_tab(tab);
			if is_anonymous {
				printf("using _%v_%v: struct ", member.name, union_idx+struct_idx);
			} else {
				printf("_%v: struct ", member.name);
			}
			if is_union {
				printf("#raw_union ");
			}
			println("{");
			
			union_idx += export_struct_members(db, tab+1, union_idx+struct_idx+1);
			print_tab(tab);
			println("},");
			union_idx += 1;
		} else {
			if DEBUG_OUTPUT {
				print_tab(tab);
				printf("// field row: %v\n", member_row_idx);
			}
			print_tab(tab);
			printf("%v : %v,\n", export_variable_name(member.name), odin_type);
		}

		member_row_idx += 1;
	}

	return union_idx;
}

export_struct :: proc(db: ^Database, struct_idx: u32) {
	struct_row := typedef_row_get(db, struct_idx);
	if DEBUG_OUTPUT {
		printf("// typedef row: %v attr: %v\n", struct_idx, struct_row.attr);
	}
	println(struct_row.name, ":: struct {");
	export_struct_members(db, 0, struct_idx);
	println("}\n");
}

DEBUG_OUTPUT :: false;


USE_OUTPUT_BUFFER :: true;

when USE_OUTPUT_BUFFER {
	OUTPUT_BUFFER_SIZE :: 16*1024;
	output_buffer_data : [OUTPUT_BUFFER_SIZE]byte;
	output_buffer_cursor := 0;

	output_buffer_flush :: proc() {
		to_flush := string(output_buffer_data[0:output_buffer_cursor]);
		fmt.print(to_flush);
		output_buffer_cursor = 0;
	}
	print_to_buffer :: proc(s: string) {
		copy(output_buffer_data[output_buffer_cursor:], s);
		output_buffer_cursor += len(s);
		if output_buffer_cursor>(OUTPUT_BUFFER_SIZE/2) {
			output_buffer_flush();
		}
	}
	println :: inline proc(args: ..any) { print_to_buffer(fmt.tprintln(..args)); }
	printf  :: inline proc(format: string, args: ..any) { print_to_buffer(fmt.tprintf(format,..args)); }
}
else {
	println :: inline proc(args: ..any) -> int { return fmt.println(..args); }
	printf  :: inline proc(format: string, args: ..any) -> int { return fmt.printf(format, ..args); }
}

//println :: proc(args: ..any) -> int { return 0; }
//printf  :: proc(format: string, args: ..any) -> int { return 0; }

main :: proc() {


	path := "Windows.Win32.winmd";
	data, data_ok := os.read_entire_file(path);
	if !data_ok {
		os.exit(1);
	}
	db := &Database{data=data};
	if !parse_database(db) {
		os.exit(1);
	}

	skip_global_functions := false;
	for arg in os.args {
		if arg=="-skip_global_functions" {
			skip_global_functions = true;
		}
	}

	target_namespace := "Windows.Win32.Direct3D11";
	if len(os.args)>1 {
		target_namespace = os.args[1];
	}

	lib_name := "xinput";
	if len(os.args)>2 {
		lib_name = os.args[2];
	}
	package_name := "win32_winmd";

	assert( size_of(b32)==size_of(win32.BOOL) );
	println("package", package_name);

	if DEBUG_OUTPUT {
		println("/*");
		println("module          ", db.module);
		println("type_ref        ", db.type_ref);
		println("type_def        ", db.type_def);
		println("field           ", db.field);
		println("method_def      ", db.method_def);
		println("param           ", db.param);
		println("interface_impl  ", db.interface_impl);
		println("member_ref      ", db.member_ref);
		println("constant        ", db.constant);
		println("custom_attribute", db.custom_attribute);
		println("class_layout    ", db.class_layout);
		println("field_layout    ", db.field_layout);
		println("module_ref      ", db.module_ref);
		println("impl_map        ", db.impl_map);
		println("assembly        ", db.assembly);
		println("assembly_ref    ", db.assembly_ref);
		println("nested_class    ", db.nested_class);
		println("*/");
	}

	parse_custom_attributes(db);
	
	enums : [dynamic]u32;
	structs : [dynamic]u32;
	interfaces : [dynamic]u32;
	delegates : [dynamic]u32;
	globals : [dynamic]u32;
	{
		row_idx : u32 = 0;
		for ; row_idx<db.type_def.row_count; row_idx+=1 {

			// filter namespace
			typedef_row := typedef_row_get(db, row_idx);

			fullname := strings.concatenate( {typedef_row.namespace, ".", typedef_row.name});
			db.typedef_map_pername[fullname] = row_idx;

			if strings.compare(typedef_row.namespace, target_namespace) !=0 {
				continue;
			}

			base_type := base_type_get(db, type_def_or_ref_from_table(&db.type_def, row_idx, 3));
		
			is_global := typedef_row.name == "Apis" && base_type.name=="Object" && base_type.namespace=="System";
			is_enum := base_type.name=="Enum" && base_type.namespace=="System";
			is_struct := base_type.name=="ValueType" && base_type.namespace=="System";
			is_interface := base_type.name=="" && base_type.namespace=="";
			is_delegate := base_type.name=="MulticastDelegate" && base_type.namespace=="System";

			if is_enum {
				append(&enums, row_idx);
			} else if is_global {
				append(&globals, row_idx);
			} else if is_interface {
				append(&interfaces, row_idx);
			} else if is_struct {
				append(&structs, row_idx);
			} else if is_delegate {
				append(&delegates, row_idx);
			}
		}
	}
	if len(globals)>0 {
		println("\n// Globals");
		for idx in globals {
			export_typedef_fields(db, idx, .Global);
		}
	}
	if len(enums)>0 {
		println("\n// Enums");
		for idx in enums {
			export_typedef_fields(db, idx, .Enum);
		}
	}
	if len(structs)>0 {
		println("\n// Structs");
		for idx in structs {
			export_struct(db, idx);
		}
	}
	if len(delegates)>0 {
		println("\n// Delegates");
		for idx in delegates {
			export_typedef_functions(db, idx, .Delegate);
		}
	}
	if len(interfaces)>0 {
		println("\n// Interfaces");
		for idx in interfaces {
			export_interface(db, idx);
		}
	}
	if len(globals)>0 {
		println("\n// Global Functions");
		if skip_global_functions {
			println("/* SKIPPED");
		}
		printf("foreign import %s \"system:%s.lib\"\n", lib_name, lib_name);
		println("@(default_calling_convention = \"std\")");
		println("foreign", lib_name, "{");
		for idx in globals {
			export_typedef_functions(db, idx, .Global);
		}
		println("}");
		if skip_global_functions {
			println("*/");
		}
	}
	when USE_OUTPUT_BUFFER {
		output_buffer_flush();
	}
}