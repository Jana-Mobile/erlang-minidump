% Macros for decoding 32/64bit unsigned integers
-define(UINT8, 1/little-unsigned-integer-unit:8).
-define(UINT16LE, 2/little-unsigned-integer-unit:8).
-define(UINT32LE, 4/little-unsigned-integer-unit:8).
-define(UINT64LE, 8/little-unsigned-integer-unit:8).

% Sized of various structs
-define(MDVSFIXEDFILEINFOSIZE, 52).

-define(MINIDUMP_TYPE_NORMAL, 16#00000000).
-define(MINIDUMP_TYPE_WITH_DATA_SEGS, 16#00000001).
-define(MINIDUMP_TYPE_WITH_FULL_MEMORY, 16#00000002).
-define(MINIDUMP_TYPE_WITH_HANDLE_DATA, 16#00000004).
-define(MINIDUMP_TYPE_FILTER_MEMORY, 16#00000008).
-define(MINIDUMP_TYPE_SCAN_MEMORY, 16#00000010).
-define(MINIDUMP_TYPE_WITH_UNLOADED_MODULES, 16#00000020).
-define(MINIDUMP_TYPE_WITH_INDIRECTLY_REFERENCED_MEMORY, 16#00000040).
-define(MINIDUMP_TYPE_FILTER_MODULE_PATHS, 16#00000080).
-define(MINIDUMP_TYPE_WITH_PROCESS_THREAD_DATA, 16#00000100).
-define(MINIDUMP_TYPE_WITH_PRIVATE_READ_WRITE_MEMORY, 16#00000200).
-define(MINIDUMP_TYPE_WITHOUT_OPTIONAL_DATA, 16#00000400).
-define(MINIDUMP_TYPE_WITH_FULL_MEMORY_INFO, 16#00000800).
-define(MINIDUMP_TYPE_WITH_THREAD_INFO, 16#00001000).
-define(MINIDUMP_TYPE_WITH_CODE_SEGS, 16#00002000).
-define(MINIDUMP_TYPE_WITHOUT_AUXILIARY_STATE, 16#00004000).
-define(MINIDUMP_TYPE_WITH_FULL_AUXILIARY_STATE, 16#00008000).
-define(MINIDUMP_TYPE_WITH_PRIVATE_WRITE_COPY_MEMORY, 16#00010000).
-define(MINIDUMP_TYPE_IGNORE_INACCESSIBLE_MEMORY, 16#00020000).
-define(MINIDUMP_TYPE_WITH_TOKEN_INFORMATION, 16#00040000).
-define(MINIDUMP_TYPE_WITH_MODULE_HEADERS, 16#00080000).
-define(MINIDUMP_TYPE_FILTER_TRIAGE, 16#00100000).
-define(MINIDUMP_TYPE_VALID_TYPE_FLAGS, 16#001fffff).
-define(MINIDUMP_FLAGS, [
    ?MINIDUMP_TYPE_NORMAL, ?MINIDUMP_TYPE_WITH_DATA_SEGS, ?MINIDUMP_TYPE_WITH_FULL_MEMORY,
    ?MINIDUMP_TYPE_WITH_HANDLE_DATA, ?MINIDUMP_TYPE_FILTER_MEMORY, ?MINIDUMP_TYPE_SCAN_MEMORY,
    ?MINIDUMP_TYPE_WITH_UNLOADED_MODULES, ?MINIDUMP_TYPE_WITH_INDIRECTLY_REFERENCED_MEMORY,
    ?MINIDUMP_TYPE_FILTER_MODULE_PATHS, ?MINIDUMP_TYPE_WITH_PROCESS_THREAD_DATA,
    ?MINIDUMP_TYPE_WITH_PRIVATE_READ_WRITE_MEMORY, ?MINIDUMP_TYPE_WITHOUT_OPTIONAL_DATA,
    ?MINIDUMP_TYPE_WITH_FULL_MEMORY_INFO, ?MINIDUMP_TYPE_WITH_THREAD_INFO,
    ?MINIDUMP_TYPE_WITH_CODE_SEGS, ?MINIDUMP_TYPE_WITHOUT_AUXILIARY_STATE,
    ?MINIDUMP_TYPE_WITH_FULL_AUXILIARY_STATE, ?MINIDUMP_TYPE_WITH_PRIVATE_WRITE_COPY_MEMORY,
    ?MINIDUMP_TYPE_IGNORE_INACCESSIBLE_MEMORY, ?MINIDUMP_TYPE_WITH_TOKEN_INFORMATION,
    ?MINIDUMP_TYPE_WITH_MODULE_HEADERS, ?MINIDUMP_TYPE_FILTER_TRIAGE
]).

-define(MINIDUMP_STREAM_TYPE_UNUSED, 16#00).
-define(MINIDUMP_STREAM_TYPE_RESERVED_0, 16#01).
-define(MINIDUMP_STREAM_TYPE_RESERVED_1, 16#02).
-define(MINIDUMP_STREAM_TYPE_THREAD_LIST, 16#03).
-define(MINIDUMP_STREAM_TYPE_MODULE_LIST, 16#04).
-define(MINIDUMP_STREAM_TYPE_MEMORY_LIST, 16#05).
-define(MINIDUMP_STREAM_TYPE_EXCEPTION, 16#06).
-define(MINIDUMP_STREAM_TYPE_SYSTEM_INFO, 16#07).
-define(MINIDUMP_STREAM_TYPE_THREAD_EX_LIST, 16#08).
-define(MINIDUMP_STREAM_TYPE_MEMORY_64_LIST, 16#09).
-define(MINIDUMP_STREAM_TYPE_COMMENTS_A, 16#0a).
-define(MINIDUMP_STREAM_TYPE_COMMENTS_W, 16#0b).
-define(MINIDUMP_STREAM_TYPE_HANDLE_DATA, 16#0c).
-define(MINIDUMP_STREAM_TYPE_FUNCTION_TABLE, 16#0d).
-define(MINIDUMP_STREAM_TYPE_UNLOADED_MODULE_LIST, 16#0e).
-define(MINIDUMP_STREAM_TYPE_MISC_INFO, 16#0f).
-define(MINIDUMP_STREAM_TYPE_MEMORY_INFO_LIST, 16#10).
-define(MINIDUMP_STREAM_TYPE_THREAD_INF0_LIST, 16#11).
-define(MINIDUMP_STREAM_TYPE_HANDLE_OPERATION_LIST, 16#12).
-define(MINIDUMP_STREAM_LAST_RESERVED, 16#FFFF).
% These stream types are google-specific
-define(MINIDUMP_STREAM_LINUX_CPU_INFO, 16#47670003).
-define(MINIDUMP_STREAM_LINUX_PROC_STATUS, 16#47670004).
-define(MINIDUMP_STREAM_LINUX_LSB_RELEASE, 16#47670005).
-define(MINIDUMP_STREAM_LINUX_CMD_LINE, 16#47670006).
-define(MINIDUMP_STREAM_LINUX_ENVIRON, 16#47670007).
-define(MINIDUMP_STREAM_LINUX_AUXV, 16#47670008).
-define(MINIDUMP_STREAM_LINUX_MAPS, 16#47670009).
-define(MINIDUMP_STREAM_LINUX_DSO_DEBUG, 16#4767000A).

-define(CPU_ARCHITECTURE_x86, 0).
-define(CPU_ARCHITECTURE_MIPS, 1).
-define(CPU_ARCHITECTURE_ALPHA, 2).
-define(CPU_ARCHITECTURE_PPC, 3).
-define(CPU_ARCHITECTURE_SHX, 4).
-define(CPU_ARCHITECTURE_ARM, 5).
-define(CPU_ARCHITECTURE_IA64, 6).
-define(CPU_ARCHITECTURE_ALPHA64, 7).
-define(CPU_ARCHITECTURE_MSIL, 8).
-define(CPU_ARCHITECTURE_AMD64, 9).
-define(CPU_ARCHITECTURE_X86_WIN64, 10).

-define(MD_CONTEXT_ARM_REG_FP, 11).
-define(MD_CONTEXT_ARM_REG_SP, 13).
-define(MD_CONTEXT_ARM_REG_LR, 14).
-define(MD_CONTEXT_ARM_REG_PC, 15).

-record(minidump_header, {
    signature, version, stream_count, stream_directory_rva, checksum,
    time_date_stamp, flags
}).

-record(minidump_directory, {
    stream_type, stream_size, stream_rva
}).

-record(minidump_stream, {stream_type, stream_data}).

-record(minidump_thread, {
    thread_id, suspend_count, priority_class, priority, teb, stack_mem_start,
    stack_mem_size, stack_mem_rva, thread_context_size, thread_context_rva
}).

-record(minidump_exception_stream, {
    thread_id, exception_record, thread_context
}).

-record(minidump_exception, {
    exception_code, exception_flags, exception_record, exception_address,
    number_parameters, exception_information
}).

-record(minidump_location, {
    size, rva
}).

-record(minidump_memory_descriptor, {
    start_of_memory_range, memory
}).

-record(minidump_module, {
    base_of_image, size_of_image, checksum, time_date_stamp, module_name_rva,
    version_info, cv_record, misc_record
}).

-record(minidump_vs_fixed_file_info, {
    signature, struct_version, file_version_hi, file_version_lo,
    product_version_hi, product_version_lo,
    file_flags_mask, file_flags, file_os, file_type, file_subtype,
    file_date_hi, file_date_lo
}).

-record(minidump_cpu_info_x86, {
    vendor_id_0, vendor_id_1, vendor_id_2,
    version_info, feature_info, extended_features
}).

-record(minidump_cpu_info_arm, {
    cpu_id, elf_hw_caps
}).

-record(minidump_cpu_info_other, {
    features_0, features_1
}).

-record(minidump_raw_context_arm, {
    context_flags, registers, status_register, floating_point_registers,
    floating_point_status_register, floating_point_extra
}).

-record(minidump_system_info, {
    processor_arch, processor_level, processor_revision, processor_count,
    product_type, os_major_version, os_minor_version,
    os_build_number, os_platform_id,
    csd_version_rva, suite_mask, cpu_info
}).

-record(minidump_linux_dso, {
    version, map_rva, dso_count, brk, ld_base, dynamic
}).
