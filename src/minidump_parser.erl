-module(minidump_parser).
-compile(export_all).

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

minidump_type(?MINIDUMP_TYPE_NORMAL) -> minidump_type_normal;
minidump_type(?MINIDUMP_TYPE_WITH_DATA_SEGS) -> minidump_type_with_data_segs;
minidump_type(?MINIDUMP_TYPE_WITH_FULL_MEMORY) -> minidump_type_with_full_memory;
minidump_type(?MINIDUMP_TYPE_WITH_HANDLE_DATA) -> minidump_type_with_handle_data;
minidump_type(?MINIDUMP_TYPE_FILTER_MEMORY) -> minidump_type_filter_memory;
minidump_type(?MINIDUMP_TYPE_SCAN_MEMORY) -> minidump_type_scan_memory;
minidump_type(?MINIDUMP_TYPE_WITH_UNLOADED_MODULES) -> minidump_type_with_unloaded_modules;
minidump_type(?MINIDUMP_TYPE_WITH_INDIRECTLY_REFERENCED_MEMORY) -> minidump_type_with_indirectly_referenced_memory;
minidump_type(?MINIDUMP_TYPE_FILTER_MODULE_PATHS) -> minidump_type_filter_module_paths;
minidump_type(?MINIDUMP_TYPE_WITH_PROCESS_THREAD_DATA) -> minidump_type_process_thread_data;
minidump_type(?MINIDUMP_TYPE_WITH_PRIVATE_READ_WRITE_MEMORY) -> minidump_type_with_private_read_write_memory;
minidump_type(?MINIDUMP_TYPE_WITHOUT_OPTIONAL_DATA) -> minidump_type_without_optional_data;
minidump_type(?MINIDUMP_TYPE_WITH_FULL_MEMORY_INFO) -> minidump_type_with_full_memory_info;
minidump_type(?MINIDUMP_TYPE_WITH_THREAD_INFO) -> minidump_type_with_thread_info;
minidump_type(?MINIDUMP_TYPE_WITH_CODE_SEGS) -> minidump_type_with_code_segs;
minidump_type(?MINIDUMP_TYPE_WITHOUT_AUXILIARY_STATE) -> minidump_type_without_auxiliary_state;
minidump_type(?MINIDUMP_TYPE_WITH_FULL_AUXILIARY_STATE) -> minidump_type_with_full_auxiliary_state;
minidump_type(?MINIDUMP_TYPE_WITH_PRIVATE_WRITE_COPY_MEMORY) -> minidump_type_with_private_write_copy_memory;
minidump_type(?MINIDUMP_TYPE_IGNORE_INACCESSIBLE_MEMORY) -> minidump_type_ignore_inaccessible_memory;
minidump_type(?MINIDUMP_TYPE_WITH_TOKEN_INFORMATION) -> minidump_type_with_token_information;
minidump_type(?MINIDUMP_TYPE_WITH_MODULE_HEADERS) -> minidump_type_with_module_headers;
minidump_type(?MINIDUMP_TYPE_FILTER_TRIAGE) -> minidump_type_filter_triage.

minidump_stream_type(?MINIDUMP_STREAM_TYPE_UNUSED) -> stream_type_unused;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_RESERVED_0) -> stream_type_reserved_0;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_RESERVED_1) -> stream_type_reserved_1;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_THREAD_LIST) -> stream_type_thread_list;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_MODULE_LIST) -> stream_type_module_list;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_MEMORY_LIST) -> stream_type_memory_list;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_EXCEPTION) -> stream_type_exception;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_SYSTEM_INFO) -> stream_type_system_info;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_THREAD_EX_LIST) -> stream_type_thread_ex_list;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_MEMORY_64_LIST) -> stream_type_memory_64_list;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_COMMENTS_A) -> stream_type_comments_a;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_COMMENTS_W) -> stream_type_comments_w;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_HANDLE_DATA) -> stream_type_handle_data;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_FUNCTION_TABLE) -> stream_type_function_table;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_UNLOADED_MODULE_LIST) -> stream_type_unloaded_module_list;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_MISC_INFO) -> stream_type_misc_info;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_MEMORY_INFO_LIST) -> stream_type_memory_info_list;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_THREAD_INF0_LIST) -> stream_type_thread_info_list;
minidump_stream_type(?MINIDUMP_STREAM_TYPE_HANDLE_OPERATION_LIST) -> stream_type_handle_operation_list;
minidump_stream_type(?MINIDUMP_STREAM_LINUX_CPU_INFO) -> stream_type_linux_cpu_info;
minidump_stream_type(?MINIDUMP_STREAM_LINUX_PROC_STATUS) -> stream_type_linux_proc_status;
minidump_stream_type(?MINIDUMP_STREAM_LINUX_LSB_RELEASE) -> stream_type_linux_lsb_release;
minidump_stream_type(?MINIDUMP_STREAM_LINUX_CMD_LINE) -> stream_type_linux_cmd_line;
minidump_stream_type(?MINIDUMP_STREAM_LINUX_ENVIRON) -> stream_type_linux_environ;
minidump_stream_type(?MINIDUMP_STREAM_LINUX_AUXV) -> stream_type_linux_auxv;
minidump_stream_type(?MINIDUMP_STREAM_LINUX_MAPS) -> stream_type_linux_maps;
minidump_stream_type(?MINIDUMP_STREAM_LINUX_DSO_DEBUG) -> stream_type_linux_dso_debug.

signal_name(1) -> sighup;
signal_name(2) -> sigint;
signal_name(3) -> sigquit;
signal_name(4) -> sigill;
signal_name(6) -> sigabrt;
signal_name(8) -> sigfpe;
signal_name(9) -> sigkill;
signal_name(11) -> sigsev;
signal_name(13) -> sigpipe;
signal_name(15) -> sigterm.

-record(minidump_header, {
    signature, version, stream_count, stream_directory_rva, checksum,
    time_date_stamp, flags
}).
-record(minidump_directory, {
    stream_type, stream_size, stream_rva
}).
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

parse_file(Filename) ->
    {ok, Bin} = file:read_file(Filename),
    {Header, Rest} = parse_header(Bin),
    io:format("~p streams detected~n", [Header#minidump_header.stream_count]),
    io:format("Header: ~p~n", [Header]),
    io:format("Flags: 0x~.16B: ~p~n", [
        Header#minidump_header.flags,
        sets:to_list(parse_flags(Header#minidump_header.flags))
    ]),
    MinidumpDirectories = parse_minidump_directories(Header, Bin),
    io:format("Stream data: ~n"),
    lists:foreach(
        fun(D) ->
            io:format("Stream type: ~p size ~p~n", [
                D#minidump_directory.stream_type,
                D#minidump_directory.stream_size
            ])
        end,
        MinidumpDirectories
    ),
    ParsedStreams = [
        parse_stream(Directory, Bin) || Directory <- MinidumpDirectories
    ],
    lists:foreach(
        fun(S) ->
            ok % io:format("Stream: ~p~n", [S])
        end,
        ParsedStreams
    ),
    ok.

parse_thread_info(Bin) ->
    <<ThreadId:?UINT32LE, SuspendCount:?UINT32LE,
      PriorityClass:?UINT32LE, Priority:?UINT32LE,
      Teb:?UINT64LE, StackMemStart:?UINT64LE,
      StackMemSize:?UINT32LE, StackMemRva:?UINT32LE,
      ThreadContextSize:?UINT32LE, ThreadContextRva:?UINT32LE,
      Rest/binary>> = Bin,
    #minidump_thread{
        thread_id=ThreadId,
        suspend_count=SuspendCount,
        priority_class=PriorityClass,
        priority=Priority,
        teb=Teb,
        stack_mem_start=StackMemStart,
        stack_mem_size=StackMemSize,
        stack_mem_rva=StackMemRva,
        thread_context_size=ThreadContextSize,
        thread_context_rva=ThreadContextRva
    }.

parse_vs_fixedfileinfo(Binary) ->
    <<Signature:?UINT32LE,
      StructVersion:?UINT32LE,
      FileVersionHi:?UINT32LE,
      FileVersionLo:?UINT32LE,
      ProductVersionHi:?UINT32LE,
      ProductVersionLo:?UINT32LE,
      FileFlagsMask:?UINT32LE,
      FileFlags:?UINT32LE,
      FileOs:?UINT32LE,
      FileType:?UINT32LE,
      FileSubtype:?UINT32LE,
      FileDateHi:?UINT32LE,
      FileDateLo:?UINT32LE>> = Binary,
    #minidump_vs_fixed_file_info{
        signature=Signature,
        struct_version=StructVersion,
        file_version_hi=FileVersionHi,
        file_version_lo=FileVersionLo,
        product_version_hi=ProductVersionHi,
        product_version_lo=ProductVersionLo,
        file_flags_mask=FileFlagsMask,
        file_flags=FileFlags,
        file_os=FileOs,
        file_type=FileType,
        file_subtype=FileSubtype,
        file_date_hi=FileDateHi,
        file_date_lo=FileDateLo
    }.

parse_md_module(Binary) ->
    <<BaseOfImage:?UINT64LE,
      SizeOfImage:?UINT32LE,
      Checksum:?UINT32LE,
      TimeDateStamp:?UINT32LE,
      ModuleNameRva:?UINT32LE,
      VersionInfo:?MDVSFIXEDFILEINFOSIZE/binary,
      CvRecordSize:?UINT32LE, CvRecordRva:?UINT32LE,
      MiscRecordSize:?UINT32LE, MiscRecordRva:?UINT32LE,
      _Reserved0:?UINT64LE, _Reserved1:?UINT64LE>> = Binary,
    #minidump_module{
        base_of_image=BaseOfImage,
        size_of_image=SizeOfImage,
        checksum=Checksum,
        time_date_stamp=TimeDateStamp,
        module_name_rva=ModuleNameRva,
        version_info=parse_vs_fixedfileinfo(VersionInfo),
        cv_record=#minidump_location{
            size=CvRecordSize,
            rva=CvRecordRva
        },
        misc_record=#minidump_location{
            size=MiscRecordSize,
            rva=MiscRecordRva
        }
    }.


parse_minidump_memory_descriptor(Data) ->
    <<StartOfMemoryRange:?UINT64LE,
      MemorySize:?UINT32LE,
      MemoryRva:?UINT32LE>> = Data,
    #minidump_memory_descriptor{
        start_of_memory_range=StartOfMemoryRange,
        memory=#minidump_location{
            size=MemorySize,
            rva=MemoryRva
        }
    }.


parse_md_cpu_info(?CPU_ARCHITECTURE_x86, Bin) ->
    <<VendorId0:?UINT32LE,
      VendorId1:?UINT32LE,
      VendorId2:?UINT32LE,
      VersionInfo:?UINT32LE,
      FeatureInfo:?UINT32LE,
      ExtendedFeatures:?UINT32LE,
      _Rest/binary>> = Bin,
    #minidump_cpu_info_x86{
        vendor_id_0=VendorId0,
        vendor_id_1=VendorId1,
        vendor_id_2=VendorId2,
        version_info=VersionInfo,
        feature_info=FeatureInfo,
        extended_features=ExtendedFeatures
    };
parse_md_cpu_info(?CPU_ARCHITECTURE_ARM, Bin) ->
    <<CpuId:?UINT32LE,
      ElfHwcaps:?UINT32LE,
      _Rest/binary>> = Bin,
    #minidump_cpu_info_arm{
        cpu_id=CpuId,
        elf_hw_caps=ElfHwcaps
    };
parse_md_cpu_info(_, Bin) ->
    <<ProcessorFeatures0:?UINT64LE,
      ProcessorFeatures1:?UINT64LE,
      _Rest/binary>> = Bin,
    #minidump_cpu_info_other{
        features_0=ProcessorFeatures0,
        features_1=ProcessorFeatures1
    }.

parse_stream(Directory=#minidump_directory{stream_type=StreamType}, Binary) ->
    Data = extract_stream_data(Directory, Binary),
    parse_stream_binary(StreamType, Data).

-record(minidump_system_info, {
    processor_arch, processor_level, processor_revision, processor_count,
    product_type, os_major_version, os_minor_version,
    os_build_number, os_platform_id,
    csd_version_rva, suite_mask, cpu_info
}).

parse_stream_binary(stream_type_system_info, Data) ->
    <<ProcessorArch:?UINT16LE,
      ProcessorLevel:?UINT16LE,
      ProcessorRevision:?UINT16LE,
      ProcessorCount:?UINT8,
      ProductType:?UINT8,
      OsMajorVersion:?UINT32LE,
      OsMinorVersion:?UINT32LE,
      OsBuildNumber:?UINT32LE,
      OsPlatformId:?UINT32LE,
      CSDVersionRva:?UINT32LE,
      SuiteMask:?UINT16LE,
      _Reserved:?UINT16LE,
      CpuInfoBin/binary>> = Data,
    CpuInfo = parse_md_cpu_info(ProcessorArch, CpuInfoBin),
    SystemInfo=#minidump_system_info{
        processor_arch=ProcessorArch,
        processor_level=ProcessorLevel,
        processor_revision=ProcessorRevision,
        processor_count=ProcessorCount,
        product_type=ProductType,
        os_major_version=OsMajorVersion,
        os_minor_version=OsMinorVersion,
        os_build_number=OsBuildNumber,
        os_platform_id=OsPlatformId,
        csd_version_rva=CSDVersionRva,
        suite_mask=SuiteMask,
        cpu_info=CpuInfo
    },
    io:format("System info: ~p~n", [SystemInfo]),
    SystemInfo;
parse_stream_binary(stream_type_memory_list, Data) ->
    <<MemoryRangeCount:?UINT32LE, Data1/binary>> = Data,
    MinidumpMemoryDescriptorSize = (
        8    % Start of memory range
        + 4  % Embedded location datasize
        + 4  % Embedded location RVA
    ),
    TotalMemoryDescriptorSize = MemoryRangeCount * MinidumpMemoryDescriptorSize,
    <<MemoryDescriptorData:TotalMemoryDescriptorSize/binary, _Rest/binary>> = Data1,
    MemoryRanges = [
        parse_minidump_memory_descriptor(MDData)
        || <<MDData:MinidumpMemoryDescriptorSize/binary>>
        <= MemoryDescriptorData
    ],
    io:format("~p memory ranges loaded~n", [length(MemoryRanges)]),
    MemoryRanges;
parse_stream_binary(stream_type_thread_list, Data) ->
    <<ThreadCount:?UINT32LE, Data1/binary>> = Data,
    io:format("Found ~p threads~n", [ThreadCount]),
    ThreadDescriptorSize = (
        4    % Thread ID
        + 4  % Suspend count
        + 4  % Priority class
        + 4  % Priority
        + 8  % Thread Environment Block
        + 8  % Stack memory start address
        + 4  % Stack memory size
        + 4  % Stack memory RVA
        + 4  % Thread context size
        + 4  % Thread context RVA
    ),
    TotalThreadDescriptorSize = ThreadDescriptorSize * ThreadCount,
    <<ThreadDataBinary:TotalThreadDescriptorSize/binary, _/binary>> = Data1,
    ThreadData = [
        parse_thread_info(ThreadBin)
        || <<ThreadBin:ThreadDescriptorSize/binary>>
        <= ThreadDataBinary
    ],
    ThreadData;
parse_stream_binary(stream_type_exception, Data) ->
    <<ThreadId:?UINT32LE, _Alignment:?UINT32LE,
      % Minidump exception record, embedded
      ExceptionCode:?UINT32LE, ExceptionFlags:?UINT32LE,
      ExceptionRecord:?UINT64LE, ExceptionAddress:?UINT64LE,
      NumberParameters:?UINT32LE, _Alignment2:?UINT32LE,
      % Array of 15 uint64s
      ExceptionInformationArray:120/binary,
      % Minidump location descriptor, embedded
      ThreadContextSize:?UINT32LE, ThreadContextRva:?UINT32LE>> = Data,
    % Parse the exception info array
    ExceptionInformation = [
        E || <<E:?UINT64LE>> <= ExceptionInformationArray
    ],
    Stream = #minidump_exception_stream{
        thread_id=ThreadId,
        exception_record=#minidump_exception{
            exception_code=ExceptionCode,
            exception_flags=ExceptionFlags,
            exception_record=ExceptionRecord,
            exception_address=ExceptionAddress,
            number_parameters=NumberParameters,
            exception_information=ExceptionInformation
        },
        thread_context=#minidump_location{
            size=ThreadContextSize,
            rva=ThreadContextRva
        }
    },
    io:format("Thread was killed by signal ~p in thread ~p~n", [
        signal_name(ExceptionCode),
        ThreadId
    ]),
    Stream;
parse_stream_binary(stream_type_module_list, Data) ->
    <<ModuleCount:?UINT32LE, Data1/binary>> = Data,
    MDModuleSize = 108,
    ModuleDataSize = MDModuleSize * ModuleCount,
    <<ModuleData:ModuleDataSize/binary, _Data2/binary>> = Data1,
    MDModules = [
        parse_md_module(ModBin) || <<ModBin:MDModuleSize/binary>>
        <= ModuleData
    ],
    io:format("~p modules loaded~n", [length(MDModules)]),
    MDModules;
parse_stream_binary(stream_type_linux_cpu_info, Data) ->
    % CPU info stream is the contents of /proc/cpuinfo as a string.
    [{type, stream_type_linux_cpu_info},
     {text, Data}];
parse_stream_binary(stream_type_linux_proc_status, Data) ->
    % CPU info stream is the contents of /proc/self/status as a string.
    [{type, stream_type_linux_proc_status},
     {text, Data}];
parse_stream_binary(stream_type_linux_maps, Data) ->
    % Contents of /proc/self/maps
    [{type, stream_type_linux_maps},
     {text, Data}];
parse_stream_binary(stream_type_linux_cmd_line, Data) ->
    % Command line that the program was started with.
    % May have trailing nulls, so strip those.
    Cmdline = hd(binary:split(Data, <<0>>)),
    [{type, stream_type_linux_cmd_line},
     {text, Cmdline}];
parse_stream_binary(stream_type_linux_auxv, Data) ->
    % Auxiliary vector. Contains some OS specific information.
    % List of ulong keys and ulong values.
    Auxv = [
        {Key, Value} || <<Key:?UINT64LE, Value:?UINT64LE>>
        <= Data
    ],
    [{type, stream_type_linux_auxv},
     {map, Auxv}];
parse_stream_binary(stream_type_linux_environ, Data) ->
    % Environment variables, delimited by the null byte.
    EnvVars = binary:split(Data, <<0>>, [global]),
    % Convert them to a proplist
    EnvVarsProplist = [
        {Key, Value} || [Key, Value]
        <- [
            binary:split(Var, <<"=">>) || Var <- EnvVars
        ]
    ],
    [{type, stream_type_linux_environ},
     {map, EnvVarsProplist}];
parse_stream_binary(Type, _Data) ->
    io:format("Can't parse stream type ~p yet~n", [Type]),
    [{type, Type}].

extract_stream_data(Directory, Bin) ->
    Rva = Directory#minidump_directory.stream_rva,
    Size = Directory#minidump_directory.stream_size,
    <<_Ignored:Rva/binary, Stream:Size/binary, _Rest/binary>> = Bin,
    Stream.

parse_minidump_directories(Header=#minidump_header{stream_directory_rva=Rva}, Bin) ->
    % Trim off the directory RVA to get the start of the directories
    <<_:Rva/binary, Rest1/binary>> = Bin,

    % Calculate the size of the directory array
    DirectorySize = (
      4    % MINIDUMP_DIRECTORY StreamType
      + 4  % MINIDUMP_LOCATION_DESCRIPTOR DataSize
      + 4  % MINIDUMP_LOCATION_DESCRIPTOR RVA
    ),
    TotalDirectorySize = DirectorySize * Header#minidump_header.stream_count,

    % Extract the directory binary data
    <<DirectoryData:TotalDirectorySize/binary, Rest2/binary>> = Rest1,

    % Parse each of the directories
    Directories = [
        #minidump_directory{
            stream_type=minidump_stream_type(StreamType),
            stream_size=Size,
            stream_rva=RVA
        } || <<StreamType:?UINT32LE, Size:?UINT32LE, RVA:?UINT32LE>> <= DirectoryData
    ],
    Directories.

parse_flags(Flags) ->
    parse_flags(Flags, ?MINIDUMP_FLAGS, sets:new()).
parse_flags(_Flags, [], FlagSet) ->
    FlagSet;
parse_flags(Flags, [Flag|Flags1], Set) ->
    case Flags band Flag of
        0 -> parse_flags(Flags, Flags1, Set);
        _ ->
            io:format("It's a match~n"),
            parse_flags(
                Flags,
                Flags1,
                sets:add_element(minidump_type(Flag), Set)
            )
    end.


parse_header(Bin) ->
    <<Signature:?UINT32LE, Version:?UINT32LE, StreamCount:?UINT32LE,
      StreamDirectoryRVA:?UINT32LE, Checksum:?UINT32LE,
      TimeDateStamp:?UINT32LE, Flags:?UINT64LE, Rest/binary>> = Bin,
    {#minidump_header{
        signature=Signature,
        version=Version,
        stream_count=StreamCount,
        stream_directory_rva=StreamDirectoryRVA,
        checksum=Checksum,
        time_date_stamp=TimeDateStamp,
        flags=Flags
    }, Rest}.

