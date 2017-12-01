-module(minidump_parser).
-compile(export_all).

-define(UINT32LE, 4/little-unsigned-integer-unit:8).
-define(UINT64LE, 8/little-unsigned-integer-unit:8).

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

-record(minidump_header, {
    signature, version, stream_count, stream_directory_rva, checksum,
    time_date_stamp, flags
}).
-record(minidump_directory, {
    stream_type, stream_size, stream_rva
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
            io:format("Stream: ~p~n", [S])
        end,
        ParsedStreams
    ),
    ok.

parse_stream(Directory=#minidump_directory{stream_type=stream_type_linux_cpu_info}, Bin) ->
    % CPU info stream is the contents of /proc/cpuinfo as a string.
    [{type, Directory#minidump_directory.stream_type},
     {text, extract_stream_data(Directory, Bin)}];
parse_stream(Directory=#minidump_directory{stream_type=stream_type_linux_proc_status}, Bin) ->
    % CPU info stream is the contents of /proc/self/status as a string.
    [{type, Directory#minidump_directory.stream_type},
     {text, extract_stream_data(Directory, Bin)}];
parse_stream(Directory=#minidump_directory{stream_type=stream_type_linux_cmd_line}, Bin) ->
    % Command line that the program was started with.
    % May have trailing nulls, so strip those.
    Cmdline = hd(binary:split(
        extract_stream_data(Directory, Bin),
        <<0>>
    )),
    [{type, Directory#minidump_directory.stream_type},
     {text, Cmdline}];
parse_stream(Directory=#minidump_directory{stream_type=stream_type_linux_auxv}, Bin) ->
    % Auxiliary vector. Contains some OS specific information.
    % List of ulong keys and ulong values.
    Auxv = [
        {Key, Value} || <<Key:?UINT64LE, Value:?UINT64LE>>
        <= extract_stream_data(Directory, Bin)
    ],
    [{type, Directory#minidump_directory.stream_type},
     {map, Auxv}];
parse_stream(Directory=#minidump_directory{stream_type=stream_type_linux_environ}, Bin) ->
    % Environment variables, delimited by the null byte.
    EnvVars = binary:split(
        extract_stream_data(Directory, Bin),
        <<0>>,
        [global]
    ),
    % Convert them to a proplist
    EnvVarsProplist = [
        {Key, Value} || [Key, Value]
        <- [
            binary:split(Var, <<"=">>) || Var <- EnvVars
        ]
    ],
    [{type, Directory#minidump_directory.stream_type},
     {map, EnvVarsProplist}];
parse_stream(#minidump_directory{stream_type=Type}, _Bin) ->
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

    io:format("Directory data: ~p~n", [DirectoryData]),

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

