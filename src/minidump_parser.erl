-module(minidump_parser).
-compile(export_all).
-behaviour(gen_server).
-include_lib("stdlib/include/ms_transform.hrl").
-include("include/records.hrl").

-record(state, {
    raw_data,
    minidump_header,
    text_data_ets, % Ets table for raw text streams, like /proc info
    module_ets % List of modules, indexed by image base
}).

%% Public API

start_link(Filename) ->
    gen_server:start_link(?MODULE, [Filename], []).

%% Callbacks

init([Filename]) ->
    gen_server:cast(self(), {parse, Filename}),
    {ok, #state{}}.

handle_call(Request, From, State) ->
    lager:info("Call ~p From ~p", [Request, From]),
    {reply, ignored, State}.

handle_cast({parse, Filename}, State) ->
    State1 = parse_file(State, Filename),
    {noreply, State1};
handle_cast(Msg, State) ->
    lager:info("Cast ~p", [Msg]),
    {noreply, State}.

handle_info(Info, State) ->
    lager:info("Info ~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(OldVsn, State, _Extra) ->
    lager:info("~p updated from vsn ~p", [?MODULE, OldVsn]),
    {ok, State}.

%% Implementation

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

parse_file(State, Filename) ->
    {ok, Bin} = file:read_file(Filename),
    {Header, Rest} = parse_header(Bin),
    State1 = State#state{
        raw_data=Bin,
        minidump_header=Header,
        text_data_ets=ets:new(text_data, [set]),
        module_ets=ets:new(modules, [set, {keypos, 2}])
    },
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
        parse_stream(State1, Directory) || Directory <- MinidumpDirectories
    ],
    lists:foreach(
        fun(S) ->
            ok %io:format("Stream type: ~p~n", [S])
        end,
        ParsedStreams
    ),
    [ThreadListStream] = [
        S || S <- ParsedStreams, is_tuple(S), element(1, S) =:= thread_list
    ],
    [CrashedThread] = [
        T || T <- element(2, ThreadListStream), element(2, T) =:= 15539
    ],
    io:format("Crashed thread: ~p~n", [CrashedThread]),
    StackRva = CrashedThread#minidump_thread.stack_mem_rva,
    StackSize = CrashedThread#minidump_thread.stack_mem_size,
    <<_Ignored:StackRva/binary, StackData:StackSize/binary, _Rest/binary>> = Bin,
    StackMemStart = CrashedThread#minidump_thread.stack_mem_start,
    StackPointer = binary_to_integer(<<"ffb55c90">>, 16),
    scan_stack_repeatedly(State1, StackData, StackMemStart, StackPointer, 30),
    State1.

scan_stack_repeatedly(State, Stack, StackStart, StackPointer, 0) ->
    ok;
scan_stack_repeatedly(State, Stack, StackStart, StackPointer, MaxDepth) ->
    case scan_for_return_address(State, Stack, StackStart, StackPointer) of
        {found, Sp, Ip, Module} ->
            scan_stack_repeatedly(State, Stack, StackStart, Sp+4, MaxDepth-1);
        _ ->
            ok
    end.

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

parse_md_raw_context_arm(Binary) ->
    RegisterCount = 16,
    TotalRegisterSize = 4 * RegisterCount,
    FPRegCount = 32,
    TotalFPRegSize = 8 * FPRegCount,
    FPExtraCount = 8,
    TotalExtraSize = 4 * FPExtraCount,
    <<ContextFlags:?UINT32LE,
      RegisterData:TotalRegisterSize/binary,
      CPSR:?UINT32LE,
      FPSCR:?UINT64LE,
      FPRegs:TotalFPRegSize/binary,
      FPExtraBin:TotalExtraSize/binary
    >> = Binary,
    Registers = [
        R || <<R:?UINT32LE>> <= RegisterData
    ],
    FPRegisters = [
        R || <<R:64/float-little>> <= FPRegs
    ],
    FPExtra = [
        R || <<R:?UINT32LE>> <= FPExtraBin
    ],
    #minidump_raw_context_arm{
        context_flags=ContextFlags,
        registers=Registers,
        status_register=CPSR,
        floating_point_registers=FPRegisters,
        floating_point_status_register=FPSCR,
        floating_point_extra=FPExtra
    }.

parse_stream(State, Directory=#minidump_directory{stream_type=StreamType}) ->
    Data = extract_stream_data(State, Directory),
    Stream = parse_stream_binary(State, StreamType, Data),
    case Stream of
        #minidump_exception_stream{
        thread_context=Location
    } ->
        Context = extract_binary(State, Location),
        ArmCtx = parse_md_raw_context_arm(Context),
        print_minidump_context(ArmCtx),
            ok;
        _ ->
            ok
    end,
    Stream.


register_name(?MD_CONTEXT_ARM_REG_FP) -> <<"fp">>;
register_name(?MD_CONTEXT_ARM_REG_SP) -> <<"sp">>;
register_name(?MD_CONTEXT_ARM_REG_LR) -> <<"lr">>;
register_name(?MD_CONTEXT_ARM_REG_PC) -> <<"pc">>;
register_name(RegisterNumber) ->
    N = integer_to_binary(RegisterNumber),
    <<"r", N/binary>>.

print_registers(Registers) when is_list(Registers) ->
    print_registers(0, Registers).

print_registers(_RegNum, []) -> ok;
print_registers(RegNum, Registers) ->
    {Regs, Registers1} = lists:split(4, Registers),
    Names = [
        register_name(RegNum + I) || I <- lists:seq(0, 3)
    ],
    lists:foreach(
        fun({Name, Value}) ->
            Pad = case byte_size(Name) of
                2 -> "    ";
                3 -> "   "
            end,
            io:format("~s = 0x~8.16.0b~s", [Name, Value, Pad])
        end,
        lists:zip(Names, Regs)
    ),
    io:format("~n"),
    print_registers(RegNum + 4, Registers1).

print_minidump_context(ArmCtx=#minidump_raw_context_arm{}) ->
    Registers = ArmCtx#minidump_raw_context_arm.registers,
    print_registers(Registers).

scan_for_return_address(State, MemoryBin, MemoryStartAddress, LastSp) ->
    % io:format("Last stack pointer: 0x~.16b~n", [LastSp]),
    % io:format("Memory address base: 0x~.16b~n", [MemoryStartAddress]),
    Offset = LastSp - MemoryStartAddress,
    <<_:Offset/binary, IP:?UINT32LE, _/binary>> = MemoryBin,
    case instruction_address_seems_valid(State, IP) of
        {true, Module} ->
            ModuleName = extract_module_name(State#state.raw_data, Module#minidump_module.module_name_rva),
            ModuleNameDecoded = unicode:characters_to_binary(ModuleName, {utf16, little}),
            % Not sure why I'm off by 2 here...
            ModuleOffset = IP - Module#minidump_module.base_of_image - 2,
            io:format(
                "[frame] ~s + 0x~.16b~n",
                [ModuleNameDecoded, ModuleOffset]
            ),
            io:format(
                "    sp = 0x~.16b, pc = 0x~.16b~n",
                [LastSp + 4, IP]
            ),
            {found, LastSp, IP, Module};
        false ->
            scan_for_return_address(State, MemoryBin, MemoryStartAddress, LastSp + 4)
    end.

extract_module_name(Binary, NameRva) ->
    <<_:NameRva/binary, NameLen:?UINT32LE, Rest/binary>> = Binary,
    <<Name:NameLen/binary, _/binary>> = Rest,
    Name.

instruction_address_seems_valid(State, IP) ->
    case modules_with_address(State, IP) of
        [] -> false;
        [Module] -> {true, Module}
    end.

modules_with_address(State, Address) ->
    % Select all modules with a base address <= Address
    PotentialModules = ets:select(
        State#state.module_ets,
        ets:fun2ms(fun(M=#minidump_module{base_of_image=Base}) when Base =< Address -> M end)
    ),

    % Filter the list to just modules where base + size >= Address, or
    % all modules that contain the address
    _ContainingModules = [
        M || M=#minidump_module{base_of_image=Base, size_of_image=Size}
        <- PotentialModules, Base + Size > Address
    ].

parse_md_dso_debug_32(Data) ->
    <<Version:?UINT32LE,
      MapRva:?UINT32LE,
      DsoCount:?UINT32LE,
      Brk:?UINT32LE,
      LdBase:?UINT32LE,
      Dynamic:?UINT32LE>> = Data,
    #minidump_linux_dso{
        version=Version,
        map_rva=MapRva,
        dso_count=DsoCount,
        brk=Brk,
        ld_base=LdBase,
        dynamic=Dynamic
    }.

parse_md_dso_debug_64(Data) ->
    <<Version:?UINT32LE,
      MapRva:?UINT32LE,
      DsoCount:?UINT32LE,
      Brk:?UINT64LE,
      LdBase:?UINT64LE,
      Dynamic:?UINT64LE>> = Data,
    #minidump_linux_dso{
        version=Version,
        map_rva=MapRva,
        dso_count=DsoCount,
        brk=Brk,
        ld_base=LdBase,
        dynamic=Dynamic
    }.

parse_stream_binary(State, stream_type_linux_dso_debug, Data) ->
    WordSize = 32,
    ParserFun = case WordSize of
        32 -> fun parse_md_dso_debug_32/1;
        64 -> fun parse_md_dso_debug_64/1
    end,
    RecordSize = case WordSize of
        32 -> 12 + 12;
        64 -> 12 + 24
    end,
    DsoEntries = [
        ParserFun(Record) || <<Record:RecordSize/binary>>
        <= Data
    ],
    io:format("~p DSO entries loaded~n", [length(DsoEntries)]),
    DsoEntries;
parse_stream_binary(State, stream_type_system_info, Data) ->
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
parse_stream_binary(State, stream_type_memory_list, Data) ->
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
parse_stream_binary(State, stream_type_thread_list, Data) ->
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
    lists:foreach(
        fun(Thread) ->
            case Thread#minidump_thread.thread_id of
                15539 ->
                    io:format("Crashing thread: ~p~n", [Thread]);
                _  -> ok
            end
        end,
        ThreadData
    ),
    {thread_list, ThreadData};
parse_stream_binary(State, stream_type_exception, Data) ->
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
    io:format("Exception data: ~p~n", [Stream]),
    Stream;
parse_stream_binary(State, stream_type_module_list, Data) ->
    ModuleEts = State#state.module_ets,
    <<ModuleCount:?UINT32LE, Data1/binary>> = Data,
    MDModuleSize = 108,
    ModuleDataSize = MDModuleSize * ModuleCount,
    <<ModuleData:ModuleDataSize/binary, _Data2/binary>> = Data1,
    MDModules = [
        parse_md_module(ModBin) || <<ModBin:MDModuleSize/binary>>
        <= ModuleData
    ],
    lists:foreach(
        fun(Module) -> ets:insert(ModuleEts, Module) end,
        MDModules
    ),
    io:format("~p modules loaded~n", [length(MDModules)]),
    MDModules;
parse_stream_binary(State, stream_type_linux_cpu_info, Data) ->
    % CPU info stream is the contents of /proc/cpuinfo as a string.
    [{type, stream_type_linux_cpu_info},
     {text, Data}];
parse_stream_binary(State, stream_type_linux_proc_status, Data) ->
    % CPU info stream is the contents of /proc/self/status as a string.
    [{type, stream_type_linux_proc_status},
     {text, Data}];
parse_stream_binary(State, stream_type_linux_maps, Data) ->
    % Contents of /proc/self/maps
    [{type, stream_type_linux_maps},
     {text, Data}];
parse_stream_binary(State, stream_type_linux_cmd_line, Data) ->
    % Command line that the program was started with.
    % May have trailing nulls, so strip those.
    Cmdline = hd(binary:split(Data, <<0>>)),
    [{type, stream_type_linux_cmd_line},
     {text, Cmdline}];
parse_stream_binary(State, stream_type_linux_auxv, Data) ->
    % Auxiliary vector. Contains some OS specific information.
    % List of ulong keys and ulong values.
    Auxv = [
        {Key, Value} || <<Key:?UINT64LE, Value:?UINT64LE>>
        <= Data
    ],
    [{type, stream_type_linux_auxv},
     {map, Auxv}];
parse_stream_binary(State, stream_type_linux_environ, Data) ->
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
parse_stream_binary(State, stream_type_unused, _Data) ->
    % Reserved.
    undefined;
parse_stream_binary(State, Type, _Data) ->
    io:format("Can't parse stream type ~p yet~n", [Type]),
    [{type, Type}].

extract_stream_data(State=#state{}, Directory=#minidump_directory{}) ->
    Rva = Directory#minidump_directory.stream_rva,
    Size = Directory#minidump_directory.stream_size,
    extract_binary(State, Rva, Size).

extract_binary(State=#state{}, #minidump_location{rva=Rva, size=Size}) ->
    extract_binary(State, Rva, Size).

extract_binary(#state{raw_data=Data}, Rva, Size) ->
    <<_Skip:Rva/binary, Value:Size/binary, _Rest/binary>> = Data,
    Value.

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

