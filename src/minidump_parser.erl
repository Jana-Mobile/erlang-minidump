-module(minidump_parser).
-behaviour(gen_server).
-include_lib("stdlib/include/ms_transform.hrl").
-include("include/records.hrl").

-export([
    parse_file/1,
    parse_binary/1,
    close/1,
    get_crashing_thread_id/1,
    get_streams_of_type/2,
    get_thread_by_id/2,
    get_stack_for_thread/2
]).

% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-record(state, {
    raw_data,
    minidump_header,
    streams,  % Parsed minidump streams
    text_data_ets, % Ets table for raw text streams, like /proc info
    module_ets % List of modules, indexed by image base
}).

%% Public API

parse_file(Filename) ->
    gen_server:start_link(?MODULE, [{file, Filename}], []).

parse_binary(Binary) when is_binary(Binary) ->
    gen_server:start_link(?MODULE, [{binary, Binary}], []).

close(Pid) when is_pid(Pid) ->
    gen_server:call(Pid, close).

get_crashing_thread_id(Pid) when is_pid(Pid) ->
    gen_server:call(Pid, get_crashing_thread_id).

get_streams_of_type(Pid, StreamType) when is_pid(Pid) ->
    gen_server:call(Pid, {get_streams_of_type, StreamType}).

get_thread_by_id(Pid, ThreadId) when is_pid(Pid) and is_integer(ThreadId) ->
    gen_server:call(Pid, {get_thread_by_id, ThreadId}).

get_stack_for_thread(Pid, ThreadId) when is_pid(Pid) and is_integer(ThreadId) ->
    gen_server:call(Pid, {get_stack_for_thread, ThreadId}).

%% Callbacks

init([{file, Filename}]) ->
    gen_server:cast(self(), {parse_file, Filename}),
    {ok, #state{}};
init([{binary, Binary}]) ->
    gen_server:cast(self(), {parse_binary, Binary}),
    {ok, #state{}}.

handle_call(close, _From, State) ->
    {stop, normal, ok, State};
handle_call(get_crashing_thread_id, _From, State) ->
    CrashedThreadId = get_crashing_thread_id_impl(State),
    {reply, CrashedThreadId, State};
handle_call({get_streams_of_type, Type}, _From, State) ->
    Streams = get_streams_of_type_impl(State, Type),
    {reply, Streams, State};
handle_call({get_thread_by_id, ThreadId}, _From, State) ->
    Thread = get_thread_by_id_impl(State, ThreadId),
    {reply, Thread, State};
handle_call({get_stack_for_thread, ThreadId}, _From, State) ->
    {reply, get_stack_for_thread_impl(State, ThreadId), State};
handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

handle_cast({parse_file, Filename}, State) ->
    State1 = parse_file(State, Filename),
    {noreply, State1};
handle_cast({parse_binary, Binary}, State) ->
    State1 = parse_binary(State, Binary),
    {noreply, State1};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
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
    parse_binary(State, Bin).

parse_binary(State, Bin) ->
    Header = parse_header(Bin),
    State1 = State#state{
        raw_data=Bin,
        minidump_header=Header,
        text_data_ets=ets:new(text_data, [set]),
        module_ets=ets:new(modules, [set, {keypos, 2}])
    },
    MinidumpDirectories = parse_minidump_directories(Header, Bin),
    ParsedStreams = [
        parse_stream(State1, Directory) || Directory <- MinidumpDirectories
    ],
    State1#state{
        streams=ParsedStreams
    }.

-spec get_crashing_thread_id_impl(#state{}) -> {error, any()} | {ok, pos_integer()}.
get_crashing_thread_id_impl(State) ->
    case get_streams_of_type_impl(State, stream_type_exception) of
        [] ->
            {error, no_exception_data_stream};
        [ExnStream|_] ->
            ExnStreamData = ExnStream#minidump_stream.stream_data,
            {ok, ExnStreamData#minidump_exception_stream.thread_id}
    end.

-spec get_streams_of_type_impl(#state{}, atom()) -> [#minidump_stream{}].
get_streams_of_type_impl(State, StreamType) ->
    [Stream || Stream <- State#state.streams,
               Stream#minidump_stream.stream_type =:= StreamType].

-spec get_thread_by_id_impl(#state{}, pos_integer()) -> {error, any()} | {ok, #minidump_thread{}}.
get_thread_by_id_impl(State, ThreadId) ->
    case get_streams_of_type_impl(State, stream_type_thread_list) of
        [] -> {error, missing_thread_list_stream};
        [Stream|_] ->
            PossibleThread = [
                Thread || Thread <- Stream#minidump_stream.stream_data,
                          Thread#minidump_thread.thread_id =:= ThreadId
            ],
            case PossibleThread of
                [] -> {error, not_found};
                [Thread|_] -> {ok, Thread}
            end
    end.

get_stack_for_thread_impl(State, ThreadId) ->
    case get_thread_by_id_impl(State, ThreadId) of
        {error, Reason} -> {error, Reason};
        {ok, Thread} ->
            StackPage = extract_binary(
                State,
                Thread#minidump_thread.stack_mem_rva,
                Thread#minidump_thread.stack_mem_size
            ),
            StackMemStart = Thread#minidump_thread.stack_mem_start,
            ThreadContext = get_thread_context_impl(State, Thread),
            StackPointer = get_register_from_context(ThreadContext, ?MD_CONTEXT_ARM_REG_SP),
            InstructionPointer = get_register_from_context(ThreadContext, ?MD_CONTEXT_ARM_REG_PC),

            % Get the top level frame manually
            FirstFrameModule = hd(modules_with_address(State, InstructionPointer)),
            FirstFrameModuleName = extract_module_name(
                State#state.raw_data,
                FirstFrameModule#minidump_module.module_name_rva
            ),
            CodeViewData = extract_binary(State, FirstFrameModule#minidump_module.cv_record),
            FirstFrameModuleVersion = cv_record_to_guid(CodeViewData),
            FirstFrame = #stack_frame{
                instruction_pointer=InstructionPointer,
                module_name=FirstFrameModuleName,
                module_version=FirstFrameModuleVersion,
                module_offset=InstructionPointer-FirstFrameModule#minidump_module.base_of_image-2
            },

            StackFrames = stack_to_list(
                State, StackPage, StackMemStart, StackPointer
            ),
            {ok, [FirstFrame|StackFrames]}
    end.

get_register_from_context(#minidump_raw_context_arm{registers=Registers}, Register) ->
    lists:nth(Register + 1, Registers).

get_thread_context_impl(State, Thread=#minidump_thread{}) ->
    ThreadContextBin = extract_binary(
        State,
        Thread#minidump_thread.thread_context_rva,
        Thread#minidump_thread.thread_context_size
    ),
    parse_md_raw_context_arm(ThreadContextBin).

print_stackinfo(State, ParsedStreams) ->
    Bin = State#state.raw_data,
    [ThreadListStream] = [
        S || S <- ParsedStreams, is_tuple(S), element(1, S) =:= thread_list
    ],
    [CrashedThread] = [
        T || T <- element(2, ThreadListStream), element(2, T) =:= 15539
    ],
    StackRva = CrashedThread#minidump_thread.stack_mem_rva,
    StackSize = CrashedThread#minidump_thread.stack_mem_size,
    <<_Ignored:StackRva/binary, StackData:StackSize/binary, _Rest/binary>> = Bin,
    StackMemStart = CrashedThread#minidump_thread.stack_mem_start,
    StackPointer = binary_to_integer(<<"ffb55c90">>, 16),
    stack_to_list(State, StackData, StackMemStart, StackPointer, 30).

stack_to_list(State, Stack, StackStart, StackPointer) ->
    stack_to_list(State, Stack, StackStart, StackPointer, 30).
stack_to_list(State, Stack, StackStart, StackPointer, Depth) ->
    stack_to_list(State, Stack, StackStart, StackPointer, Depth, []).
stack_to_list(State, Stack, StackStart, StackPointer, 0, Acc) ->
    lists:reverse(Acc);
stack_to_list(State, Stack, StackStart, StackPointer, MaxDepth, Acc) ->
    {found, Sp, Ip, Module} = scan_for_return_address(
        State, Stack, StackStart, StackPointer
    ),
    ModuleName = extract_module_name(State#state.raw_data, Module#minidump_module.module_name_rva),
    CodeViewData = extract_binary(State, Module#minidump_module.cv_record),
    ModuleVersion = cv_record_to_guid(CodeViewData),
    ModuleNameDecoded = unicode:characters_to_binary(ModuleName, {utf16, little}),
    % Not sure why I'm off by 2 here...
    ModuleOffset = Ip - Module#minidump_module.base_of_image - 2,
    Frame = #stack_frame{
        instruction_pointer=Ip,
        module_name=ModuleNameDecoded,
        module_version=ModuleVersion,
        module_offset=ModuleOffset
    },
    stack_to_list(State, Stack, StackStart, Sp+4, MaxDepth-1, [Frame|Acc]).

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
    parse_stream_binary(State, StreamType, Data).

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

cv_record_to_guid(<<"LEpB", DebugId/binary>>) ->
    % This uses a really weird packing, since it's reinterpreting an ELF
    % style record (BpEL header) into a MSGUID struct
    <<D1:?UINT32LE, D2:?UINT16LE, D3:?UINT16LE, DR/binary>> = DebugId,
    list_to_binary(lists:flatten(
        io_lib:format("~8.16.0B~4.16.0B~4.16.0B~s", [
            D1, D2, D3,
            [io_lib:format("~2.16.0B",[X]) || <<X:8>> <= DR]
        ])
    ));
cv_record_to_guid(_) -> <<"unknown">>.

scan_for_return_address(State, MemoryBin, MemoryStartAddress, LastSp) ->
    Offset = LastSp - MemoryStartAddress,
    <<_:Offset/binary, IP:?UINT32LE, _/binary>> = MemoryBin,
    case instruction_address_seems_valid(State, IP) of
        {true, Module} ->
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

-spec parse_stream_binary(#state{}, atom(), binary()) -> #minidump_stream{}.
parse_stream_binary(_State, stream_type_linux_dso_debug, Data) ->
    % Ought to be 32 for all our dumps
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
    #minidump_stream{
        stream_type=stream_type_linux_dso_debug,
        stream_data=DsoEntries
    };
parse_stream_binary(_State, stream_type_system_info, Data) ->
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
    #minidump_stream{
        stream_type=stream_type_system_info,
        stream_data=SystemInfo
    };
parse_stream_binary(_State, stream_type_memory_list, Data) ->
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
    #minidump_stream{
        stream_type=stream_type_memory_list,
        stream_data=MemoryRanges
    };
parse_stream_binary(_State, stream_type_thread_list, Data) ->
    <<ThreadCount:?UINT32LE, Data1/binary>> = Data,
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
    #minidump_stream{
        stream_type=stream_type_thread_list,
        stream_data=ThreadData
    };
parse_stream_binary(_State, stream_type_exception, Data) ->
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
    #minidump_stream{
        stream_type=stream_type_exception,
        stream_data=Stream
    };
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
    #minidump_stream{
        stream_type=stream_type_module_list,
        stream_data=MDModules
    };
parse_stream_binary(_State, stream_type_linux_cpu_info, Data) ->
    % CPU info stream is the contents of /proc/cpuinfo as a string.
    #minidump_stream{
        stream_type=stream_type_linux_cpu_info,
        stream_data=Data
    };
parse_stream_binary(_State, stream_type_linux_proc_status, Data) ->
    % CPU info stream is the contents of /proc/self/status as a string.
    #minidump_stream{
        stream_type=stream_type_linux_proc_status,
        stream_data=Data
    };
parse_stream_binary(_State, stream_type_linux_maps, Data) ->
    % Contents of /proc/self/maps
    #minidump_stream{
        stream_type=stream_type_linux_maps,
        stream_data=Data
    };
parse_stream_binary(_State, stream_type_linux_cmd_line, Data) ->
    % Command line that the program was started with.
    % May have trailing nulls, so strip those.
    Cmdline = hd(binary:split(Data, <<0>>)),
    #minidump_stream{
        stream_type=stream_type_linux_cmd_line,
        stream_data=Cmdline
    };
parse_stream_binary(_State, stream_type_linux_auxv, Data) ->
    % Auxiliary vector. Contains some OS specific information.
    % List of ulong keys and ulong values.
    Auxv = [
        {Key, Value} || <<Key:?UINT64LE, Value:?UINT64LE>>
        <= Data
    ],
    #minidump_stream{
        stream_type=stream_type_linux_auxv,
        stream_data=Auxv
    };
parse_stream_binary(_State, stream_type_linux_environ, Data) ->
    % Environment variables, delimited by the null byte.
    EnvVars = binary:split(Data, <<0>>, [global]),
    % Convert them to a proplist
    EnvVarsProplist = [
        {Key, Value} || [Key, Value]
        <- [
            binary:split(Var, <<"=">>) || Var <- EnvVars
        ]
    ],
    #minidump_stream{
        stream_type=stream_type_linux_environ,
        stream_data=EnvVarsProplist
    };
parse_stream_binary(_State, stream_type_unused, _Data) ->
    % Reserved.
    #minidump_stream{
        stream_type=stream_type_unused
    }.

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
            parse_flags(
                Flags,
                Flags1,
                sets:add_element(minidump_type(Flag), Set)
            )
    end.


parse_header(Bin) ->
    <<Signature:?UINT32LE, Version:?UINT32LE, StreamCount:?UINT32LE,
      StreamDirectoryRVA:?UINT32LE, Checksum:?UINT32LE,
      TimeDateStamp:?UINT32LE, Flags:?UINT64LE, _Rest/binary>> = Bin,
    #minidump_header{
        signature=Signature,
        version=Version,
        stream_count=StreamCount,
        stream_directory_rva=StreamDirectoryRVA,
        checksum=Checksum,
        time_date_stamp=TimeDateStamp,
        flags=Flags
    }.
