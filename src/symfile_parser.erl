-module(symfile_parser).
-compile(export_all).
-behaviour(gen_server).

-export([start_link/1]).

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-record(state, {
    file_ets, func_ets, func_line_ets, stack_ets, public_ets,
    code_id, module_os, module_cpu, module_uuid, module_name
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

parse_file(State=#state{}, Filename) ->
    {ok, Bin} = file:read_file(Filename),
    State1 = State#state{
        file_ets=ets:new(file, [set]),
        func_ets=ets:new(func, [set]),
        func_line_ets=ets:new(func_line_ets, [set]),
        stack_ets=ets:new(stack, [set]),
        public_ets=ets:new(public, [set])
    },
    Lines = binary:split(Bin, <<"\n">>, [global]),
    parse_lines(State1, Lines),
    io:format("Loaded ~p symbol lines~n", [length(Lines)]),
    State1.

% Expected prefixes:
% PUBLIC <extern_offset> 0 <name>
% STACK CFI INIT <entry_offset> <entry size> <rule map>
% STACK CFI <delta_offset> <rule map>
% FUNC <func_offset (hex)> <size (hex)> <param-size (hex)> <name>
% <hex> <line_offset (hex)> <line size (hex)> <line number> <file ID>
% FILE <source ID> <name>
% INFO CODE_ID <code id>
% MODULE <os> <cpu> <uuid> <module-name>
parse_lines(_State, []) ->
    ok;
parse_lines(State, [Line|Lines]) ->
    State1 = parse_line(State, Line),
    parse_lines(State1, Lines).

parse_line(State, <<>>) -> State;
parse_line(State=#state{}, <<"MODULE ", ModuleData/binary>>) ->
    io:format("Module: ~p~n", [ModuleData]),
    [Os, Cpu, Uuid, ModuleName] = binary:split(ModuleData, <<" ">>, [global]),
    State#state{
        module_os=Os,
        module_cpu=Cpu,
        module_uuid=Uuid,
        module_name=ModuleName
    };
parse_line(State=#state{}, <<"INFO CODE_ID ", CodeId/binary>>) ->
    State#state{code_id=CodeId};
parse_line(State=#state{file_ets=Ets}, <<"FILE ", FileData/binary>>) ->
    [SourceIdBin, Name] = binary:split(FileData, <<" ">>),
    SourceId = binary_to_integer(SourceIdBin),
    ets:insert(Ets, {SourceId, Name}),
    State;
parse_line(State=#state{func_ets=Ets}, <<"FUNC ", Data/binary>>) ->
    [OffsetHex, Data1] = binary:split(Data, <<" ">>),
    [SizeHex, Data2] = binary:split(Data1, <<" ">>),
    [ParamSizeHex, FuncName] = binary:split(Data2, <<" ">>),
    Offset = binary_to_integer(OffsetHex, 16),
    Size = binary_to_integer(SizeHex, 16),
    ParamSize = binary_to_integer(ParamSizeHex, 16),
    ets:insert(Ets, {Offset, Size, ParamSize, FuncName}),
    State;
parse_line(State=#state{public_ets=Ets}, <<"PUBLIC ", Data/binary>>) ->
    [OffsetHex, Data1] = binary:split(Data, <<" ">>),
    [_, Name] = binary:split(Data1, <<" ">>),
    Offset = binary_to_integer(OffsetHex, 16),
    ets:insert(Ets, {Offset, Name}),
    State;
parse_line(State=#state{stack_ets=Ets}, <<"STACK CFI INIT ", Data/binary>>) ->
    [OffsetHex, Data1] = binary:split(Data, <<" ">>),
    [SizeHex, RuleMap] = binary:split(Data1, <<" ">>),
    Offset = binary_to_integer(OffsetHex, 16),
    Size = binary_to_integer(SizeHex, 16),
    ets:insert(Ets, {Offset, Size, RuleMap}),
    State;
parse_line(State=#state{stack_ets=Ets}, <<"STACK CFI ", Data/binary>>) ->
    [OffsetHex, RuleMap] = binary:split(Data, <<" ">>),
    Offset = binary_to_integer(OffsetHex, 16),
    ets:insert(Ets, {Offset, 0, RuleMap}),
    State;
parse_line(State=#state{func_line_ets=Ets}, Data) when is_binary(Data) ->
    % Function lines start with raw hex
    [OffsetHex, SizeHex, LineNumberHex, FileId] = binary:split(
        Data, <<" ">>, [global]
    ),
    Offset = binary_to_integer(OffsetHex, 16),
    Size = binary_to_integer(SizeHex, 16),
    LineNumber = binary_to_integer(LineNumberHex, 16),
    ets:insert(Ets, {Offset, Size, LineNumber, FileId}),
    State.

