-module(symfile_parser).
-compile(export_all).
-behaviour(gen_server).
-include_lib("stdlib/include/ms_transform.hrl").
-define(TIMEOUT, 10000).

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

get_func_with_offset(Pid, Offset) ->
    gen_server:call(Pid, {get_func, Offset}, ?TIMEOUT).

get_file_by_number(Pid, Number) ->
    gen_server:call(Pid, {get_file, Number}, ?TIMEOUT).

get_symbol_with_offset(Pid, Offset) ->
    gen_server:call(Pid, {get_public, Offset}, ?TIMEOUT).

%% Callbacks

init([Filename]) ->
    gen_server:cast(self(), {parse, Filename}),
    {ok, #state{}}.

handle_call({get_func, Offset}, _From, State) ->
    Func = case get_func_with_offset_impl(State, Offset) of
        [] -> not_found;
        [F|_] -> {ok, F}
    end,
    {reply, Func, State};
handle_call({get_file, Number}, _From, State) ->
    FileEts = State#state.file_ets,
    File = case ets:lookup(FileEts, Number) of
        [] -> not_found;
        [F|_] -> {ok, F}
    end,
    {reply, File, State};
handle_call({get_public, Offset}, _From, State) ->
    Sym = case get_public_with_offset_impl(State, Offset) of
        [] -> not_found;
        [S|_] -> {ok, S}
    end,
    {reply, Sym, State};
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
        func_ets=ets:new(func, [set, {keypos, 2}]),
        func_line_ets=ets:new(func_line_ets, [set]),
        stack_ets=ets:new(stack, [set]),
        public_ets=ets:new(public, [set, {keypos, 2}])
    },
    Lines = binary:split(Bin, <<"\n">>, [global]),
    parse_lines(State1, Lines),
    State1.

get_func_with_offset_impl(State, Offset) ->
    % Select all modules with a base address <= Address
    PotentialFuncs = ets:select(
        State#state.func_ets,
        ets:fun2ms(fun(F=#symfile_func{offset=Base}) when Base =< Offset -> F end)
    ),

    % Filter the list to just modules where base + size >= Address, or
    % all modules that contain the address
    _ContainingFuncs = [
        M || M=#symfile_func{offset=Base, size=Size}
        <- PotentialFuncs, Base + Size > Offset
    ].

get_public_with_offset_impl(State, Offset) ->
    % Select all public records with a base offset <= Offset
    Potentials = ets:select(
        State#state.public_ets,
        ets:fun2ms(fun(F=#symfile_public{offset=Base}) when Base =< Offset -> F end)
    ),

    case Potentials of
        [] -> [];
        _ ->
            % We don't really have a size for publics, so take the highest one
            Lowest = lists:foldl(
                fun(S1=#symfile_public{offset=O1}, S2=#symfile_public{offset=O2}) ->
                    case O1 > O2 of
                        true -> S1;
                        false -> S2
                    end
                end,
                hd(Potentials),
                Potentials
            ),
            [Lowest]
    end.

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
    ets:insert(Ets, #symfile_func{offset=Offset, size=Size, param_size=ParamSize, name=FuncName}),
    State;
parse_line(State=#state{public_ets=Ets}, <<"PUBLIC ", Data/binary>>) ->
    [OffsetHex, Data1] = binary:split(Data, <<" ">>),
    [_, Name] = binary:split(Data1, <<" ">>),
    Offset = binary_to_integer(OffsetHex, 16),
    ets:insert(Ets, #symfile_public{offset=Offset, name=Name}),
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

