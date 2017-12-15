-module(symfile_server).
-behaviour(gen_server).

-export([
    start_link/1,
    symbols_for_file_hash/3
]).

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-record(state, {
    symfile_dir,
    parser_contexts,
    keys_by_pid
}).

%% Public API

start_link(SymfileDir) ->
    gen_server:start_link(?MODULE, [SymfileDir], []).

% Load all files in the symbol file directory
symbols_for_file_hash(Pid, Filename, Hash) ->
    gen_server:call(Pid, {get_sym_for_file_hash, Filename, Hash}).

%% Callbacks

init([SymfileDir]) ->
    % Trap exit so we can remove terminated children
    process_flag(trap_exit, true),
    {ok, #state{
        symfile_dir=SymfileDir,
        parser_contexts=#{},
        keys_by_pid=#{}
    }}.

handle_call({get_sym_for_file_hash, Filename, Hash}, _From, State) ->
    {State1, SymContext} = get_syms_for_file_hash(State, Filename, Hash),
    {reply, SymContext, State1};
handle_call(Request, From, State) ->
    lager:info("Call ~p From ~p", [Request, From]),
    {reply, ignored, State}.

handle_cast(Msg, State) ->
    lager:info("Cast ~p", [Msg]),
    {noreply, State}.

handle_info({'EXIT', FromPid, _Reason}, State) ->
    State1 = remove_downed_pid(State, FromPid),
    {noreply, State1};
handle_info(Info, State) ->
    lager:info("Info ~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(OldVsn, State, _Extra) ->
    lager:info("~p updated from vsn ~p", [?MODULE, OldVsn]),
    {ok, State}.

%% Implementation

remove_downed_pid(State, Pid) ->
    case maps:get(Pid, State#state.keys_by_pid, not_found) of
        not_found ->
            % We don't know that pid
            State;
        {Filename, Hash} ->
            % We do know that pid, and away it goes
            State#state{
                parser_contexts=maps:remove(
                    {Filename, Hash}, State#state.parser_contexts
                ),
                keys_by_pid=maps:remove(
                    Pid, State#state.keys_by_pid
                )
            }
    end.

get_syms_for_file_hash(State, Filename, Hash) ->
    % Check if we already have a parser context for this file hash
    SymContext = maps:get(
        {Filename, Hash},
        State#state.parser_contexts,
        not_found
    ),

    % If we don't, try and load it. If we do, just return it.
    _Return = case SymContext of
        not_found ->
            {_State1, _Retval} = load_file_hash(State, Filename, Hash);
        Pid ->
            {State, {ok, Pid}}
    end.

load_file_hash(State, Filename, Hash) ->
    Symfile = filename:join([
        State#state.symfile_dir, Filename, Hash
    ]),
    case filelib:is_file(Symfile) of
        false -> {State, not_found};
        true ->
            {ok, Pid} = symfile_parser:start_link(Symfile),
            State1 = State#state{
                parser_contexts=maps:put(
                    {Filename, Hash},
                    Pid,
                    State#state.parser_contexts
                ),
                keys_by_pid=maps:put(
                    Pid,
                    {Filename, Hash},
                    State#state.keys_by_pid
                )
            },
            {State1, {ok, Pid}}
    end.

