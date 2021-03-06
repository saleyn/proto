%%%----------------------------------------------------------------------------
%%% @author Serge Aleynikov <saleyn@gmail.com>
%%% @copyright (c) 2014 Serge Aleynikov
%%% @doc Generic TCP/SSL socket acceptor behavior.
%%% @see [http://www.trapexit.org/index.php/Building_a_Non-blocking_TCP_server_using_OTP_principles]
%%% @see [https://github.com/essiene/jsonevents/blob/master/src/gen_listener_tcp.erl]
%%%----------------------------------------------------------------------------
%%% Created: 2015-05-10
%%%----------------------------------------------------------------------------
-module(gen_sock_acceptor).
-behaviour(gen_server).

-export([
    start/4,
    start/5,
    start_link/4,
    start_link/5,
    call/2,
    call/3,
    multicall/2,
    multicall/3,
    multicall/4,
    cast/2,
    abcast/2,
    abcast/3,
    reply/2
]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3,
    format_status/2
]).

-export([sockname/1, filter_ip_address/2]).

-record(lstate, {
    type    = tcp :: tcp | ssl,
    verbose = 0   :: integer(),
    socket        :: (port() | ssl:socket()),
    lsock         :: port(),
    acceptor,
    mod,
    mod_state,
    call,
    cast,
    info
}).

-include_lib("kernel/include/logger.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(TAG, '$gen_sock_acceptor_mod').

%%%----------------------------------------------------------------------------
%%% Interface API
%%%----------------------------------------------------------------------------

-callback init(Args::term()) ->
    {ok, {Port::integer(), ListenerTcpOptions::list()}, State::term()} |
    {stop, Reason::term()} |
    ignore.
-callback handle_accept(Req::term(), State::term()) ->
    {noreply, NewState::term()} |
    {noreply, NewState::term(), timeout() | hibernate} |
    {stop, Reason::term(), Reply::term(), NewState::term()} |
    {stop, Reason::term(), NewState::term()}.
-callback handle_accept_error(Req::term(), State::term()) ->
    {noreply, NewState::term()} |
    {noreply, NewState::term(), timeout() | hibernate} |
    {stop, Reason::term(), NewState::term()}.
-callback handle_call(Request::term(), From::{pid(), Tag::term()}, State::term()) ->
    {reply, Reply::term(), NewState::term()} |
    {reply, Reply::term(), NewState::term(), timeout() | hibernate} |
    {noreply, NewState::term()} |
    {noreply, NewState::term(), timeout() | hibernate} |
    {stop, Reason::term(), Reply::term(), NewState::term()} |
    {stop, Reason::term(), NewState::term()}.
-callback handle_cast(Request::term(), State::term()) ->
    {noreply, NewState::term()} |
    {noreply, NewState::term(), timeout() | hibernate} |
    {stop, Reason::term(), NewState::term()}.
-callback handle_info(Info::timeout | term(), State::term()) ->
    {noreply, NewState::term()} |
    {noreply, NewState::term(), timeout() | hibernate} |
    {stop, Reason::term(), NewState::term()}.
-callback code_change(OldVsn::(term() | {down,term()}), State::term(), Extra::term()) ->
    {ok, NewState::term()} | {error, Reason::term()}.
-callback terminate(Reason::(normal | shutdown | {shutdown, term()} | term()),
    State::term()) -> term().
-callback format_status(Opt, StatusData) -> Status when
      Opt :: 'normal' | 'terminate',
      StatusData :: [PDict | State],
      PDict :: [{Key :: term(), Value :: term()}],
      State :: term(),
      Status :: term().

-optional_callbacks([
    handle_accept_error/2, handle_call/3, handle_cast/2, handle_info/2,
    terminate/2, code_change/3, format_status/2]).

%%%----------------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------------

start_link(Name, Type, Mod, ModArgs, GenOptions)
    when (Type=:=tcp orelse Type=:=ssl), is_atom(Mod), is_list(ModArgs), is_list(GenOptions) ->
    gen_server:start_link(Name, ?MODULE, add_opts(Type, Mod, ModArgs), GenOptions).

start_link(Type, Mod, ModArgs, GenOptions)
    when (Type=:=tcp orelse Type=:=ssl), is_atom(Mod), is_list(ModArgs), is_list(GenOptions) ->
    gen_server:start_link(?MODULE, add_opts(Type, Mod, ModArgs), GenOptions).

start(Name, Type, Mod, ModArgs, GenOptions)
    when (Type=:=tcp orelse Type=:=ssl), is_atom(Mod), is_list(ModArgs), is_list(GenOptions) ->
    gen_server:start(Name, ?MODULE, add_opts(Type, Mod, ModArgs), GenOptions).

start(Type, Mod, ModArgs, GenOptions)
    when (Type=:=tcp orelse Type=:=ssl), is_atom(Mod), is_list(ModArgs), is_list(GenOptions) ->
    gen_server:start(?MODULE, add_opts(Type, Mod, ModArgs), GenOptions).

call(ServerRef, Request) ->
    gen_server:call(ServerRef, Request).

call(ServerRef, Request, Timeout) ->
    gen_server:call(ServerRef, Request, Timeout).

multicall(Name, Request) ->
    gen_server:multi_call(Name, Request).

multicall(Nodes, Name, Request) ->
    gen_server:multi_call(Nodes, Name, Request).

multicall(Nodes, Name, Request, Timeout) ->
    gen_server:multi_call(Nodes, Name, Request, Timeout).

cast(ServerRef, Request) ->
    gen_server:cast(ServerRef, Request).

abcast(Name, Request) ->
    gen_server:abcast(Name, Request).

abcast(Nodes, Name, Request) ->
    gen_server:abcast(Nodes, Name, Request).

reply(Client, Reply) ->
    gen_server:reply(Client, Reply).

-spec sockname(Pid::pid() | atom()) ->
    {ok, {Addr::tuple(), Port::integer()}} | {error, Reason::term()}.
sockname(ServerRef) ->
    gen_server:call(ServerRef, {?TAG, sockname}).

%% @doc Given an IP address, return true if it matches to one of the masks
%%      in the `Whitelist'.
%% E.g.:
%% ```
%%  false = filter_ip_address({127,0,0,1}, []).     %% No match by default
%%  true  = filter_ip_address({127,0,0,1}, [[]]).   %% Match everything
%%  true  = filter_ip_address({127,0,0,1}, [[127]]).
%%  false = filter_ip_address({127,1,2,3}, [[127, 0]]).
%%  true  = filter_ip_address({127,1,0,3}, [[201,17,10],[127,1]]).
%% '''
-spec filter_ip_address(IP::(tuple()|list()), Whitelist::[IP::list()]) -> boolean().
filter_ip_address(_IP, [] = _IPs) ->
    false;
filter_ip_address(IP, [H|T]) when is_tuple(IP) ->
    L = tuple_to_list(IP),
    filter_ip_address(L, L, H, T);
filter_ip_address(IP, [H|T]) when is_list(IP) ->
    filter_ip_address(IP, IP, H, T).

%%-----------------------------------------------------------------------------
%% gen_server callbacks
%%-----------------------------------------------------------------------------

init([{?TAG, Type, Mod, Verbose} | ModArgs]) ->
    process_flag(priority, max),
    %process_flag(trap_exit, true),
    try
        case Mod:init(ModArgs) of
        {ok, {Port, ListenOpts}, ModState} when is_integer(Port), is_list(ListenOpts) ->
            {ok, LSock}    = sock:listen(Type, Port, ListenOpts),
            {ok, {Addr,_}} = sock:sockname(LSock),
            LSPort         = sock:extract_port_from_socket(LSock),
            List = [{info, started_listener}, {type, Type}, {addr, Addr}, {port, Port},
                   {lsock, LSPort},   {verbose, Verbose} | ListenOpts],
            info_report(Verbose, 0, List),

            Call  = erlang:function_exported(Mod, handle_call, 3),
            Cast  = erlang:function_exported(Mod, handle_cast, 2),
            Info  = erlang:function_exported(Mod, handle_info, 2),
            
            State = #lstate{
                type=Type, verbose=Verbose, socket=LSock, lsock=LSPort,
                mod=Mod,   mod_state=ModState,
                call=Call, cast=Cast, info=Info
            },
            {ok, create_acceptor(State)};
        ignore ->
            ignore;
        {stop, Reason} ->
            {stop, Reason};
        Other ->
            {stop, {unexpected_return, Other}}
        end
    catch _:Err:STrace ->
        {stop, {Err, STrace}}
    end.

handle_call({?TAG, sockname}, _From, #lstate{lsock=Sock}=State) ->
    Reply = inet:sockname(Sock),
    {reply, Reply, State};
handle_call(Req, _From, #lstate{call=false}=State) ->
    {stop, {not_implemented, Req}, State};
handle_call(Req, From, #lstate{mod=Mod, mod_state=ModState}=St) ->
    try
        case Mod:handle_call(Req, From, ModState) of 
        {reply, Reply, NewModState} ->
            {reply, Reply, St#lstate{mod_state=NewModState}};
        {reply, Reply, NewModState, TimeoutOrHibernate} ->
            {reply, Reply, St#lstate{mod_state=NewModState}, TimeoutOrHibernate};
        {noreply, NewModState} ->
            {noreply, St#lstate{mod_state=NewModState}};
        {noreply, NewModState, TimeoutOrHibernate} ->
            {noreply, St#lstate{mod_state=NewModState}, TimeoutOrHibernate};
        {stop, Reason, NewModState} ->
            {stop, Reason, St#lstate{mod_state=NewModState}};
        {stop, Reason, Reply, NewModState} ->
            {stop, Reason, Reply, St#lstate{mod_state=NewModState}}
        end
    catch Type:Err:STrace ->
        ?LOG_ERROR(
            [{action, handle_call}, {error, Err}, {module, Mod},
             {Type, Err}, {stack, STrace}]),
        {stop, Err, St}
    end.

handle_cast(Req, #lstate{cast=false}=St) ->
    {stop, {cast_not_implemented, Req}, St};
handle_cast(Req, #lstate{mod=Mod, mod_state=ModState}=St) ->
    try
        case Mod:handle_cast(Req, ModState) of
        {noreply, NewModState} ->
            {noreply, St#lstate{mod_state=NewModState}};
        {noreply, NewModState, TimeoutOrHibernate} ->
            {noreply, St#lstate{mod_state=NewModState}, TimeoutOrHibernate};
        {stop, Reason, NewModState} ->
            {stop, Reason, St#lstate{mod_state=NewModState}}
        end
    catch Type:Err:STrace ->
        ?LOG_ERROR(
            [?MODULE, {action, handle_cast}, {error, Err}, {module, Mod},
                      {Type, Err}, {stack, STrace}]),
        {stop, Err, St}
    end.

handle_info({inet_async, LSock, ARef, {ok, RawCSock}},
            #lstate{lsock=LSock, socket=SSocket, acceptor=ARef, mod=Mod, mod_state=ModState}=St) ->
    info_report(St#lstate.verbose, 2,
        fun() -> [{info, new_connection},
                  {csock, sock:extract_port_from_socket(RawCSock)},
                  {lsock, St#lstate.lsock}, {async_ref, ARef},
                  {module, Mod},  {module_state, ModState}] end),
    {ok, CSock} = sock:handle_async_accept(SSocket, RawCSock),
    try
        case Mod:handle_accept(CSock, ModState) of
        {noreply, NewModState} ->
            {noreply, create_acceptor(St#lstate{mod_state=NewModState})};
        {noreply, NewModState, TimeoutOrHibernate} ->
            {noreply, create_acceptor(St#lstate{mod_state=NewModState}), TimeoutOrHibernate};
        {stop, Reason, NewModState} ->
            {stop, Reason, St#lstate{mod_state=NewModState}}
        end
    catch Type:Err:STrace ->
        ?LOG_ERROR([{action, handle_accept}, {Type, Err}, {stack, STrace}]),
        catch sock:setopts(CSock, [{linger, {false, 0}}]),
        sock:close(CSock),
        {noreply, create_acceptor(St)}
    end;

handle_info({inet_async, LS, ARef, Error},
            #lstate{lsock=LS, acceptor=ARef, mod=Mod, mod_state=MState}=St) ->
    case erlang:function_exported(Mod, handle_accept_error, 2) of
    true ->
        try
            case Mod:handle_accept_error(Error, MState) of
            {noreply, NewMState} ->
                {noreply, create_acceptor(St#lstate{mod_state=NewMState})};
            {noreply, NewMState, hibernate} ->
                {noreply, create_acceptor(St#lstate{mod_state=NewMState}), hibernate};
            {noreply, NewMState, Timeout} ->
                {noreply, create_acceptor(St#lstate{mod_state=NewMState}), Timeout};
            {stop, Reason, NewMState} ->
                {stop, Reason, St#lstate{mod_state=NewMState}}
            end
        catch Type:Err:STrace ->
            ?LOG_ERROR([{action, handle_accept_error}, {error, Error}, {module, Mod},
                        {Type, Err}, {stack, STrace}]),
            {stop, Error, St}
        end;
    false ->
        ?LOG_ERROR([{action, accept_error},   {reason, Error},
                    {lsock, St#lstate.lsock}, {async_ref, ARef}]),
        {stop, Error, St}
    end;

handle_info(_Info, #lstate{info=false}=St) ->
    {noreply, St};
handle_info(Info, #lstate{mod=Mod, mod_state=ModState}=St) ->
    try
        case Mod:handle_info(Info, ModState) of
        {noreply, NewModState} ->
            {noreply, St#lstate{mod_state=NewModState}};
        {noreply, NewModState, TimeoutOrHibernate} ->
            {noreply, St#lstate{mod_state=NewModState}, TimeoutOrHibernate};
        {stop, Reason, NewModState} ->
            {stop, Reason, St#lstate{mod_state=NewModState}}
        end
    catch Type:Err:STrace ->
        ?LOG_ERROR(
            [{action, handle_info}, {error, Err}, {module, Mod},
             {Type, Err}, {stack, STrace}]),
        {stop, Err, St}
    end.

terminate(Reason, #lstate{verbose = V, mod=Mod, mod_state=ModState}=St) ->
    info_report(V, 1, [{info, listener_terminating}, {reason, Reason}]),
    sock:close(St#lstate.socket),
    erlang:function_exported(Mod, terminate, 2)
        andalso (catch Mod:terminate(Reason, ModState)).

code_change(OldVsn, #lstate{mod=Mod, mod_state=ModState}=St, Extra) ->
    case erlang:function_exported(Mod, code_change, 2) of
    true ->
        {ok, NewModState} = Mod:code_change(OldVsn, ModState, Extra),
        {ok, St#lstate{mod_state=NewModState}};
    false ->
        {ok, St}
    end.

format_status(Opt, [PDict, #lstate{mod=Mod, lsock=SS, mod_state=MState} = LS]) ->
    case erlang:function_exported(Mod, format_status, 2) of
    true ->
        Mod:format_status(Opt, [PDict, MState]);
    false ->
        Data = lists:map(
            fun
                ({socket, X}) when is_tuple(X) ->
                    {socket, {ssl_socket,SS}}; %% Display non-verbose SSL socket
                (Other) ->
                    Other
            end,
            lists:zip(record_info(fields, lstate), tl(tuple_to_list(LS)))),
        [{data, [{"State", Data}]}]
    end.

%%%----------------------------------------------------------------------------
%%% Internal functions
%%%----------------------------------------------------------------------------

create_acceptor(#lstate{lsock=LSock, verbose=Verbose} = St) ->
    {ok, Ref} = sock:async_accept(LSock),
    info_report(Verbose, 2, [{waiting_for_connection, St#lstate.lsock}]),
    St#lstate{acceptor=Ref}.

info_report(Verbose, Level, Report) when Verbose >= Level ->
    if is_function(Report, 0) ->
        ?LOG_INFO(Report());
    true ->
        ?LOG_INFO(Report)
    end;
info_report(_, _, _Report) ->
    ok.

add_opts(Type, Mod, ModArgs) ->
    Verbose = proplists:get_value(debug, ModArgs, 0),
    [{?TAG, Type, Mod, Verbose} | ModArgs].

filter_ip_address([] = _IP, _OrigIP, _Mask, _Masks) ->
    true;
filter_ip_address(_IP, _OrigIP, [], _) ->
    true;
filter_ip_address([_ | _], _OrigIP, [], _Rest) ->
    true;
filter_ip_address([_ | _], _OrigIP, [0 | _], _) ->
    true;
filter_ip_address([I | T1] =_IP, OrigIP, [I | T2], Rest) ->
    filter_ip_address(T1, OrigIP,   T2,  Rest);
filter_ip_address(_IP, OrigIP, _,  [T2 | Rest]) ->
    filter_ip_address(OrigIP, OrigIP, T2, Rest);
filter_ip_address(_IP, _OrigIP, _, []) ->
    false.

%%%----------------------------------------------------------------------------
%%% Test cases
%%%----------------------------------------------------------------------------

-ifdef(EUNIT).

filter_ip_address_test() ->
    ?assertNot(filter_ip_address({127,1,2,3}, [])),
    ?assert(   filter_ip_address({127,0,0,1}, [[127,0,0,1]])),
    ?assert(   filter_ip_address({127,1,2,3}, [[127]])),
    ?assert(   filter_ip_address({127,1,2,3}, [[127,0,0]])),
    ?assert(   filter_ip_address({127,1,2,3}, [[127,1,2]])),
    ?assert(   filter_ip_address({127,1,2,3}, [[127,1,2,0]])),
    ?assert(   filter_ip_address({127,1,2,3}, [[201], [127]])),
    ?assert(   filter_ip_address({127,1,2,3}, [[]])),
    ?assert(   filter_ip_address({127,1,2,3}, [[], [123]])),
    ?assertNot(filter_ip_address({127,1,2,3}, [[201], [255]])),
    ?assert(   filter_ip_address({127,1,2,3}, [[201,0],[127,1,2]])).

-endif.
