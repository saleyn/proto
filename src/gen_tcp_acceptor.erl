%%%-------------------------------------------------------------------
%%% @author Serge Aleynikov <saleyn@gmail.com>
%%% @copyright (c) 2014 Serge Aleynikov
%%% @doc Generic TCP socket acceptor.
%%% @see [http://www.trapexit.org/index.php/Building_a_Non-blocking_TCP_server_using_OTP_principles]
%%% @see [https://github.com/essiene/jsonevents/blob/master/src/gen_listener_tcp.erl]
%%%-------------------------------------------------------------------
%%% Created: 2015-05-10
%%%-------------------------------------------------------------------
-module(gen_tcp_acceptor).
-behaviour(gen_server).

-export([
    start/3,
    start/4,
    start_link/3,
    start_link/4,
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

-export([sockname/1]).

-record(lstate, {
    verbose = 0::integer(),
    socket,
    acceptor,
    mod,
    mod_state,
    call,
    cast,
    info
}).

-define(TAG, '$gen_tcp_acceptor_mod').

%%%-------------------------------------------------------------------
%%% Interface API
%%%-------------------------------------------------------------------

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
-callback handle_call(Request::term(), From::{pid(), Tag::term()},
    State::term()) ->
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

-optional_callbacks([
    handle_accept_error/2, hangle_call/3, handle_cast/2, handle_info/2,
    terminate/2, code_change/3, format_status/2]).

%%%-------------------------------------------------------------------
%%% API
%%%-------------------------------------------------------------------

start_link(Name, Mod, Args, Options) ->
    gen_server:start_link(Name, ?MODULE, add_mod(Mod, Args), Options).

start_link(Mod, Args, Options) ->
    gen_server:start_link(?MODULE, add_mod(Mod, Args), Options).

start(Name, Mod, Args, Options) ->
    gen_server:start(Name, ?MODULE, add_mod(Mod, Args), Options).

start(Mod, Args, Options) ->
    gen_server:start(?MODULE, add_mod(Mod, Args), Options).

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

%%--------------------------------------------------------------------
%% gen_server callbacks
%%--------------------------------------------------------------------

init([{?TAG, Mod} | InitArgs]) ->
    process_flag(priority, max),
    %process_flag(trap_exit, true),
    try
        case Mod:init(InitArgs) of
        {ok, {Port, Options}, ModState} ->
            Verbose  = proplists:get_value(verbose, Options, 0),
            Options0 = proplists:delete(verbose, Options),

            {ok, LSock}    = gen_tcp:listen(Port, Options0),
            {ok, {Addr,_}} = inet:sockname(LSock),
            List = [started_listener, {addr, Addr}, {port, Port},
                   {lsock, LSock} | Options0],
            info_report(Verbose, 1, List), 

            Call  = erlang:function_exported(Mod, handle_call, 3),
            Cast  = erlang:function_exported(Mod, handle_cast, 2),
            Info  = erlang:function_exported(Mod, handle_info, 2),
            
            State = #lstate{
                verbose=Verbose, socket=LSock,
                mod=Mod, mod_state=ModState,
                call=Call, cast=Cast, info=Info
            },
            {ok, create_acceptor(State)};
        ignore ->
            ignore;
        {stop, Reason} ->
            {stop, Reason};
        Other ->
            {stop, Other}
        end
    catch _:Err ->
        {stop, {Err, erlang:get_stacktrace()}}
    end.

handle_call({?TAG, sockname}, _From, #lstate{socket=Socket}=State) ->
    Reply = inet:sockname(Socket),
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
    catch Type:Err ->
        error_report(St#lstate.verbose, 1,
            [?MODULE, {action, handle_call}, {error, Err}, {module, Mod},
                      {Type, Err}, {stack, erlang:get_stacktrace()}]),
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
    catch Type:Err ->
        error_report(St#lstate.verbose, 1,
            [?MODULE, {action, handle_cast}, {error, Err}, {module, Mod},
                      {Type, Err}, {stack, erlang:get_stacktrace()}]),
        {stop, Err, St}
    end.

handle_info({inet_async, LSock, ARef, {ok, CSock}},
            #lstate{socket=LSock, acceptor=ARef, mod=Mod, mod_state=ModState}=St) ->
    info_report(St#lstate.verbose, 2,
        [new_connection, {csock, CSock}, {lsock, LSock}, {async_ref, ARef},
                         {module, Mod},  {module_state, ModState}]),
    register_client_socket(CSock, LSock),

    try
        case Mod:handle_accept(CSock, ModState) of
        {noreply, NewModState} ->
            {noreply, create_acceptor(St#lstate{mod_state=NewModState})};
        {noreply, NewModState, TimeoutOrHibernate} ->
            {noreply, create_acceptor(St#lstate{mod_state=NewModState}), TimeoutOrHibernate};
        {stop, Reason, NewModState} ->
            {stop, Reason, St#lstate{mod_state=NewModState}}
        end
    catch Type:Err ->
        error_report(St#lstate.verbose, 0,
            [?MODULE, {action, handle_accept}, {Type, Err},
                      {stack, erlang:get_stacktrace()}]),
        gen_tcp:close(CSock),
        {noreply, St}
    end;

handle_info({inet_async, LS, ARef, Error},
            #lstate{verbose=V, socket=LS, acceptor=ARef, mod=Mod, mod_state=MState}=LState) ->
    case erlang:function_exported(Mod, handle_accept_error, 2) of
    true ->
        try
            case Mod:handle_accept_error(Error, MState) of
            {noreply, NewMState} ->
                {noreply, create_acceptor(LState#lstate{mod_state=NewMState})};
            {noreply, NewMState, hibernate} ->
                {noreply, create_acceptor(LState#lstate{mod_state=NewMState}), hibernate};
            {noreply, NewMState, Timeout} ->
                {noreply, create_acceptor(LState#lstate{mod_state=NewMState}), Timeout};
            {stop, Reason, NewMState} ->
                {stop, Reason, LState#lstate{mod_state=NewMState}}
            end
        catch Type:Err ->
            error_report(V, 0,
                [?MODULE, {action, handle_accept_error}, {error, Error}, {module, Mod},
                          {Type, Err}, {stack, erlang:get_stacktrace()}]),
            {stop, Error, LState}
        end;
    false ->
        error_report(V, 0,
            [accept_error, {reason, Error}, {lsock, LS}, {async_ref, ARef}]),
        {stop, Error, LState}
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
    catch Type:Err ->
        error_report(St#lstate.verbose, 1,
            [?MODULE, {action, handle_info}, {error, Err}, {module, Mod},
                      {Type, Err}, {stack, erlang:get_stacktrace()}]),
        {stop, Err, St}
    end.

terminate(Reason, #lstate{verbose = V, mod=Mod, mod_state=ModState}=St) ->
    info_report(V, 1, [listener_terminating, {reason, Reason}]),
    gen_tcp:close(St#lstate.socket),
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

format_status(Opt, [PDict, #lstate{mod=Mod, mod_state=MState} = LS]) ->
    case erlang:function_exported(Mod, format_status, 2) of
    true ->
        Mod:format_status(Opt, [PDict, MState]);
    false when Opt =:= terminate ->
        LS;
    false ->
        Data = lists:zip(record_info(fields, lstate), tl(tuple_to_list(LS))),
        [{data, [{"State", Data}]}]
    end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

% prim_inet imports
register_client_socket(CSock, LSock) when is_port(CSock), is_port(LSock) ->
    {ok, Mod}  = inet_db:lookup_socket(LSock),
    true       = inet_db:register_socket(CSock, Mod),
    LOpts      = [active, nodelay, keepalive, delay_send, priority, tos],
    {ok, Opts} = prim_inet:getopts(LSock, LOpts),
    ok         = prim_inet:setopts(CSock, Opts).

create_acceptor(#lstate{socket=LSock, verbose=Verbose} = St) ->
    {ok, Ref} = prim_inet:async_accept(LSock, -1), 
    info_report(Verbose, 2, [waiting_for_connection]),
    St#lstate{acceptor=Ref}.

info_report(Verbose, Level, Report) when Verbose >= Level ->
    error_logger:info_report(Report);
info_report(_, _, _Report) ->
    ok.

error_report(Verbose, Level, Report) when Verbose >= Level ->
    error_logger:error_report(Report);
error_report(_, _, _Report) ->
    ok.

add_mod(Mod, Args) ->
    [{?TAG, Mod} | Args].
