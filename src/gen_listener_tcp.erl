%% @see https://github.com/travelping/gen_listener_tcp/tree/master/src
%% See example: ../examples/echo_server.erl
-module(gen_listener_tcp).
-behaviour(gen_server).

-export([behaviour_info/1]).

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
    code_change/3
]).

-export([sockname/1]).

-record(lstate, {
    verbose = false :: boolean(),
    socket,
    acceptor,
    mod,
    mod_state
}).

behaviour_info(callbacks) -> [
    {init,          1},
    {handle_accept, 2},
    {handle_call,   3},
    {handle_cast,   2},
    {handle_info,   2},
    {terminate,     2},
    {code_change,   3}
].

-define(TAG, '__gen_listener_tcp_mod').

start_link(Name, Module, Args, Options) ->
    gen_server:start_link(Name, ?MODULE, add_mod(Module, Args), Options).

start_link(Module, Args, Options) ->
    gen_server:start_link(?MODULE, add_mod(Module, Args), Options).

start(Name, Module, Args, Options) ->
    gen_server:start(Name, ?MODULE, add_mod(Module, Args), Options).

start(Module, Args, Options) ->
    gen_server:start(?MODULE, add_mod(Module, Args), Options).

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

sockname(ServerRef) ->
    call(ServerRef, {?TAG, sockname}).

% gen_server callbacks

init([{?TAG, Module} | InitArgs]) ->
    process_flag(trap_exit, true),

    case Module:init(InitArgs) of
    {ok, {Port, Options}, ModState} ->
        Verbose = proplists:get_bool(verbose, Options),
        Options0 = proplists:delete(verbose, Options),

        {ok, LSock} = gen_tcp:listen(Port, Options0),

        List = [started_listener, {port, Port}, {lsock, LSock} | Options0],
        info_report(Verbose, List), 

        {ok, create_acceptor(LSock, Module, ModState, Verbose)};
    ignore ->
        ignore;
    {stop, Reason} ->
        {stop, Reason};
    Other ->
        {stop, Other}
    end.


handle_call({?TAG, sockname}, _From, #lstate{socket=Socket}=St) ->
    Reply = inet:sockname(Socket),
    {reply, Reply, St};

handle_call(Request, From, #lstate{mod=Mod, mod_state=ModState}=St) ->
    case Mod:handle_call(Request, From, ModState) of 
    {reply, Reply, NewModState} ->
        {reply, Reply, St#lstate{mod_state=NewModState}};
    {reply, Reply, NewModState, hibernate} ->
        {reply, Reply, St#lstate{mod_state=NewModState}, hibernate};
    {reply, Reply, NewModState, Timeout} ->
        {reply, Reply, St#lstate{mod_state=NewModState}, Timeout};
    {noreply, NewModState} ->
        {noreply, St#lstate{mod_state=NewModState}};
    {noreply, NewModState, hibernate} ->
        {noreply, St#lstate{mod_state=NewModState}, hibernate};
    {noreply, NewModState, Timeout} ->
        {noreply, St#lstate{mod_state=NewModState}, Timeout};
    {stop, Reason, NewModState} ->
        {stop, Reason, St#lstate{mod_state=NewModState}};
    {stop, Reason, Reply, NewModState} ->
        {stop, Reason, Reply, St#lstate{mod_state=NewModState}}
    end.

handle_cast(Request, #lstate{mod=Mod, mod_state=ModState}=St) ->
    case Mod:handle_cast(Request, ModState) of
    {noreply, NewModState} ->
        {noreply, St#lstate{mod_state=NewModState}};
    {noreply, NewModState, hibernate} ->
        {noreply, St#lstate{mod_state=NewModState}, hibernate};
    {noreply, NewModState, Timeout} ->
        {noreply, St#lstate{mod_state=NewModState}, Timeout};
    {stop, Reason, NewModState} ->
        {stop, Reason, St#lstate{mod_state=NewModState}}
    end.


handle_info({inet_async, LSock, ARef, {ok, CSock}},
            #lstate{verbose = V, socket=LSock, acceptor=ARef, mod=Mod, mod_state=ModState}=St) ->
    info_report(V, [new_connection, {csock, CSock}, {lsock, LSock}, {async_ref, ARef}]),
    patch_client_socket(CSock, LSock),

    info_report(V, [handling_accept, {module, Mod}, {module_state, ModState}]),

    try
        case Mod:handle_accept(CSock, ModState) of
        {noreply, NewModState} ->
            {noreply, create_acceptor(St#lstate{mod_state=NewModState})};
        {noreply, NewModState, hibernate} ->
            {noreply, create_acceptor(St#lstate{mod_state=NewModState}), hibernate};
        {noreply, NewModState, Timeout} ->
            {noreply, create_acceptor(St#lstate{mod_state=NewModState}), Timeout};
        {stop, Reason, NewModState} ->
            {stop, Reason, St#lstate{mod_state=NewModState}}
        end
    catch
        Type:Err ->
            error_report(V, [?MODULE, {action, handle_accept}, {type, Type}, {exception, Err}]),
            gen_tcp:close(CSock),
            {noreply, St}
    end;

handle_info({inet_async, LSock, ARef, Error},
            #lstate{verbose = V, socket=LSock, acceptor=ARef}=ListenerState) ->
    error_report(V, [acceptor_error, {reason, Error}, {lsock, LSock}, {async_ref, ARef}]),
    {stop, Error, ListenerState};

handle_info(Info, #lstate{mod=Mod, mod_state=ModState}=St) ->
    case Mod:handle_info(Info, ModState) of
    {noreply, NewModState} ->
        {noreply, St#lstate{mod_state=NewModState}};
    {noreply, NewModState, hibernate} ->
        {noreply, St#lstate{mod_state=NewModState}, hibernate};
    {noreply, NewModState, Timeout} ->
        {noreply, St#lstate{mod_state=NewModState}, Timeout};
    {stop, Reason, NewModState} ->
        {stop, Reason, St#lstate{mod_state=NewModState}}
    end.

terminate(Reason, #lstate{verbose = V, mod=Mod, mod_state=ModState}=St) ->
    info_report(V, [listener_terminating, {reason, Reason}]),
    gen_tcp:close(St#lstate.socket),
    Mod:terminate(Reason, ModState).

code_change(OldVsn, #lstate{mod=Mod, mod_state=ModState}=St, Extra) ->
    {ok, NewModState} = Mod:code_change(OldVsn, ModState, Extra),
    {ok, St#lstate{mod_state=NewModState}}.


% prim_inet imports
patch_client_socket(CSock, LSock) when is_port(CSock), is_port(LSock) ->
    {ok, Mod}  = inet_db:lookup_socket(LSock),
    true       = inet_db:register_socket(CSock, Mod),
    LOpts      = [active, nodelay, keepalive, delay_send, priority, tos],
    {ok, Opts} = prim_inet:getopts(LSock, LOpts),
    ok         = prim_inet:setopts(CSock, Opts).

create_acceptor(St) when is_record(St, lstate) ->
    create_acceptor(St#lstate.socket, St#lstate.mod, St#lstate.mod_state, St#lstate.verbose).

create_acceptor(LSock, Mod, ModState, Verbose) when is_port(LSock) ->
    {ok, Ref} = prim_inet:async_accept(LSock, -1), 

    info_report(Verbose, waiting_for_connection),
    #lstate{verbose = Verbose, socket=LSock, acceptor=Ref, mod=Mod, mod_state=ModState}.

info_report(_Verbose = false, _Report) ->
	ok;
info_report(Verbose, Report) when Verbose == true; Verbose == info ->
	error_logger:info_report(Report).

error_report(_Verbose = false, _Report) ->
	ok;
error_report(Verbose, Report) when Verbose == true; Verbose == error ->
	error_logger:error_report(Report).

add_mod(Mod, Args) ->
    [{?TAG, Mod} | Args].
