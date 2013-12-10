%%%-------------------------------------------------------------------
%%% @author Serge Aleynikov <saleyn@gmail.com>
%%% @copyright (c) 2008, Essien Ita Essien
%%% @doc Generic socket connection listener behavior
%%% @see https://github.com/essiene/jsonevents/blob/master/src/gen_listener_tcp.erl
%%% @end
%%% Created: 2013-12-10 Serge Aleynikov
%%%-------------------------------------------------------------------
-module(gen_tcp_listener).
-behaviour(gen_server).

-compile({inline, [
     start/3,       start/4,
     start_link/3,  start_link/4,
     call/2,        call/3,
     multicall/2,   multicall/3,     multicall/4,
     cast/2,        cast/3,
     abcast/2,      abcast/3,
     reply/2
]}).

-export([behaviour_info/1]).

-export([
     start/3,       start/4,
     start_link/3,  start_link/4,
     call/2,        call/3,
     multicall/2,   multicall/3,     multicall/4,
     cast/2,        cast/3,
     abcast/2,      abcast/3,
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

-record(state, {
    name,
    socket,
    acceptor,
    mod,
    mod_state
}).


behaviour_info(callbacks) ->
    [
     {init,         1},
     {handle_accept,2},
     {handle_call,  3},
     {handle_cast,  2},
     {handle_info,  2},
     {terminate,    2},
     {code_change,  3}
    ].

start_link(Name, Mod, InitArgs, Options) ->
    gen_server:start_link(Name, ?MODULE, [{'$gen_tcp_listener', Mod} | InitArgs], Options).

start_link(Mod, InitArgs, Options) ->
    gen_server:start_link(?MODULE, [{'$gen_tcp_listener', Mod} | InitArgs], Options).

start(Name, Mod, InitArgs, Options) ->
    gen_server:start(Name, ?MODULE, [{'$gen_tcp_listener', Mod} | InitArgs], Options).

start(Mod, InitArgs, Options) ->
    gen_server:start(?MODULE, [{'$gen_tcp_listener', Mod} | InitArgs], Options).

call(ServerRef, Request) ->
    gen_server:call(ServerRef, Request).

call(ServerRef, Request, Timeout) ->
    gen_server:call(ServerRef, Request, Timeout).

multicall(Name, Request) ->
    gen_server:multicall(Name, Request).

multicall(Nodes, Name, Request) ->
    gen_server:multicall(Nodes, Name, Request).

multicall(Nodes, Name, Request, Timeout) ->
    gen_server:multicall(Nodes, Name, Request, Timeout).

cast(ServerRef, Request) ->
    gen_server:cast(ServerRef, Request).

cast(ServerRef, Request, Timeout) ->
    gen_server:cast(ServerRef, Request, Timeout).

abcast(Name, Request) ->
    gen_server:abcast(Name, Request).

abcast(Nodes, Name, Request) ->
    gen_server:abcast(Nodes, Name, Request).

reply(Client, Reply) ->
    gen_server:reply(Client, Reply).

% gen_server callbacks

init([{'$gen_tcp_listener', Mod} | InitArgs]) ->
    process_flag(trap_exit, true),

    case Mod:init(InitArgs) of
        {ok, {Port, SockOpts}, ModState} ->
            {ok, ListenSocket} = gen_tcp:listen(Port, SockOpts),

            error_logger:info_report([
                listener_started, {port, Port} | SockOpts]), 

            {ok, create_acceptor(ListenSocket, Mod, ModState)};
        ignore          -> ignore;
        {stop, Reason}  -> {stop, Reason};
        Other           -> {stop, Other}
    end.


handle_call(Request, From, #state{mod=Mod, mod_state=ModState}=St) ->
    case Mod:handle_call(Request, From, ModState) of 
        {reply, Reply, NewModState} ->
            {reply, Reply, St#state{mod_state=NewModState}};
        {reply, Reply, NewModState, hibernate} ->
            {reply, Reply, St#state{mod_state=NewModState}, hibernate};
        {reply, Reply, NewModState, Timeout} ->
            {reply, Reply, St#state{mod_state=NewModState}, Timeout};
        {noreply, NewModState} ->
            {noreply, St#state{mod_state=NewModState}};
        {noreply, NewModState, hibernate} ->
            {noreply, St#state{mod_state=NewModState}, hibernate};
        {noreply, NewModState, Timeout} ->
            {noreply, St#state{mod_state=NewModState}, Timeout};
        {stop, Reason, NewModState} ->
            {stop, Reason, St#state{mod_state=NewModState}};
        {stop, Reason, Reply, NewModState} ->
            {stop, Reason, Reply, St#state{mod_state=NewModState}}
    end.

handle_cast(Request, #state{mod=Mod, mod_state=ModState}=St) ->
    case Mod:handle_cast(Request, ModState) of
        {noreply, NewModState} ->
            {noreply, St#state{mod_state=NewModState}};
        {noreply, NewModState, hibernate} ->
            {noreply, St#state{mod_state=NewModState}, hibernate};
        {noreply, NewModState, Timeout} ->
            {noreply, St#state{mod_state=NewModState}, Timeout};
        {stop, Reason, NewModState} ->
            {stop, Reason, St#state{mod_state=NewModState}}
    end.


handle_info({inet_async, LSock, ARef, {ok, ClientSock}},
            #state{socket=LSock, acceptor=ARef, mod=Mod, mod_state=ModState}=St) ->
    %error_logger:info_report(
    %    [new_connection, {csock,ClientSock}, {lsock,LSock}, {async_ref,ARef}]),
    patch_client_socket(ClientSock, LSock),

    %error_logger:info_report([handling_accept, {module, Mod}, {module_state, ModState}]),

    try
        case Mod:handle_accept(ClientSock, ModState) of
            {noreply, NewModState} ->
                {noreply, create_acceptor(St#state{mod_state=NewModState})};
            {noreply, NewModState, hibernate} ->
                {noreply, create_acceptor(St#state{mod_state=NewModState}), hibernate};
            {noreply, NewModState, Timeout} ->
                {noreply, create_acceptor(St#state{mod_state=NewModState}), Timeout};
            {stop, Reason, NewModState} ->
                {stop, Reason, create_acceptor(St#state{mod_state=NewModState})}
        end
    catch
        Type:Exception ->
            error_logger:error_report(
                [?MODULE, {action, handle_accept}, {type, Type}, {exception, Exception}]),
            gen_tcp:close(ClientSock),
            {noreply, St}
    end;

handle_info({inet_async, LSock, ARef, Error}, #state{socket=LSock, acceptor=ARef}=St) ->
    error_logger:error_report(
        [acceptor_error, {reason, Error}, {lsock, LSock}, {async_ref, ARef}]),
    {stop, Error, St};

handle_info(Info, #state{mod=Mod, mod_state=ModState}=St) ->
    case Mod:handle_info(Info, ModState) of
        {noreply, NewModState} ->
            {noreply, St#state{mod_state=NewModState}};
        {noreply, NewModState, hibernate} ->
            {noreply, St#state{mod_state=NewModState}, hibernate};
        {noreply, NewModState, Timeout} ->
            {noreply, St#state{mod_state=NewModState}, Timeout};
        {stop, Reason, NewModState} ->
            {stop, Reason, St#state{mod_state=NewModState}}
    end.

terminate(Reason, #state{mod=Mod, mod_state=ModState}=St) ->
    gen_tcp:close(St#state.socket),
    Mod:terminate(Reason, ModState).

code_change(OldVsn, #state{mod=Mod, mod_state=ModState}=St, Extra) ->
    {ok, NewModState} = Mod:code_change(OldVsn, ModState, Extra),
    {ok, St#state{mod_state=NewModState}}.


% prim_inet imports
patch_client_socket(CSock, LSock) when is_port(CSock), is_port(LSock) ->
    {ok, Mod}   = inet_db:lookup_socket(LSock),
    true        = inet_db:register_socket(CSock, Mod),
    {ok, Opts}  = prim_inet:getopts(LSock, [active,nodelay,keepalive,delay_send,priority,tos]),
    ok          = prim_inet:setopts(CSock, Opts).

create_acceptor(#state{} = St) ->
    create_acceptor(St#state.socket, St#state.mod, St#state.mod_state).

create_acceptor(ListenSocket, Mod, ModState) when is_port(ListenSocket) ->
    {ok, Ref} = prim_inet:async_accept(ListenSocket, -1), 
    #state{socket=ListenSocket, acceptor=Ref, mod=Mod, mod_state=ModState}.

