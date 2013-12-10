%% Implements a simple Echo server using the gen_listener_tcp behaviour.

-module(echo_server).
-behaviour(gen_listener_tcp).

-define(TCP_PORT, 9999).

%% API
-export([start/0]).

%% gen_listener_tcp callbacks
-export([init/1,
         handle_accept/2,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%% @doc Start the server.
start() ->
    gen_tcp_listener:start({local, ?MODULE}, ?MODULE, [], []).

%% @doc The echo client process.
echo_client(Socket) ->
    error_logger:info_msg("echo_client started\n"),
    ok = inet:setopts(Socket, [{active, once}]),
    receive
        {tcp, Socket, <<"quit", _R/binary>>} ->
            error_logger:info_msg("Quitting...\n"),
            gen_tcp:send(Socket, "Bye now.\r\n"),
            gen_tcp:close(Socket);
        {tcp, Socket, Data} ->
            error_logger:info_msg("Got Data: ~p\n", [Data]),
            gen_tcp:send(Socket, [<<"Received ">>, Data]),
            echo_client(Socket);
        {tcp_closed, Socket} ->
            error_logger:info_msg("Client disconnected\n")
    end.

init([]) ->
    Opts = [binary, inet, {active,false}, {backlog,10}, {nodelay,true},
            {packet,raw}, {reuseaddr,true}],
    {ok, {?TCP_PORT, Opts}, State = undefined}.

handle_accept(Sock, State) ->
    Pid = spawn(fun() -> echo_client(Sock) end),
    gen_tcp:controlling_process(Sock, Pid),
    {noreply, State}.

handle_call(Request, _From, State) ->
    {stop, {unhandled_call, Request}, State}.

handle_cast(_Request, State) ->
    {stop, {unhandled_cast, Request}, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
