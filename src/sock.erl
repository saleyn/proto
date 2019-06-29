%%% Author: Serge Aleynikov <saleyn@gmail.com>
%%% Change: 2015-05-14
%%%             * Added setting passive mode when upgrading server's
%%%               tcp to ssl socket.
%%%             * Added support for {active, N} mode
%%%             * Changed internal representation of default options
%%%             * Fixed race conditions in several socket tests

%%% Copyright 2009 Jack Danger Canty <code@jackcanty.com>. All rights reserved.
%%%
%%% Permission is hereby granted, free of charge, to any person obtaining
%%% a copy of this software and associated documentation files (the
%%% "Software"), to deal in the Software without restriction, including
%%% without limitation the rights to use, copy, modify, merge, publish,
%%% distribute, sublicense, and/or sell copies of the Software, and to
%%% permit persons to whom the Software is furnished to do so, subject to
%%% the following conditions:
%%%
%%% The above copyright notice and this permission notice shall be
%%% included in all copies or substantial portions of the Software.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
%%% EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
%%% MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
%%% NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
%%% LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
%%% OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
%%% WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

%% @doc Facilitates transparent gen_tcp/ssl socket handling
-module(sock).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% API
-export([connect/3, connect/4, connect/5]).
-export([listen/2, listen/3, accept/1, accept/2]).
-export([send/2, recv/2, recv/3]).
-export([controlling_process/2]).
-export([sockname/1, peername/1]).
-export([setopts/2, format_error/2]).
-export([close/1, shutdown/2]).
-export([active/2]).
-export([async_accept/1]).
-export([handle_async_accept/1, handle_async_accept/2]).
-export([extract_port_from_socket/1]).
-export([to_ssl_server/1,to_ssl_server/2,to_ssl_server/3]).
-export([to_ssl_client/1,to_ssl_client/2,to_ssl_client/3]).
-export([type/1]).

%%%-----------------------------------------------------------------
%%% API
%%%-----------------------------------------------------------------
connect(Protocol, Address, Port) ->
    connect(Protocol, Address, Port, [], infinity).
connect(Protocol, Address, Port, Opts) ->
    connect(Protocol, Address, Port, Opts, infinity).
connect(tcp, Address, Port, Opts, Time) ->
    gen_tcp:connect(Address, Port, tcp_connect_options(Opts), Time);
connect(ssl, Address, Port, Opts, Time) ->
    ssl:connect(Address, Port, ssl_connect_options(Opts), Time).

listen(Protocol, Port) ->
    listen(Protocol, Port, []).
listen(ssl, Port, Options) ->
    ssl:listen(Port, ssl_listen_options(Options));
listen(tcp, Port, Options) ->
    gen_tcp:listen(Port, tcp_listen_options(Options)).

accept(Socket) ->
    accept(Socket, infinity).
accept(Socket, Timeout) when is_port(Socket) ->
    case gen_tcp:accept(Socket, Timeout) of
        {ok, NewSocket} ->
            {ok, Opts} = inet:getopts(Socket, [active,keepalive,packet,reuseaddr]),
            inet:setopts(NewSocket, Opts),
            {ok, NewSocket};
        Error ->
            Error
    end;
accept(Socket, Timeout) ->
    case ssl:transport_accept(Socket, Timeout) of
        {ok, NewSocket} ->
            case ssl:handshake(NewSocket) of
                {ok, _} ->
                    {ok, NewSocket};
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

send(Socket, Data) when is_port(Socket) ->
    gen_tcp:send(Socket, Data);
send(Socket, Data) ->
    ssl:send(Socket, Data).

recv(Socket, Length) ->
    recv(Socket, Length, infinity).
recv(Socket, Length, Timeout) when is_port(Socket) ->
    gen_tcp:recv(Socket, Length, Timeout);
recv(Socket, Data, Timeout) ->
    ssl:recv(Socket, Data, Timeout).

controlling_process(Socket, NewOwner) when is_port(Socket) ->
    gen_tcp:controlling_process(Socket, NewOwner);
controlling_process(Socket, NewOwner) ->
    ssl:controlling_process(Socket, NewOwner).

peername(Socket) when is_port(Socket) ->
    inet:peername(Socket);
peername(Socket) ->
    ssl:peername(Socket).

sockname(Socket) when is_port(Socket) ->
    inet:sockname(Socket);
sockname(Socket) ->
    ssl:sockname(Socket).

close(Socket) when is_port(Socket) ->
    gen_tcp:close(Socket);
close(Socket) ->
    ssl:close(Socket).

shutdown(Socket, How) when is_port(Socket) ->
    gen_tcp:shutdown(Socket, How);
shutdown(Socket, How) ->
    ssl:shutdown(Socket, How).

setopts(Socket, Opts) when is_port(Socket) ->
    inet:setopts(Socket, Opts);
setopts(Socket, Opts) ->
    ssl:setopts(Socket, Opts).

active(Socket, Mode) when is_port(Socket) andalso (Mode =:= once orelse is_integer(Mode))  ->
    inet:setopts(Socket, [{active, Mode}]);
active(Socket, Mode) when (Mode =:= once orelse is_integer(Mode))  ->
    ssl:setopts(Socket, [{active, Mode}]).

format_error(Socket, Error) when is_port(Socket) ->
    inet:format_error(Error);
format_error(_Socket, Error) ->
    ssl:format_error(Error).

%% @doc {inet_async,...} will be sent to current process when a client connects
async_accept(Socket) when is_port(Socket) ->
    prim_inet:async_accept(Socket, -1);
async_accept(Socket) ->
    Port = extract_port_from_socket(Socket),
    async_accept(Port).

%% @doc handle the {inet_async,...} message
handle_async_accept({inet_async, ListenSocket, _, {ok,ClientSocket}}) ->
    handle_async_accept(ListenSocket, ClientSocket).
handle_async_accept(ListenObject, ClientSocket) ->
    ListenSocket = extract_port_from_socket(ListenObject),
    case set_sockopt(ListenSocket, ClientSocket) of
        ok -> ok;
        Error -> erlang:error(set_sockopt, Error)
    end,
    %% If the listening socket is SSL then negotiate the client socket
    case is_port(ListenObject) of
        true ->
            {ok, ClientSocket};
        false ->
            {ok, UpgradedClientSocket} = to_ssl_server(ClientSocket),
            {ok, UpgradedClientSocket}
    end.

%% @doc Upgrade a TCP connection to SSL
to_ssl_server(Socket) ->
    to_ssl_server(Socket, []).
to_ssl_server(Socket, Options) ->
    to_ssl_server(Socket, Options, infinity).
to_ssl_server(Socket, Options, Timeout) when is_port(Socket) ->
    % Make sure active is set to false before trying to upgrade a connection to an ssl
    % connection, otherwhise ssl handshake messages may be deliverd to the wrong process.
    {ok, [{_, Active}]} = inet:getopts(Socket, [active]),
    if Active -> inet:setopts(Socket, [{active, false}]);
       true   -> ok
    end,
    Res = ssl:handshake(Socket, ssl_listen_options(Options), Timeout),
    if Active -> inet:setopts(Socket, [{active, true}]);
       true   -> ok
    end,
    Res;
to_ssl_server(_Socket, _Options, _Timeout) ->
    erlang:error(ssl_connected, "Socket is already using SSL").
to_ssl_client(Socket) ->
    to_ssl_client(Socket, []).
to_ssl_client(Socket, Options) ->
    to_ssl_client(Socket, Options, infinity).
to_ssl_client(Socket, Options, Timeout) when is_port(Socket) ->
    ssl:connect(Socket, ssl_connect_options(Options), Timeout);
to_ssl_client(_Socket, _Options, _Timeout) ->
    erlang:error(ssl_connected, "Socket is already using SSL").

type(Socket) when is_port(Socket) ->
    tcp;
type(_Socket) ->
    ssl.

%%%-----------------------------------------------------------------
%%% Internal functions (OS_Mon configuration)
%%%-----------------------------------------------------------------
-define(FULLNAME(F),
    filename:join(filename:dirname(filename:dirname(code:which(?MODULE))), F)).

def_tcp_listen_opts() ->
    #{active    => false,
      backlog   => 30,
      keepalive => true,
      packet    => line,
      reuseaddr => true}.

def_tcp_conn_opts() ->
    #{active    => false,
      packet    => line}.
      
def_ssl_listen_opts() ->
    (def_tcp_listen_opts())#{certfile  => ?FULLNAME("certs/server/cert.pem"),
                             depth     => 0,
                             keyfile   => ?FULLNAME("certs/server/key.pem"),
                             reuse_sessions => false,
                             ssl_imp   => new}.
def_ssl_conn_opts() ->
    (def_tcp_conn_opts())#{  certfile  => ?FULLNAME("certs/client/cert.pem"),
                             depth     => 0,
                             keyfile   => ?FULLNAME("certs/client/key.pem"),
                             ssl_imp   => new}.


tcp_listen_options([Format|Options]) when Format =:= list; Format =:= binary ->
    tcp_listen_options(Options, Format);
tcp_listen_options(Options) ->
    tcp_listen_options(Options, list).
tcp_listen_options(Options, Format) ->
    proplist_merge([Format|Options], def_tcp_listen_opts()).

ssl_listen_options([Format|Options]) when Format =:= list; Format =:= binary ->
    ssl_listen_options(Options, Format);
ssl_listen_options(Options) ->
    ssl_listen_options(Options, list).
ssl_listen_options(Options, Format) ->
    proplist_merge([Format|Options], def_ssl_listen_opts()).

tcp_connect_options([Format|Options]) when Format =:= list; Format =:= binary ->
    tcp_connect_options(Options, Format);
tcp_connect_options(Options) ->
    tcp_connect_options(Options, list).
tcp_connect_options(Options, Format) ->
    proplist_merge([Format|Options], def_tcp_conn_opts()).

ssl_connect_options([Format|Options]) when Format =:= list; Format =:= binary ->
    ssl_connect_options(Options, Format);
ssl_connect_options(Options) ->
    ssl_connect_options(Options, list).
ssl_connect_options(Options, Format) ->
    proplist_merge([Format|Options], def_ssl_conn_opts()).

proplist_merge([], Map) ->
    lists:foldl(
        fun
            ({I, true}, Acc) when I=:=list; I=:=binary -> [I | Acc];
            ({I,false}, Acc) when I=:=list; I=:=binary -> Acc;
            (T,         Acc)                           -> [T | Acc]
        end,
        [],
        maps:to_list(Map));
proplist_merge([{Opt, Value} | T], Map) ->
    proplist_merge(T, maps:put(Opt, Value, Map));
proplist_merge([Opt | T], Map) when is_atom(Opt) ->
    proplist_merge(T, maps:put(Opt, true, Map)).

extract_port_from_socket({sslsocket,_,{SSLPort,_}}) ->
    SSLPort;
extract_port_from_socket(Socket) ->
    Socket.

-spec(set_sockopt(ListSock :: port(), CliSocket :: port()) -> 'ok' | any()).
set_sockopt(ListenObject, ClientSocket) ->
    ListenSocket = extract_port_from_socket(ListenObject),
    true = inet_db:register_socket(ClientSocket, inet_tcp),
    case prim_inet:getopts(ListenSocket, [active, nodelay, keepalive, delay_send, priority, tos]) of
        {ok, Opts} ->
            case prim_inet:setopts(ClientSocket, Opts) of
                ok -> ok;
                Error -> sock:close(ClientSocket), Error
            end;
        Error -> sock:close(ClientSocket), Error
    end.

-ifdef(EUNIT).
-define(TEST_PORT, 7586).

connect_test_() ->
    [
        {"listen and connect via tcp",
        fun() ->
            Self = self(),
            spawn(fun() ->
                        {ok, ListenSocket} = listen(tcp, ?TEST_PORT),
                        ?assert(is_port(ListenSocket)),
                        {ok, ServerSocket} = accept(ListenSocket),
                        controlling_process(ServerSocket, Self),
                        Self ! ListenSocket
                end),
            {ok, ClientSocket} = connect(tcp, "localhost", ?TEST_PORT),
            receive ListenSocket when is_port(ListenSocket) -> ok end,
            ?assert(is_port(ClientSocket)),
            close(ListenSocket)
        end
        },
        {"listen and connect via ssl",
        fun() ->
            Self = self(),
            application:ensure_all_started(ssl),
            spawn(fun() ->
                        {ok, ListenSocket} = listen(ssl, ?TEST_PORT),
                        ?assertMatch([sslsocket|_], tuple_to_list(ListenSocket)),
                        {ok, ServerSocket} = accept(ListenSocket),
                        controlling_process(ServerSocket, Self),
                        Self ! ListenSocket
                end),
            {ok, ClientSocket} = connect(ssl, "localhost", ?TEST_PORT,  []),
            receive {sslsocket,_,_} = ListenSocket -> ok end,
            ?assertMatch([sslsocket|_], tuple_to_list(ClientSocket)),
            close(ListenSocket)
        end
        }
    ].

evented_connections_test_() ->
    [
        {"current process receives connection to TCP listen sockets",
        fun() ->
            {ok, ListenSocket} = listen(tcp, ?TEST_PORT),
            async_accept(ListenSocket),
            spawn(fun()-> connect(tcp, "localhost", ?TEST_PORT) end),
            receive
                {inet_async, ListenSocket, _, {ok,ServerSocket}} -> ok
            end,
            {ok, NewServerSocket} = handle_async_accept(ListenSocket, ServerSocket),
            ?assert(is_port(ServerSocket)),
            ?assertEqual(ServerSocket, NewServerSocket), %% only true for TCP
            ?assert(is_port(ListenSocket)),
            async_accept(ListenSocket),
            % Stop the async
            spawn(fun()-> connect(tcp, "localhost", ?TEST_PORT) end),
            receive _Ignored -> ok end,
            close(NewServerSocket),
            close(ListenSocket)
        end
        },
        {"current process receives connection to SSL listen sockets",
        fun() ->
            application:ensure_all_started(ssl),
            {ok, ListenSocket} = listen(ssl, ?TEST_PORT),
            async_accept(ListenSocket),
            spawn(fun()-> connect(ssl, "localhost", ?TEST_PORT) end),
            receive
                {inet_async, _ListenPort, _, {ok,ServerSocket}} -> ok
            end,
            {ok, NewServerSocket} = handle_async_accept(ListenSocket, ServerSocket),
            ?assert(is_port(ServerSocket)),
            ?assertMatch([sslsocket|_], tuple_to_list(NewServerSocket)),
            ?assertMatch([sslsocket|_], tuple_to_list(ListenSocket)),
            async_accept(ListenSocket),
            % Stop the async
            spawn(fun()-> connect(ssl, "localhost", ?TEST_PORT) end),
            receive _Ignored -> ok end,
            close(ListenSocket),
            close(NewServerSocket)
        end
        },
        %% TODO: figure out if the following passes because
        %% of an incomplete test case or if this really is
        %% a magical feature where a single listener
        %% can respond to either ssl or tcp connections.
        {"current TCP listener receives SSL connection",
        fun() ->
            application:ensure_all_started(ssl),
            {ok, ListenSocket} = listen(tcp, ?TEST_PORT),
            async_accept(ListenSocket),
            spawn(fun()-> connect(ssl, "localhost", ?TEST_PORT) end),
            receive
                {inet_async, _ListenPort, _, {ok,ServerSocket}} -> ok
            end,
            {ok, ServerSocket} = handle_async_accept(ListenSocket, ServerSocket),
            ?assert(is_port(ListenSocket)),
            ?assert(is_port(ServerSocket)),
            {ok, NewServerSocket} = to_ssl_server(ServerSocket),
            ?assertMatch([sslsocket|_], tuple_to_list(NewServerSocket)),
            % Stop the async
            spawn(fun()-> connect(ssl, "localhost", ?TEST_PORT) end),
            receive _Ignored -> ok end,
            close(ListenSocket),
            close(NewServerSocket)
        end
        }
    ].

accept_test_() ->
    [
        {"Accept via tcp",
        fun() ->
            {ok, ListenSocket} = listen(tcp, ?TEST_PORT, tcp_listen_options([])),
            ?assert(is_port(ListenSocket)),
            spawn(fun()-> connect(ssl, "localhost", ?TEST_PORT, tcp_connect_options([])) end),
            {ok, ServerSocket} = accept(ListenSocket),
            ?assert(is_port(ListenSocket)),
            close(ServerSocket),
            close(ListenSocket)
        end
        },
        {"Accept via ssl",
        fun() ->
            application:ensure_all_started(ssl),
            {ok, ListenSocket} = listen(ssl, ?TEST_PORT),
            ?assertMatch([sslsocket|_], tuple_to_list(ListenSocket)),
            spawn(fun()->connect(ssl, "localhost", ?TEST_PORT) end),
            accept(ListenSocket),
            close(ListenSocket)
        end
        }
    ].

type_test_() ->
    [
        {"a tcp socket returns 'tcp'",
        fun() ->
            {ok, ListenSocket} = listen(tcp, ?TEST_PORT),
            ?assertMatch(tcp, type(ListenSocket)),
            close(ListenSocket)
        end
        },
        {"an ssl socket returns 'ssl'",
        fun() ->
            application:ensure_all_started(ssl),
            {ok, ListenSocket} = listen(ssl, ?TEST_PORT),
            ?assertMatch(ssl, type(ListenSocket)),
            close(ListenSocket)
        end
        }
    ].

active_once_test_() ->
    [
        {"socket is set to active:once on tcp",
        fun() ->
            {ok, ListenSocket} = listen(tcp, ?TEST_PORT, tcp_listen_options([])),
            ?assertEqual({ok, [{active,false}]}, inet:getopts(ListenSocket, [active])),
            active(ListenSocket, once),
            ?assertEqual({ok, [{active,once}]}, inet:getopts(ListenSocket, [active])),
            close(ListenSocket)
        end
        },
        {"socket is set to active:once on ssl",
        fun() ->
            {ok, ListenSocket} = listen(ssl, ?TEST_PORT, ssl_listen_options([])),
            ?assertEqual({ok, [{active,false}]}, ssl:getopts(ListenSocket, [active])),
            active(ListenSocket, once),
            ?assertEqual({ok, [{active,once}]}, ssl:getopts(ListenSocket, [active])),
            close(ListenSocket)
        end
        }
    ].

option_test_() ->
    [
        {"options properly merge",
        fun() ->
            ?assertEqual([{a,1},{b,true},{c,5},{d,2}], proplist_merge([{a,1},b,{c,5}], #{a=>3,d=>2}))
        end
        }
%       {"tcp_listen_options has defaults",
%       fun() ->
%           ?assertEqual([list|?TCP_LISTEN_OPTIONS], tcp_listen_options([]))
%       end
%       },
%       {"tcp_connect_options has defaults",
%       fun() ->
%           ?assertEqual([list|?TCP_CONNECT_OPTIONS], tcp_connect_options([]))
%       end
%       },
%       {"ssl_listen_options has defaults",
%       fun() ->
%           ?assertEqual([list|?SSL_LISTEN_OPTIONS], ssl_listen_options([]))
%       end
%       },
%       {"ssl_connect_options has defaults",
%       fun() ->
%           ?assertEqual([list|?SSL_CONNECT_OPTIONS], ssl_connect_options([]))
%       end
%       },
%       {"tcp_listen_options defaults to list type",
%       fun() ->
%           ?assertEqual([list|?TCP_LISTEN_OPTIONS], tcp_listen_options([{active,false}])),
%           ?assertEqual([binary|?TCP_LISTEN_OPTIONS], tcp_listen_options([binary,{active,false}]))
%       end
%       },
%       {"tcp_connect_options defaults to list type",
%       fun() ->
%           ?assertEqual([list|?TCP_CONNECT_OPTIONS], tcp_connect_options([{active,false}])),
%           ?assertEqual([binary|?TCP_CONNECT_OPTIONS], tcp_connect_options([binary,{active,false}]))
%       end
%       },
%       {"ssl_listen_options defaults to list type",
%       fun() ->
%           ?assertEqual([list|?SSL_LISTEN_OPTIONS], ssl_listen_options([{active,false}])),
%           ?assertEqual([binary|?SSL_LISTEN_OPTIONS], ssl_listen_options([binary,{active,false}]))
%       end
%       },
%       {"ssl_connect_options defaults to list type",
%       fun() ->
%           ?assertEqual([list|?SSL_CONNECT_OPTIONS], ssl_connect_options([{active,false}])),
%           ?assertEqual([binary|?SSL_CONNECT_OPTIONS], ssl_connect_options([binary,{active,false}]))
%       end
%       },
%       {"tcp_listen_options merges provided proplist",
%       fun() ->
%           ?assertMatch([list,{active, true},
%                              {backlog, 30},
%                              {keepalive, true},
%                              {packet, 2},
%                              {reuseaddr, true}],
%                        tcp_listen_options([{active, true},{packet,2}]))
%       end
%       },
%       {"tcp_connect_options merges provided proplist",
%       fun() ->
%           ?assertMatch([list,{active, true},
%                              {packet, 2}],
%                        tcp_connect_options([{active, true},{packet,2}]))
%       end
%       },
%       {"ssl_listen_options merges provided proplist",
%       fun() ->
%           ?assertMatch([list,{active, true},
%                              {backlog, 30},
%                              {certfile, "cert.pem"},
%                              {depth, 0},
%                              {keepalive, true},
%                              {keyfile, "key.pem"},
%                              {packet, 2},
%                              {reuse_sessions, false},
%                              {reuseaddr, true},
%                              {ssl_imp, new}],
%                        ssl_listen_options([{active, true},{packet,2}]))
%       end
%       },
%       {"ssl_connect_options merges provided proplist",
%       fun() ->
%           ?assertMatch([list,{active, true},
%                              {certfile, "cert.pem"},
%                              {depth, 0},
%                              {keyfile, "key.pem"},
%                              {packet, 2},
%                              {ssl_imp, new}],
%                        ssl_connect_options([{active, true},{packet,2}]))
%       end
%       }
    ].

ssl_upgrade_test_() ->
    [
        {"TCP connection can be upgraded to ssl",
        fun() ->
            Self = self(),
            application:ensure_all_started(ssl),
            spawn(fun() ->
                    {ok, ListenSocket} = listen(tcp, ?TEST_PORT),
                    {ok, ServerSocket} = accept(ListenSocket),
                    {ok, NewServerSocket} = sock:to_ssl_server(ServerSocket),
                    Self ! NewServerSocket
                  end),
            {ok, ClientSocket} = connect(tcp, "localhost", ?TEST_PORT),
            ?assert(is_port(ClientSocket)),
            {ok, NewClientSocket} = to_ssl_client(ClientSocket),
            ?assertMatch([sslsocket|_], tuple_to_list(NewClientSocket)),
            receive NewServerSocket -> ok end,
            ?assertMatch([sslsocket|_], tuple_to_list(NewServerSocket)),
            close(NewClientSocket),
            close(NewServerSocket)
        end
        },
        {"SSL server connection can't be upgraded again",
        fun() ->
            application:ensure_all_started(ssl),
            spawn(fun() ->
                    {ok, ListenSocket} = listen(ssl, ?TEST_PORT),
                    {ok, ServerSocket} = accept(ListenSocket),
                    ?assertException(error, ssl_connected, to_ssl_server(ServerSocket)),
                    close(ServerSocket)
                  end),
            {ok, ClientSocket} = connect(tcp, "localhost", ?TEST_PORT),
            inet:setopts(ClientSocket, [{linger, {false, 0}}]),
            close(ClientSocket)
        end
        },
        {"SSL client connection can't be upgraded again",
        fun() ->
            Self = self(),
            application:ensure_all_started(ssl),
            spawn(fun() ->
                    {ok, ListenSocket} = listen(ssl, ?TEST_PORT),
                    {ok, ServerSocket} = accept(ListenSocket),
                    Self ! ServerSocket
                  end),
            {ok, ClientSocket} = connect(ssl, "localhost", ?TEST_PORT),
            receive ServerSocket -> ok end,
            ?assertException(error, ssl_connected, to_ssl_client(ClientSocket)),
            close(ClientSocket),
            close(ServerSocket)
        end
        }
    ].
-endif.
