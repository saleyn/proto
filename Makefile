all: src/gen_listener_tcp.erl examples/echo_server.erl compile

compile:
	rebar compile

src/gen_listener_tcp.erl examples/echo_server.erl: examples
	wget -O $@ https://raw.githubusercontent.com/travelping/gen_listener_tcp/master/$@

examples:
	mkdir -p $@

clean:
	rm -fr src/gen_listener_tcp.erl examples/echo_server.erl ebin
	[ -d examples -a ! "$(ls -A examples)" ] && rmdir examples || true
