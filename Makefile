all: compile

get-deps:
	rebar3 get-deps

compile:
	rebar3 compile

eunit:
	rebar3 eunit

clean:
	rebar3 clean
