all: compile

get-deps:
	rebar3 get-deps

compile:
	rebar3 compile

dialyzer:
	rebar3 dialyzer

eunit:
	rebar3 eunit -v -c

clean:
	rebar3 clean

hex-publish:
	rebar3 hex publish --repo=hexpm

