% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License. You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
% License for the specific language governing permissions and limitations under
% the License.

-module(pbkdf2).

-export([pbkdf2/4, pbkdf2/5, compare_secure/2, to_hex/1]).

-type(hex_char() :: 48 .. 57 | 97 .. 102).
-type(hex_list() :: [hex_char()]).

-type(digest_func_info() :: md4 | md5 | ripemd160 | sha | sha224 | sha256 | sha384 | sha512).

-define(MAX_DERIVED_KEY_LENGTH, (1 bsl 32 - 1)).

%%--------------------------------------------------------------------
%% Public API
%%--------------------------------------------------------------------

-spec(pbkdf2(MacFunc, Password, Salt, Iterations) -> {ok, Key} when
    MacFunc    :: digest_func_info(),
    Password   :: binary(),
    Salt       :: binary(),
    Iterations :: integer(),
    Key        :: binary()).
pbkdf2(MacFunc, Password, Salt, Iterations) ->
	DerivedLength = dk_length(MacFunc),
    pbkdf2(MacFunc, Password, Salt, Iterations, DerivedLength).

-spec(pbkdf2(MacFunc, Password, Salt, Iterations, DkLength) -> {ok, Key} | {error, derived_key_too_long} when
    MacFunc       :: digest_func_info(),
    Password      :: binary(),
    Salt          :: binary(),
    Iterations    :: integer(),
    DkLength      :: integer(),
    Key           :: binary()).
pbkdf2(_MacFunc, _Password, _Salt, _Iterations, DerivedLength) when DerivedLength > ?MAX_DERIVED_KEY_LENGTH ->
    {error, derived_key_too_long};
pbkdf2(md4 = F, Password, Salt, Iterations, DkLength) ->
    pbkdf2_loop(F, Password, Salt, Iterations, DkLength);
pbkdf2(md5 = F, Password, Salt, Iterations, DkLength) ->
    pbkdf2_loop(F, Password, Salt, Iterations, DkLength);
pbkdf2(ripemd160 = F, Password, Salt, Iterations, DkLength) ->
    pbkdf2_loop(F, Password, Salt, Iterations, DkLength);
pbkdf2(DigestFunc, Password, Salt, Iterations, DkLength) ->
    pbkdf2_otp(DigestFunc, Password, Salt, Iterations, DkLength).

-if(?OTP_RELEASE >= 25).
pbkdf2_otp(DigestFunc, Password, Salt, Iterations, DkLength) ->
    Bin = crypto:pbkdf2_hmac(DigestFunc, Password, Salt, Iterations, DkLength),
    {ok, Bin}.
-else.
pbkdf2_otp(DigestFunc, Password, Salt, Iterations, DkLength) ->
    pbkdf2_loop(DigestFunc, Password, Salt, Iterations, DkLength).
-endif.

pbkdf2_loop(MacFunc, Password, Salt, Iterations, DerivedLength) ->
	MacFunc1 = resolve_mac_func(MacFunc),
	Bin = pbkdf2(MacFunc1, Password, Salt, Iterations, DerivedLength, 1, []),
	{ok, Bin}.

-spec(to_hex(Data) -> HexData when
    Data    :: binary() | [byte()],
	HexData :: binary() | hex_list()).
to_hex(Data) when is_binary(Data) ->
    string:lowercase(binary:encode_hex(Data));
to_hex(Data) when is_list(Data) ->
    binary_to_list(string:lowercase(binary:encode_hex(list_to_binary(Data)))).

%%--------------------------------------------------------------------
%% Internal Functions
%%--------------------------------------------------------------------

-spec(pbkdf2(MacFunc, Password, Salt, Iterations, DerivedLength, BlockIndex, Acc) -> Key when
	MacFunc       :: fun((binary(), binary()) -> binary()),
	Password      :: binary(),
	Salt          :: binary(),
	Iterations    :: integer(),
	DerivedLength :: integer(),
	BlockIndex    :: integer(),
	Acc           :: iodata(),
	Key           :: binary()).
pbkdf2(MacFunc, Password, Salt, Iterations, DerivedLength, BlockIndex, Acc) ->
	case iolist_size(Acc) > DerivedLength of
		true  -> <<Bin:DerivedLength/binary, _/binary>> = iolist_to_binary(lists:reverse(Acc)),
                 Bin;
		false -> Block = pbkdf2(MacFunc, Password, Salt, Iterations, BlockIndex, 1, <<>>, <<>>),
                 pbkdf2(MacFunc, Password, Salt, Iterations, DerivedLength, BlockIndex + 1, [Block | Acc])
    end.

-spec(pbkdf2(MacFunc, Password, Salt, Iterations, BlockIndex, Iteration, Prev, Acc) -> Key when
	MacFunc    :: fun((binary(), binary()) -> binary()),
	Password   :: binary(),
	Salt       :: binary(),
	Iterations :: integer(),
	BlockIndex :: integer(),
	Iteration  :: integer(),
	Prev       :: binary(),
	Acc        :: binary(),
	Key        :: binary()).
pbkdf2(_MacFunc, _Password, _Salt, Iterations, _BlockIndex, Iteration, _Prev, Acc) when Iteration > Iterations ->
	Acc;
pbkdf2(MacFunc, Password, Salt, Iterations, BlockIndex, 1, _Prev, _Acc) ->
	InitialBlock = MacFunc(Password, <<Salt/binary, BlockIndex:32/integer>>),
	pbkdf2(MacFunc, Password, Salt, Iterations, BlockIndex, 2, InitialBlock, InitialBlock);
pbkdf2(MacFunc, Password, Salt, Iterations, BlockIndex, Iteration, Prev, Acc) ->
	Next = MacFunc(Password, Prev),
	pbkdf2(MacFunc, Password, Salt, Iterations, BlockIndex, Iteration + 1, Next, crypto:exor(Next, Acc)).

resolve_mac_func({hmac, DigestFunc}) ->
    fun(Key, Data) -> mac_calc_fun(DigestFunc, Key, Data) end;
resolve_mac_func(MacFunc) when is_function(MacFunc) ->
	MacFunc;

resolve_mac_func(md4) -> resolve_mac_func({hmac, md4});
resolve_mac_func(md5) -> resolve_mac_func({hmac, md5});
resolve_mac_func(ripemd160) -> resolve_mac_func({hmac, ripemd160});
resolve_mac_func(sha) -> resolve_mac_func({hmac, sha});
resolve_mac_func(sha224) -> resolve_mac_func({hmac, sha224});
resolve_mac_func(sha256) -> resolve_mac_func({hmac, sha256});
resolve_mac_func(sha384) -> resolve_mac_func({hmac, sha384});
resolve_mac_func(sha512) -> resolve_mac_func({hmac, sha512}).

-if(?OTP_RELEASE >= 23).
mac_calc_fun(DigestFunc, Key, Data) ->
    HMAC = crypto:mac_init(hmac, DigestFunc, Key),
    HMAC1 = crypto:mac_update(HMAC, Data),
    crypto:mac_final(HMAC1).
-else.
mac_calc_fun(DigestFunc, Key, Data) ->
    HMAC = crypto:hmac_init(DigestFunc, Key),
    HMAC1 = crypto:hmac_update(HMAC, Data),
    crypto:hmac_final(HMAC1).
-endif.

%% Compare two strings or binaries for equality without short-circuits to avoid timing attacks.

-spec(compare_secure(First, Second) -> boolean() when
	First  :: binary() | string(),
	Second :: binary() | string()).
compare_secure(<<X/binary>>, <<Y/binary>>) ->
	compare_secure(binary_to_list(X), binary_to_list(Y));
compare_secure(X, Y) when is_list(X) and is_list(Y) ->
	case length(X) == length(Y) of
		true  -> compare_secure(X, Y, 0);
		false -> false
	end;
compare_secure(_X, _Y) -> false.

-spec(compare_secure(First, Second, Accum) -> boolean() when
	First  :: string(),
	Second :: string(),
	Accum  :: integer()).
compare_secure([X|RestX], [Y|RestY], Result) ->
	compare_secure(RestX, RestY, (X bxor Y) bor Result);
compare_secure([], [], Result) ->
	Result == 0.

dk_length(md4) -> 16;
dk_length(md5) -> 16;
dk_length(ripemd160) -> 20;
dk_length(sha) -> 20;
dk_length(sha224) -> 28;
dk_length(sha256) -> 32;
dk_length(sha384) -> 48;
dk_length(sha512) -> 64.
