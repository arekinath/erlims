%% erlims
%%
%% Copyright 2021 The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(ims_client).

-compile([{parse_transform, lager_transform}]).

-export([open/0, start/2]).
-export_type([client/0]).

-type token() :: binary().
-type response() :: map() | binary().

-record(?MODULE, {
    gun :: pid()
    }).

-opaque client() :: #?MODULE{}.

-spec open() -> {ok, client()}.
open() ->
    {ok, Gun} = gun:open("auth.ims.its.uq.edu.au", 443),
    {ok, _Proto} = gun:await_up(Gun, 30000),
    {ok, #?MODULE{gun = Gun}}.

-spec start(token(), client()) ->
    {continue, token(), client()} |
    {error, any(), client()} |
    {ok, token(), response(), client()} |
    {ok, response(), client()}.
start(Token0, S0 = #?MODULE{gun = Gun}) ->
    Authz = iolist_to_binary([<<"Negotiate ">>, base64:encode(Token0)]),
    Req = gun:get(Gun, "/agent/start", [
        {<<"accept">>, <<"application/json">>},
        {<<"user-agent">>, <<"erlims">>},
        {<<"authorization">>, Authz}
        ]),
    case gun:await(Gun, Req, 30000) of
        {response, HasFin, 401, HdrList} ->
            HdrMap = maps:from_list(HdrList),
            case HasFin of
                fin -> ok;
                nofin -> {ok, _Body} = gun:await_body(Gun, Req)
            end,
            case HdrMap of
                #{<<"www-authenticate">> := Auth} ->
                    <<"Negotiate ", Token1B64/binary>> = Auth,
                    Token1 = base64:decode(Token1B64),
                    {continue, Token1, S0};
                _ ->
                    {error, {http_error, 401}, S0}
            end;
        {response, fin, Status, _HdrList} when (Status >= 300) ->
            {error, {http_error, Status}, S0};
        {response, nofin, Status, HdrList} when (Status >= 300) ->
            HdrMap = maps:from_list(HdrList),
            {ok, Body} = gun:await_body(Gun, Req),
            #{<<"content-type">> := CType} = HdrMap,
            case CType of
                <<"application/json", _/binary>> ->
                    BodyJSON = jsx:decode(Body, [return_maps]),
                    {error, {http_error, Status, BodyJSON}, S0};
                _ ->
                    {error, {http_error, Status, Body}, S0}
            end;
        {response, nofin, _Status, HdrList} ->
            HdrMap = maps:from_list(HdrList),
            {ok, Body} = gun:await_body(Gun, Req),
            #{<<"content-type">> := CType} = HdrMap,
            FinalBody = case CType of
                <<"application/json", _/binary>> ->
                    BodyJSON = jsx:decode(Body, [return_maps]),
                    BodyJSON;
                _ ->
                    Body
            end,
            case HdrMap of
                #{<<"www-authenticate">> := Auth} ->
                    <<"Negotiate ", Token1B64/binary>> = Auth,
                    Token1 = base64:decode(Token1B64),
                    {ok, Token1, FinalBody, S0};
                _ ->
                    {ok, FinalBody, S0}
            end
    end.
