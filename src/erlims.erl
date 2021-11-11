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

%% @private
-module(erlims).

-compile([{parse_transform, lager_transform}]).

-include_lib("kerlberos/include/KRB5.hrl").

-export([main/1]).

unlock_ebox(BoxPath) ->
    ExecPath = os:find_executable("pivy-box"),
    Port = erlang:open_port({spawn_executable, ExecPath}, [
        in, binary, stream, exit_status, {line, 1024},
        {args, ["key", "unlock", "-R", BoxPath]}
        ]),
    receive
        {Port, {exit_status, 0}} ->
            ok;
        {Port, {exit_status, N}} ->
            io:format("erlims: error: pivy-box exited with status ~B\n", [N]),
            halt(1)
    end,
    receive
        {Port, {data, {_Eol, Pw}}} ->
            Pw
    end,
    Pw.

main(Args) ->
    {ok, _} = application:ensure_all_started(erlims),

    OptSpecList = [
        {help, $h, undefined, undefined, "Show usage information"},
        {verbose, $v, undefined, undefined, "Set debug log level"},
        {user, $u, "username", string, "Username to log in with"},
        {ebox, $e, "path", string, "Path to ebox containing user password"}
    ],

    case getopt:parse(OptSpecList, Args) of
        {ok, {Options, []}} ->
            case lists:member(help, Options) of
                true ->
                    getopt:usage(OptSpecList, "erlims"),
                    halt(1);
                _ ->
                    case proplists:get_value(user, Options) of
                        undefined ->
                            io:format("erlims: error: -u option is required\n"),
                            getopt:usage(OptSpecList, "erlims"),
                            halt(1);
                        _ ->
                            main_opts(Options)
                    end
            end;
        {ok, {_Options, _ExtraArgs}} ->
            io:format("erlims: error: extra arguments given\n"),
            getopt:usage(OptSpecList, "erlims"),
            halt(1);
        {error, {Why, Data}} ->
            io:format("erlims: error: ~s ~p\n", [Why, Data]),
            getopt:usage(OptSpecList, "erlims"),
            halt(1)
    end.

main_opts(Options) ->
    case lists:member(verbose, Options) of
        true ->
            lager:set_loglevel(lager_console_backend, debug);
        _ ->
            lager:set_loglevel(lager_console_backend, emergency)
    end,
    User = [proplists:get_value(user, Options)],

    Pw = case proplists:get_value(ebox, Options) of
        undefined ->
            termutils:getpw();
        Path ->
            unlock_ebox(Path)
    end,

    lager:debug("authing to krb5..."),
    {ok, R0} = krb_realm:open("KRB5.UQ.EDU.AU"),
    case krb_realm:authenticate(R0, User, Pw) of
        {ok, TGT0} -> ok;
        {error, bad_secret} ->
            TGT0 = none,
            io:format("erlims: error: invalid username or password\n"),
            halt(1);
        {error, AuthWhy} ->
            TGT0 = none,
            io:format("erlims: error authenticating to KRB5: ~p\n", [AuthWhy]),
            halt(1)
    end,

    lager:debug("obtaining cross-realm tgt..."),
    {ok, TGT1} = krb_realm:obtain_ticket(R0, TGT0, ["krbtgt", "UQ.EDU.AU"]),

    lager:debug("obtaining service ticket..."),
    {ok, R1} = krb_realm:open("UQ.EDU.AU"),
    {ok, SvcTkt} = krb_realm:obtain_ticket(R1, TGT1,
        ["HTTP", "auth.ims.its.uq.edu.au"]),

    #{ticket := Tkt} = SvcTkt,
    #'Ticket'{realm = TktRealm, sname = SName, 'enc-part' = EP} = Tkt,
    #'EncryptedData'{etype = ET, kvno = KvNo, cipher = D} = EP,
    lager:debug("kvno = ~B", [KvNo]),
    <<D0:16/binary, D1/binary>> = D,
    D0Hex = [ io_lib:format("~2.16.0B",[X]) || <<X:8>> <= D0 ],
    D1Hex = [ io_lib:format("~2.16.0B",[X]) || <<X:8>> <= D1 ],
    #'PrincipalName'{'name-string' = SNameParts} = SName,
    Hash = iolist_to_binary(["$krb5tgs$",
        integer_to_list(krb_crypto:atom_to_etype(ET)),
        "$*", User, "$", TktRealm, "$", lists:join("/", SNameParts),
        "*$", D0Hex, "$", D1Hex]),
    lager:debug("hash = ~s", [Hash]),

    lager:debug("connecting to auth.ims..."),
    {ok, ImsClient} = ims_client:open(),

    lager:debug("authenticating... "),
    {continue, Token0, S0} = gss_spnego:initiate(#{
        ticket => SvcTkt,
        chan_bindings => <<0:128/big>>,
        mutual_auth => true
        }),
    case continue(ImsClient, Token0, S0) of
        {ok, #{<<"sessionid">> := SessId, <<"user">> := FinalUser}} ->
            io:format("started session ~s as ~s\n", [SessId, FinalUser]),
            halt(0);
        {ok, Resp} ->
            io:format("ok, response: ~p\n", [Resp]),
            halt(0);
        {error, Why} ->
            io:format("erlims: error: ~p\n", [Why]),
            halt(1)
    end.

continue(C0, Token0, S0) ->
    case ims_client:start(Token0, C0) of
        {ok, Resp, _C1} ->
            {ok, Resp};
        {ok, Token1, Resp, _C1} ->
            case gss_spnego:continue(Token1, S0) of
                {ok, _S1} -> {ok, Resp};
                {error, Why} -> {error, Why}
            end;
        {error, Why, _C1} ->
            {error, Why};
        {continue, Token1, C1} ->
            case gss_spnego:continue(Token1, S0) of
                {continue, Token2, S1} ->
                    continue(C1, Token2, S1);
                {ok, Token2, _S1} ->
                    case ims_client:start(Token2, C1) of
                        {error, Why, _C2} ->
                            {error, Why};
                        {ok, Resp, _C2} ->
                            {ok, Resp}
                    end;
                {error, Why} ->
                    {error, Why}
            end
    end.
