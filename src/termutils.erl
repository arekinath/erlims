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

-module(termutils).

-export([getpw/0]).

-define(OP_PUTC,0).
-define(OP_MOVE,1).
-define(OP_INSC,2).
-define(OP_DELC,3).
-define(OP_BEEP,4).

-spec getpw() -> binary().
getpw() ->
    case io:setopts([binary, {echo, false}]) of
        ok ->
            file:write(standard_error, "\e[2K\r"),
            PwLine = io:get_line(<<"Password:">>),
            ok = io:setopts([binary, {echo, true}]),
            file:write(standard_error, "\e[2K\r"),
            io:format("\n"),
            [Pw | _] = binary:split(PwLine, <<"\n">>),
            Pw;
        _ ->
            Port = open_port({spawn, 'tty_sl -e'}, [binary, eof]),
            port_command(Port, <<?OP_PUTC, "Password:">>),
            receive
                {Port, {data, PwLine}} ->
                    [Pw | _] = binary:split(PwLine, <<"\n">>),
                    port_command(Port, <<?OP_PUTC, $\n>>),
                    port_close(Port),
                    Pw
            end
    end.
