-module(h323_sup).
-behaviour(supervisor).

-export([start_link/0,start_child/1]).
-export([init/1]).

-define(SERVER,?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?SERVER, []).
start_child(Index)->
	supervisor:start_child(?SERVER,[Index]).
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
init([]) ->
	Elem={h323_server, {h323_server, start_link, []},
        temporary , 5000, worker, [h323_server]},
	%Elem={h323_server, {h323_server, start_link, []},permanent, 5000, worker, [h323_server]},
    Procs = [Elem],
	RestartStrategy={ simple_one_for_one, 10, 10},
    {ok, { RestartStrategy, Procs}}.