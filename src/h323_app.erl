-module(h323_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

-import(h323_sup,[start_link/0]).
-import(application,[get_env/1]).
-import(rasdb,[makeTerTable/1,deleteTerTable/0]).

start(_Type,_StartArgs) ->
	%io:format("app startArgs [~p]~n",[_StartArgs]),
	%{ok,Num}=application:get_env(h323_app,ternum),
	Num=100,
	rasdb:makeTerTable(Num),
    case h323_sup:start_link() of
	    {ok,Pid} ->
		    {ok,Pid};
		Other ->
			{error,Other}
	end.

stop(_State) ->
	rasdb:deleteTerTable(),
    ok.