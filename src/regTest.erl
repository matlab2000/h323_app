%%====================================================================
%%
%% @author Juanse Perez Herrero <juanseph@gmail.com> [http://bytefilia.com]
%% @copyright CC Attribution - 2013
%%
%% A sample otp gen_server template
%%
%%====================================================================
-module(regTest).
-behaviour(gen_server).

% interface calls
-export([startTest/1, stopTest/0]).
    
% gen_server callbacks
-export([init/1,
         handle_call/3, 
         handle_cast/2,
         handle_info/2, 
         terminate/2, 
         code_change/3]).

-import(ras,[sendRas/3,sendQ931/3,sendH245/3]).

-include("ras.hrl").
%%====================================================================
%% Server interface
%%====================================================================
%% Booting server (and linking to it)
startTest(Params) ->
    io:format("Starting with ~p~n",[Params]),
    gen_server:start(?MODULE, [Params], []).

%% Stopping server asynchronously
stopTest() ->
    io:format("Stopping~n"),
    gen_server:cast(?MODULE, shutdown).


-record(state,{pid,auths,name,ip}).

%%====================================================================
%% gen_server callbacks
%%====================================================================
init([{Pid,Auths,Name,IP}]) ->
    process_flag(trap_exit, true),
    {ok, #state{pid=Pid,auths=Auths,name=Name,ip=IP}}.

%% Synchronous, possible return values  
% {reply,Reply,NewState} 
% {reply,Reply,NewState,Timeout}
% {reply,Reply,NewState,hibernate}
% {noreply,NewState}
% {noreply,NewState,Timeout}
% {noreply,NewState,hibernate}
% {stop,Reason,Reply,NewState} 
% {stop,Reason,NewState}
handle_call(Message, From, State) -> 
    io:format("Generic call handler: '~p' from '~p' while in '~p'~n",[Message, From, State]),
    {reply, ok, State}.

%% Asynchronous, possible return values
% {noreply,NewState} 
% {noreply,NewState,Timeout}
% {noreply,NewState,hibernate}
% {stop,Reason,NewState}
%% normal termination clause
handle_cast(shutdown, State) ->
    io:format("Generic cast handler: *shutdown* while in '~p'~n",[State]),
    {stop, normal, State};
%% generic async handler
handle_cast({ras,Msg}, #state{pid=Pid,auths=Auths,name=Name,ip=IP}=State) ->

    NewAuths=
    case element(1,Msg) of
        % 'GatekeeperReject'->
        %     io:format("GRQ reject~n");
        'GatekeeperConfirm'->
            io:format("GRQ confirm~n"),
            ras:sendRas(rasr,makeRRQ,[Name]),
            Auths;
        % 'RegistrationReject'->
        %     io:format("RRQ reject~n");
        'RegistrationConfirm'->
            io:format("RRQ confirm~n"),
            erlang:send_after(5*1000,Pid,{unreg}),
            Auths;
        'UnregistrationReject'->
            io:format("URQ reject~n"),
	        case Auths of
		        [Auth|Rest] ->
			        RegPara = #regPara{ip=IP,auth = [Auth]},

			        gen_server:cast(Pid,{reg,RegPara,self()}),
			        Rest;
		        _->
			        Auths
	        end;
        'UnregistrationConfirm'->
            io:format("URQ confirm~n"),
            case Auths of
                [Auth|Rest] ->
                    RegPara = #regPara{ip=IP,auth = [Auth]},

                    gen_server:cast(Pid,{reg,RegPara,self()}),
                    Rest;
                _->
                    Auths
            end;
        % 'AdmissionReject'->
        %     io:format("ARQ reject~n");
        'AdmissionConfirm'->
            io:format("ARQ confirm~n"),
            ras:sendQ931(q931,encodeSetup,[Name]),
            Auths;
        % 'DisengageReject'->
        %     io:format("DRQ reject~n");
        % 'DisengageConfirm'->
        %     io:format("DRQ confirm~n");
        % 'BandwidthReject'->
        %     io:format("BRQ reject~n");
        % 'BandwidthConfirm'->
        %     io:format("BRQ confirm~n");
        % 'LocationReject'->
        %     io:format("LRQ reject~n");
        % 'LocationConfirm'->
        %     io:format("LRQ confirm~n");
        _->
            io:format("not process msg! name ~p body ~p ~n",[element(1,Msg),Msg]),
            Auths
    end,

    {noreply, State#state{auths=NewAuths}};


handle_cast(Message, State) ->
    io:format("Generic cast handler: '~p' while in '~p'~n",[Message, State]),
    {noreply, State}.

%% Informative calls
% {noreply,NewState} 
% {noreply,NewState,Timeout} 
% {noreply,NewState,hibernate}
% {stop,Reason,NewState}
handle_info(_Message, _Server) -> 
    io:format("Generic info handler: '~p' '~p'~n",[_Message, _Server]),
    {noreply, _Server}.

%% Server termination
terminate(_Reason, _Server) -> 
    io:format("Generic termination handler: '~p' '~p'~n",[_Reason, _Server]).


%% Code change
code_change(_OldVersion, _Server, _Extra) -> 
    {ok, _Server}.    