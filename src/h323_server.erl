-module(h323_server).
-author(xueys).

-behaviour(gen_server).




-export([start_link/0,start_link/1]). % convenience call for startup
-export([reg/1,reg/2,unreg/1,makeCall/2,hangupCall/1]).
-export([start/1]).

-export([init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3]). % gen_server callbacks

-define(SERVER, ?MODULE).

-import(ras,[decodeRas/2,sendRas/3,sendQ931/3,sendH245/3]).
-import(rasa,[makeARQ/1,parseARQ/2,makeACF/1,parseACF/2,makeARJ/1,parseARJ/2]).
-import(rasa,[makeDRQ/1,parseDRQ/2,makeDCF/1,parseDCF/2,makeDRJ/1,parseDRJ/2]).

-import(rasg,[makeGRQ/1,parseGRQ/2,makeGCF/1,parseGCF/2,makeGRJ/1,parseGRJ/2]).

-import(rasr,[makeRRQ/1,parseRRQ/2,makeRCF/1,parseRCF/2,makeRRJ/1,parseRRJ/2]).
-import(rasr,[makeURQ/1,parseURQ/2,makeUCF/1,parseUCF/2,makeURJ/1,parseURJ/2]).

-import(rasdb,[makeTerTable/1,deleteTerTable/0,nameFromIndex/1,lookupTable/2]).
-import(rasdb,[getAndIncreaseSeqNum/1,updateGKID/2,updateEPID/2,updateRasSock/2,updateRecord/3,
    updateQ931ListenSock/2,updateQ931ConnectSock/2,updateH245ListenSock/2,updateH245ConnectSock/2]).

-import(rasutil,[createServerSock/2,createClientSock/3,createUdpSock/2]).
-import(uuid,[v4/0,to_binary/1]).

-import(regTest,[startTest/1, stopTest/0]).

-include("H235-SECURITY-MESSAGES.hrl").
-include("H323-MESSAGES.hrl").
-include("ras.hrl").
-include("q931.hrl").
-include("h245.hrl").


-export([h323Test/0,h323Test/1,h323Test/2,terTest/1,terTest/2]).
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

terReg(Pid,Auths,IP) ->
	[Auth|_]=Auths,
	RegPara = #regPara{ip=IP,auth = [Auth]},
	reg(Pid,RegPara).

terReg(Pid,Auths,Name,IP) ->
	[Auth|Rest]=Auths,
	{ok,RegPid}=regTest:startTest({Pid,Rest,Name,IP}),
	RegPara = #regPara{ip=IP,auth = [Auth]},
	reg(Pid,RegPara,RegPid).


terCall(Pid,IP)->
	CallPara=#callPara{addr={ip,IP},port=?DEFAULT_CALLPORT,rate=768},
	makeCall(Pid,CallPara),
	timer:sleep(1000*3),
	hangupCall(Pid).

terCall(Pid)->
	IP=rasutil:localIP(),
	CallPara=#callPara{addr={ip,tuple_to_list(IP)},port=?DEFAULT_CALLPORT,rate=768},
	makeCall(Pid,CallPara),
	timer:sleep(1000*3),
	hangupCall(Pid).

terTest(Idx)->
	IP=tuple_to_list(rasutil:localIP()),
	{ok,Pid}=start(Idx),
	Name=rasdb:nameFromIndex(Idx),
	terReg(Pid,['h2351_I'],Name,IP).  %%['cat','md5','h2351_I']


terTest(Idx,IP)->
	{ok,Pid}=start(Idx),
	Name=rasdb:nameFromIndex(Idx),
	terReg(Pid,['h2351_I'],Name,IP).


h323Test()->
	IP=tuple_to_list(rasutil:localIP()),
	h323Test( IP).

h323Test(IP) ->
	h323Test(1,IP).

h323Test(Num,IP) when is_integer(Num),Num>=1 ->
	%application:start(h323_app),
	lists:map(  fun(Idx)-> spawn(?MODULE, terTest,[Idx,IP]) end ,lists:seq(1,Num)).


%%% convenience method for startup
start_link() ->
	io:format("server start link without parameters ~n"),
	gen_server:start_link(?SERVER, [], []).

start_link(Index) ->
	io:format("server start link ~p~n",[Index]),
    gen_server:start_link(?SERVER, [Index], []).

%%%%%%%%%%%%interface%%%%%%%%%%%%%%%%%%%%%%%%%
start(Index) ->
	supervisor:start_child(h323_sup,[Index]).


reg(Pid) when is_pid(Pid) ->
	RegPara=#regPara{auth=['md5']},
    reg(Pid,RegPara).

reg(Pid,RegPara) when is_pid(Pid),is_record(RegPara,regPara)->
	gen_server:cast(Pid,{reg,RegPara}).

reg(Pid,RegPara,RegPid) when is_pid(Pid),is_record(RegPara,regPara),is_pid(RegPid) ->
	gen_server:cast(Pid,{reg,RegPara,RegPid}).

unreg(Pid) when is_pid(Pid) ->
    gen_server:cast(Pid,{unreg}).

makeCall(Pid,CallPara)  when is_pid(Pid) ->
    gen_server:cast(Pid,{call,CallPara}).

hangupCall(Pid)  when is_pid(Pid) ->
    gen_server:cast(Pid,{hangup}).


%onSocketEvent(Pid ,Value) when is_pid(Pid) ->
%	gen_server:cast(Pid,[Value]).

%%% gen_server callbacks
-record(tcpProc,{client=null,needLen=0,nowLen=0,data=[]}).
-record(state,{index, name,gk,peer,terminal,
    q931client, % if we listen ,accept socket
    h245client,
    q931conn, % if we caller, make this socket
    h245conn,
	regPid
}).

init([Index]) ->
	process_flag(trap_exit, true),
	Name=rasdb:nameFromIndex(Index),
	io:format("Start terminal ~p~n",[Name]),

	Ter=hd(rasdb:lookupTable(Name,terminal)),
	Gk=hd(rasdb:lookupTable(Name,gk)),
	Peer=hd(rasdb:lookupTable(Name,peer)),
	%create ras
	#gk{rasPort = RasPort}=Gk,
    {ok,RasSock}=rasutil:createUdpSock(RasPort,self()),
	rasdb:updateRasSock(Name,RasSock),

	#terminal{q931Port = Q931Port,h245Port = H245Port}=Ter,

    {ok,Q931Sock}=rasutil:createServerSock(Q931Port,self()),
	rasdb:updateQ931ListenSock(Name,Q931Sock),
    {ok,H245Sock}=rasutil:createServerSock(H245Port,self()),
	rasdb:updateH245ListenSock(Name,H245Sock),

	{ok, #state{index=Index,name=Name,gk=Gk#gk{rasSock = RasSock},peer=Peer,
		terminal=Ter#terminal{q931Sock = Q931Sock,h245Sock = H245Sock },
        q931client =#tcpProc{}, h245client = #tcpProc{},
        q931conn  = #tcpProc{},h245conn = #tcpProc{}
    }}.

handle_call(_Request, _From, #state{name=Name}=State) ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	Gk=hd(rasdb:lookupTable(Name,gk)),
	Peer=hd(rasdb:lookupTable(Name,peer)),
	Reply=0,
    {reply, Reply, State}.

handle_cast({reg,RegPara}, #state{name=Name}=State)->
	#regPara{ip=IP,password = Password,auth=Auth}=RegPara,
	rasdb:updateRecord(terminal, Name,[{#terminal.password,Password},
		{#terminal.terauth,Auth}]),
	rasdb:updateRecord(gk,Name,[{#gk.ip,IP}]),
	io:format("reg Password ~p Auth ~p~n",[Password,Auth]),
	ras:sendRas(rasg,makeGRQ,[Name]),
	{noreply,State};

handle_cast({reg,RegPara,RegPid}, #state{name=Name}=State)->
	#regPara{ip=IP,password = Password,auth=Auth}=RegPara,
	rasdb:updateRecord(terminal, Name,[{#terminal.password,Password},
		{#terminal.terauth,Auth}]),
	io:format("reg Password ~p Auth ~p~n",[Password,Auth]),
	rasdb:updateRecord(gk,Name,[{#gk.ip,IP}]),
	ras:sendRas(rasg,makeGRQ,[Name]),
	NewState=State#state{regPid=RegPid},
	{noreply,NewState};

handle_cast({unreg}, #state{name=Name}=State) ->
	ras:sendRas(rasr,makeURQ,[Name]),
	{noreply,State};

handle_cast({call,CallPara}, #state{name=Name,gk=Gk,peer=Peer,terminal=Ter,q931conn=Q931Conn}=State)->
	%#state{index=Index,name=Name,gk=Gk,peer=Peer,terminal=Ter}=State,
	#terminal{ useGK = UseGK}=Ter,

	#callPara{addr=Addr,port=Port,rate=Rate,useTunnel = UseTunnel,useCrypto = UseCrypto,
		useH460 = UseH460 ,useFastStart=UseFastStart}=CallPara,

	NewPeer=Peer#peer{ isOrig = true,useTunnel = UseTunnel,useCyrpt = UseCrypto,
		useH460 = UseH460,useFastStart = UseFastStart,rate=Rate},
	NewPeer1=case Addr of
		{ip,IP} ->
            io:format("IP is ~p~n",[IP]),
            {ok,Sock}= rasutil:createClientSock(list_to_tuple(IP),Port,self()),
            CallID=uuid:v4(),
            ConfID=uuid:v4(),
			NewPeerX=NewPeer#peer{ip=IP,q931Sock = Sock,callID = CallID,confID = ConfID},
			rasdb:updateRecord(peer,Name,[{#peer.ip,IP},{#peer.q931Port,Port},{#peer.q931Sock ,Sock},
                {#peer.callID ,CallID},{#peer.confID ,ConfID}]),
			NewPeerX;
		{e164,E164} ->
			NewPeer;
	    {h323id,H323ID} ->
		    NewPeer;
		_->
			ok
	end,

	if
		UseGK==true ->
			ras:sendRas(rasa,makeARQ,[Name]);
		true ->
			ras:sendQ931(q931,encodeQ931,[Name,?SETUP])
	end,

	NewState=State#state{peer=NewPeer1,q931conn=Q931Conn#tcpProc{client=NewPeer1#peer.q931Sock } },
	{noreply,NewState};

handle_cast({hangup}, #state{name=Name}=State)->
	#state{index=Index,name=Name,gk=Gk,peer=Peer,terminal=Ter}=State,
	ras:sendQ931(q931,encodeQ931,[Name,?RELEASE]),
	{noreply,State};

handle_cast({acceptNew,LSocket,CSocket},#state{terminal=Ter,
    q931client = Q931ClientProc,h245client = H245ClientProc }=State)->
    #terminal{q931Sock = Q931ListenSock,h245Sock=H245ListenSock}=Ter,
    NewState=case LSocket of
        Q931ListenSock ->
            State#state{ q931client=Q931ClientProc#tcpProc{client=CSocket}};
        H245ListenSock ->
            State#state{ h245client = H245ClientProc#tcpProc{client=CSocket}}
    end,
    {noreply,NewState};

handle_cast({tcp,Socket,Data},#state{name=Name,
    q931client = Q931ClientProc,q931conn = Q931ConnProc,h245client = H245ClientProc,h245conn = H245ConnProc}=State) ->

    #tcpProc{client = Q931Client } = Q931ClientProc,
    #tcpProc{client = Q931Conn } = Q931ConnProc,
    #tcpProc{client = H245Client } = H245ClientProc,
    #tcpProc{client = H245Conn } = H245ConnProc,
	io:format("Socket ~p;Q931Client ~p Q31Conn ~p H245Client ~p H245Conn ~p~n",
		[Socket,Q931Client,Q931Conn,H245Client,H245Conn]),
	NewState=case Socket of
        Q931Client ->
            {ok,NewProc,Pkts}=parseTcp(Q931ClientProc,Data),
            lists:foreach(fun (Pkt) -> q931:decodeQ931(Pkt,{Name,self()}) end ,Pkts),
            State#state{q931client = NewProc} ;
        Q931Conn ->
            {ok,NewProc,Pkts}=parseTcp(Q931ConnProc,Data),
            lists:foreach(fun (Pkt) -> q931:decodeQ931(Pkt,{Name,self()}) end ,Pkts),
            State#state{q931conn = NewProc} ;
        H245Client->
            {ok,NewProc,Pkts}=parseTcp(H245ClientProc,Data),
            lists:foreach(fun (Pkt) -> h245:decodeH245(Pkt,{Name,self()}) end ,Pkts),
            State#state{h245client = NewProc} ;
        H245Conn->
            {ok,NewProc,Pkts}=parseTcp(H245ConnProc,Data),
            lists:foreach(fun (Pkt) -> h245:decodeH245(Pkt,{Name,self()}) end ,Pkts),
            State#state{h245conn = NewProc}
	end,
	{noreply,NewState};

handle_cast([{tcp_closed,Socket}],#state{name=Name}=State) ->
	{noreply,State};

handle_cast({tcp_error,Socket,Reason},#state{name=Name}=State) ->
	{noreply,State};

handle_cast({udp,Socket,Host,Port,Data}, #state{name=Name,regPid=RegPid}=State)->
    #state{index=Index,name=Name,gk=Gk,peer=Peer,terminal=Ter}=State,
    #gk{ip=GkIP,rasPort=RasPort,rasSock=RasSock}=Gk,
	io:format("udp recv msg from ~p:~p~n",[Host,Port]),
    case Socket of
        RasSock ->
            {ok,Msg}=ras:decodeRas(Data,Name),
	        if
		        is_pid(RegPid)==true ->
					gen_server:cast(RegPid,{ras,Msg});
				true->
					case element(1,Msg) of
					% 'GatekeeperReject'->
					%     io:format("GRQ reject~n");
						'GatekeeperConfirm'->
							io:format("GRQ confirm ~p~n",[Msg]),
							ras:sendRas(rasr,makeRRQ,[Name]);
					% 'RegistrationReject'->
					%     io:format("RRQ reject~n");
						'RegistrationConfirm'->
							io:format("RRQ confirm ~p~n",[Msg]),
							erlang:send_after(5*1000,self(),{unreg});
					% 'UnregistrationReject'->
					%     io:format("URQ reject~n");
						'UnregistrationConfirm'->
							io:format("URQ confirm ~p~n",[Msg]);
					% 'AdmissionReject'->
					%     io:format("ARQ reject~n");
						'AdmissionConfirm'->
							io:format("ARQ confirm ~p~n",[Msg]),
							ras:sendQ931(q931,encodeSetup,[Name]);
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
							io:format("not process msg!  ~p ~n",[Msg])
					end
		    end;
        _ ->
            io:format("not RasSock~n")
    end,
    {noreply,State};

handle_cast({display,Display},#state{name=Name}=State) ->
    io:format("peer display ~w~n",[list_to_binary(Display)]),
    {noreply,State};

handle_cast({rate,Rate},#state{name=Name}=State) ->
    io:format("peer rate ~p~n",[Rate]),
    {noreply,State};

handle_cast({uuie,Msg},#state{name=Name,peer=Peer,h245conn = H245Conn}=State)->
    #'H323-UserInformation'{
        'h323-uu-pdu'=#'H323-UU-PDU'{
            'h323-message-body'=H323Msg,
            %nonStandardData = asn1_NOVALUE,
            %h4501SupplementaryService = asn1_NOVALUE,
            h245Tunneling=H245Tunnel,
            h245Control = H245Control
            %nonStandardControl = asn1_NOVALUE,
            %callLinkage = asn1_NOVALUE,
            %tunnelledSignallingMessage = asn1_NOVALUE,
            %provisionalRespToH245Tunneling = asn1_NOVALUE,
            %stimulusControl = asn1_NOVALUE,
            %genericData = asn1_NOVALUE
        },
        'user-data'=UserData
    }=Msg,
    io:format("H323Msg ~p~n",[H323Msg]),
    io:format("H245Tunnel ~p H245Control ~p~n",[H245Tunnel,H245Control]),
    NewState=case H323Msg of
        {connect,
            #'Connect-UUIE'{
                h245Address={
                    ipAddress,#'TransportAddress_ipAddress'{ip=H245IP,port=H245Port}
                }
            }
        } ->
            IP=list_to_tuple(binary_to_list(H245IP)),
            {ok,Sock}=rasutil:createClientSock(IP,H245Port,self()),
            NewPeer=Peer#peer{ h245Port = H245Port,h245Sock  = Sock},
            rasdb:updateRecord(peer,Name,[{#peer.h245Port,H245Port},{#peer.h245Sock,Sock}]),
            io:format("Peer H245 ~p:~p~n",[H245IP,H245Port]),
            ras:sendH245(h245,encodeMasterSlaveDetermination,{Name,self()}),
	        ras:sendH245(h245,encodeTerminalCapabilitySet,{Name,self()}),
            State#state{peer=NewPeer,h245conn = H245Conn#tcpProc{client=Sock }};
        _->
            State
    end,
    {noreply,NewState};

handle_cast({h245,Msg},#state{name=Name}=State) ->
    {noreply,State};

handle_cast(_Msg,  #state{name=Name}=State) ->
	#state{index=Index,name=Name,gk=Gk,peer=Peer,terminal=Ter}=State,
    io:format("handle_cast _Msg ~p~n",[_Msg]),
    {noreply, State}.

handle_info({unreg},  #state{name=Name}=State) ->
	unreg(self()),
	{noreply, State};

handle_info(_Info,  #state{name=Name}=State) ->
    {noreply, State}.

terminate(_Reason,  #state{name=Name}=State) ->
    ok.

code_change(_OldVsn,  #state{name=Name}=State, _Extra) ->
    {ok, State}.
%%% Internal functions

parseTcp(#tcpProc{needLen=NeedLen,nowLen=NowLen,data=OldData}=Proc,Data)->
    NewData=[Data|OldData],
    NowLen1=byte_size(Data)+NowLen,
    if
        NeedLen > 0 ->
            if
                NowLen1 < NeedLen ->
                    NewProc=Proc#tcpProc{nowLen = NowLen1, data = NewData},
                    {ok,NewProc,[]};
                true ->
                    {ok, Acc, Rest, NeedBytes} = parseTPKT(list_to_binary(lists:reverse(NewData))),
                    if
                        length(Acc) > 0 ->
                            io:format("Pkt ~p~n", [Acc]);
                        true ->
                            ok
                    end,
                    NewProc=Proc#tcpProc{needLen = NeedBytes, nowLen = byte_size(Rest), data = [Rest]},
                    {ok,NewProc,Acc}
            end;
        true ->
            if
                NowLen1 >= 4 ->
                    {ok, Acc, Rest, NeedBytes} = parseTPKT(list_to_binary(lists:reverse(NewData))),
                    if
                        length(Acc) > 0 ->
                            io:format("Pkt ~p~n", [Acc]);
                        true ->
                            ok
                    end,
                    NewProc=Proc#tcpProc{needLen = NeedBytes, nowLen = byte_size(Rest), data = [Rest]},
                    {ok,NewProc,Acc};
                true ->
                    NewProc=Proc#tcpProc{nowLen = NowLen1, data = NewData},
                    {ok,NewProc,[]}
            end
    end.

parseTPKT(Bin) when is_binary(Bin) ->
    parseTPKT(Bin,[]).

parseTPKT(Bin,Acc) when is_binary(Bin) ->
    case Bin of
        <<3,0,Len:16,Rest/binary>> ->
            RestLen=byte_size(Rest),
            io:format("parseTPKT Len ~p Rest ~p~n",[Len,RestLen]),

            if
                RestLen < Len-4 ->
                    Rest1= <<3,0,Len:16,Rest/binary>>,
                    {ok, Acc,Rest1,Len } ;
                true ->
                    BodyLen=Len-4,
                    case Rest of
                        <<Body:BodyLen/binary,Rest1/binary>> when byte_size(Rest1)>0 ->
                            case parseTPKT(Rest1,[Body|Acc]) of
                                {ok,Acc1,LeftBytes,NeedLen} ->
                                    {ok,Acc1,LeftBytes,NeedLen};
                                {error,RestBytes} ->
                                    {error,RestBytes}

                            end;
                        <<Body:BodyLen/binary>>->
                            {ok,lists:reverse([Body|Acc]),<<>>,0 };
                        _ ->
                            {error,Rest}
                    end
            end
    end.