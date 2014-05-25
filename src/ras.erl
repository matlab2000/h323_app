-module(ras).
-author('xueys').
-compile(export_all).

-import(rasa,[makeARQ/1,parseARQ/2,makeACF/1,parseACF/2,makeARJ/1,parseARJ/2]).
-import(rasa,[makeDRQ/1,parseDRQ/2,makeDCF/1,parseDCF/2,makeDRJ/1,parseDRJ/2]).

-import(rasg,[makeGRQ/1,parseGRQ/2,makeGCF/1,parseGCF/2,makeGRJ/1,parseGRJ/2]).

-import(rasr,[makeRRQ/1,parseRRQ/2,makeRCF/1,parseRCF/2,makeRRJ/1,parseRRJ/2]).
-import(rasr,[makeURQ/1,parseURQ/2,makeUCF/1,parseUCF/2,makeURJ/1,parseURJ/2]).

-import(rasdb,[makeTerTable/1,deleteTerTable/0,nameFromIndex/1,lookupTable/2]).
-import(rasdb,[getAndIncreaseSeqNum/1,updateGKID/2,updateEPID/2,updateRasSock/2,
updateQ931ListenSock/2,updateQ931ConnectSock/2,updateH245ListenSock/2,updateH245ConnectSock/2]).

-import(q931,[decodeQ931/2]).
-import(h245,[decodeH245/2]).

-export([decodeRas/2]).
-export([sendRas/3,sendQ931/3,sendH245/3]).

-include_lib("kernel/include/inet.hrl").

-include("H235-SECURITY-MESSAGES.hrl").
-include("H323-MESSAGES.hrl").
-include("ras.hrl").
-include("q931.hrl").
-include("h245.hrl").
%GK搜索

decodeRas(Filename) when is_list(Filename) ->
    {ok,Bytes}=file:read_file(Filename),
    decodeRas(Bytes);
decodeRas(Bytes) when is_binary(Bytes)->
    case 'H323-MESSAGES':decode('RasMessage', Bytes) of
        {ok,Ras} ->   
            io:format("decodeRAS Ras ~p~n",[Ras]);  
        {error,Reason} ->
            io:format("decode Ras error ~p ~n",[Reason]),
            {error,Reason}
    end.

decodeRas(Bytes,Name) when is_binary(Bytes) ->
    %io:format("decodeRAS: ~p~n",[Bytes]),
    case 'H323-MESSAGES':decode('RasMessage', Bytes) of
        {ok,Ras} -> 
            %io:format("decode Ras ok ~p~n",[Ras]),
            case Ras of 
                {gatekeeperRequest      ,GRQ}->
                    rasg:parseGRQ(GRQ,Name);
                {gatekeeperConfirm      ,GCF}->
                    rasg:parseGCF(GCF,Name);
                {gatekeeperReject       ,GRJ}->
                    rasg:parseGRJ(GRJ,Name);
                {registrationRequest    ,RRQ}->
                    rasr:parseRRQ(RRQ,Name); 
                {registrationConfirm    ,RCF}->
                    rasr:parseRCF(RCF,Name); 
                {registrationReject     ,RRJ}->
                    rasr:parseRRJ(RRJ,Name);
                {unregistrationRequest  ,URQ}->
                    rasr:parseURQ(URQ,Name);  
                {unregistrationConfirm  ,UCF}->
                    rasr:parseUCF(UCF,Name);  
                {unregistrationReject   ,URJ}->
                    rasr:parseURJ(URJ,Name);  
                {admissionRequest       ,ARQ}->
                    rasa:parseARQ(ARQ,Name);  
                {admissionConfirm       ,ACF}->
                    rasa:parseACF(ACF,Name);
                {admissionReject        ,ARJ}->
                    rasa:parseARJ(ARJ,Name);
                {bandwidthRequest       ,BRQ}->
                    parseBRQ(BRQ,Name);
                {bandwidthConfirm       ,BCF}->
                    parseBCF(BCF,Name);
                {bandwidthReject        ,BRJ}->
                    parseBRJ(BRJ,Name);
                {disengageRequest       ,DRQ}->
                    parseDRQ(DRQ,Name);
                {disengageConfirm       ,DCF}->
                    parseDCF(DCF,Name);
                {disengageReject        ,DRJ}->
                    parseDRJ(DRJ,Name);
                {locationRequest        ,LRQ}->
                    parseLRQ(LRQ,Name);
                {locationConfirm        ,LCF}->
                    parseLCF(LCF,Name);
                {locationReject         ,LRJ}->
                    parseLRJ(LRJ,Name);
                {infoRequest            ,IRQ}->
                    parseIRQ(IRQ,Name);
                {infoRequestResponse    ,IRR}->
                    parseIRR(IRR,Name);
                {nonStandardMessage     ,NSM}->
                    parseNSM(NSM,Name);
                {unknownMessageResponse    ,XRS}->
                    parseXRS(XRS,Name);
                {requestInProgress          ,RIP}->
                    parseRIP(RIP,Name);
                {resourcesAvailableIndicate ,RAI}->
                    parseRAI(RAI,Name);
                {resourcesAvailableConfirm  ,RAC}->
                    parseRAC(RAC,Name);
                {infoRequestAck            ,IACK}->
                    parseIACK(IACK,Name);
                {infoRequestNak            ,INAK}->
                    parseINAK(INAK,Name);
                {serviceControlIndication   ,SCI}->
                    parseSCI(SCI,Name);
                {serviceControlResponse     ,SCR}->
                    parseSCR(SCR,Name);
                {admissionConfirmSequence   ,ACS}->   %% sequence of admissionConfirm
                    parseACS(ACS,Name)
            end;
        {error,Reason} ->
            io:format("decode Ras error ~p ~n",[Reason]),
            {error,Reason}
    end.

%%%%%%%%%%%%%
% Name is in Params
sendRas(Mod,Func,Params) ->
	io:format("Mod ~p Func ~p Params ~p~n",[Mod,Func,Params]),
    [Name]=Params,
    Gk=hd(rasdb:lookupTable(Name,gk)),

    #gk{ip=Ip,rasSock =Sock}=Gk,
    {ok,Bytes}=apply(Mod,Func,[Name]),
    gen_udp:send(Sock,list_to_tuple(Ip),?DEFAULT_RASPORT,Bytes).

%%%%%%%%%%%%%
sendQ931(Mod,Func,Params) ->
    %io:format("sendQ931 ~p~p~p~p~n",[Mod,Func,Params,is_list(Params)]),
    [Name,MsgType]=Params,
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{useTunnel=UseTunnel}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{q931Sock = Q931Sock }=Peer,

	{ok,Bytes}=apply(Mod,Func,Params),
    BLen=byte_size(Bytes)+4,

%%     NewQ931Sock=if
%%         MsgType==?SETUP ->
%%             {ok,Sock}=gen_tcp:connect(list_to_tuple(PeerIP),?DEFAULT_CALLPORT,[binary,{active,false},{packet,0}]),
%%             rasdb:updateQ931ConnectSock(Name,Sock),
%%             Sock;
%%         true->
%%             Q931Sock
%%     end,
	gen_tcp:send(Q931Sock,<<3,0,BLen:16,Bytes/binary>>). %TPKT Ver,Reserved,totalLen(include TPKT header)

sendH245(Mod,Func,Params) ->
    [Name|_]=Params,
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{useTunnel=UseTunnel}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{ip=PeerIP, h245Port = H245Port,h245Sock = H245Sock }=Peer,

	{ok,Bytes}=apply(Mod,Func,[Name]),
    BLen=byte_size(Bytes)+4,
	NewH245Sock=if
        H245Sock==undefined ->
            {ok,Sock1}=gen_tcp:connect(list_to_tuple(PeerIP),H245Port,[binary,{active,false},{packet,0}]),
            rasdb:updateH245ConnectSock(Name,Sock1),
            Sock1;
        true ->
            H245Sock
    end,
	gen_tcp:send(NewH245Sock,<<3,0,BLen:16,Bytes/binary>>).
%% 	receive
%% 		{tcp,NewH245Sock,Bin}->
%% 			decodeH245(Bin,Name)
%% 	after Timeout->
%% 		{error,timeout}
%% 	end.


terFun(Index)  -> 
%%     {ok,GCF}=sendReq(Index,rasg,makeGRQ,2000),
%%     io:format("gcf ~p~n",[element(1,GCF)]),
%%
%%     {ok,RCF}=sendReq(Index,rasr,makeRRQ,2000),
%%     io:format("rcf ~p~n",[element(1,RCF)]).

%%     {ok,ACF}=sendReq(Index,rasa,makeARQ,2000),
%%     io:format("acf ~p~n",[element(1,ACF)]).

	ok.
  

terStart(Index) ->    
    spawn_link(?MODULE,terFun,[Index]).  %fun()-> terFun(RasInfo) end).
    

start()->
    start(1).

start(Num)->
    process_flag(trap_exit,true),
    rasdb:makeTerTable(Num),
    lists:foreach( fun (X) -> terStart(X) end ,lists:seq(1,Num)),
    receive
        {'EXIT',F,Reason} ->
            io:format("main process found child exit:~p,[~p].~n" ,[F,Reason]);
        Other ->
            io:format("other msg in main process:~p~n" ,[Other])
    end.


%注销

%管理


%不管理


%定位
makeLRQ(Name)->
	io:format("makeLRQ!").
parseLRQ(LRQ,Name)->
    io:format("parseLRQ ~p~n",[LRQ]),
    {ok,LRQ}.

makeLCF(Name)->
    io:format("makeLCF!").
parseLCF(LCF,Name)->
	io:format("parseLCF ~p~n!",[LCF]),
    {ok,LCF}.

makeLRJ(Name)->
    io:format("makeLRJ!").
parseLRJ(LRJ,Name)->
	io:format("parseLRJ ~p~n!",[LRJ]),
    {ok,LRJ}.

%带宽
makeBRQ(Name)->
	io:format("makeBRQ!").
parseBRQ(BRQ,Name)->
    io:format("parseBRQ ~p~n",[BRQ]),
    {ok,BRQ}.

makeBCF(Name)->
    io:format("makeBCF!").
parseBCF(BCF,Name)->
	io:format("parseBCF ~p~n!",[BCF]),
    {ok,BCF}.

makeBRJ(Name)->
    io:format("makeBRJ!").
parseBRJ(BRJ,Name)->
	io:format("parseBRJ ~p~n!",BRJ),
    {ok,BRJ}.
%
makeIRQ(Name)->
	io:format("makeIRQ!").

parseIRQ(IRQ,Name)->
    io:format("parseIRQ ~p~n",[IRQ]),
    {ok,IRQ}.

makeIACK(Name)->
    io:format("makeIACK!").

parseIACK(IACK,Name)->
	io:format("parseIACK ~p~n!",[IACK]),
    {ok,IACK}.

makeINAK(Name)->
    io:format("makeINAK!").

parseINAK(INAK,Name)->
	io:format("parseINAK ~p~n!",[INAK]),
    {ok,INAK}.

makeIRR(Name)->
    io:format("makeIRR!").

parseIRR(IRR,Name)->
	io:format("parseIRR ~p~n!",[IRR]),
    {ok,IRR}.

makeNSM(Name)->
	io:format("makeNSM!").
parseNSM(NSM,Name)->
	io:format("parseNSM ~p~n!",[NSM]),
    {ok,NSM}.

makeXRS(Name)->
	io:format("makeXRS!").
parseXRS(XRS,Name)->
	io:format("parseXRS ~p~n!",[XRS]),
    {ok,XRS}.


makeRIP(Name)->
	io:format("makeRIP!").

parseRIP(RIP,Name)->
	io:format("parseRIP ~p~n!",RIP),
    {ok,RIP}.


makeRAI(Name)->
	io:format("makeRAI!").
parseRAI(RAI,Name)->
	io:format("parseRAI ~p~n!",[RAI]),
    {ok,RAI}.

makeRAC(Name)->
	io:format("makeRAC!").
parseRAC(RAC,Name)->
	io:format("parseRAC ~p~n!",[RAC]),
    {ok,RAC}.


makeSCI(Name)->
	io:format("makeSCI!").
parseSCI(SCI,Name)->
	io:format("parseSCI ~p~n!",[SCI]),
    {ok,SCI}.

makeSCR(Name)->
	io:format("makeSCR!").
parseSCR(SCR,Name)->
	io:format("parseSCR ~p~n!",[SCR]),
    {ok,SCR}.

makeACS(Name)->
    io:format("makeACS!").
parseACS(ACS,Name)->
    io:format("parseACS ~p~n",[ACS]),
    {ok,ACS}.
