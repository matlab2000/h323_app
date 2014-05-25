-module(rasdb).
-author('xueys').
%-compile(export_all).
-export([makeTerTable/1,deleteTerTable/0,lookupTable/2,nameFromIndex/1]).

-export([updateGKID/2,updateEPID/2,updateRasSock/2,updateQ931ListenSock/2,
        updateQ931ConnectSock/2,updateH245ListenSock/2,updateH245ConnectSock/2,
        updateOrig/2,updateCRV/2]).

-export([getAndIncreaseCryptoRand/1,getAndIncreaseSeqNum/1,updateCryptoRand/2]).
-export([updateRecord/3]).

-import(rasutil,[localIP/0]).

-include_lib("kernel/include/inet.hrl").

-include("H235-SECURITY-MESSAGES.hrl").
-include("H323-MESSAGES.hrl").
-include("ras.hrl").



makeTerTable(Num)->
    case ets:info(rasinfoTbl) of 
        undefined ->
	        ets:new(gkTbl,[public,set,named_table,{keypos,#gk.name}]),
	        ets:new(peerTbl,[public,set,named_table,{keypos,#peer.name}]),
            ets:new(terminalTbl,[public,set,named_table,{keypos,#terminal.name}]);
        _ ->
	        ets:delete_all_objects(gkTbl),
	        ets:delete_all_objects(peerTbl),
            ets:delete_all_objects(terminalTbl)
    end,
	lists:map( fun (X) -> ets:insert(gkTbl,X) end ,lists:map(fun (Idx) -> generateGkInfo(Idx) end ,lists:seq(1,Num))),
	lists:map( fun (X) -> ets:insert(peerTbl,X) end ,lists:map(fun (Idx) -> generatePeerInfo(Idx) end ,lists:seq(1,Num))),
    lists:map( fun (X) -> ets:insert(terminalTbl,X) end ,lists:map(fun (Idx) -> generateTerInfo(Idx) end ,lists:seq(1,Num))).

deleteTerTable() ->
	case ets:info(gkTbl) of
		undefined ->
			io:format("gkTbl not exists");
		_ ->
			ets:delete(gkTbl)
	end,
	case ets:info(peerTbl) of
		undefined ->
			io:format("peerTbl not exists");
		_ ->
			ets:delete(peerTbl)
	end,
    case ets:info(terminalTbl) of
        undefined ->
            io:format("terminalTbl not exists");
        _ ->
            ets:delete(terminalTbl)
    end.

nameFromIndex(Index) ->
    ?NAMEPREFIX++integer_to_list(Index).

lookupTable(Index,Type) when is_integer(Index) ->
    Name=nameFromIndex(Index),
	lookupTable(Name,Type);
lookupTable(Name,Type) when is_list(Name) ->
    case tblType2Name(Type) of
        {ok,TblName} ->
            ets:lookup(TblName,Name);
        _ ->
            io:format("lookupTable type ~p not ok~n",[Type])
	end.

updateRecord(Type,Key,Spec)->
    updateElement(Type,Key,Spec).

replaceRecord(Type,Record) ->
	case tblType2Name(Type) of
		{ok,TblName} ->
            Name=element(1,Record),
            ets:delete(TblName,Name),
			ets:insert(TblName,Record);
		_ ->
			io:format("replaceRecord table type  ~p not ok~n",[Type])
	end.


getAndIncreaseCryptoRand(Name) ->
	Type=terminal,
    TerInfo=hd(lookupTable(Name,Type)),
    #terminal{random=Rand}=TerInfo,
    updateElement(Type,Name,[{#terminal.random,Rand+1}]),
    Rand.

updateCryptoRand(Name,Rand) ->
	Type=terminal,
	updateElement(Type,Name,[{#terminal.random,Rand}]).


getAndIncreaseSeqNum(Name) ->
	Type=terminal,
	TerInfo=hd(lookupTable(Name,Type)),
	#terminal{seqNum  =Seq}=TerInfo,
	updateElement(Type,Name,[{#terminal.seqNum,Seq+1}]),
	Seq.

updateGKID(Name,GKID) ->
	Type=gk,
	updateElement(Type,Name,[{#gk.gkid,GKID}]).

updateEPID(Name,EPID) ->
	Type=gk,
	updateElement(Type,Name,[{#gk.epid,EPID}]).


updateRasSock(Name,Sock) ->
	Type=gk,
	updateElement(Type,Name,[{#gk.rasSock,Sock}]).

updateQ931ListenSock(Name,Sock)->
	Type=terminal,
	updateElement(Type,Name,[{#terminal.q931Sock,Sock}]).

updateQ931ConnectSock(Name,Sock)->
	Type=peer,
	updateElement(Type,Name,[{#peer.q931Sock,Sock}]).

updateH245ListenSock(Name,Sock)->
	Type=terminal,
	updateElement(Type,Name,[{#terminal.h245Sock,Sock}]).

updateH245ConnectSock(Name,Sock)->
	Type=peer,
	updateElement(Type,Name,[{#peer.h245Sock,Sock}]).

updateOrig(Name,IsOrig) ->
	Type=peer,
	updateElement(Type,Name,[{#peer.isOrig,IsOrig}]).

updateCRV(Name,CRV) ->
    Type=peer,
    updateElement(Type,Name,[{#peer.crv,CRV}]).
%%%%%%%%%%%%%%%%inner%%%%%%%%%%%%%%%%%%%%%%%%%%%%

generateGkInfo(Index)->
	IP=tuple_to_list(localIP()),
	#gk{
		name=?NAMEPREFIX ++integer_to_list(Index),
		ip=IP,
		rasPort = ?BASERASPORT+Index
	}.

generatePeerInfo(Index)->
	#peer{
		name=?NAMEPREFIX ++integer_to_list(Index),
		q931Port =?BASECALLPORT+Index ,
		h245Port =?BASECONTROLPORT+Index
	}.

generateTerInfo(Index)->
	Rand=random:uniform(255),
	IP=tuple_to_list(localIP()),
	#terminal{
		name=?NAMEPREFIX ++integer_to_list(Index),
		ip=IP,
		h323id=?H323IDPREFIX++integer_to_list(Index),
		e164=?E164PREFIX++integer_to_list(Index) ,
		seqNum=Index,
		random=Rand,
		%gk=Gk,
		q931Port = ?LISTEN_BASECALLPORT+Index,
		h245Port = ?LISTEN_BASECONTROLPORT+Index,
		%peer=Peer,
		password="111111"
	}.

tblType2Name(Type) ->
	case Type of
		terminal ->
			{ok,terminalTbl};
		gk ->
			{ok,gkTbl};
		peer ->
			{ok,peerTbl};
		_ ->
			{error,"not valid Type"}
	end.

updateElement(Type,Key,Spec) ->
	case tblType2Name(Type) of
		{ok,TblName} ->
			ets:update_element(TblName,Key,Spec);
		_ ->
			io:format("can't decide table name from type ~p~n",[Type])
	end.

