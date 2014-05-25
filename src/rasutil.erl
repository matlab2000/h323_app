-module(rasutil).
-author('xueys').
%-compile(export_all).
-export([localIP/0,parseRasAddress/1,fixUCS2/1,makeTimeStamp/0,getToken/2]).
-export([authToOIDS/1]).
-export([createServerSock/2,createClientSock/3,createUdpSock/2]).
-import(uuid,[v4/0]).
-import(h323_server,[onSocketEvent/2]).

-include_lib("kernel/include/inet.hrl").

-include("H235-SECURITY-MESSAGES.hrl").
-include("H323-MESSAGES.hrl").
-include("ras.hrl").

-define(TCP_OPTIONS, [binary, {packet, 0}, {active, true}, {reuseaddr, true}]).

% ip2List() ->
%     ip2List("10.129.43.24").

% ip2List( Ip ) when is_list(Ip) ->
%     {ok,Iplist}=inet_parse:address(Ip),
%     tuple_to_list(Iplist).

localIP() ->
    {ok,Hostname}=inet:gethostname(),
    {ok,#hostent{}=Hostent }=inet:gethostbyname(Hostname),
    %io:format("list ~p~n",Hostent#hostent.h_addr_list),
    lists:nth(1,Hostent#hostent.h_addr_list).

parseRasAddress( Addr )->
    case Addr of 
        {ipAddress,#'TransportAddress_ipAddress'{ip=IP,port=PORT}} ->
            {ok,{IP,PORT}};
        _ ->
            {error,"not ipAddress"}
    end.

fixUCS2(Name) when is_list(Name) ->
    Len=length(Name),
    A=lists:nth(Len,Name),
    if 
        A==0 ->
            Name; 
        true -> 
            Name++[0]
    end.

makeTimeStamp()->
    {MegaSecs,Secs,_}=now(),
    MegaSecs*1000000+Secs.

authNameToOID(AuthName) ->
    case AuthName of
        'md5' -> ?MD5_OID;
        'cat' -> ?CAT_OID;
        _ -> undefined
    end.

authToOIDS(Auth) when is_list(Auth) ->
    lists:map( fun (X) -> authNameToOID(X) end, Auth ).

createServerSock(Port,Pid) when is_integer(Port)->
	case gen_tcp:listen(Port, ?TCP_OPTIONS) of
		{ok, LSocket} ->
			spawn(fun() -> acceptServer(LSocket,Pid) end),
            {ok,LSocket};
		{error,Reason} ->
			io:format("create server socket Port ~p error ~p~n",[Port,Reason]),
			{error,Reason}
	end.

% Wait for incoming connections and spawn a process that will process incoming packets.
acceptServer(LSocket,Pid) ->
	case gen_tcp:accept(LSocket,infinity) of
		{ok,Socket} ->
			XPid = spawn(fun() ->
				io:format("Connection accepted ~n", []),
				loopServer(Socket,Pid)
			end),
			gen_tcp:controlling_process(Socket, XPid),
			gen_server:cast(Pid,{acceptNew,LSocket,Socket}),
			acceptServer(LSocket,Pid);
		{error,Reason}->
			io:format("Accept LSocket~p failed,reason ~p~n ",[LSocket,Reason])
	end.


% Echo back whatever data we receive on Socket.
loopServer(Socket,Pid) ->
	%inet:setopts(Socket, [{active, once}]),
	receive
		{tcp, Socket, Data} ->
			gen_server:cast(Pid,{tcp,Socket,Data}),
			loopServer(Socket,Pid);
		{tcp_closed, Socket}->
			gen_server:cast(Pid,{tcp_closed,Socket});
		{tcp_error, Socket, Reason} ->
			io:format("Error on socket ~p reason: ~p~n", [Socket, Reason]),
			gen_server:cast(Pid,{tcp_error,Socket,Reason})
	end.


createClientSock(Host,Port,Pid) ->
	{ok,Sock}=gen_tcp:connect(Host,Port,[binary,{active,true},{packet,0}]),
	XPid = spawn(fun() ->
		loopClient(Sock,Pid)
	end),
	gen_tcp:controlling_process(Sock, XPid),
    {ok,Sock}.

loopClient(Socket,Pid) ->
	receive
		{tcp, Socket, Data} ->
			gen_server:cast(Pid,{tcp,Socket,Data}),
			loopClient(Socket,Pid);
		{tcp_closed, Socket}->
			gen_server:cast(Pid,{tcp_closed,Socket});
		{tcp_error, Socket, Reason} ->
			io:format("Error on socket ~p reason: ~p~n", [Socket, Reason]),
			gen_server:cast(Pid,{tcp_error,Socket,Reason})
	end.

createUdpSock(Port,Pid) ->
	{ok,Sock}=gen_udp:open(Port,[binary,{active,true}]),
	XPid = spawn(fun() ->
		loopUdp(Sock,Pid)
	end),
	gen_udp:controlling_process(Sock, XPid),
    {ok,Sock}.

loopUdp(Socket,Pid)->
	receive
		{udp, Socket,Host,Port,Data} ->
			gen_server:cast(Pid,{udp,Socket,Host,Port,Data}),
            loopUdp(Socket,Pid)
	end.

getToken(Name,Timestamp) ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{terauth = AuthMethods }=Ter,

    AuthMethod=lists:nth(1,AuthMethods),
    {ok,ClearToken,CryptoToken}=rascrypto:makeCryptToken(Name,Timestamp, AuthMethod) , %?MD5_OID)    
    Clear=case AuthMethod of
        'cat' ->
            [ClearToken];
        _  ->
            asn1_NOVALUE
    end,
    Crypto=[CryptoToken],
    {ok,Clear,Crypto}.

