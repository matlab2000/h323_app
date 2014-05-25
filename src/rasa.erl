-module(rasa).
-author('xueys').
%-compile(export_all).
-export([makeARQ/1,parseARQ/2,makeACF/1,parseACF/2,makeARJ/1,parseARJ/2]).
-export([makeDRQ/1,parseDRQ/2,makeDCF/1,parseDCF/2,makeDRJ/1,parseDRJ/2]).


-import(rasutil,[fixUCS2/1]).

-import(rasdb,[makeTerTable/1,deleteTerTable/0,nameFromIndex/1,lookupTable/2]).
-import(rasdb,[getAndIncreaseSeqNum/1,updateGKID/2,updateEPID/2,updateRasSock/2,
updateQ931ListenSock/2,updateQ931ConnectSock/2,updateH245ListenSock/2,updateH245ConnectSock/2]).


-include_lib("kernel/include/inet.hrl").

-include("H235-SECURITY-MESSAGES.hrl").
-include("H323-MESSAGES.hrl").
-include("ras.hrl").

makeARQ(Name)->
    Peer=hd(rasdb:lookupTable(Name,peer)),
    %#peer{ip=PeerIP,h323id=PeerH323ID,e164=PeerE164,q931Port=PeerPort,confID=CONFID,callID=CALLID,crv=CRV}=Peer,

    makeARQ(Name,Peer).

makeARQ(Name,Peer)->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{h323id=H323ID,e164=E164,password=Password,terauth=AuthMethods}=Ter,
	Gk=hd(rasdb:lookupTable(Name,gk)),
	#gk{gkid=GKID,epid=EPID}=Gk,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{e164=PeerE164,h323id=PeerH323ID,crv=CRV,confID=CONFID,rate=Rate}=Peer,


    Timestamp=rasutil:makeTimeStamp(),%calendar:datetime_to_gregorian_seconds(erlang:universaltime()),  %1345742767,
    
    %OIDS= rasutil:authToOIDS(Auth), %lists:map( fun (X) -> authToOID(X) end, Auth ),
    AuthMethod=lists:nth(1,AuthMethods),
    io:format("makeARQ AuthMethod ~p~n",[AuthMethods]),
    {ok,ClearToken,CryptoToken}=rascrypto:makeCryptToken(Name,Timestamp, AuthMethod) , %?MD5_OID)    
    %[Clear,Crypto]=lists:foldr(fun (X) -> rascrypto:makeCryptToken(Name,Timestamp,X),[[],[]],OIDS),
    Clear=case AuthMethod of
        'cat' ->
            [ClearToken];
        Other ->
            asn1_NOVALUE
    end,
    Crypto=[CryptoToken],

	SeqNum=rasdb:getAndIncreaseSeqNum(Name),

    ARQ= {'AdmissionRequest',
        requestSeqNum=SeqNum,
        callType={pointToPoint,'NULL'},
        % callModel=asn1_NOVALUE,
        endpointIdentifier=rasutil:fixUCS2(EPID) ,
        destinationInfo=[{'dialedDigits',PeerE164},{'h323-ID',rasutil:fixUCS2(PeerH323ID)}],
        % destCallSignalAddress=asn1_NOVALUE,
        % destExtraCallInfo=asn1_NOVALUE,
        srcInfo=[{dialedDigits,E164},{'h323-ID',rasutil:fixUCS2(H323ID)}],
        % srcCallSignalAddress=asn1_NOVALUE,
        bandWidth= Rate,
        callReferenceValue=CRV,
        % nonStandardData=asn1_NOVALUE,
        % callServices=asn1_NOVALUE,
        conferenceID= CONFID,
        activeMC=false,
        answerCall=false,
        canMapAlias=true,
        callIdentifier=#'CallIdentifier'{
          guid= CONFID },
        % srcAlternatives=asn1_NOVALUE,
        % destAlternatives=asn1_NOVALUE,
        gatekeeperIdentifier=rasutil:fixUCS2(GKID) ,
        tokens=Clear,
        cryptoTokens=  Crypto,
        % integrityCheckValue=asn1_NOVALUE,
        % transportQOS=asn1_NOVALUE,
        % willSupplyUUIEs=true,
        % callLinkage=asn1_NOVALUE,
        % gatewayDataRate=asn1_NOVALUE,
        % capacity=asn1_NOVALUE,
        % circuitInfo=asn1_NOVALUE,
        % desiredProtocols=asn1_NOVALUE,
        % desiredTunnelledProtocol=asn1_NOVALUE,
        % featureSet=asn1_NOVALUE,
        % genericData=asn1_NOVALUE,
        canMapSrcAlias=false
        },

    io:format("makeARQ ARQ ~p~n",[ARQ]),
    
    case 'H323-MESSAGES':encode('RasMessage', {admissionRequest,ARQ} ) of
        {ok,Bytes} -> 
            io:format("encode ARQ ok ~p~n",[Bytes]),
            rascrypto:makeAllCryptoToken(Name,AuthMethod,Bytes);
        {error,Reason} ->
            io:format("encode ARQ error ~p ~n",[Reason]),
            {error,Reason}
    end.
    
parseARQ(ARQ,Name)->
    io:format("parseARQ ~p~n!",[ARQ]),
    {ok,ARQ}.

makeACF(Name)->
    io:format("makeACF!").
parseACF(ACF,Name)->
    io:format("parseACF ~p~n!",[ACF]),
    {ok,ACF}.

makeARJ(Name)->
    io:format("makeARJ!").
parseARJ(ARJ,Name)->
    io:format("parseARJ ~p~n!",[ARJ]),
    {ok,ARJ}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
makeDRQ(Name)->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{h323id=H323ID,e164=E164,password=Password,terauth=AuthMethods}=Ter,
	Gk=hd(rasdb:lookupTable(Name,gk)),
	#gk{gkid=GKID,epid=EPID}=Gk,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{e164=PeerE164,h323id=PeerH323ID,crv=CRV,confID=CONFID,rate=Rate}=Peer,

    Timestamp=rasutil:makeTimeStamp(),%calendar:datetime_to_gregorian_seconds(erlang:universaltime()),  %1345742767,
    
    %OIDS= rasutil:authToOIDS(Auth), %lists:map( fun (X) -> authToOID(X) end, Auth ),
    AuthMethod=lists:nth(1,AuthMethods),
    io:format("makeDRQ AuthMethod ~p~n",[AuthMethods]),
    {ok,ClearToken,CryptoToken}=rascrypto:makeCryptToken(Name,Timestamp, AuthMethod) , %?MD5_OID)    
    %[Clear,Crypto]=lists:foldr(fun (X) -> rascrypto:makeCryptToken(Name,Timestamp,X),[[],[]],OIDS),
    Clear=case AuthMethod of
        'cat' ->
            [ClearToken];
        Other ->
            asn1_NOVALUE
    end,
    Crypto=[CryptoToken],

    DRQ=#'DisengageRequest'{
        requestSeqNum=15984,
        endpointIdentifier= rasutil:fixUCS2(EPID) ,
        conferenceID = CONFID,
        callReferenceValue = CRV,
        disengageReason = {normalDrop,'NULL'},
        nonStandardData = asn1_NOVALUE,
        callIdentifier = #'CallIdentifier'{
                  guid = CONFID },
        gatekeeperIdentifier = rasutil:fixUCS2(GKID),
        tokens=Clear,
        cryptoTokens = Crypto, 
        integrityCheckValue=asn1_NOVALUE,
        answeredCall=false,
        callLinkage=asn1_NOVALUE,
        capacity=asn1_NOVALUE,
        circuitInfo=asn1_NOVALUE,
        usageInformation=#'RasUsageInformation'{nonStandardUsageFields=[],alertingTime=1345742776,connectTime=1345742779,
                  endTime=1345742782},
        terminationCause={releaseCompleteCauseIE,<<128,144>>},
        serviceControl=asn1_NOVALUE,
        genericData=asn1_NOVALUE
        },


    io:format("makeDRQ DRQ ~p~n",[DRQ]),
    
    case 'H323-MESSAGES':encode('RasMessage', {disengageRequest,DRQ} ) of
        {ok,Bytes} -> 
            io:format("encode DRQ ok ~p~n",[Bytes]),
            rascrypto:makeAllCryptoToken(Name,AuthMethod,Bytes);
        {error,Reason} ->
            io:format("encode DRQ error ~p ~n",[Reason]),
            {error,Reason}
    end.

parseDRQ(DRQ,Name)->
    io:format("parseDRQ ~p~n",[DRQ]),
    {ok,DRQ}.

makeDCF(Name)->
    io:format("makeDCF!").
parseDCF(DCF,Name)->
    io:format("parseDCF ~p~n!",[DCF]),
    {ok,DCF}.

makeDRJ(Name)->
    io:format("makeDRJ!").
parseDRJ(DRJ,Name)->
    io:format("parseDRJ ~p~n!",[DRJ]),
    {ok,DRJ}.
