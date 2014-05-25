-module(rasr).
-author('xueys').
%-compile(export_all).
-export([makeRRQ/1,parseRRQ/2,makeRCF/1,parseRCF/2,makeRRJ/1,parseRRJ/2]).
-export([makeURQ/1,parseURQ/2,makeUCF/1,parseUCF/2,makeURJ/1,parseURJ/2]).

-import(rascrypto,[makeCryptToken/3]).
-import(rasutil,[fixUCS2/1,authToOIDS/1]).
-import(rasdb,[generateRasInfo/1,makeRasInfoTable/1,deleteRasInfoTable/0,nameFromIndex/1,lookupRasInfo/1]).
-import(rasdb,[updateRasInfoSeq/2,updateRasInfoGKID/2,updateRasInfoEPID/2,updateRasInfoSock/2]).

-include_lib("kernel/include/inet.hrl").

-include("H235-SECURITY-MESSAGES.hrl").
-include("H323-MESSAGES.hrl").
-include("ras.hrl").

makeRRQ(Name)->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=LocalIP,h323id=H323ID,q931Port = Q931Port,product = Product,version = Version,terauth=AuthMethods}=Ter,
	Gk=hd(rasdb:lookupTable(Name,gk)),
	#gk{rasPort = RasPort,gkid=GKID}=Gk,

    Timestamp=rasutil:makeTimeStamp(),
	{Clear,Crypto}=case AuthMethods of
		[AuthMethod|_] when is_list(AuthMethods) orelse is_tuple(AuthMethods) ->
	        {ok,ClearToken,CryptoToken}=rascrypto:makeCryptToken(Name,Timestamp, AuthMethod) ,
	        case AuthMethod of
		        'cat' ->
			        {[ClearToken],[CryptoToken]};
		        _  ->
			        {asn1_NOVALUE,[CryptoToken]}
	        end;
		_ ->
			{asn1_NOVALUE,asn1_NOVALUE}
	end,
	SeqNum=rasdb:getAndIncreaseSeqNum(Name),

    RRQ=#'RegistrationRequest'{
	    requestSeqNum=SeqNum,
	    protocolIdentifier=?H2250_OID, discoveryComplete=true,
        callSignalAddress=[{ipAddress,
	        #'TransportAddress_ipAddress'{ip=list_to_binary(LocalIP),port=Q931Port}}],
        rasAddress=[{ipAddress,#'TransportAddress_ipAddress'{ip=list_to_binary(LocalIP),port=RasPort}}],
        terminalType=#'EndpointType'{
            vendor = #'VendorIdentifier'{
              vendor = #'H221NonStandard'{
                t35CountryCode = 9,
                t35Extension = 0,
                manufacturerCode = 61},
              productId = list_to_binary(Product),
              versionId = list_to_binary(Version) },
            terminal=#'TerminalInfo'{nonStandardData = asn1_NOVALUE},
            mc = false,
            undefinedNode = false}, 
        terminalAlias = [{'h323-ID',rasutil:fixUCS2(H323ID)}], %{dialedDigits,E164},
        gatekeeperIdentifier = GKID,
        endpointVendor=#'VendorIdentifier'{
              vendor = #'H221NonStandard'{
                t35CountryCode = 9,
                t35Extension = 0,
                manufacturerCode = 61},
              productId = list_to_binary(Product),
              versionId = list_to_binary(Version) },
	    %% with extensions
	    timeToLive = 300,
	    tokens = Clear,
	    cryptoTokens = Crypto,
	    keepAlive = false,
	    willSupplyUUIEs = true,
	    maintainConnection = false,
	    supportsAltGK = 'NULL',
	    usageReportingCapability = #'RasUsageInfoTypes'{nonStandardUsageTypes=[],startTime='NULL',endTime='NULL',terminationCause='NULL'},
	    callCreditCapability = #'CallCreditCapability'{ canEnforceDurationLimit = true}
	    },
    %io:format("makeRRQ RRQ ~p~n",[RRQ]),
    
    case 'H323-MESSAGES':encode('RasMessage', {registrationRequest,RRQ} ) of
        {ok,Bytes} -> 
            %io:format("encode RRQ ok ~p~n",[Bytes]),
	        case AuthMethods of
		        [Auth|_] when is_list(AuthMethods) orelse is_tuple(AuthMethods) ->
                    rascrypto:makeAllCryptoToken(Name,Auth,Bytes);
                _->
					{ok,Bytes}
			end;
        {error,Reason} ->
            io:format("encode RRQ error ~p ~n",[Reason]),
            {error,Reason}
    end.

parseRRQ(RRQ,Name)->
    io:format("parseRRQ ~p~n",[RRQ]).

makeRCF(Name)->
    io:format("makeRCF!").

parseRCF(RCF,Name)->
    #'RegistrationConfirm'{requestSeqNum=Seq,callSignalAddress=Addr,terminalAlias=Alias,gatekeeperIdentifier=GKID,
        endpointIdentifier=EPID,timeToLive=TTL,willRespondToIRR=RspToIRR,preGrantedARQ=PreGrantedARQ}=RCF,
    %io:format("parseRCF ~p~n!",[RCF]),
    rasdb:updateEPID(Name,EPID),
    {ok,RCF}.

makeRRJ(Name)->
    io:format("makeRRJ!").

parseRRJ(RRJ,Name)->
    io:format("parseRRJ ~p~n!",[RRJ]),
    {ok,RRJ}.


makeURQ(Name)->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{h323id=H323ID}=Ter,
	Gk=hd(rasdb:lookupTable(Name,gk)),
	#gk{gkid=GKID,epid=EPID}=Gk,

	SeqNum=rasdb:getAndIncreaseSeqNum(Name),

	URQ=#'UnregistrationRequest'{
		requestSeqNum=SeqNum,
		callSignalAddress=[],
		endpointAlias = [{'h323-ID',rasutil:fixUCS2(H323ID)}],
		nonStandardData = asn1_NOVALUE,
		endpointIdentifier = EPID,
		alternateEndpoints = asn1_NOVALUE,
		gatekeeperIdentifier = GKID,
		tokens = asn1_NOVALUE,
		cryptoTokens = asn1_NOVALUE,
		integrityCheckValue = asn1_NOVALUE,
		reason = asn1_NOVALUE,
		endpointAliasPattern = asn1_NOVALUE,
		supportedPrefixes = asn1_NOVALUE,
		alternateGatekeeper = asn1_NOVALUE,
		genericData = asn1_NOVALUE
	},

	%io:format("makeURQ URQ ~p~n",[URQ]),

	case 'H323-MESSAGES':encode('RasMessage', {unregistrationRequest, URQ}) of
	{ok, Bytes} ->
		%io:format("encode RRQ ok ~p~n", [Bytes]),
		{ok,Bytes};
	{error, Reason} ->
		io:format("encode RRQ error ~p ~n", [Reason]),
		{error, Reason}
	end .

parseURQ(URQ,Name)->
    %io:format("parseURQ ~p~n",[URQ]),
    {ok,URQ}.

makeUCF(Name)->
    io:format("makeUCF!").

parseUCF(UCF,Name)->
    %io:format("parseUCF ~p~n!",[UCF]),
    {ok,UCF}.


makeURJ(Name)->
    io:format("makeURJ!").
parseURJ(URJ,Name)->
    io:format("parseURJ ~p~n!",[URJ]),
    {ok,URJ}.