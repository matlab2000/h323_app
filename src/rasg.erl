-module(rasg).
-author('xueys').
%-compile(export_all).
-export([makeGRQ/1,parseGRQ/2,makeGCF/1,parseGCF/2,makeGRJ/1,parseGRJ/2]).

-import(rasutil,[fixUCS2/1,parseRasAddress/1,authToOIDS/1]).
-import(rasdb,[makeTerTable/1,deleteTerTable/0,nameFromIndex/1,lookupTable/2]).
-import(rasdb,[getAndIncreaseSeqNum/1,updateGKID/2,updateEPID/2,updateRasSock/2,
updateQ931ListenSock/2,updateQ931ConnectSock/2,updateH245ListenSock/2,updateH245ConnectSock/2]).

-include_lib("kernel/include/inet.hrl").

-include("H235-SECURITY-MESSAGES.hrl").
-include("H323-MESSAGES.hrl").
-include("ras.hrl").


makeGRQ(Name) ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=Ip,h323id=H323ID,product = Product,version = Version}=Ter,
	Gk=hd(rasdb:lookupTable(Name,gk)),
	#gk{rasPort = RasPort}=Gk,
	SeqNum=rasdb:getAndIncreaseSeqNum(Name),
    %OIDS= rasutil:authToOIDS(AuthMethods),
    ValidOIDS=[],  %lists:filter(fun (X) -> X =/= undefined end,OIDS),

    GRQ=#'GatekeeperRequest'{
        requestSeqNum=SeqNum,
        protocolIdentifier=?H2250_OID, 
        rasAddress={ipAddress,
            #'TransportAddress_ipAddress'{
             ip =list_to_binary(Ip) ,
             port = RasPort}},
        endpointType=#'EndpointType'{
            vendor = #'VendorIdentifier'{
              vendor = #'H221NonStandard'{
                t35CountryCode = 9,
                t35Extension = 0,
                manufacturerCode = 61},
              productId =  list_to_binary(Product),
              versionId = list_to_binary(Version) 
            },
            mc = false,
            undefinedNode = false}, 
        %gatekeeperIdentifier = asn1_NOVALUE, 
        %callServices = asn1_NOVALUE, 
        endpointAlias =  [{'h323-ID',rasutil:fixUCS2(H323ID)}], %{dialedDigits,E164},
        %alternateEndpoints = asn1_NOVALUE, 
        %tokens = asn1_NOVALUE, 
        %cryptoTokens = asn1_NOVALUE, 
        authenticationCapability = [ {pwdHash,'NULL'}], 
        algorithmOIDs =ValidOIDS, %AlgOIDS,
        %integrity = asn1_NOVALUE, 
        %integrityCheckValue = asn1_NOVALUE, 
        supportsAltGK = 'NULL'
        %featureSet = asn1_NOVALUE, 
        %genericData = asn1_NOVALUE
        },
    %io:format("GRQ record ~p~n",[GRQ]),
    case 'H323-MESSAGES':encode('RasMessage', {gatekeeperRequest,GRQ} ) of
        {ok,Bytes} -> 
            %io:format("encode GRQ ok ~p~n",[Bytes]),
            {ok,Bytes};
            %decH323('H323-UserInformation',Bytes);
        {error,Reason} ->
            io:format("encode GRQ error ~p ~n",[Reason]),
            {error,Reason}
    end.


parseGRQ(GRQ,Name)->
    %#'GatekeeperRequest'{}=
    io:format("parseGRQ ~p~n!",[GRQ]),
    {ok,GRQ}.

makeGCF(Name)->
    io:format("makeGCF!").

parseGCF(#'GatekeeperConfirm'{gatekeeperIdentifier=GKID }=GCF,Name)->
    rasdb:updateGKID(Name,GKID),
    {ok,GCF}.

makeGRJ(Name)->
    io:format("makeGRJ!").

parseGRJ(GRJ,Name)->
    io:format("parseGRJ ~p~n!",[GRJ]),
    {ok,GRJ}.
