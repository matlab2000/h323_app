-module(rascrypto).
-author('xueys').
%-compile(export_all).
-export([makeCryptToken/3,makeAllCryptoToken/3]).

-import(rasutil,[fixUCS2/1]).

-import(rasdb,[makeTerTable/1,deleteTerTable/0,nameFromIndex/1,lookupTable/2]).
-import(rasdb,[getAndIncreaseSeqNum/1,updateGKID/2,updateEPID/2,updateRasSock/2,
updateQ931ListenSock/2,updateQ931ConnectSock/2,updateH245ListenSock/2,updateH245ConnectSock/2]).

-include_lib("kernel/include/inet.hrl").

-include("H235-SECURITY-MESSAGES.hrl").
-include("H323-MESSAGES.hrl").
-include("ras.hrl").


makeCryptToken(Name,Timestamp,AuthMethod) when AuthMethod=='md5' ->
    Ter=hd(rasdb:lookupTable(Name,terminal)),
    #terminal{h323id=H323ID,e164=E164,password=Password}=Ter,
	Gk=hd(rasdb:lookupTable(Name,gk)),
	#gk{gkid=GKID}=Gk,

    ClearToken=#'ClearToken'{
        tokenOID= {0,0}, 
        timeStamp = Timestamp, 
        password = rasutil:fixUCS2(Password),
        generalID = rasutil:fixUCS2(H323ID)
        },

    case 'H235-SECURITY-MESSAGES':encode('ClearToken', ClearToken ) of
        {ok,Bytes} ->
            %crypto:hash(md5, Bytes);  
            CryptoToken={cryptoEPPwdHash,
               #'CryptoH323Token_cryptoEPPwdHash'{
                   alias={'h323-ID',fixUCS2(H323ID)},
                   timeStamp=Timestamp,
                   token=#'CryptoH323Token_cryptoEPPwdHash_token'{
                       algorithmOID=?MD5_OID,
                       paramS=#'Params'{ranInt=asn1_NOVALUE,iv8=asn1_NOVALUE,iv16=asn1_NOVALUE},
                       hash= erlang:md5(Bytes)
                }}},   
            {ok,ClearToken,CryptoToken};
        {error,Reason} ->
            io:format("encode ClearToken error ~p ~n",[Reason]),
            {error,Reason}
    end;
makeCryptToken(Name,Timestamp,AuthMethod) when AuthMethod=='cat' ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{h323id=H323ID,e164=E164,password=Password}=Ter,
	Gk=hd(rasdb:lookupTable(Name,gk)),
	#gk{gkid=GKID}=Gk,

    Rand=random:uniform(255),
    PWD= list_to_binary(Password),
    Data = <<Rand:8,PWD/binary,Timestamp:32/integer-big>>,
    Challenge=erlang:md5(Data),
    ClearToken=#'ClearToken'{
        tokenOID= ?CAT_OID, 
        timeStamp = Timestamp, 
        password = rasutil:fixUCS2(Password), 
        challenge = Challenge, 
        random = Rand, 
        generalID = rasutil:fixUCS2(H323ID)
        },

    case 'H235-SECURITY-MESSAGES':encode('ClearToken', ClearToken ) of
        {ok,Bytes} ->
            %crypto:hash(md5, Bytes);  
            CryptoToken={cryptoEPPwdHash,
               #'CryptoH323Token_cryptoEPPwdHash'{
                   alias={'h323-ID',fixUCS2(H323ID)},
                   timeStamp=Timestamp,
                   token=#'CryptoH323Token_cryptoEPPwdHash_token'{
                       algorithmOID=?MD5_OID,
                       paramS=#'Params'{ranInt=asn1_NOVALUE,iv8=asn1_NOVALUE,iv16=asn1_NOVALUE},
                       hash= erlang:md5(Bytes)
                }}},
            {ok,ClearToken#'ClearToken'{password=asn1_NOVALUE},CryptoToken};
        {error,Reason} ->
            io:format("encode ClearToken error ~p ~n",[Reason]),
            {error,Reason}
    end;
makeCryptToken(Name,Timestamp,AuthMethod) when AuthMethod=='h2351_I' ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{h323id=H323ID,e164=E164,password=Password,pattern=Pattern,random=Rand}=Ter,
	Gk=hd(rasdb:lookupTable(Name,gk)),
	#gk{gkid=GKID}=Gk,

    rasdb:updateCryptoRand(Name,Rand+1),

    DHkey=#'DHset'{halfkey= <<0>> , modSize= <<0>>, generator= <<0>>},
    ClearToken=#'ClearToken'{
        tokenOID= ?H235_T_OID, 
        timeStamp = Timestamp, 
        random = Rand, 
        generalID = rasutil:fixUCS2(GKID),
        sendersID= rasutil:fixUCS2(H323ID),
        dhkey=DHkey
        },

    case 'H235-SECURITY-MESSAGES':encode('ClearToken', ClearToken ) of
        {ok,Bytes} ->
            CryptoToken={nestedcryptoToken,{cryptoHashedToken,
                #'CryptoToken_cryptoHashedToken'{
                    tokenOID=?H235_A_OID,
                    hashedVals=ClearToken,
                    token=#'CryptoToken_cryptoHashedToken_token'{
                        algorithmOID=?H235_U_OID,
                        paramS= #'Params'{ranInt=asn1_NOVALUE,iv8=asn1_NOVALUE,iv16=asn1_NOVALUE},
                        hash= Pattern
                    }
                }}},
            {ok,ClearToken,CryptoToken};    
        {error,Reason} ->
            io:format("encode ClearToken error ~p ~n",[Reason]),
            {error,Reason}
    end.

makeAllCryptoToken(Name,AuthMethod,Bytes) ->
    if 
        AuthMethod=='h2351_I' ->
	        Ter=hd(rasdb:lookupTable(Name,terminal)),
	        #terminal{h323id=H323ID,e164=E164,password=Password,pattern=Pattern,random=Rand}=Ter,
	        Gk=hd(rasdb:lookupTable(Name,gk)),
	        #gk{gkid=GKID}=Gk,

            X= <<0,0,0,0,0,0,0,0,0,0,0,0>>,
            PWD= crypto:hash(sha, list_to_binary(Password)),
            %search and set to zero
            BytesZ=binary:replace(Bytes,Pattern,X),
            %mac
            HMAC=crypto:hmac(sha,PWD,BytesZ,12),
            %fill
            [H,T]=binary:split(Bytes,Pattern),
            {ok,list_to_binary([H,HMAC,T])};
        true ->
            {ok,Bytes}
    end.