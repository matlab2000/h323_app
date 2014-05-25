-module(q931).
-author('xueys').
-compile(export_all).

-include("H235-SECURITY-MESSAGES.hrl").
-include("H323-MESSAGES.hrl").
-include("ras.hrl").
-include("q931.hrl").

-import(rasutil,[fixUCS2/1,parseRasAddress/1]).

-import(rasdb,[makeTerTable/1,deleteTerTable/0,nameFromIndex/1,lookupTable/2]).
-import(rasdb,[getAndIncreaseSeqNum/1,updateGKID/2,updateEPID/2,updateRasSock/2,
    updateRecord/3,
    updateQ931ListenSock/2,updateQ931ConnectSock/2,
    updateH245ListenSock/2,updateH245ConnectSock/2]).

-export([decodeQ931/2]).
-export([encodeQ931/2]).

getEndpointType(Name)->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{product=Product,version=Version}=Ter,

	#'EndpointType'{
		nonStandardData = asn1_NOVALUE,
		vendor = #'VendorIdentifier'{
			vendor = #'H221NonStandard'{t35CountryCode = 86, t35Extension = 0, manufacturerCode = 1},
			productId = list_to_binary(Product),
			versionId = list_to_binary(Version),
			enterpriseNumber = asn1_NOVALUE
		},
		gatekeeper = asn1_NOVALUE,
		gateway = asn1_NOVALUE,
		mcu = #'McuInfo'{nonStandardData = asn1_NOVALUE, protocol = asn1_NOVALUE},
		terminal = asn1_NOVALUE,
		mc = false,
		undefinedNode = false,
		set = asn1_NOVALUE,
		supportedTunnelledProtocols = asn1_NOVALUE}.

getSourceInfo(Name) ->
	getEndpointType(Name).

getDestInfo(Name) ->
	getEndpointType(Name).

encodeSetup(Name) when is_list(Name) ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=IP,q931Port = Q931Port,e164=E164,h323id=H323ID,product=Product,version=Version,terauth=AuthMethods}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{ip=PeerIP,h323id=PeerH323ID,e164=PeerE164,q931Port=PeerPort,confID=CONFID,callID=CALLID}=Peer,

	Setup_UUIE = #'Setup-UUIE'{
		protocolIdentifier = ?H225v4,
		h245Address = asn1_NOVALUE,
		sourceAddress = [{'h323-ID',rasutil:fixUCS2(H323ID)}],
		sourceInfo = getSourceInfo(Name),
		%destinationAddress = [{dialedDigits, PeerE164}],
		destCallSignalAddress = {ipAddress,
			#'TransportAddress_ipAddress'{
				ip = list_to_binary(PeerIP),
				port = PeerPort}},
		destExtraCallInfo = asn1_NOVALUE,
		destExtraCRV = asn1_NOVALUE,
		activeMC = false,
		conferenceID = CONFID,
		conferenceGoal = {create, 'NULL'},
		callServices = asn1_NOVALUE,
		callType = {pointToPoint, 'NULL'},
		sourceCallSignalAddress = {ipAddress,
			#'TransportAddress_ipAddress'{ip = list_to_binary(IP), port = Q931Port}},
		remoteExtensionAddress = asn1_NOVALUE,
		callIdentifier = #'CallIdentifier'{ guid = CALLID },
		h245SecurityCapability = asn1_NOVALUE,
		tokens = asn1_NOVALUE,
		cryptoTokens = asn1_NOVALUE,
		fastStart = asn1_NOVALUE,
		mediaWaitForConnect = false,
		canOverlapSend = false,
		endpointIdentifier = asn1_NOVALUE,
		multipleCalls = false,
		maintainConnection = false,
		connectionParameters = asn1_NOVALUE,
		language = asn1_NOVALUE,
		presentationIndicator = asn1_NOVALUE,
		screeningIndicator = asn1_NOVALUE,
		serviceControl = asn1_NOVALUE,
		symmetricOperationRequired = asn1_NOVALUE,
		capacity = asn1_NOVALUE,
		circuitInfo = asn1_NOVALUE,
		desiredProtocols = asn1_NOVALUE,
		neededFeatures = asn1_NOVALUE,
		desiredFeatures = asn1_NOVALUE,
		supportedFeatures = asn1_NOVALUE,
		parallelH245Control = asn1_NOVALUE,
		additionalSourceAddresses = asn1_NOVALUE,
		hopCount = asn1_NOVALUE
	},
	Setup = #'H323-UserInformation'{
		'h323-uu-pdu' = #'H323-UU-PDU'{
			'h323-message-body' = {setup, Setup_UUIE},
			nonStandardData = asn1_NOVALUE,
			h4501SupplementaryService = asn1_NOVALUE,
			h245Tunneling = false,
			h245Control = asn1_NOVALUE,
			nonStandardControl = asn1_NOVALUE,
			callLinkage = asn1_NOVALUE,
			tunnelledSignallingMessage = asn1_NOVALUE,
			provisionalRespToH245Tunneling = asn1_NOVALUE,
			stimulusControl = asn1_NOVALUE,
			genericData = asn1_NOVALUE
		},
		'user-data' = asn1_NOVALUE
	},
    %io:format("Setup is ~p~n",[Setup]),
	case 'H323-MESSAGES':encode('H323-UserInformation', Setup) of
		{ok, Bytes} ->
			{ok, Bytes};
		{error, Reason} ->
            io:format("encode setup error,Setup is ~p~n",[Setup]),
			{error, Reason}
	end.

encodeAlerting(Name) ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=IP,q931Port = Q931Port,e164=E164,h323id=H323ID,product=Product,version=Version,terauth=AuthMethods}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{ip=PeerIP,h323id=PeerH323ID,e164=PeerE164,q931Port=PeerPort,confID=CONFID,callID=CALLID,crv=CRV}=Peer,

	Alerting_UUIE = #'Alerting-UUIE'{
		protocolIdentifier = ?H225v4,
		destinationInfo = getDestInfo(Name),
		h245Address = asn1_NOVALUE,
		callIdentifier = CALLID,
		h245SecurityMode = asn1_NOVALUE,
		tokens = asn1_NOVALUE,
		cryptoTokens = asn1_NOVALUE,
		fastStart = asn1_NOVALUE,
		multipleCalls = false,
		maintainConnection = false,
		alertingAddress = asn1_NOVALUE,
		presentationIndicator = asn1_NOVALUE,
		screeningIndicator = asn1_NOVALUE,
		fastConnectRefused = asn1_NOVALUE,
		serviceControl = asn1_NOVALUE,
		capacity = asn1_NOVALUE,
		featureSet = asn1_NOVALUE
	},

	Alerting = #'H323-UserInformation'{
		'h323-uu-pdu' = #'H323-UU-PDU'{
			'h323-message-body' = {alerting, Alerting_UUIE},
			nonStandardData = asn1_NOVALUE,
			h4501SupplementaryService = asn1_NOVALUE,
			h245Tunneling = false,
			h245Control = asn1_NOVALUE,
			nonStandardControl = asn1_NOVALUE,
			callLinkage = asn1_NOVALUE,
			tunnelledSignallingMessage = asn1_NOVALUE,
			provisionalRespToH245Tunneling = asn1_NOVALUE,
			stimulusControl = asn1_NOVALUE,
			genericData = asn1_NOVALUE
		},
		'user-data' = asn1_NOVALUE
	},

	case 'H323-MESSAGES':encode('H323-UserInformation', Alerting) of
		{ok, Bytes} ->
			{ok, Bytes};
		{error, Reason} ->
			{error, Reason}
	end.


encodeCallProceeding(Name) ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=IP,q931Port = Q931Port,e164=E164,h323id=H323ID,product=Product,version=Version,terauth=AuthMethods}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{ip=PeerIP,h323id=PeerH323ID,e164=PeerE164,q931Port=PeerPort,confID=CONFID,callID=CALLID,crv=CRV}=Peer,

	CallProceeding_UUIE = #'CallProceeding-UUIE'{
		protocolIdentifier = ?H225v4,
		destinationInfo = getDestInfo(Name),
		h245Address = asn1_NOVALUE,
		callIdentifier = CALLID,
		h245SecurityMode = asn1_NOVALUE,
		tokens = asn1_NOVALUE,
		cryptoTokens = asn1_NOVALUE,
		fastStart = asn1_NOVALUE,
		multipleCalls = false,
		maintainConnection = false,
		fastConnectRefused = asn1_NOVALUE,
		featureSet = asn1_NOVALUE
	},

	CallProceeding = #'H323-UserInformation'{
		'h323-uu-pdu' = #'H323-UU-PDU'{
			'h323-message-body' = {callProceeding, CallProceeding_UUIE},
			nonStandardData = asn1_NOVALUE,
			h4501SupplementaryService = asn1_NOVALUE,
			h245Tunneling = false,
			h245Control = asn1_NOVALUE,
			nonStandardControl = asn1_NOVALUE,
			callLinkage = asn1_NOVALUE,
			tunnelledSignallingMessage = asn1_NOVALUE,
			provisionalRespToH245Tunneling = asn1_NOVALUE,
			stimulusControl = asn1_NOVALUE,
			genericData = asn1_NOVALUE
		},
		'user-data' = asn1_NOVALUE
	},

	case 'H323-MESSAGES':encode('H323-UserInformation', CallProceeding) of
		{ok, Bytes} ->
			{ok, Bytes};
		{error, Reason} ->
			{error, Reason}
	end.


encodeConnect(Name) ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=IP,q931Port = Q931Port,e164=E164,h323id=H323ID,product=Product,version=Version,terauth=AuthMethods}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{confID=CONFID,callID=CALLID}=Peer,

	Connect_UUIE = #'Connect-UUIE'{
		protocolIdentifier = ?H225v4,
		h245Address = asn1_NOVALUE,
		destinationInfo = getDestInfo(Name),
		conferenceID = CONFID,
		callIdentifier = CALLID,
		h245SecurityMode = asn1_NOVALUE,
		tokens = asn1_NOVALUE,
		cryptoTokens = asn1_NOVALUE,
		fastStart = asn1_NOVALUE,
		multipleCalls = false,
		maintainConnection = false,
		language = asn1_NOVALUE,
		connectedAddress = asn1_NOVALUE,
		presentationIndicator = asn1_NOVALUE,
		screeningIndicator = asn1_NOVALUE,
		fastConnectRefused = asn1_NOVALUE,
		serviceControl = asn1_NOVALUE,
		capacity = asn1_NOVALUE,
		featureSet = asn1_NOVALUE

	},

	Connect = #'H323-UserInformation'{
		'h323-uu-pdu' = #'H323-UU-PDU'{
			'h323-message-body' = {connect, Connect_UUIE},
			nonStandardData = asn1_NOVALUE,
			h4501SupplementaryService = asn1_NOVALUE,
			h245Tunneling = false,
			h245Control = asn1_NOVALUE,
			nonStandardControl = asn1_NOVALUE,
			callLinkage = asn1_NOVALUE,
			tunnelledSignallingMessage = asn1_NOVALUE,
			provisionalRespToH245Tunneling = asn1_NOVALUE,
			stimulusControl = asn1_NOVALUE,
			genericData = asn1_NOVALUE
		},
		'user-data' = asn1_NOVALUE
	},

	case 'H323-MESSAGES':encode('H323-UserInformation', Connect) of
		{ok, Bytes} ->
			{ok, Bytes};
		{error, Reason} ->
			{error, Reason}
	end.

encodeInformation(Name) ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=IP,q931Port = Q931Port,e164=E164,h323id=H323ID,product=Product,version=Version,terauth=AuthMethods}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{ip=PeerIP,h323id=PeerH323ID,e164=PeerE164,q931Port=PeerPort,confID=CONFID,callID=CALLID,crv=CRV}=Peer,

	Information_UUIE = #'Information-UUIE'{
		protocolIdentifier = ?H225v4,
		callIdentifier = CALLID,
		tokens = asn1_NOVALUE,
		cryptoTokens = asn1_NOVALUE,
		fastStart = asn1_NOVALUE,
		fastConnectRefused = asn1_NOVALUE,
		circuitInfo = asn1_NOVALUE
	},

	Information = #'H323-UserInformation'{
		'h323-uu-pdu' = #'H323-UU-PDU'{
			'h323-message-body' = {information, Information_UUIE},
			nonStandardData = asn1_NOVALUE,
			h4501SupplementaryService = asn1_NOVALUE,
			h245Tunneling = false,
			h245Control = asn1_NOVALUE,
			nonStandardControl = asn1_NOVALUE,
			callLinkage = asn1_NOVALUE,
			tunnelledSignallingMessage = asn1_NOVALUE,
			provisionalRespToH245Tunneling = asn1_NOVALUE,
			stimulusControl = asn1_NOVALUE,
			genericData = asn1_NOVALUE
		},
		'user-data' = asn1_NOVALUE
	},

	case 'H323-MESSAGES':encode('H323-UserInformation', Information) of
		{ok, Bytes} ->
			{ok, Bytes};
		{error, Reason} ->
			{error, Reason}
	end.

encodeReleaseComplete(Name) ->

	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=IP,q931Port = Q931Port,e164=E164,h323id=H323ID,product=Product,version=Version,terauth=AuthMethods}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{ip=PeerIP,h323id=PeerH323ID,e164=PeerE164,q931Port=PeerPort,confID=CONFID,callID=CALLID,crv=CRV}=Peer,

	ReleaseComplete_UUIE = #'ReleaseComplete-UUIE'{
		protocolIdentifier = ?H225v4,
		reason = asn1_NOVALUE,
		callIdentifier = CALLID,
		tokens = asn1_NOVALUE,
		cryptoTokens = asn1_NOVALUE,
		busyAddress = asn1_NOVALUE,
		presentationIndicator = asn1_NOVALUE,
		screeningIndicator = asn1_NOVALUE,
		capacity = asn1_NOVALUE,
		serviceControl = asn1_NOVALUE,
		featureSet = asn1_NOVALUE
	},

	ReleaseComplete = #'H323-UserInformation'{
		'h323-uu-pdu' = #'H323-UU-PDU'{
			'h323-message-body' = {releaseComplete, ReleaseComplete_UUIE},
			nonStandardData = asn1_NOVALUE,
			h4501SupplementaryService = asn1_NOVALUE,
			h245Tunneling = false,
			h245Control = asn1_NOVALUE,
			nonStandardControl = asn1_NOVALUE,
			callLinkage = asn1_NOVALUE,
			tunnelledSignallingMessage = asn1_NOVALUE,
			provisionalRespToH245Tunneling = asn1_NOVALUE,
			stimulusControl = asn1_NOVALUE,
			genericData = asn1_NOVALUE
		},
		'user-data' = asn1_NOVALUE
	},

	case 'H323-MESSAGES':encode('H323-UserInformation', ReleaseComplete) of
		{ok, Bytes} ->
			{ok, Bytes};
		{error, Reason} ->
			{error, Reason}
	end.

encodeFacility(Name) ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=IP,q931Port = Q931Port,e164=E164,h323id=H323ID,product=Product,version=Version,terauth=AuthMethods}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{ip=PeerIP,h323id=PeerH323ID,e164=PeerE164,q931Port=PeerPort,confID=CONFID,callID=CALLID,crv=CRV}=Peer,

	Facility_UUIE = #'Facility-UUIE'{
		protocolIdentifier = ?H225v4,
		alternativeAddress = asn1_NOVALUE,
		alternativeAliasAddress = asn1_NOVALUE,
		conferenceID = asn1_NOVALUE,
		reason = {routeCallToGatekeeper, 'NULL'},
		callIdentifier = CALLID,
		destExtraCallInfo = asn1_NOVALUE,
		remoteExtensionAddress = asn1_NOVALUE,
		tokens = asn1_NOVALUE,
		cryptoTokens = asn1_NOVALUE,
		conferences = asn1_NOVALUE,
		h245Address = asn1_NOVALUE,
		fastStart = asn1_NOVALUE,
		multipleCalls = false,
		maintainConnection = false,
		fastConnectRefused = asn1_NOVALUE,
		serviceControl = asn1_NOVALUE,
		circuitInfo = asn1_NOVALUE,
		featureSet = asn1_NOVALUE,
		destinationInfo = asn1_NOVALUE,
		h245SecurityMode = asn1_NOVALUE
	},

	Facility = #'H323-UserInformation'{
		'h323-uu-pdu' = #'H323-UU-PDU'{
			'h323-message-body' = {facility, Facility_UUIE},
			nonStandardData = asn1_NOVALUE,
			h4501SupplementaryService = asn1_NOVALUE,
			h245Tunneling = false,
			h245Control = asn1_NOVALUE,
			nonStandardControl = asn1_NOVALUE,
			callLinkage = asn1_NOVALUE,
			tunnelledSignallingMessage = asn1_NOVALUE,
			provisionalRespToH245Tunneling = asn1_NOVALUE,
			stimulusControl = asn1_NOVALUE,
			genericData = asn1_NOVALUE
		},
		'user-data' = asn1_NOVALUE
	},

	case 'H323-MESSAGES':encode('H323-UserInformation', Facility) of
		{ok, Bytes} ->
			{ok, Bytes};
		{error, Reason} ->
			{error, Reason}
	end.

encodeProgress(Name) ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=IP,q931Port = Q931Port,e164=E164,h323id=H323ID,product=Product,version=Version,terauth=AuthMethods}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{ip=PeerIP,h323id=PeerH323ID,e164=PeerE164,q931Port=PeerPort,confID=CONFID,callID=CALLID,crv=CRV}=Peer,

	Progress_UUIE = #'Progress-UUIE'{
		protocolIdentifier = ?H225v4,
		destinationInfo = getDestInfo(Name),
		h245Address = asn1_NOVALUE,
		callIdentifier = CALLID,
		h245SecurityMode = asn1_NOVALUE,
		tokens = asn1_NOVALUE,
		cryptoTokens = asn1_NOVALUE,
		fastStart = asn1_NOVALUE,
		multipleCalls = false,
		maintainConnection = false,
		fastConnectRefused = asn1_NOVALUE
	},

	Progress = #'H323-UserInformation'{
		'h323-uu-pdu' = #'H323-UU-PDU'{
			'h323-message-body' = {progress, Progress_UUIE},
			nonStandardData = asn1_NOVALUE,
			h4501SupplementaryService = asn1_NOVALUE,
			h245Tunneling = false,
			h245Control = asn1_NOVALUE,
			nonStandardControl = asn1_NOVALUE,
			callLinkage = asn1_NOVALUE,
			tunnelledSignallingMessage = asn1_NOVALUE,
			provisionalRespToH245Tunneling = asn1_NOVALUE,
			stimulusControl = asn1_NOVALUE,
			genericData = asn1_NOVALUE
		},
		'user-data' = asn1_NOVALUE
	},

	case 'H323-MESSAGES':encode('H323-UserInformation', Progress) of
		{ok, Bytes} ->
			{ok, Bytes};
		{error, Reason} ->
			{error, Reason}
	end.

encodeStatus(Name) ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=IP,q931Port = Q931Port,e164=E164,h323id=H323ID,product=Product,version=Version,terauth=AuthMethods}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{ip=PeerIP,h323id=PeerH323ID,e164=PeerE164,q931Port=PeerPort,confID=CONFID,callID=CALLID,crv=CRV}=Peer,

	Status_UUIE = #'Status-UUIE'{
		protocolIdentifier = ?H225v4,
		callIdentifier = CALLID,
		tokens = asn1_NOVALUE,
		cryptoTokens = asn1_NOVALUE
	},

	Status = #'H323-UserInformation'{
		'h323-uu-pdu' = #'H323-UU-PDU'{
			'h323-message-body' = {status, Status_UUIE},
			nonStandardData = asn1_NOVALUE,
			h4501SupplementaryService = asn1_NOVALUE,
			h245Tunneling = false,
			h245Control = asn1_NOVALUE,
			nonStandardControl = asn1_NOVALUE,
			callLinkage = asn1_NOVALUE,
			tunnelledSignallingMessage = asn1_NOVALUE,
			provisionalRespToH245Tunneling = asn1_NOVALUE,
			stimulusControl = asn1_NOVALUE,
			genericData = asn1_NOVALUE
		},
		'user-data' = asn1_NOVALUE
	},

	case 'H323-MESSAGES':encode('H323-UserInformation', Status) of
		{ok, Bytes} ->
			{ok, Bytes};
		{error, Reason} ->
			{error, Reason}
	end.

encodeStatusInquiry(Name) ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=IP,q931Port = Q931Port,e164=E164,h323id=H323ID,product=Product,version=Version,terauth=AuthMethods}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{ip=PeerIP,h323id=PeerH323ID,e164=PeerE164,q931Port=PeerPort,confID=CONFID,callID=CALLID,crv=CRV}=Peer,

	StatusInquiry_UUIE = #'StatusInquiry-UUIE'{
		protocolIdentifier = ?H225v4,
		callIdentifier = CALLID,
		tokens = asn1_NOVALUE,
		cryptoTokens = asn1_NOVALUE
	},

	StatusInquiry = #'H323-UserInformation'{
		'h323-uu-pdu' = #'H323-UU-PDU'{
			'h323-message-body' = {statusInquiry, StatusInquiry_UUIE},
			nonStandardData = asn1_NOVALUE,
			h4501SupplementaryService = asn1_NOVALUE,
			h245Tunneling = false,
			h245Control = asn1_NOVALUE,
			nonStandardControl = asn1_NOVALUE,
			callLinkage = asn1_NOVALUE,
			tunnelledSignallingMessage = asn1_NOVALUE,
			provisionalRespToH245Tunneling = asn1_NOVALUE,
			stimulusControl = asn1_NOVALUE,
			genericData = asn1_NOVALUE
		},
		'user-data' = asn1_NOVALUE
	},

	case 'H323-MESSAGES':encode('H323-UserInformation', StatusInquiry) of
		{ok, Bytes} ->
			{ok, Bytes};
		{error, Reason} ->
			{error, Reason}
	end.

encodeSetupAcknowledge(Name) ->

	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=IP,q931Port = Q931Port,e164=E164,h323id=H323ID,product=Product,version=Version,terauth=AuthMethods}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{ip=PeerIP,h323id=PeerH323ID,e164=PeerE164,q931Port=PeerPort,confID=CONFID,callID=CALLID,crv=CRV}=Peer,

	SetupAcknowledge_UUIE = #'SetupAcknowledge-UUIE'{
		protocolIdentifier = ?H225v4,
		callIdentifier = CALLID,
		tokens = asn1_NOVALUE,
		cryptoTokens = asn1_NOVALUE
	},

	SetupAcknowledge = #'H323-UserInformation'{
		'h323-uu-pdu' = #'H323-UU-PDU'{
			'h323-message-body' = {setupAcknowledge, SetupAcknowledge_UUIE},
			nonStandardData = asn1_NOVALUE,
			h4501SupplementaryService = asn1_NOVALUE,
			h245Tunneling = false,
			h245Control = asn1_NOVALUE,
			nonStandardControl = asn1_NOVALUE,
			callLinkage = asn1_NOVALUE,
			tunnelledSignallingMessage = asn1_NOVALUE,
			provisionalRespToH245Tunneling = asn1_NOVALUE,
			stimulusControl = asn1_NOVALUE,
			genericData = asn1_NOVALUE
		},
		'user-data' = asn1_NOVALUE
	},

	case 'H323-MESSAGES':encode('H323-UserInformation', SetupAcknowledge) of
		{ok, Bytes} ->
			{ok, Bytes};
		{error, Reason} ->
			{error, Reason}
	end.


encodeNotify(Name) ->

	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=IP,q931Port = Q931Port,e164=E164,h323id=H323ID,product=Product,version=Version,terauth=AuthMethods}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{ip=PeerIP,h323id=PeerH323ID,e164=PeerE164,q931Port=PeerPort,confID=CONFID,callID=CALLID,crv=CRV}=Peer,

	Notify_UUIE = #'Notify-UUIE'{
		protocolIdentifier = ?H225v4,
		callIdentifier = CALLID,
		tokens = asn1_NOVALUE,
		cryptoTokens = asn1_NOVALUE
	},

	Notify = #'H323-UserInformation'{
		'h323-uu-pdu' = #'H323-UU-PDU'{
			'h323-message-body' = {notify, Notify_UUIE},
			nonStandardData = asn1_NOVALUE,
			h4501SupplementaryService = asn1_NOVALUE,
			h245Tunneling = false,
			h245Control = asn1_NOVALUE,
			nonStandardControl = asn1_NOVALUE,
			callLinkage = asn1_NOVALUE,
			tunnelledSignallingMessage = asn1_NOVALUE,
			provisionalRespToH245Tunneling = asn1_NOVALUE,
			stimulusControl = asn1_NOVALUE,
			genericData = asn1_NOVALUE
		},
		'user-data' = asn1_NOVALUE
	},

	case 'H323-MESSAGES':encode('H323-UserInformation', Notify) of
		{ok, Bytes} ->
			{ok, Bytes};
		{error, Reason} ->
			{error, Reason}
	end.

decodeQ931(Filename) when is_list(Filename) ->
	{ok, Bytes} = file:read_file(Filename),
	decodeQ931(Bytes,"Noname").

decodeQ931(Bytes,{Name,Pid}) when is_binary(Bytes) ->
	case Bytes of
		<<Proto:8, 0:4, CRVLen:4, Rest/binary>> ->
			CLen = 8 * CRVLen,
			case Rest of
				<<CRV:CLen, 0:1, MType:7, Rest1/binary>> ->
					Flag = CRV band 16#8000,
					io:format("proto ~p crv ~p mtype ~p caller ~p ~n", [Proto, CRV, MType, Flag == 0]),
					decodeQ931Body(MType, Rest1,{Name,Pid});
				_ ->
					io:format("not q931 frame,CLen ~p~n", [CRVLen]),
					{error, "not q931 frame"}
			end;
		_ ->
			{error, "not q.931 frame"}
	end.

q391Rate2CallRate(TransRate,Rest)->
    case TransRate of
        2#10000 -> 64;
        2#10001 ->128;
        2#10011 ->384;
        2#10101 ->1536;
        2#10111 ->1920;
        2#11000 ->
            case Rest of
                <<Multi,_/binary>> ->
                    Multi*64;
                _->
                    384
            end;
        _->
            384
    end.


decodeBearer(Bytes,{Name,Pid}) ->
	case Bytes of
		<<Ext:1, Coding:2, InfoCap:5, Ext1:1, TransMode:2, TransRate:5, Rest/binary>> ->
            Rate=q391Rate2CallRate(TransRate,Rest),
			gen_server:cast(Pid,{rate,Rate});
		_ ->
			io:format("decodeBearer not ok")
	end.

%% decodeDisplay(Bytes,Name) ->
%% 	io:format("decodeDisplay ~s ~n", [binary_to_list(Bytes)]),
%% 	ok.

lookupType(MType) ->
    M=[{?ALERTING, "ALERTING"},
        {?CALL_PROCEEDING, "CALL_PROCEEDING"},
        {?CONNECT, "CONNECT"},
        {?CONNECT_ACKNOWLEDGE, "CONNECT_ACKNOWLEDGE"},
        {?PROGRESS, "PROGRESS"},
        {?SETUP, "SETUP"},
        {?SETUP_ACKNOWLEDGE, "SETUP_ACKNOWLEDGE"},
        {?RESUME,"RESUME"},
        {?RESUME_ACKNOWLEDGE,"RESUME_ACKNOWLEDGE"},
        {?RESUME_REJECT,"RESUME_REJECT"},
        {?SUSPEND, "SUSPEND"},
        {?SUSPEND_ACKNOWLEDGE, "SUSPEND_ACKNOWLEDGE"},
        {?SUSPEND_REJECT,"SUSPEND_REJECT"},
        {?USER_INFORMATION, "USER_INFORMATION"},
        {?DISCONNECT, "DISCONNECT"},
        {?RELEASE, "RELEASE"},
        {?RELEASE_COMPLETE, "RELEASE_COMPLETE"},
        {?RESTART, "RESTART"},
        {?RESTART_ACKNOWLEDGE, "RESTART_ACKNOWLEDGE"},
        {?SEGMENT, "SEGMENT"},
        {?CONGESTION_CONTROL, "CONGESTION_CONTROL"},
        {?INFORMATION, "INFORMATION"},
        {?NOTIFY, "NOTIFY"},
        {?STATUS, "STATUS"}
    ],
    case proplists:lookup(MType,M) of

        {MType,Value} ->
            Value;
        none ->
            io_lib:format("Unknown message type ~p ",[MType])
    end.

decodeUserUser(MType, Bytes,{Name,Pid}) ->
	io:format("decodeUserUser MType ~p ~n", [lookupType(MType)]),
    {ok,Msg}='H323-MESSAGES':decode('H323-UserInformation', Bytes),
    gen_server:cast(Pid,{uuie,Msg}),
    {ok,Msg}.

decodeQ931Body(MType, Bytes,{Name,Pid}) when is_integer(MType), is_binary(Bytes) ->
	case Bytes of
		<<0:1, ID:7,Rest/binary>> ->
            {Len1,Rest2}=
                case Rest of
                    <<0:1,Len:15,Rest1/binary>> when ID==?USER_USER ->
                        {Len,Rest1};
                    <<0:1,Len:7,Rest1/binary>> ->
                        {Len,Rest1}
                end,

			case ID of
				?BEARER ->
					case Rest2 of
						<<Bearer:Len1/binary, Rest3/binary>> ->
							decodeBearer(Bearer,{Name,Pid}),
							decodeQ931Body(MType, Rest3,{Name,Pid});
						_ ->
							io:format("Bearer not ok~n")
					end;
				?DISPLAY ->
					case Rest2 of
						<<Display:Len1/binary, Rest3/binary>> ->
							%decodeDisplay(Display,Name),
                            gen_server:cast(Pid,{display,binary_to_list(Display)}),
							decodeQ931Body(MType, Rest3,{Name,Pid});
						_ ->
							io:format("Display not ok ~n")
					end;
				?USER_USER ->
					ULen = Len1 - 1,
					case Rest2 of
						<<Proto, UserUser:ULen/binary, Rest3/binary>> when Proto==5, bit_size(Rest3) > 0 ->
							decodeUserUser(MType, UserUser,{Name,Pid}),
							decodeQ931Body(MType,Rest3,{Name,Pid});
						<<Proto, UserUser:ULen/binary>> when Proto==5 ->
							decodeUserUser(MType, UserUser,{Name,Pid});
						_ ->
							io:format("user-user not match! Rest ~p ByteSize ~p Len ~p ~n", [Rest2, byte_size(Rest2), ULen])
					end;
				_ ->
					io:format("not decoded element info [startswith 0]~p~n", [ID])
			end;
		<<1:1, ID:3, _:4, _/binary>> ->
			io:format("not decoded element info [startswith 1]~p~n", [ID])
	end.

getDataLen(Num) when is_integer(Num) ->
	if
		Num >=16#FF ->
			2;
		true ->
			1
	end.

getCRV(Orig) when is_boolean(Orig) ->
	CRV=random:uniform(65535),
	changeCRV(CRV,Orig).


changeCRV(CRV,Orig) when is_integer(CRV),is_boolean(Orig) ->
	Len=getDataLen(CRV),
	case Orig of
		true ->
			case Len of
				2 ->
					CRV bxor 16#8000;
				1 ->
					CRV bxor 16#80
			end;
		false ->
			case Len of
				2 ->
					CRV band 16#8000;
				1 ->
					CRV band 16#80
			end
	end.

isCRVOrig(CRV) when is_integer(CRV) ->
	case CRV of
		<<0:1,_/binary>> ->
			true;
		_ ->
			false
	end.

callRateToQ931Rate(CallRate) when is_integer(CallRate),(CallRate rem 64) == 0 ->
	case CallRate of
		64 -> 2#10000;
		128 ->2#10001;
		384 ->2#10011;
		1536->2#10101;
		1920->2#10111;
		_ ->2#11000
	end.

encodeBear(Rate) when is_integer(Rate) ->
	Value=callRateToQ931Rate(Rate),
	Multi=Rate/64,
	if
		Value==2#11000 ->
			<<0:1,?BEARER:7,4,1:1,0:2,8:5,0:1,Value,1:1,Multi:7,1:1,1:2,5:5 >>;
		true ->
			<<0:1,?BEARER:7,3,1:1,0:2,8:5,1:1,Value:7,1:1,1:2,5:5>>
	end.

encodeDisplay(Disp) when is_list(Disp) ->
	DLen=length(Disp)+1,
	DispBin=list_to_binary(Disp),
	<<0:1,?DISPLAY:7,DLen,DispBin/binary,0>>.


encodeQ931(Name,MsgType) ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{h323id=H323ID}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{isOrig=Orig,crv=CRV,rate=Rate}=Peer,

    {CRVValue,CRVLen} =
        case MsgType of
            ?SETUP ->
                Orig = true,
                Crv=getCRV(Orig),
                rasdb:updateRecord(peer,  Name,[{#peer.isOrig,Orig},{#peer.crv,Crv}]),
                CrvLen=getDataLen(Crv)*8,
                {Crv,CrvLen};
            _ ->
                CrvLen=getDataLen(CRV)*8,
                {CRV,CrvLen}
        end,
    {ok,Element,UUIE}=
        case MsgType of
            ?SETUP ->
                E=list_to_binary([encodeBear(Rate),encodeDisplay(H323ID)]),
                {ok,IE}=encodeSetup(Name),
                IELen=byte_size(IE)+1,
                UU= <<0:1,?USER_USER:7,IELen:16,5,IE/binary>>,
                {ok,E,UU};
            ?CALL_PROCEEDING ->
                E= <<>>,
                {ok,IE}=encodeCallProceeding(Name),
                {ok,E,IE};
            ?ALERTING ->
                E= <<>>,
                {ok,IE}=encodeAlerting(Name),
                {ok,E,IE};
            ?CONNECT ->
                E= <<>>,
                {ok,IE}=encodeConnect(Name),
                {ok,E,IE};
            _->
                io:format("not our message type ~p~n",[MsgType]),
                E= <<>>,
                IE= <<>>,
                {ok,E,IE}
        end,
    CLen=CRVLen div 8,
    Head= <<?Q931, 0:4, CLen:4,CRVValue:CRVLen,0:1,MsgType:7>>,
	Bytes= <<Head/binary,Element/binary,UUIE/binary>>,
    {ok,Bytes}.