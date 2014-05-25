-module(h245).
-author('xueys').
-compile(export_all).

-include("H235-SECURITY-MESSAGES.hrl").
-include("H323-MESSAGES.hrl").
-include("MULTIMEDIA-SYSTEM-CONTROL.hrl").

-include("ras.hrl").
-include("q931.hrl").
-include("h245.hrl").

-import(rasdb,[makeTerTable/1,deleteTerTable/0,nameFromIndex/1,lookupTable/2]).
-import(rasdb,[getAndIncreaseSeqNum/1,updateGKID/2,updateEPID/2,updateRasSock/2,
updateQ931ListenSock/2,updateQ931ConnectSock/2,updateH245ListenSock/2,updateH245ConnectSock/2]).


-export([decodeH245/2]).
-export([encodeMasterSlaveDetermination/1,
    encodeMasterSlaveDeterminationAck/2,
    encodeMasterSlaveDeterminationReject/1,

    encodeTerminalCapabilitySet/1,
    encodeTerminalCapabilitySetAck/2,
    encodeTerminalCapabilitySetReject/3
]).


% encodeNonStandardMessage() ->
%     NonStandardMessage=#'NonStandardMessage'{
%         requestSeqNum = 123456, 
%         nonStandardData = #''{
%             nonStandardIdentifier=,
%             data=
%         },
%         tokens = asn1_NOVALUE, 
%         cryptoTokens = asn1_NOVALUE, 
%         integrityCheckValue = asn1_NOVALUE, 
%         featureSet = asn1_NOVALUE, 
%         genericData = asn1_NOVALUE}.

%      case 'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',{request ,{nonStandard,NonStandardMessage}}) of
%         {ok,Bytes} -> 
%             {ok,Bytes};
%         {error,Reason} ->
%             {error,Reason}
%     end.   


%     masterSlaveDetermination    MasterSlaveDetermination,

encodeMasterSlaveDetermination(Name) ->
    MasterSlaveDetermination=#'MasterSlaveDetermination'{
        terminalType = 50, 
        statusDeterminationNumber=random:uniform(  trunc(math:pow(2,24)-1))
    },

    'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
	    {request ,{masterSlaveDetermination,MasterSlaveDetermination}}).

encodeMasterSlaveDeterminationAck(Name,MSType) ->
	MasterSlaveDeterminationAck=#'MasterSlaveDeterminationAck'{
		decision={MSType,'NULL'}
	},

	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{masterSlaveDeterminationAck,MasterSlaveDeterminationAck}}).

encodeMasterSlaveDeterminationReject(Name) ->
	MasterSlaveDeterminationReject=#'MasterSlaveDeterminationReject'{
		cause={identicalNumbers,'NULL'}
	},

	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{masterSlaveDeterminationReject,MasterSlaveDeterminationReject}}).

%     terminalCapabilitySet   TerminalCapabilitySet,

getMultipointCap() ->
    #'MultipointCapability'{
        multicastCapability=false, 
        multiUniCastConference=false, 
        mediaDistributionCapability= [#'MediaDistributionCapability'{
            centralizedControl=true, 
            distributedControl=false, 
            centralizedAudio=true, 
            distributedAudio=false, 
            centralizedVideo=true, 
            distributedVideo=false, 
            centralizedData = asn1_NOVALUE, 
            distributedData = asn1_NOVALUE}]
    }.

getRecvSendCap()->
    #'MultipointCapability'{
        multicastCapability=false, 
        multiUniCastConference=false, 
        mediaDistributionCapability= [#'MediaDistributionCapability'{
            centralizedControl=true, 
            distributedControl=false, 
            centralizedAudio=true, 
            distributedAudio=false, 
            centralizedVideo=true, 
            distributedVideo=false, 
            centralizedData = asn1_NOVALUE, 
            distributedData = asn1_NOVALUE}]
    }.


makeDataCap(Name,Rate)->
    #'DataApplicationCapability'{
        application = {h224,{hdlcFrameTunnelling,'NULL'}},
        maxBitRate=trunc(Rate*10)
    }.

makeAudioCap(Name,Caps)->
    All = [
        {g711Alaw64k, 30},
        {g711Alaw56k, 30},
        {g711Ulaw64k, 30},
        {g711Ulaw56k, 30},
        {'g722-64k', 30},
        {'g722-56k', 30},
        {'g722-48k', 30},

        {g7231, #'AudioCapability_g7231'{
            'maxAl-sduAudioFrames' = 30,   %	INTEGER (1..256),
            silenceSuppression = false
        }},
        {g728, 30},
        {g729, 30},
        {g729AnnexA, 30},
        {is11172AudioCapability, #'IS11172AudioCapability'{
            audioLayer1 = false,
            audioLayer2 = false,
            audioLayer3 = true,
            audioSampling32k = false,
            audioSampling44k1 = false,
            audioSampling48k = true,
            singleChannel = true,
            twoChannels = false,
            bitRate = 32
        }
        },
        {is13818AudioCapability, #'IS13818AudioCapability'{
            audioLayer1 = false,
            audioLayer2 = false,
            audioLayer3 = true,
            audioSampling16k = false,
            audioSampling22k05 = false,
            audioSampling24k = false,
            audioSampling32k = false,
            audioSampling44k1 = false,
            audioSampling48k = true,
            singleChannel = true,
            twoChannels = false,
            'threeChannels2-1' = false,
            'threeChannels3-0' = false,
            'fourChannels2-0-2-0' = false,
            'fourChannels2-2' = false,
            'fourChannels3-1' = false,
            'fiveChannels3-0-2-0' = false,
            'fiveChannels3-2' = false,
            lowFrequencyEnhancement = false,
            multilingual = false,
            bitRate = 48
        }
        },
        {g729wAnnexB, 30},
        {g729AnnexAwAnnexB, 30},
        {g7231AnnexCCapability, #'G7231AnnexCCapability'{
            'maxAl-sduAudioFrames' = 30,
            silenceSuppression = false
            %%         g723AnnexCAudioMode = #'G7231AnnexCCapability_g723AnnexCAudioMode'{
            %%                 highRateMode0,
            %%                 highRateMode1,
            %%                 lowRateMode0,
            %%                 lowRateMode1,
            %%                 sidMode0,
            %%                 sidMode1
        }
        },
        {gsmFullRate, #'GSMAudioCapability'{
            audioUnitSize = 30, comfortNoise = true, scrambled = false
        }},
        {gsmHalfRate, #'GSMAudioCapability'{
            audioUnitSize = 30, comfortNoise = true, scrambled = false
        }},
        {gsmEnhancedFullRate, #'GSMAudioCapability'{
            audioUnitSize = 30, comfortNoise = true, scrambled = false
        }},
        %%     {genericAudioCapability,#'GenericCapability'{
        %%     }},
        {g729Extensions, #'G729Extensions'{
            audioUnit = 30,
            annexA = true,
            annexB = false,
            annexD = false,
            annexE = false,
            annexF = false,
            annexG = false,
            annexH = false
        }
        },
        {vbd, #'VBDCapability'{type = vbd}},
        {audioTelephonyEvent, #'NoPTAudioTelephonyEventCapability'{
            audioTelephoneEvent = ""
        }},
        {audioTone, #'NoPTAudioToneCapability'{

        }}
    ].

getAudioType(Name) ->
	{audioData,{g711Alaw64k, 30}}.

getH263VideoType(Name)->
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{ip=PeerIP,h323id=PeerH323ID,e164=PeerE164,q931Port=PeerPort,confID=CONFID,callID=CALLID,crv=CRV,rate=Rate}=Peer,
	{videoData, {h263VideoCapability,#'H263VideoCapability'{
		sqcifMPI = asn1_NOVALUE,
		qcifMPI = asn1_NOVALUE,
		cifMPI = true,
		cif4MPI = asn1_NOVALUE,
		cif16MPI = asn1_NOVALUE,
		maxBitRate=Rate*10,
		unrestrictedVector=false,
		arithmeticCoding=false,
		advancedPrediction=false,
		pbFrames=false,
		temporalSpatialTradeOffCapability=false,
		'hrd-B' = asn1_NOVALUE,
		bppMaxKb = asn1_NOVALUE,
		slowSqcifMPI = asn1_NOVALUE,
		slowQcifMPI = asn1_NOVALUE,
		slowCifMPI = asn1_NOVALUE,
		slowCif4MPI = asn1_NOVALUE,
		slowCif16MPI = asn1_NOVALUE,
		errorCompensation=false,
		enhancementLayerInfo = asn1_NOVALUE,
		h263Options = asn1_NOVALUE
	}
	}}.

getH264VideoType(Name)->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=IP,q931Port = Q931Port,e164=E164,h323id=H323ID,product=Product,version=Version,terauth=AuthMethods}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{ip=PeerIP,h323id=PeerH323ID,e164=PeerE164,q931Port=PeerPort,confID=CONFID,callID=CALLID,crv=CRV,rate=Rate}=Peer,

	Collapsing=[
		#'GenericParameter'{
			parameterIdentifier={standard,41},  %profile
			parameterValue = {booleanArray,64}, %baseline
			supersedes = asn1_NOVALUE
		},
		#'GenericParameter'{
			parameterIdentifier={standard,42},  %level
			parameterValue= {unsignedMin,71},  %3.1
			supersedes = asn1_NOVALUE
		},
		#'GenericParameter'{
			parameterIdentifier={standard,6},   %customMaxBRandCPB
			parameterValue = {unsignedMin,52},
			supersedes = asn1_NOVALUE
		}

	],

	{videoData,{genericVideoCapability,#'GenericCapability'{
		capabilityIdentifier=?H241_H264,
		maxBitRate = Rate*10,
		collapsing = Collapsing,
		nonCollapsing = asn1_NOVALUE,
		nonCollapsingRaw = asn1_NOVALUE,
		transport = asn1_NOVALUE
	}
	}}.

getCapTable(Name)->
    [
        #'CapabilityTableEntry'{
            capabilityTableEntryNumber=1, 
            capability = {receiveAudioCapability, 
                getAudioType(Name)
            }
        },
        #'CapabilityTableEntry'{
	        capabilityTableEntryNumber = 2,
	        capability = {receiveVideoCapability,
		        getH263VideoType(Name)
	        }
        }
    ].

getCapTableDesc(Name)->
    [
        #'CapabilityDescriptor'{
            capabilityDescriptorNumber=1, 
            simultaneousCapabilities = [[1],[2]]
        }

    ].

encodeTerminalCapabilitySet({Name,Pid}) ->
    TerminalCapabilitySet=#'TerminalCapabilitySet'{
        sequenceNumber = 1, 
        protocolIdentifier=?H245v10, 
        multiplexCapability = {
            h2250Capability,
            #'H2250Capability'{
                maximumAudioDelayJitter=60, 
                receiveMultipointCapability=getMultipointCap(), 
                transmitMultipointCapability=getMultipointCap(), 
                receiveAndTransmitMultipointCapability=getMultipointCap(), 
                mcCapability=#'H2250Capability_mcCapability'{
                    centralizedConferenceMC=true, 
                    decentralizedConferenceMC=false
                },
                rtcpVideoControlCapability=false, 
                mediaPacketizationCapability=#'MediaPacketizationCapability'{
                    h261aVideoPacketization=true,
                    rtpPayloadType = asn1_NOVALUE
                },
                transportCapability = #'TransportCapability'{
                    nonStandard = asn1_NOVALUE, 
                    qOSCapabilities = asn1_NOVALUE, 
                    mediaChannelCapabilities = [
                        #'MediaChannelCapability'{ mediaTransport={'ip-UDP','NULL'}}
                    ]
                },
                redundancyEncodingCapability = asn1_NOVALUE, 
                logicalChannelSwitchingCapability=false, 
                t120DynamicPortCapability=false
            }
        },
        capabilityTable = getCapTable(Name),
        capabilityDescriptors = getCapTableDesc(Name)
    },

    'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
	    {request ,{terminalCapabilitySet,TerminalCapabilitySet}}).


encodeTerminalCapabilitySetAck({Name,Pid},Seq) ->
	TerminalCapabilitySetAck=#'TerminalCapabilitySetAck'{
		sequenceNumber=Seq
	},

	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
	{request ,{terminalCapabilitySetAck,TerminalCapabilitySetAck}}).

encodeTerminalCapabilitySetReject({Name,Pid},SeqNum,Clause) ->
	TerminalCapabilitySetReject=#'TerminalCapabilitySetReject'{
		sequenceNumber=SeqNum,
		cause={Clause,'NULL'}
	},
	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{terminalCapabilitySetReject,TerminalCapabilitySetReject}}).

%     openLogicalChannel  OpenLogicalChannel,
encodeOpenLogicalChannel({Name,Pid},ChanNum,LocalIP,LocalRTCPPort) ->
	Ter=hd(rasdb:lookupTable(Name,terminal)),
	#terminal{ip=LocalIP,q931Port = Q931Port,e164=E164,h323id=H323ID,product=Product,version=Version,terauth=AuthMethods}=Ter,
	Peer=hd(rasdb:lookupTable(Name,peer)),
	#peer{ip=PeerIP,h323id=PeerH323ID,e164=PeerE164,q931Port=PeerPort,confID=CONFID,callID=CALLID,crv=CRV}=Peer,

	OpenLogicalChannel=#'OpenLogicalChannel'{
		forwardLogicalChannelNumber=ChanNum,
		forwardLogicalChannelParameters=
			#'OpenLogicalChannel_forwardLogicalChannelParameters'{
				portNumber = asn1_NOVALUE,
				dataType={},
				multiplexParameters= {h2250LogicalChannelParameters,
					#'H2250LogicalChannelParameters'{
						nonStandard = asn1_NOVALUE,
						sessionID = 1,
						associatedSessionID = asn1_NOVALUE,
						mediaChannel = asn1_NOVALUE,
						mediaGuaranteedDelivery = false,
						mediaControlChannel = { unicastAddress,{iPAddress,
							#'UnicastAddress_iPAddress'{
								network=list_to_binary(LocalIP),
								tsapIdentifier=LocalRTCPPort
							} } },
						mediaControlGuaranteedDelivery = asn1_NOVALUE,
						silenceSuppression = true,
						destination = asn1_NOVALUE,
						dynamicRTPPayloadType = asn1_NOVALUE,
						mediaPacketization = asn1_NOVALUE,
						transportCapability = asn1_NOVALUE,
						redundancyEncoding = asn1_NOVALUE,
						source = asn1_NOVALUE
					}
				},
				forwardLogicalChannelDependency = asn1_NOVALUE,
				replacementFor = asn1_NOVALUE
			},
		reverseLogicalChannelParameters = asn1_NOVALUE,
		separateStack = asn1_NOVALUE,
		encryptionSync = asn1_NOVALUE
	},
	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{terminalCapabilitySet,OpenLogicalChannel}}).

encodeOpenLogicalChannelAck({Name,Pid},SeqNum,SessionID,LocalIP,LocalRTPPort)->
    OpenLogicalChannelAck=#'OpenLogicalChannelAck'{
        forwardLogicalChannelNumber=SeqNum,
        reverseLogicalChannelParameters = asn1_NOVALUE,
        separateStack = asn1_NOVALUE,
        forwardMultiplexAckParameters = {h2250LogicalChannelAckParameters,
            #'H2250LogicalChannelAckParameters'{
                nonStandard = asn1_NOVALUE,
                sessionID = SessionID,
                mediaChannel =  { unicastAddress,{iPAddress,
                    #'UnicastAddress_iPAddress'{
                        network=list_to_binary(LocalIP),
                        tsapIdentifier=LocalRTPPort
                    } } },
                mediaControlChannel =  { unicastAddress,{iPAddress,
                    #'UnicastAddress_iPAddress'{
                        network=list_to_binary(LocalIP),
                        tsapIdentifier=LocalRTPPort+1
                    } } },
                dynamicRTPPayloadType = asn1_NOVALUE,
                flowControlToZero=false,
                portNumber = asn1_NOVALUE
            }
        },
        encryptionSync = asn1_NOVALUE
    },
    'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
        {request ,{openLogicalChannelAck,OpenLogicalChannelAck}}).

encodeOpenLogicalChannelReject({Name,Pid},SeqNum,Clause)->
    OpenLogicalChannelReject=#'OpenLogicalChannelReject'{
        forwardLogicalChannelNumber=SeqNum,
        cause={Clause,'NULL'}
    },
    'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
        {request ,{openLogicalChannelReject,OpenLogicalChannelReject}}).

%     closeLogicalChannel CloseLogicalChannel,
encodeCloseLogicalChannel({Name,Pid},SeqNum)->
	CloseLogicalChannel=#'CloseLogicalChannel'{
		forwardLogicalChannelNumber=SeqNum,
		source={lcse,'NULL'},
		reason={unknown,'NULL'}
	},
	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{closeLogicalChannel,CloseLogicalChannel}}).

encodeCloseLogicalChannelAck({Name,Pid},SeqNum)->
	CloseLogicalChannelAck=#'CloseLogicalChannelAck'{
		forwardLogicalChannelNumber=SeqNum
	},
	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{closeLogicalChannelAck,CloseLogicalChannelAck}}).

%     requestChannelClose RequestChannelClose,
encodeRequestChannelClose({Name,Pid},SeqNum)->
	RequestChannelClose=#'RequestChannelClose'{
		forwardLogicalChannelNumber=SeqNum,
		qosCapability = asn1_NOVALUE,
		reason={normal,'NULL'}
	},
	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{closeLogicalChannelAck,RequestChannelClose}}).

encodeRequestChannelCloseAck({Name,Pid},SeqNum)->
	RequestChannelCloseAck=#'RequestChannelCloseAck'{
		forwardLogicalChannelNumber=SeqNum
	},
	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{closeLogicalChannelAck,RequestChannelCloseAck}}).

encodeRequestChannelCloseReject({Name,Pid},SeqNum)->
	RequestChannelCloseReject=#'RequestChannelCloseReject'{
		forwardLogicalChannelNumber=SeqNum,
		cause={unspecified,'NULL'}
	},
	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{closeLogicalChannelAck,RequestChannelCloseReject}}).

encodeRequestChannelCloseRelease({Name,Pid},SeqNum)->
	RequestChannelCloseRelease=#'RequestChannelCloseRelease'{
		forwardLogicalChannelNumber=SeqNum
	},
	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{closeLogicalChannelAck,RequestChannelCloseRelease}}).

%     multiplexEntrySend  MultiplexEntrySend,

%     requestMultiplexEntry   RequestMultiplexEntry,

%     requestMode RequestMode,

%     roundTripDelayRequest   RoundTripDelayRequest,
encodeRoundTripDelayRequest({Name,Pid},SeqNum)->
	RoundTripDelayRequest=#'RoundTripDelayRequest'{
		sequenceNumber=SeqNum
	},
	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{roundTripDelayRequest,RoundTripDelayRequest}}).

encodeRoundTripDelayResponse({Name,Pid},SeqNum)->
	RoundTripDelayResponse=#'RoundTripDelayResponse'{
		sequenceNumber=SeqNum
	},
	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{roundTripDelayResponse,RoundTripDelayResponse}}).

%     maintenanceLoopRequest  MaintenanceLoopRequest,

getModeTableItem(Name,SessionID,DataType)->
	#'CommunicationModeTableEntry'{
		nonStandard = asn1_NOVALUE,
		sessionID=SessionID,
		associatedSessionID = asn1_NOVALUE,
		terminalLabel = asn1_NOVALUE,
		sessionDescription="sessionDescription",
		dataType=DataType,
		mediaChannel = asn1_NOVALUE,
		mediaGuaranteedDelivery = asn1_NOVALUE,
		mediaControlChannel = asn1_NOVALUE,
		mediaControlGuaranteedDelivery = asn1_NOVALUE,
		redundancyEncoding = asn1_NOVALUE,
		sessionDependency = asn1_NOVALUE,
		destination = asn1_NOVALUE
	}.


%     communicationModeRequest    CommunicationModeRequest,
encodeCommunicationModeCommand({Name,Pid},SeqNum)->
	DataType={audioData,{g711Alaw64k, 30}},
	Item1=getModeTableItem(Name,1,DataType),
	CommunicationModeCommand=#'CommunicationModeCommand'{
		communicationModeTable=[Item1]
	},
	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{communicationModeCommand,CommunicationModeCommand}}).

encodeCommunicationModeRequest({Name,Pid},SeqNum)->
	CommunicationModeRequest=#'CommunicationModeRequest'{
	},
	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{communicationModeRequest,CommunicationModeRequest}}).

encodeCommunicationModeResponse({Name,Pid},SeqNum)->
	DataType={audioData,{g711Alaw64k, 30}},
	Item1=getModeTableItem(Name,1,DataType),
	CommunicationModeResponse={communicationModeResponse,[Item1]
	},
	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{communicationModeResponse,CommunicationModeResponse}}).


%% ConferenceRequest	::=CHOICE
%% {
%%
%% terminalListRequest	NULL,                    -- same as H.230 TCU (term->MC)
%%
%% makeMeChair	NULL,                    -- same as H.230 CCA (term->MC)
%% cancelMakeMeChair	NULL,                    -- same as H.230 CIS (term->MC)
%%
%% dropTerminal	TerminalLabel,       -- same as H.230 CCD(term->MC)
%%
%% requestTerminalID	TerminalLabel,       -- same as TCP (term->MC)
%%
%% enterH243Password	NULL,                    -- same as H.230 TCS1(MC->term)
%% enterH243TerminalID	NULL,                    -- same as H.230 TCS2/TCI
%% --  (MC->term)
%% enterH243ConferenceID	NULL,                    -- same as H.230 TCS3 (MC->term)
%% ...,
%% enterExtensionAddress	NULL,                     -- same as H.230 TCS4 (GW->term)
%% requestChairTokenOwner	NULL,                    -- same as H.230 TCA (term->MC)
%% requestTerminalCertificate 	SEQUENCE
%% {
%% terminalLabel	TerminalLabel OPTIONAL,
%% certSelectionCriteria	CertSelectionCriteria OPTIONAL,
%% sRandom	INTEGER (1..4294967295) OPTIONAL,
%% -- this is the requester's challenge
%% 		...
%% 	},
%% 	broadcastMyLogicalChannel	LogicalChannelNumber,	-- similar to H.230 MCV
%% 	makeTerminalBroadcaster	TerminalLabel,	-- similar to H.230 VCB
%% 	sendThisSource	TerminalLabel,	-- similar to H.230 VCS
%% 	requestAllTerminalIDs	NULL,
%% 	remoteMCRequest	RemoteMCRequest
%% }

%     conferenceRequest   ConferenceRequest,
encodeConferenceRequest({Name,Pid},Choice,Params)->
	case Choice of
		dropTerminal->
			{Choice,Params};
		requestTerminalID->
			{Choice,Params};
		makeTerminalBroadcaster->
			{Choice,Params};
		sendThisSource->
			{Choice,Params};
		requestTerminalCertificate->
			{Choice,Params};
		broadcastMyLogicalChannel->
			{Choice,Params};
		remoteMCRequest->
			{Choice,Params};
		_->
			{Choice,'NULL'}
	end,
	ConferenceRequest={

	},
	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{conferenceRequest,ConferenceRequest}}).

encodeConferenceResponse({Name,Pid},Choice,Params)->
	ConferenceResponse=
		case Choice of
			mCTerminalIDResponse ->
				ok

	    end,
	'MULTIMEDIA-SYSTEM-CONTROL':encode('MultimediaSystemControlMessage',
		{request ,{conferenceResponse,ConferenceResponse}}).


%     multilinkRequest    MultilinkRequest,
%     logicalChannelRateRequest   LogicalChannelRateRequest


% %%%%
%     nonStandard NonStandardMessage,

%     masterSlaveDeterminationAck MasterSlaveDeterminationAck,
%     masterSlaveDeterminationReject  MasterSlaveDeterminationReject,

%     terminalCapabilitySetAck    TerminalCapabilitySetAck,
%     terminalCapabilitySetReject TerminalCapabilitySetReject,

%     openLogicalChannelAck   OpenLogicalChannelAck,
%     openLogicalChannelReject    OpenLogicalChannelReject,
%     closeLogicalChannelAck  CloseLogicalChannelAck,

%     requestChannelCloseAck  RequestChannelCloseAck,
%     requestChannelCloseReject   RequestChannelCloseReject,

%     multiplexEntrySendAck   MultiplexEntrySendAck,
%     multiplexEntrySendReject    MultiplexEntrySendReject,

%     requestMultiplexEntryAck    RequestMultiplexEntryAck,
%     requestMultiplexEntryReject RequestMultiplexEntryReject,

%     requestModeAck  RequestModeAck,
%     requestModeReject   RequestModeReject,

%     roundTripDelayResponse  RoundTripDelayResponse,

%     maintenanceLoopAck  MaintenanceLoopAck,
%     maintenanceLoopReject   MaintenanceLoopReject,

%     ...,
%     communicationModeResponse   CommunicationModeResponse,

%     conferenceResponse  ConferenceResponse,

%     multilinkResponse   MultilinkResponse,

%     logicalChannelRateAcknowledge   LogicalChannelRateAcknowledge,
%     logicalChannelRateReject    LogicalChannelRateReject

% %%%%
%     nonStandard NonStandardMessage,

%     maintenanceLoopOffCommand   MaintenanceLoopOffCommand,

%     sendTerminalCapabilitySet   SendTerminalCapabilitySet,

%     encryptionCommand   EncryptionCommand,

%     flowControlCommand  FlowControlCommand,

%     endSessionCommand   EndSessionCommand,

%     miscellaneousCommand    MiscellaneousCommand,

%     ...,
%     communicationModeCommand    CommunicationModeCommand,

%     conferenceCommand   ConferenceCommand,

%     h223MultiplexReconfiguration    H223MultiplexReconfiguration,

%     newATMVCCommand NewATMVCCommand,

%     mobileMultilinkReconfigurationCommand   MobileMultilinkReconfigurationCommand


% %%%%
%     nonStandard NonStandardMessage,

%     functionNotUnderstood   FunctionNotUnderstood, 
    
%     masterSlaveDeterminationRelease MasterSlaveDeterminationRelease,

%     terminalCapabilitySetRelease    TerminalCapabilitySetRelease,

%     openLogicalChannelConfirm   OpenLogicalChannelConfirm,

%     requestChannelCloseRelease  RequestChannelCloseRelease,

%     multiplexEntrySendRelease   MultiplexEntrySendRelease,

%     requestMultiplexEntryRelease    RequestMultiplexEntryRelease,

%     requestModeRelease  RequestModeRelease,

%     miscellaneousIndication MiscellaneousIndication,

%     jitterIndication    JitterIndication,

%     h223SkewIndication  H223SkewIndication,

%     newATMVCIndication  NewATMVCIndication,

%     userInput   UserInputIndication,
%     ...,
%     h2250MaximumSkewIndication  H2250MaximumSkewIndication,

%     mcLocationIndication    MCLocationIndication,

%     conferenceIndication    ConferenceIndication,

%     vendorIdentification    VendorIdentification,
    
%     functionNotSupported    FunctionNotSupported,

%     multilinkIndication MultilinkIndication,

%     logicalChannelRateRelease   LogicalChannelRateRelease,

%     flowControlIndication   FlowControlIndication,

%     mobileMultilinkReconfigurationIndication    MobileMultilinkReconfigurationIndication


%%%%

decodeH245(Filename) when is_list(Filename) ->
    {ok,Bytes}=file:read_file(Filename),
    decodeH245(Bytes,"Noname").

decodeH245(Bytes,Name) when is_binary(Bytes)->
    case Bytes of 
        <<3,0,Len:16,Rest/binary>> ->  %tpkt head
            BodyLen=Len-4,
            case Rest of 
                <<H245Body:BodyLen/binary,Rest1/binary>> when bit_size(Rest1) >0 ->
                    decodeH245Msg(H245Body,Name),
                    decodeH245(Rest1);
                <<H245Body1:BodyLen/binary>> ->
                    decodeH245Msg(H245Body1,Name);
                _ ->
                    io:format("not H245 frame,Len ~p~n",[Len]),
                    {error,"not H245 frame"}
            end;
        _ ->
            {error,"not tpkt frame"}
    end.


decodeH245Msg(Bytes,Name) when is_binary(Bytes) ->
    case 'MULTIMEDIA-SYSTEM-CONTROL':decode('MultimediaSystemControlMessage',Bytes) of
        {ok,Msg} -> 
            io:format("decodeH245Msg ~p~n",[Msg]),
            {ok,Msg};
        {error,Reason} ->
            {error,Reason}
    end.  