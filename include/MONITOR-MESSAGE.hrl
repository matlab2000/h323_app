%% Generated by the Erlang ASN.1 compiler version:3.0
%% Purpose: Erlang record definitions for each named and unnamed
%% SEQUENCE and SET, and macro definitions for each value
%% definition,in module MONITOR-MESSAGE



-ifndef(_MONITOR_MESSAGE_HRL_).
-define(_MONITOR_MESSAGE_HRL_, true).

-record('HangUpCallRequest',{
requestIdentifier, endpointIdentifier, callIdentifier, callRefValue, answerCall, securityCheckValue = asn1_NOVALUE}).

-record('HangUpCallConfirm',{
requestIdentifier, endpointIdentifier, callIdentifier, callRefValue}).

-record('HangUpCallReject',{
requestIdentifier, endpointIdentifier, callIdentifier, callRefValue, failureReason}).

-record('UnRegisterRequest',{
requestIdentifier, endpointIndex}).

-record('UnRegisterConfirm',{
requestIdentifier, endpointIndex}).

-record('UnRegisterReject',{
requestIdentifier, failureReason}).

-record('VersionRequest',{
requestIdentifier, securityCheckValue = asn1_NOVALUE}).

-record('VersionConfirm',{
requestIdentifier, version = asn1_NOVALUE}).

-record('VersionReject',{
requestIdentifier, faliureReason}).

-record('LogSetRequest',{
requestIdentifier, logLevel = asn1_NOVALUE}).

-record('LogSetConfirm',{
requestIdentifier, logLevel = asn1_NOVALUE}).

-record('LogInform',{
requestIdentifier, logLevel = asn1_NOVALUE, logDirection = asn1_NOVALUE, logInfo = asn1_NOVALUE, logTime = asn1_NOVALUE}).

-record('LoginRequire',{
requestIdentifier, loginTime = asn1_NOVALUE}).

-record('LoginRequest',{
requestIdentifier, loginTime = asn1_NOVALUE, username, password, securityCheckValue = asn1_NOVALUE}).

-record('LoginConfirm',{
requestIdentifier}).

-record('LoginReject',{
requestIdentifier, faliureReason}).

-record('CloseRequest',{
requestIdentifier, securityCheckValue = asn1_NOVALUE}).

-record('CloseConfirm',{
requestIdentifier}).

-record('CloseReject',{
requestIdentifier, failureReason}).

-record('RestartRequest',{
requestIdentifier, securityCheckValue = asn1_NOVALUE}).

-record('RestartConfirm',{
requestIdentifier}).

-record('RestartReject',{
requestIdentifier, failureReason}).

-record('RegisterRequest',{
requestIdentifier, dataTransferAddress, securityCheckValue = asn1_NOVALUE}).

-record('RegisterConfirm',{
requestIdentifier, dataTransferAddress}).

-record('RegisterReject',{
requestIdentifier, failureReason}).

-record('ConfigGetRequest',{
requestIdentifier, securityCheckValue = asn1_NOVALUE}).

-record('ConfigGetConfirm',{
requestIdentifier, configurationTable}).

-record('ConfigGetReject',{
requestIdentifier, failureReason}).

-record('ConfigurationTable',{
gatekeeperIdentifier = asn1_NOVALUE, gatekeeperRasAddress = asn1_NOVALUE, gatekeeperCallSignalAddress = asn1_NOVALUE, logLevel = asn1_NOVALUE, logFileName = asn1_NOVALUE, admittedEndpoints = asn1_NOVALUE}).

-record('AdmittedEndpoint',{
callSignalAddress, terminalAliases = asn1_NOVALUE, maxCall = asn1_NOVALUE, maxBandwidth = asn1_NOVALUE}).

-record('ConfigSetRequest',{
requestIdentifier, configurationTable, securityCheckValue = asn1_NOVALUE}).

-record('ConfigSetConfirm',{
requestIdentifier, needRestart = asn1_NOVALUE}).

-record('ConfigSetReject',{
requestIdentifier, failureReason = asn1_NOVALUE}).

-record('StatisticsRequest',{
requestIdentifier}).

-record('StatisticsConfirm',{
requestIdentifier, statisticsTable}).

-record('StatisticsQueryRequest',{
requestIdentifier, sourcePrefix, destPrefix}).

-record('StatisticsQueryConfirm',{
requestIdentifier, statisticsQueryTable}).

-record('StatisticsQueryTable',{
callsBetweenZones}).

-record('BetweenZonesTable',{
sourcePrefix, destPrefix, num}).

-record('StatisticsTable',{
gatekeeperRequests, gatekeeperHandles, gatekeeperConfirms, gatekeeperRejects, registrationRequests, registrationHandles, registrationConfirms, registrationRejects, unregistrationRequests, unregistrationHandles, unregistrationConfirms, unregistrationRejects, admissionRequests, admissionHandles, admissionConfirms, admissionRejects, bandwidthRequests, bandwidthHandles, bandwidthConfirms, bandwidthRejects, disengageRequests, disengageHandles, disengageConfirms, disangageRejects, locationRequests, locationHandles, locationConfirms, locationRejects, infoReqResponses, iRRHandles, infoRequests, iNAKs, iACKs, resAvaiIndicates, resAvaiIndicateHandles, resAvailConfirms, nonStandardMessages, unknownMessages, requestInProgress, lastArjReason, lastArjRasAddress, totalErrors, lastErrorEventTime, lastErrorSeverity, lastErrorProbableCause, lastErrorAddtionalText, zoneNo, gkRoutedCalls, callsAll = asn1_NOVALUE, callsBetweenZones = asn1_NOVALUE, callsfailed = asn1_NOVALUE, setupReceives, setupHandles, setupSends, connectReceives, connectHandles, connectSends, callProReceives, callProHandles, callProSends, alertingReceives, alertingHandles, alertingSends, progressReceives, progressHandles, progressSends, facilityReceives, facilityHandles, facilitySends, rlsCompleteReceives, rlsCompleteHandles, rlsCompleteSends}).

-record('StatisticsReject',{
requestIdentifier, failureReason}).

-record('StatisticsQueryReject',{
requestIdentifier, failureReason}).

-record('EndpointRequest',{
requestIdentifier, aliasAddress = asn1_NOVALUE, callSignalAddress = asn1_NOVALUE, endpointIdentifier = asn1_NOVALUE, aliasName = asn1_NOVALUE, endpointType = asn1_NOVALUE}).

-record('EndpointConfirm',{
requestIdentifier, incompleteReply = asn1_NOVALUE, endpoints, endpNum}).

-record('EndpointReject',{
requestIdentifier, failureReason}).

-record('CallRequest',{
requestIdentifier, callingAlias = asn1_NOVALUE, calledAlias = asn1_NOVALUE, endpointIdentifier}).

-record('CallConfirm',{
requestIdentifier, endpointIdentifier, incompleteReply = asn1_NOVALUE, calls}).

-record('CallReject',{
requestIdentifier, endpointIdentifier, failureReason}).

-record('UnknowMessage',{
requestIdentifier}).

-record('EndpointEntry',{
endpointIdentifier, terminalType, rrqElapaseTime, callSignalAddresses, rasAddresses, aliasAddresses = asn1_NOVALUE, bandwidthInUse = asn1_NOVALUE, bandwidthAvailable = asn1_NOVALUE, activeCalls = asn1_NOVALUE, maximumCalls = asn1_NOVALUE, endpointVendor = asn1_NOVALUE}).

-record('CallEntry',{
callID, conferenceID, callType, callModel, bandWidth, callReferenceValue, irrElapseTime, answerCall, calledterminalType = asn1_NOVALUE, endpointIdentifier = asn1_NOVALUE, destinationInfo = asn1_NOVALUE, destExtraCallInfo = asn1_NOVALUE, srcInfo = asn1_NOVALUE, destCallSignalAddress = asn1_NOVALUE, srcCallSignalAddress = asn1_NOVALUE}).

-endif. %% _MONITOR_MESSAGE_HRL_
