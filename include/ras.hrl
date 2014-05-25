-ifndef(_RAS_HRL_).
-define(_RAS_HRL_, true).

-define(LOCALIP,[127,0,0,1]).
-define(DEFAULTRATE,384).

-define(DEFAULT_RASPORT,1719).
-define(DEFAULT_CALLPORT,1720).

-define(BASERASPORT,3719).
-define(LISTEN_BASECALLPORT,3720).
-define(LISTEN_BASECONTROLPORT,4720).
-define(BASECALLPORT,5720).
-define(BASECONTROLPORT,6720).


-define(BASERTPPORT,20000).

-define(TIMETOLIVE,3000).

-define(NAMEPREFIX,"simuTer").
-define(E164PREFIX,"8001").
-define(H323IDPREFIX,"xueys").
-define(PRODUCT,"zte video conference").
-define(VERSION,"1.4.1").

-define(PATTERN,<<"tWelVe~byteS">>).

-record(signalAddr,{
	ip,
	port,
	sock
	}).

-record(message,{
	name,
	seq,
	maxRetry,
	leftRetry,
	lastTime,
	body
	}).

-record(audioCap,{

}).
-record(videoCap,{

}).
-record(dataCap,{

}).

-record(mediaCaps,{
	audios, %audioCap
	vidoes, %videoCap
	datas   %dataCap
}).

-record(regPara,{
	ip=[127,0,0,1], % {ip,port}
	port=?DEFAULT_RASPORT,
	auth=['md5'], % 'none','md5','cat','zte','tele','h2351'
	username,
	password="111111"
}).

-record(callPara,{
	addr={ip,[127,0,0,1]},  %{ip,[]},{e164,""},{h323id,""}
	port=?DEFAULT_CALLPORT,
	rate=384,  % kbps
	useFastStart=false,
	useTunnel=false,
	useCrypto=false,
	useH460=false
}).

-record(rtpConn,{
	type,%audio,video,data
    seqNum,
    sessionID,
	dir,% in,out
	sock,%socket
	localPort,
	remotePort,
	cap  %audioCap,videoCap,dataCap
}).

% q931Sock if caller ,will be connect to other;if callee ,will be accept and port will be get from other
-record(peer,{
        name,
		isOrig=true,
		isMaster=null,
		h225status,
		h245status,
        ip=?LOCALIP,
        h323id=undefined,
        e164=undefined,
        crv,     % random
		callID,
        confID,
		q931Port=?BASECALLPORT,% index +3720
		q931Sock,
		h245Port=?BASECONTROLPORT,  % index+ 4720
		h245Sock,
		%mediaPorts=[], %[index*8+20000]  Base=?BASERTPPORT+Index*8,  Base+2,Base+4,Base+6
		%mediaSocks=[], %
        inChanNum=0,
		rtpInChans=[], % rtpConn()
        outChanNum=0,
        rtpOutChans=[],
		useTunnel=false,
		useFastStart=false,
		useCyrpt=false,
		useH460=false,
        rate=?DEFAULTRATE
    }).

-record(gk,{
	name,
	ip,
	rasPort=?BASERASPORT, % local port,different each ,not famouse port
	rasSock,  % ras socket
	timeToLive=?TIMETOLIVE,
	gkid,
	gkauthMode,
	gkauthOID,
	status,  % registered,registering,unregister
	epid
}).

-record(terminal,{
        name,
		ip,
        h323id=?H323IDPREFIX,
        e164=?E164PREFIX,
        seqNum=1,
        random,
		%%%%gk
		%call
		q931Port,  % will bind
		q931Sock,  %
		%h245
		h245Port,  % will bind
		h245Sock,
		terCap,
        %%%%%peer,  % when mode==ter
		%pid for all
		rasProc,
		q931Proc,
		h245Proc,
		%config
		useGK=false,
		useTunnel=false,
		useFastStart=false,
		useH460=false,
		useCyrpt=false,
		%crypto
		product=?PRODUCT,
		version=?VERSION,
		password,
		pattern= ?PATTERN,
		terauth=['cat']  % 'md5','cat','zte','tele',
		%'h2351_I','h2351_IA','h2352_II','h2352_III','h2353_IV',
		%'h2354_drc1','h2354_drc2','h2354_drc3',
		%'h2355_sp1','h2355_sp2',
		%h2356 media crypto
		%h2357 mikey
		%h2358 srtp crypto
		%h2359 gateway crypto
    }).

%{itu-t(0) recommendation(0) h(8) h225-0(2250) version(0) 4}
-define(H2250_OID,{0,0,8,2250,0,4}).

%{iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) md5(5)}
-define(MD5_OID,{1,2,840,113549,2,5}).
%child OIDs:  md2(2)   md4(4)   md5(5)   hmacWithSHA1(7)   hmacWithSHA224(8)   hmacWithSHA256(9)   hmacWithSHA384(10)   hmacWithSHA512(11)
-define(CAT_OID,{1,2,840,113548,10,1,2,1}).
%Annex D
-define(H235_A_OID,{0,0,8,235,0,2,1}).
%-define(H235_A_OID,{0,0,8.235,0,1,1}).
-define(H235_E_OID,{0,0,8,235,0,3,9}).
%-define(H235_E_OID,{0,0,8.235,0,2,9}).
-define(H235_T_OID,{0,0,8,235,0,2,5}).
%-define(H235_T_OID,{0,0,8.235,0,1,5}).
-define(H235_U_OID,{0,0,8,235,0,2,6}).
%-define(H235_U_OID,{0,0,8.235,0,1,6}).

-define(H235_DHdummy_OID,{0,0,8,235,0,2,40}).
%-define(H235_DHdummy_OID,{0,0,8,235,0,3,40}).
-define(H235_DH1024_OID,{0,0,8,235,0,2,43}).
%-define(H235_DH1024_OID,{0,0,8,235,0,3,43}).
-define(H235_DH1536_OID,{0,0,8,235,0,3,44}).

-define(H235_X_OID,{1,2,840,113549,3,2}).
-define(H235_X1_OID,{0,0,8,235,0,3,27}).
-define(H235_Y_OID,{1,3,14,3,2,7}).
-define(H235_Y1_OID,{0,0,8,235,0,3,28}).
-define(H235_Z1_OID,{0,0,8,235,0,3,29}).
-define(H235_Z2_OID,{0,0,8,235,0,3,30}).
-define(H235_Z3_OID,{2,16,840,1,101,3,4,1,2}).
-define(H235_Z_OID,{1,3,14,3,2,17}).

%-define(DesECB_OID,{1,3,14,3,2,6}).

-define(H235_B_OID,{0,0,8,235,0,3,2}).
%-define(H235_B_OID,{0,0,8,235,0,2,2}).
%-define(H235_B_OID,{0,0,8,235,0,1,2}).
-define(H235_P_OID,{0,0,8,235,0,2,4}).
%-define(H235_P_OID,{0,0,8,235,0,1,4}).
-define(H235_R_OID,{0,0,8,235,0,2,3}).
%-define(H235_R_OID,{0,0,8,235,0,1,3}).
-define(H235_S_OID,{0,0,8,235,0,2,7}).
%-define(H235_S_OID,{0,0,8,235,0,1,7}).
-define(H235_V_OID,{1,2,840,113549,1,1,4}).
-define(H235_W_OID,{1,2,840,113549,1,1,5}).


% #define  ARQNSD_OBJECT_ID        "1.3.6.1.4.1.3902.3101.1"
% #define  LRQNSD_OBJECT_ID        "1.3.6.1.4.1.3902.3101.2"
% #define  LRQ_TOKEN_ID            "1.3.6.1.4.1.3902.3101.3"
% #define  RRQNSD_OBJECT_ID        "1.3.6.1.4.1.3902.3001"
% #define  NSM_OBJECT_ID           "1.3.6.1.4.1.3902.3002"
% #define  FL_NSD_OBJECT_ID        "1.3.6.1.4.1.3902.3003"
% #define  PPMC_OBJECT_ID          "1.3.6.1.4.1.3902.3003"
% #define  PPMC_LCF_OBJECT_ID      "1.3.6.1.4.1.3902.3004"

-endif. %% _RAS_HRL_