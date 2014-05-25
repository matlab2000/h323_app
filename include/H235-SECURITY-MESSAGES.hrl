%% Generated by the Erlang ASN.1 compiler version:3.0
%% Purpose: Erlang record definitions for each named and unnamed
%% SEQUENCE and SET, and macro definitions for each value
%% definition,in module H235-SECURITY-MESSAGES



-ifndef(_H235_SECURITY_MESSAGES_HRL_).
-define(_H235_SECURITY_MESSAGES_HRL_, true).

-record('SIGNED',{
toBeSigned, algorithmOID, paramS, signature}).

-record('ENCRYPTED',{
algorithmOID, paramS, encryptedData}).

-record('HASHED',{
algorithmOID, paramS, hash}).


%-record('NonStandardParameter',{
%nonStandardIdentifier, data}).

-record('DHset',{
halfkey, modSize, generator}). % with extension mark

-record('ECpoint',{
x = asn1_NOVALUE, y = asn1_NOVALUE}). % with extension mark

-record('ECKASDH_eckasdhp',{
'public-key', modulus, base, weierstrassA, weierstrassB}).

-record('ECKASDH_eckasdh2',{
'public-key', fieldSize, base, weierstrassA, weierstrassB}).

-record('ECGDSASignature',{
r, s}).

-record('TypedCertificate',{
type, certificate}). % with extension mark

-record('ClearToken',{
tokenOID, timeStamp = asn1_NOVALUE, password = asn1_NOVALUE, dhkey = asn1_NOVALUE, challenge = asn1_NOVALUE, random = asn1_NOVALUE, certificate = asn1_NOVALUE, generalID = asn1_NOVALUE, nonStandard = asn1_NOVALUE,
%% with extensions
eckasdhkey = asn1_NOVALUE, sendersID = asn1_NOVALUE}).

-record('Params',{
ranInt = asn1_NOVALUE, iv8 = asn1_NOVALUE,
%% with extensions
iv16 = asn1_NOVALUE}).

-record('CryptoToken_cryptoEncryptedToken',{
tokenOID, token}).

-record('CryptoToken_cryptoEncryptedToken_token',{
algorithmOID, paramS, encryptedData}).

-record('CryptoToken_cryptoSignedToken',{
tokenOID, token}).

-record('CryptoToken_cryptoSignedToken_token',{
toBeSigned, algorithmOID, paramS, signature}).

-record('CryptoToken_cryptoHashedToken',{
tokenOID, hashedVals, token}).

-record('CryptoToken_cryptoHashedToken_token',{
algorithmOID, paramS, hash}).

-record('CryptoToken_cryptoPwdEncr',{
algorithmOID, paramS, encryptedData}).

-record('H235Key_sharedSecret',{
algorithmOID, paramS, encryptedData}).

-record('H235Key_certProtectedKey',{
toBeSigned, algorithmOID, paramS, signature}).

-record('KeySignedMaterial',{
generalId, mrandom, srandom = asn1_NOVALUE, timeStamp = asn1_NOVALUE, encrptval}).

-record('KeySignedMaterial_encrptval',{
algorithmOID, paramS, encryptedData}).

-record('H235CertificateSignature',{
certificate, responseRandom, requesterRandom = asn1_NOVALUE, signature}). % with extension mark

-record('H235CertificateSignature_signature',{
toBeSigned, algorithmOID, paramS, signature}).

-record('ReturnSig',{
generalId, responseRandom, requestRandom = asn1_NOVALUE, certificate = asn1_NOVALUE}).

-record('KeySyncMaterial',{
generalID, keyMaterial}). % with extension mark

-endif. %% _H235_SECURITY_MESSAGES_HRL_