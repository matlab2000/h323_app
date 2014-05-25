%% Generated by the Erlang ASN.1 PER-compiler version, utilizing bit-syntax:3.0
%% Purpose: encoder and decoder to the types in mod RASEXT-MESSAGE

-module('RASEXT-MESSAGE').
-compile(nowarn_unused_vars).
-include("RASEXT-MESSAGE.hrl").
-asn1_info([{vsn,'3.0'},
            {module,'RASEXT-MESSAGE'},
            {options,[{i,"D:/GK_LINUX/test/erlang"},
 warnings,per,errors,
 {cwd,"D:/GK_LINUX/test/erlang"},
 {outdir,"D:/GK_LINUX/test/erlang"},
 {i,"."},
 {i,"d:/GK_LINUX/test/erlang"}]}]).

-export([encoding_rule/0,bit_string_format/0,         legacy_erlang_types/0]).
-export([
'enc_RRQsNonStandardData'/1,
'enc_RCFsNonStandardData'/1,
'enc_RASNonStandardData'/1,
'enc_RRQNonStandardData'/1,
'enc_RCFNonStandardData'/1,
'enc_ConferenceStatusDescriptor'/1,
'enc_TerStatusDescriptor'/1
]).

-export([
'dec_RRQsNonStandardData'/1,
'dec_RCFsNonStandardData'/1,
'dec_RASNonStandardData'/1,
'dec_RRQNonStandardData'/1,
'dec_RCFNonStandardData'/1,
'dec_ConferenceStatusDescriptor'/1,
'dec_TerStatusDescriptor'/1
]).

-export([info/0]).


-export([encode/2,decode/2]).

encoding_rule() -> per.

bit_string_format() -> bitstring.

legacy_erlang_types() -> false.

encode(Type, Data) ->
try complete(encode_disp(Type, Data)) of
  Bytes ->
    {ok,Bytes}
  catch
    Class:Exception when Class =:= error; Class =:= exit ->
      case Exception of
        {error,Reason}=Error ->
          Error;
        Reason ->
         {error,{asn1,Reason}}
      end
end.

decode(Type,Data) ->
try decode_disp(Type, Data) of
  {Result,Rest} ->
    {ok,Result}
  catch
    Class:Exception when Class =:= error; Class =:= exit ->
      case Exception of
        {error,Reason}=Error ->
          Error;
        Reason ->
         {error,{asn1,Reason}}
      end
end.

encode_disp('RRQsNonStandardData',Data) -> 'enc_RRQsNonStandardData'(Data);
encode_disp('RCFsNonStandardData',Data) -> 'enc_RCFsNonStandardData'(Data);
encode_disp('RASNonStandardData',Data) -> 'enc_RASNonStandardData'(Data);
encode_disp('RRQNonStandardData',Data) -> 'enc_RRQNonStandardData'(Data);
encode_disp('RCFNonStandardData',Data) -> 'enc_RCFNonStandardData'(Data);
encode_disp('ConferenceStatusDescriptor',Data) -> 'enc_ConferenceStatusDescriptor'(Data);
encode_disp('TerStatusDescriptor',Data) -> 'enc_TerStatusDescriptor'(Data);
encode_disp(Type,_Data) -> exit({error,{asn1,{undefined_type,Type}}}).


decode_disp('RRQsNonStandardData',Data) -> 'dec_RRQsNonStandardData'(Data);
decode_disp('RCFsNonStandardData',Data) -> 'dec_RCFsNonStandardData'(Data);
decode_disp('RASNonStandardData',Data) -> 'dec_RASNonStandardData'(Data);
decode_disp('RRQNonStandardData',Data) -> 'dec_RRQNonStandardData'(Data);
decode_disp('RCFNonStandardData',Data) -> 'dec_RCFNonStandardData'(Data);
decode_disp('ConferenceStatusDescriptor',Data) -> 'dec_ConferenceStatusDescriptor'(Data);
decode_disp('TerStatusDescriptor',Data) -> 'dec_TerStatusDescriptor'(Data);
decode_disp(Type,_Data) -> exit({error,{asn1,{undefined_type,Type}}}).




info() ->
   case ?MODULE:module_info(attributes) of
     Attributes when is_list(Attributes) ->
       case lists:keyfind(asn1_info, 1, Attributes) of
         {_,Info} when is_list(Info) ->
           Info;
         _ ->
           []
       end;
     _ ->
       []
   end.
'enc_RRQsNonStandardData'(Val) ->
[begin
Enc1@element = element(2, Val),
Enc2@element = element(3, Val),
if Enc1@element =:= asn1_NOVALUE ->
if Enc2@element =:= asn1_NOVALUE ->
<<0:1,0:1,0:1>>;
true ->
<<0:1,0:1,1:1>>
end;
true ->
if Enc2@element =:= asn1_NOVALUE ->
<<0:1,1:1,0:1>>;
true ->
<<0:1,1:1,1:1>>
end
end
end,
begin
Enc3@element = element(4, Val),
Enc4@element = element(5, Val),
if Enc3@element =:= asn1_NOVALUE ->
if Enc4@element =:= asn1_NOVALUE ->
<<0:1,0:1>>;
true ->
<<0:1,1:1>>
end;
true ->
if Enc4@element =:= asn1_NOVALUE ->
<<1:1,0:1>>;
true ->
<<1:1,1:1>>
end
end
end,
begin
Enc5@element = element(6, Val),
Enc7@element = element(2, Val),
if Enc5@element =:= asn1_NOVALUE ->
if Enc7@element =:= asn1_NOVALUE ->
<<0:1>>;
Enc7@element =:= false ->
<<0:1,0:1>>;
Enc7@element =:= true ->
<<0:1,1:1>>
end;
true ->
if Enc7@element =:= asn1_NOVALUE ->
<<1:1>>;
Enc7@element =:= false ->
<<1:1,0:1>>;
Enc7@element =:= true ->
<<1:1,1:1>>
end
end
end,
begin
Enc10@element = element(3, Val),
if Enc10@element =:= asn1_NOVALUE ->
[];
Enc10@element =:= false ->
<<0:1>>;
Enc10@element =:= true ->
<<1:1>>
end
end,
begin
Enc13@element = element(4, Val),
if Enc13@element =:= asn1_NOVALUE ->
[];
Enc13@element =:= false ->
<<0:1>>;
Enc13@element =:= true ->
<<1:1>>
end
end,
begin
Enc16@element = element(5, Val),
if Enc16@element =:= asn1_NOVALUE ->
[];
Enc16@element =:= false ->
<<0:1>>;
Enc16@element =:= true ->
<<1:1>>
end
end|begin
Enc19@element = element(6, Val),
if Enc19@element =:= asn1_NOVALUE ->
[];
Enc19@element =:= false ->
<<0:1>>;
Enc19@element =:= true ->
<<1:1>>
end
end].


dec_RRQsNonStandardData(Bytes) ->
{Ext,Bytes1} = begin
<<V1@V0:1,V1@Buf1/bitstring>> = Bytes,
{V1@V0,V1@Buf1}
end,
{Opt,Bytes2} = begin
<<V2@V0:5,V2@Buf1/bitstring>> = Bytes1,
{V2@V0,V2@Buf1}
end,

%% attribute number 1 with type BOOLEAN
{Term1,Bytes3} = case (Opt bsr 4) band 1 of
1 ->
begin
<<V3@V0:1,V3@Buf1/bitstring>> = Bytes2,
V3@Int2 = case V3@V0 of
0 -> false;
1 -> true
end,
{V3@Int2,V3@Buf1}
end;
0 ->
{asn1_NOVALUE,Bytes2}
end,

%% attribute number 2 with type BOOLEAN
{Term2,Bytes4} = case (Opt bsr 3) band 1 of
1 ->
begin
<<V4@V0:1,V4@Buf1/bitstring>> = Bytes3,
V4@Int2 = case V4@V0 of
0 -> false;
1 -> true
end,
{V4@Int2,V4@Buf1}
end;
0 ->
{asn1_NOVALUE,Bytes3}
end,

%% attribute number 3 with type BOOLEAN
{Term3,Bytes5} = case (Opt bsr 2) band 1 of
1 ->
begin
<<V5@V0:1,V5@Buf1/bitstring>> = Bytes4,
V5@Int2 = case V5@V0 of
0 -> false;
1 -> true
end,
{V5@Int2,V5@Buf1}
end;
0 ->
{asn1_NOVALUE,Bytes4}
end,

%% attribute number 4 with type BOOLEAN
{Term4,Bytes6} = case (Opt bsr 1) band 1 of
1 ->
begin
<<V6@V0:1,V6@Buf1/bitstring>> = Bytes5,
V6@Int2 = case V6@V0 of
0 -> false;
1 -> true
end,
{V6@Int2,V6@Buf1}
end;
0 ->
{asn1_NOVALUE,Bytes5}
end,

%% attribute number 5 with type BOOLEAN
{Term5,Bytes7} = case Opt band 1 of
1 ->
begin
<<V7@V0:1,V7@Buf1/bitstring>> = Bytes6,
V7@Int2 = case V7@V0 of
0 -> false;
1 -> true
end,
{V7@Int2,V7@Buf1}
end;
0 ->
{asn1_NOVALUE,Bytes6}
end,

%% Extensions
{Extensions,Bytes8} = case Ext of
0 -> {<<>>,Bytes7};
1 ->
{V8@V0,V8@Buf1} = case Bytes7 of
<<0:1,V8@V3:6,V8@Buf4/bitstring>> ->
V8@Add5 = V8@V3 + 1,
{V8@Add5,V8@Buf4};
<<1:1,V8@Buf2/bitstring>> ->
V8@Pad6 = bit_size(V8@Buf2) band 7,
{V8@V3,V8@Buf4} = case V8@Buf2 of
<<_:V8@Pad6,0:1,V8@V8:7,V8@Buf9/bitstring>> when V8@V8 =/= 0 ->
{V8@V8,V8@Buf9};
<<_:V8@Pad6,1:1,0:1,V8@V9:14,V8@Buf10/bitstring>> when V8@V9 =/= 0 ->
{V8@V9,V8@Buf10}
end,
{V8@V3,V8@Buf4}
end,
<<V8@V11:V8@V0/bitstring-unit:1,V8@Buf12/bitstring>> = V8@Buf1,
{V8@V11,V8@Buf12}
end,
Bytes9= skipextensions(Bytes8, 1, Extensions),
{{'RRQsNonStandardData',Term1,Term2,Term3,Term4,Term5},Bytes9}.

'enc_RCFsNonStandardData'(Val) ->
[begin
Enc1@element = element(2, Val),
Enc2@element = element(3, Val),
if Enc1@element =:= asn1_NOVALUE ->
if Enc2@element =:= asn1_NOVALUE ->
<<0:1,0:1,0:1>>;
true ->
<<0:1,0:1,1:1>>
end;
true ->
if Enc2@element =:= asn1_NOVALUE ->
<<0:1,1:1,0:1>>;
true ->
<<0:1,1:1,1:1>>
end
end
end,
begin
Enc4@element = element(2, Val),
if Enc4@element =:= asn1_NOVALUE ->
[];
true ->
'H323-MESSAGES':enc_TransportAddress(Enc4@element)
end
end|begin
Enc6@element = element(3, Val),
if Enc6@element =:= asn1_NOVALUE ->
[];
true ->
'H323-MESSAGES':enc_TransportAddress(Enc6@element)
end
end].


dec_RCFsNonStandardData(Bytes) ->
{Ext,Bytes1} = begin
<<V1@V0:1,V1@Buf1/bitstring>> = Bytes,
{V1@V0,V1@Buf1}
end,
{Opt,Bytes2} = begin
<<V2@V0:2,V2@Buf1/bitstring>> = Bytes1,
{V2@V0,V2@Buf1}
end,

%% attribute number 1 with type TransportAddress
{Term1,Bytes3} = case (Opt bsr 1) band 1 of
1 ->
'H323-MESSAGES':dec_TransportAddress(Bytes2);
0 ->
{asn1_NOVALUE,Bytes2}
end,

%% attribute number 2 with type TransportAddress
{Term2,Bytes4} = case Opt band 1 of
1 ->
'H323-MESSAGES':dec_TransportAddress(Bytes3);
0 ->
{asn1_NOVALUE,Bytes3}
end,

%% Extensions
{Extensions,Bytes5} = case Ext of
0 -> {<<>>,Bytes4};
1 ->
{V3@V0,V3@Buf1} = case Bytes4 of
<<0:1,V3@V3:6,V3@Buf4/bitstring>> ->
V3@Add5 = V3@V3 + 1,
{V3@Add5,V3@Buf4};
<<1:1,V3@Buf2/bitstring>> ->
V3@Pad6 = bit_size(V3@Buf2) band 7,
{V3@V3,V3@Buf4} = case V3@Buf2 of
<<_:V3@Pad6,0:1,V3@V8:7,V3@Buf9/bitstring>> when V3@V8 =/= 0 ->
{V3@V8,V3@Buf9};
<<_:V3@Pad6,1:1,0:1,V3@V9:14,V3@Buf10/bitstring>> when V3@V9 =/= 0 ->
{V3@V9,V3@Buf10}
end,
{V3@V3,V3@Buf4}
end,
<<V3@V11:V3@V0/bitstring-unit:1,V3@Buf12/bitstring>> = V3@Buf1,
{V3@V11,V3@Buf12}
end,
Bytes6= skipextensions(Bytes5, 1, Extensions),
{{'RCFsNonStandardData',Term1,Term2},Bytes6}.

'enc_RASNonStandardData'(Val) ->
{ChoiceTag,ChoiceVal} = Val,
if ChoiceTag =:= terStatusChangeReport ->
[<<0:1>>|enc_TerStatusDescriptor(ChoiceVal)];
ChoiceTag =:= conferenceChangeReport ->
[<<1:1>>|enc_ConferenceStatusDescriptor(ChoiceVal)]
end.


dec_RASNonStandardData(Bytes) ->
{Choice,Bytes1} = 
begin
<<V1@V0:1/unsigned-unit:1,V1@Buf1/bitstring>> = Bytes,
{V1@V0,V1@Buf1}
end,
case Choice of
0 ->
{Val,NewBytes} = begin
dec_TerStatusDescriptor(Bytes1)
end,
{{terStatusChangeReport,Val},NewBytes};
1 ->
{Val,NewBytes} = begin
dec_ConferenceStatusDescriptor(Bytes1)
end,
{{conferenceChangeReport,Val},NewBytes}
end.
'enc_RRQNonStandardData'(Val) ->
[begin
Enc1@element = element(3, Val),
if Enc1@element =:= asn1_NOVALUE ->
<<0:1,0:1>>;
true ->
<<0:1,1:1>>
end
end,
align,
begin
Enc3@element = element(2, Val),
if Enc3@element bsr 8 =:= 0 ->
Enc3@element;
true ->
exit({error,{asn1,{illegal_value,Enc3@element}}})
end
end|begin
Enc5@element = element(3, Val),
if Enc5@element =:= asn1_NOVALUE ->
[];
true ->
enc_RRQNonStandardData_terStatusRequestList(Enc5@element)
end
end].
'enc_RRQNonStandardData_terStatusRequestList'(Val) ->
Enc1@len = length(Val),
[if Enc1@len < 128 ->
[align,
Enc1@len];
Enc1@len < 16384 ->
[align|<<2:2,Enc1@len:14>>]
end|['H323-MESSAGES':enc_AliasAddress(Comp) || Comp <- Val]].


dec_RRQNonStandardData_terStatusRequestList(Bytes) ->
%% Length with constraint no
V1@Pad3 = bit_size(Bytes) band 7,
{V1@V0,V1@Buf1} = case Bytes of
<<_:V1@Pad3,0:1,V1@V5:7,V1@Buf6/bitstring>> ->
{V1@V5,V1@Buf6};
<<_:V1@Pad3,1:1,0:1,V1@V6:14,V1@Buf7/bitstring>> ->
{V1@V6,V1@Buf7}
end,
dec_components1(V1@V0, V1@Buf1, []).



dec_RRQNonStandardData(Bytes) ->
{Ext,Bytes1} = begin
<<V1@V0:1,V1@Buf1/bitstring>> = Bytes,
{V1@V0,V1@Buf1}
end,
{Opt,Bytes2} = begin
<<V2@V0:1,V2@Buf1/bitstring>> = Bytes1,
{V2@V0,V2@Buf1}
end,

%% attribute number 1 with type INTEGER
{Term1,Bytes3} = begin
V3@Pad2 = bit_size(Bytes2) band 7,
<<_:V3@Pad2,V3@V0:1/unsigned-unit:8,V3@Buf1/bitstring>> = Bytes2,
{V3@V0,V3@Buf1}
end,

%% attribute number 2 with type SEQUENCE OF
{Term2,Bytes4} = case Opt band 1 of
1 ->
'dec_RRQNonStandardData_terStatusRequestList'(Bytes3);
0 ->
{asn1_NOVALUE,Bytes3}
end,

%% Extensions
{Extensions,Bytes5} = case Ext of
0 -> {<<>>,Bytes4};
1 ->
{V4@V0,V4@Buf1} = case Bytes4 of
<<0:1,V4@V3:6,V4@Buf4/bitstring>> ->
V4@Add5 = V4@V3 + 1,
{V4@Add5,V4@Buf4};
<<1:1,V4@Buf2/bitstring>> ->
V4@Pad6 = bit_size(V4@Buf2) band 7,
{V4@V3,V4@Buf4} = case V4@Buf2 of
<<_:V4@Pad6,0:1,V4@V8:7,V4@Buf9/bitstring>> when V4@V8 =/= 0 ->
{V4@V8,V4@Buf9};
<<_:V4@Pad6,1:1,0:1,V4@V9:14,V4@Buf10/bitstring>> when V4@V9 =/= 0 ->
{V4@V9,V4@Buf10}
end,
{V4@V3,V4@Buf4}
end,
<<V4@V11:V4@V0/bitstring-unit:1,V4@Buf12/bitstring>> = V4@Buf1,
{V4@V11,V4@Buf12}
end,
Bytes6= skipextensions(Bytes5, 1, Extensions),
{{'RRQNonStandardData',Term1,Term2},Bytes6}.

'enc_RCFNonStandardData'(Val) ->
[begin
Enc1@element = element(3, Val),
if Enc1@element =:= asn1_NOVALUE ->
<<0:1,0:1>>;
true ->
<<0:1,1:1>>
end
end,
align,
begin
Enc3@element = element(2, Val),
if Enc3@element bsr 8 =:= 0 ->
Enc3@element;
true ->
exit({error,{asn1,{illegal_value,Enc3@element}}})
end
end|begin
Enc5@element = element(3, Val),
if Enc5@element =:= asn1_NOVALUE ->
[];
true ->
enc_RCFNonStandardData_terStatusResponseList(Enc5@element)
end
end].
'enc_RCFNonStandardData_terStatusResponseList'(Val) ->
Enc1@len = length(Val),
[if Enc1@len < 128 ->
[align,
Enc1@len];
Enc1@len < 16384 ->
[align|<<2:2,Enc1@len:14>>]
end|[enc_TerStatusDescriptor(Comp) || Comp <- Val]].


dec_RCFNonStandardData_terStatusResponseList(Bytes) ->
%% Length with constraint no
V1@Pad3 = bit_size(Bytes) band 7,
{V1@V0,V1@Buf1} = case Bytes of
<<_:V1@Pad3,0:1,V1@V5:7,V1@Buf6/bitstring>> ->
{V1@V5,V1@Buf6};
<<_:V1@Pad3,1:1,0:1,V1@V6:14,V1@Buf7/bitstring>> ->
{V1@V6,V1@Buf7}
end,
dec_components2(V1@V0, V1@Buf1, []).



dec_RCFNonStandardData(Bytes) ->
{Ext,Bytes1} = begin
<<V1@V0:1,V1@Buf1/bitstring>> = Bytes,
{V1@V0,V1@Buf1}
end,
{Opt,Bytes2} = begin
<<V2@V0:1,V2@Buf1/bitstring>> = Bytes1,
{V2@V0,V2@Buf1}
end,

%% attribute number 1 with type INTEGER
{Term1,Bytes3} = begin
V3@Pad2 = bit_size(Bytes2) band 7,
<<_:V3@Pad2,V3@V0:1/unsigned-unit:8,V3@Buf1/bitstring>> = Bytes2,
{V3@V0,V3@Buf1}
end,

%% attribute number 2 with type SEQUENCE OF
{Term2,Bytes4} = case Opt band 1 of
1 ->
'dec_RCFNonStandardData_terStatusResponseList'(Bytes3);
0 ->
{asn1_NOVALUE,Bytes3}
end,

%% Extensions
{Extensions,Bytes5} = case Ext of
0 -> {<<>>,Bytes4};
1 ->
{V4@V0,V4@Buf1} = case Bytes4 of
<<0:1,V4@V3:6,V4@Buf4/bitstring>> ->
V4@Add5 = V4@V3 + 1,
{V4@Add5,V4@Buf4};
<<1:1,V4@Buf2/bitstring>> ->
V4@Pad6 = bit_size(V4@Buf2) band 7,
{V4@V3,V4@Buf4} = case V4@Buf2 of
<<_:V4@Pad6,0:1,V4@V8:7,V4@Buf9/bitstring>> when V4@V8 =/= 0 ->
{V4@V8,V4@Buf9};
<<_:V4@Pad6,1:1,0:1,V4@V9:14,V4@Buf10/bitstring>> when V4@V9 =/= 0 ->
{V4@V9,V4@Buf10}
end,
{V4@V3,V4@Buf4}
end,
<<V4@V11:V4@V0/bitstring-unit:1,V4@Buf12/bitstring>> = V4@Buf1,
{V4@V11,V4@Buf12}
end,
Bytes6= skipextensions(Bytes5, 1, Extensions),
{{'RCFNonStandardData',Term1,Term2},Bytes6}.

'enc_ConferenceStatusDescriptor'(Val) ->
[begin
Enc2@element = element(2, Val),
if Enc2@element bsr 8 =:= 0 ->
[<<0:1>>,
align,
Enc2@element];
true ->
exit({error,{asn1,{illegal_value,Enc2@element}}})
end
end|begin
Enc4@element = element(3, Val),
enc_ConferenceStatusDescriptor_conferenceAlias(Enc4@element)
end].
'enc_ConferenceStatusDescriptor_conferenceAlias'(Val) ->
Enc1@len = length(Val),
[if Enc1@len < 128 ->
[align,
Enc1@len];
Enc1@len < 16384 ->
[align|<<2:2,Enc1@len:14>>]
end|['H323-MESSAGES':enc_AliasAddress(Comp) || Comp <- Val]].


dec_ConferenceStatusDescriptor_conferenceAlias(Bytes) ->
%% Length with constraint no
V1@Pad3 = bit_size(Bytes) band 7,
{V1@V0,V1@Buf1} = case Bytes of
<<_:V1@Pad3,0:1,V1@V5:7,V1@Buf6/bitstring>> ->
{V1@V5,V1@Buf6};
<<_:V1@Pad3,1:1,0:1,V1@V6:14,V1@Buf7/bitstring>> ->
{V1@V6,V1@Buf7}
end,
dec_components3(V1@V0, V1@Buf1, []).



dec_ConferenceStatusDescriptor(Bytes) ->
{Ext,Bytes1} = begin
<<V1@V0:1,V1@Buf1/bitstring>> = Bytes,
{V1@V0,V1@Buf1}
end,

%% attribute number 1 with type INTEGER
{Term1,Bytes2} = begin
V2@Pad2 = bit_size(Bytes1) band 7,
<<_:V2@Pad2,V2@V0:1/unsigned-unit:8,V2@Buf1/bitstring>> = Bytes1,
{V2@V0,V2@Buf1}
end,

%% attribute number 2 with type SEQUENCE OF
{Term2,Bytes3} = 'dec_ConferenceStatusDescriptor_conferenceAlias'(Bytes2),

%% Extensions
{Extensions,Bytes4} = case Ext of
0 -> {<<>>,Bytes3};
1 ->
{V3@V0,V3@Buf1} = case Bytes3 of
<<0:1,V3@V3:6,V3@Buf4/bitstring>> ->
V3@Add5 = V3@V3 + 1,
{V3@Add5,V3@Buf4};
<<1:1,V3@Buf2/bitstring>> ->
V3@Pad6 = bit_size(V3@Buf2) band 7,
{V3@V3,V3@Buf4} = case V3@Buf2 of
<<_:V3@Pad6,0:1,V3@V8:7,V3@Buf9/bitstring>> when V3@V8 =/= 0 ->
{V3@V8,V3@Buf9};
<<_:V3@Pad6,1:1,0:1,V3@V9:14,V3@Buf10/bitstring>> when V3@V9 =/= 0 ->
{V3@V9,V3@Buf10}
end,
{V3@V3,V3@Buf4}
end,
<<V3@V11:V3@V0/bitstring-unit:1,V3@Buf12/bitstring>> = V3@Buf1,
{V3@V11,V3@Buf12}
end,
Bytes5= skipextensions(Bytes4, 1, Extensions),
{{'ConferenceStatusDescriptor',Term1,Term2},Bytes5}.

'enc_TerStatusDescriptor'(Val) ->
[begin
Enc2@element = element(2, Val),
if Enc2@element bsr 8 =:= 0 ->
[<<0:1>>,
align,
Enc2@element];
true ->
exit({error,{asn1,{illegal_value,Enc2@element}}})
end
end|begin
Enc4@element = element(3, Val),
enc_TerStatusDescriptor_terNo(Enc4@element)
end].
'enc_TerStatusDescriptor_terNo'(Val) ->
Enc1@len = length(Val),
[if Enc1@len < 128 ->
[align,
Enc1@len];
Enc1@len < 16384 ->
[align|<<2:2,Enc1@len:14>>]
end|['H323-MESSAGES':enc_AliasAddress(Comp) || Comp <- Val]].


dec_TerStatusDescriptor_terNo(Bytes) ->
%% Length with constraint no
V1@Pad3 = bit_size(Bytes) band 7,
{V1@V0,V1@Buf1} = case Bytes of
<<_:V1@Pad3,0:1,V1@V5:7,V1@Buf6/bitstring>> ->
{V1@V5,V1@Buf6};
<<_:V1@Pad3,1:1,0:1,V1@V6:14,V1@Buf7/bitstring>> ->
{V1@V6,V1@Buf7}
end,
dec_components4(V1@V0, V1@Buf1, []).



dec_TerStatusDescriptor(Bytes) ->
{Ext,Bytes1} = begin
<<V1@V0:1,V1@Buf1/bitstring>> = Bytes,
{V1@V0,V1@Buf1}
end,

%% attribute number 1 with type INTEGER
{Term1,Bytes2} = begin
V2@Pad2 = bit_size(Bytes1) band 7,
<<_:V2@Pad2,V2@V0:1/unsigned-unit:8,V2@Buf1/bitstring>> = Bytes1,
{V2@V0,V2@Buf1}
end,

%% attribute number 2 with type SEQUENCE OF
{Term2,Bytes3} = 'dec_TerStatusDescriptor_terNo'(Bytes2),

%% Extensions
{Extensions,Bytes4} = case Ext of
0 -> {<<>>,Bytes3};
1 ->
{V3@V0,V3@Buf1} = case Bytes3 of
<<0:1,V3@V3:6,V3@Buf4/bitstring>> ->
V3@Add5 = V3@V3 + 1,
{V3@Add5,V3@Buf4};
<<1:1,V3@Buf2/bitstring>> ->
V3@Pad6 = bit_size(V3@Buf2) band 7,
{V3@V3,V3@Buf4} = case V3@Buf2 of
<<_:V3@Pad6,0:1,V3@V8:7,V3@Buf9/bitstring>> when V3@V8 =/= 0 ->
{V3@V8,V3@Buf9};
<<_:V3@Pad6,1:1,0:1,V3@V9:14,V3@Buf10/bitstring>> when V3@V9 =/= 0 ->
{V3@V9,V3@Buf10}
end,
{V3@V3,V3@Buf4}
end,
<<V3@V11:V3@V0/bitstring-unit:1,V3@Buf12/bitstring>> = V3@Buf1,
{V3@V11,V3@Buf12}
end,
Bytes5= skipextensions(Bytes4, 1, Extensions),
{{'TerStatusDescriptor',Term1,Term2},Bytes5}.


%%%
%%% Run-time functions.
%%%

dec_components1(0, Bytes, Acc) ->
{lists:reverse(Acc),Bytes};
dec_components1(Num, Bytes, Acc) ->
{Term,Remain} = 'H323-MESSAGES':dec_AliasAddress(Bytes),
dec_components1(Num-1, Remain, [Term|Acc]).

dec_components2(0, Bytes, Acc) ->
{lists:reverse(Acc),Bytes};
dec_components2(Num, Bytes, Acc) ->
{Term,Remain} = dec_TerStatusDescriptor(Bytes),
dec_components2(Num-1, Remain, [Term|Acc]).

dec_components3(0, Bytes, Acc) ->
{lists:reverse(Acc),Bytes};
dec_components3(Num, Bytes, Acc) ->
{Term,Remain} = 'H323-MESSAGES':dec_AliasAddress(Bytes),
dec_components3(Num-1, Remain, [Term|Acc]).

dec_components4(0, Bytes, Acc) ->
{lists:reverse(Acc),Bytes};
dec_components4(Num, Bytes, Acc) ->
{Term,Remain} = 'H323-MESSAGES':dec_AliasAddress(Bytes),
dec_components4(Num-1, Remain, [Term|Acc]).

align(Bin) when is_binary(Bin) ->
    Bin;
align(BitStr) when is_bitstring(BitStr) ->
    AlignBits = bit_size(BitStr) rem 8,
    <<_:AlignBits,Rest/binary>> = BitStr,
    Rest.

complete(L0) ->
    L = complete(L0, []),
    case list_to_bitstring(L) of
        <<>> ->
            <<0>>;
        Bin ->
            Bin
    end.

complete([], Bits, []) ->
    case Bits band 7 of
        0 ->
            [];
        N ->
            [<<0:(8 - N)>>]
    end;
complete([], Bits, [H|More]) ->
    complete(H, Bits, More);
complete([align|T], Bits, More) ->
    case Bits band 7 of
        0 ->
            complete(T, More);
        1 ->
            [<<0:7>>|complete(T, More)];
        2 ->
            [<<0:6>>|complete(T, More)];
        3 ->
            [<<0:5>>|complete(T, More)];
        4 ->
            [<<0:4>>|complete(T, More)];
        5 ->
            [<<0:3>>|complete(T, More)];
        6 ->
            [<<0:2>>|complete(T, More)];
        7 ->
            [<<0:1>>|complete(T, More)]
    end;
complete([[]|T], Bits, More) ->
    complete(T, Bits, More);
complete([[_|_] = H], Bits, More) ->
    complete(H, Bits, More);
complete([[_|_] = H|T], Bits, More) ->
    complete(H, Bits, [T|More]);
complete([H|T], Bits, More) when is_integer(H); is_binary(H) ->
    [H|complete(T, Bits, More)];
complete([H|T], Bits, More) ->
    [H|complete(T, Bits + bit_size(H), More)];
complete(Bin, Bits, More) when is_binary(Bin) ->
    [Bin|complete([], Bits, More)];
complete(Bin, Bits, More) ->
    [Bin|complete([], Bits + bit_size(Bin), More)].

complete([], []) ->
    [];
complete([], [H|More]) ->
    complete(H, More);
complete([align|T], More) ->
    complete(T, More);
complete([[]|T], More) ->
    complete(T, More);
complete([[_|_] = H], More) ->
    complete(H, More);
complete([[_|_] = H|T], More) ->
    complete(H, [T|More]);
complete([H|T], More) when is_integer(H); is_binary(H) ->
    [H|complete(T, More)];
complete([H|T], More) ->
    [H|complete(T, bit_size(H), More)];
complete(Bin, More) when is_binary(Bin) ->
    [Bin|complete([], More)];
complete(Bin, More) ->
    [Bin|complete([], bit_size(Bin), More)].

decode_length(Buffer) ->
    case align(Buffer) of
        <<0:1,Oct:7,Rest/binary>> ->
            {Oct,Rest};
        <<2:2,Val:14,Rest/binary>> ->
            {Val,Rest};
        <<3:2,_Val:14,_Rest/binary>> ->
            exit({error,{asn1,{decode_length,{nyi,above_16k}}}})
    end.

skipextensions(Bytes0, Nr, ExtensionBitstr)
    when is_bitstring(ExtensionBitstr) ->
    Prev = Nr - 1,
    case ExtensionBitstr of
        <<_:Prev,1:1,_/bitstring>> ->
            {Len,Bytes1} = decode_length(Bytes0),
            <<_:Len/binary,Bytes2/bitstring>> = Bytes1,
            skipextensions(Bytes2, Nr + 1, ExtensionBitstr);
        <<_:Prev,0:1,_/bitstring>> ->
            skipextensions(Bytes0, Nr + 1, ExtensionBitstr);
        _ ->
            Bytes0
    end.
