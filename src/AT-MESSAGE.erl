%% Generated by the Erlang ASN.1 PER-compiler version, utilizing bit-syntax:3.0
%% Purpose: encoder and decoder to the types in mod AT-MESSAGE

-module('AT-MESSAGE').
-compile(nowarn_unused_vars).
-include("AT-MESSAGE.hrl").
-asn1_info([{vsn,'3.0'},
            {module,'AT-MESSAGE'},
            {options,[{i,"D:/GK_LINUX/test/erlang"},
 warnings,per,errors,
 {cwd,"D:/GK_LINUX/test/erlang"},
 {outdir,"D:/GK_LINUX/test/erlang"},
 {i,"."},
 {i,"d:/GK_LINUX/test/erlang"}]}]).

-export([encoding_rule/0,bit_string_format/0,         legacy_erlang_types/0]).
-export([
'enc_LRQsNonStandardData'/1,
'enc_LCFsNonStandardData'/1
]).

-export([
'dec_LRQsNonStandardData'/1,
'dec_LCFsNonStandardData'/1
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

encode_disp('LRQsNonStandardData',Data) -> 'enc_LRQsNonStandardData'(Data);
encode_disp('LCFsNonStandardData',Data) -> 'enc_LCFsNonStandardData'(Data);
encode_disp(Type,_Data) -> exit({error,{asn1,{undefined_type,Type}}}).


decode_disp('LRQsNonStandardData',Data) -> 'dec_LRQsNonStandardData'(Data);
decode_disp('LCFsNonStandardData',Data) -> 'dec_LCFsNonStandardData'(Data);
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
'enc_LRQsNonStandardData'(Val) ->
[align|begin
Enc1@element = element(2, Val),
if Enc1@element bsr 8 =:= 0 ->
[Enc1@element];
true ->
exit({error,{asn1,{illegal_value,Enc1@element}}})
end
end].


dec_LRQsNonStandardData(Bytes) ->

%% attribute number 1 with type INTEGER
{Term1,Bytes1} = begin
V1@Pad2 = bit_size(Bytes) band 7,
<<_:V1@Pad2,V1@V0:1/unsigned-unit:8,V1@Buf1/bitstring>> = Bytes,
{V1@V0,V1@Buf1}
end,
{{'LRQsNonStandardData',Term1},Bytes1}.

'enc_LCFsNonStandardData'(Val) ->
[begin
Enc1@element = element(3, Val),
if Enc1@element =:= asn1_NOVALUE ->
<<0:1>>;
true ->
<<1:1>>
end
end,
begin
Enc2@element = element(2, Val),
if Enc2@element bsr 32 =:= 0 ->
begin
Enc2@element@bin = binary:encode_unsigned(Enc2@element),
Enc2@element@bin_size0 = byte_size(Enc2@element@bin),
Enc2@element@bin_size = Enc2@element@bin_size0 - 1,
[<<Enc2@element@bin_size:2>>,
align|Enc2@element@bin]
end;
true ->
exit({error,{asn1,{illegal_value,Enc2@element}}})
end
end|begin
Enc4@element = element(3, Val),
if Enc4@element =:= asn1_NOVALUE ->
[];
true ->
'H323-MESSAGES':enc_AliasAddress(Enc4@element)
end
end].


dec_LCFsNonStandardData(Bytes) ->
{Opt,Bytes1} = begin
<<V1@V0:1,V1@Buf1/bitstring>> = Bytes,
{V1@V0,V1@Buf1}
end,

%% attribute number 1 with type INTEGER
{Term1,Bytes2} = begin
<<V2@V0:2/unsigned-unit:1,V2@Buf1/bitstring>> = Bytes1,
V2@Add2 = V2@V0 + 1,
V2@Pad5 = bit_size(V2@Buf1) band 7,
<<_:V2@Pad5,V2@V3:V2@Add2/unsigned-unit:8,V2@Buf4/bitstring>> = V2@Buf1,
{V2@V3,V2@Buf4}
end,

%% attribute number 2 with type AliasAddress
{Term2,Bytes3} = case Opt band 1 of
1 ->
'H323-MESSAGES':dec_AliasAddress(Bytes2);
0 ->
{asn1_NOVALUE,Bytes2}
end,
{{'LCFsNonStandardData',Term1,Term2},Bytes3}.


%%%
%%% Run-time functions.
%%%

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
