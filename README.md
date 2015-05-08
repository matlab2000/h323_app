h323_app
========

a simple h323 RAS message  test tool

this tool is written for test gnugk's performance. there's some os limits you should take care of.
1)limit of os
max thread number and max file handle number limit for os. if you broke it, the gnugk will crash.

1.1) max thread number of per process
when new ras come in, the function
void RasServer::CreateRasJob(GatekeeperMessage * msg, bool syncronous) will create thread,if too much, the ceiling of thread's number of per process will reach. default is 1024 or some other number,it depends.

1.2) file handle number limit
2015/04/15 18:10:01.816 0             assert.cxx(112)   PWLib   Assertion fail:
Operating System error, file ptlib/unix/tlibthrd.cxx, line 402, Error=24
Assertion fail: Operating System error, file ptlib/unix/tlibthrd.cxx, line 402,
Error=24
<A>bort, <C>ore dump, <I>gnore?

because each process has limit for file handle number. 

solution: gnugk has a nice config ,
  RedirectGK=Endpoints > 100 j Calls > 50

or you can limit the number of concurrent thread of gnugk.


2)the h323id's encoding
for h323id,it's should be ucs-2,but for some producer,it's different:
for chinese word "终端"，ucs-2 encoding is 0x73c8 0x7aef，gbk encoding is 0xd6 0xd5 0xb6 0xcb，and utf8 encoding is 0xe7,0xbb,0x88,0xe7,0xab,0xaf
we find that in wire there's 
	 for lifesize：  0x00 0xe7 0x00 0xbb 0x00 0x88 0x00 0xe7 0x00 0xab 0x00 0xaf  （utf-8)
	 C40(tandberg)：   0x7e 0x8c8 0x7a 0xef (ucs-2)
	 T800（zte)： 0x00 0xd6 0x00 0xd5 0x00 0xb6 0x00 0xcb (gbk)
	 
it seems like C40 is the correct one. maybe we should guess it and convert all  to utf-8 for web's showing.
the gnugk use ptlib and treat it as utf-8 and ucs-2, the PString 's AsUCS2 use
gchar * g_ucs2 = g_convert(theArray, GetSize()-1, "UCS-2", "UTF-8", 0, &g_len, 0) to do the job




