--  This file is part of the sparkcrypto library.

--  Copyright (C) 2010  secunet Security Networks AG
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>

--  This library  is free software:  you can  redistribute it and/or  modify it
--  under the  terms of the GNU  Lesser General Public License  as published by
--  the Free Software Foundation, either version  3 of the License, or (at your
--  option) any later version.

--  This library is distributed in the hope that it will be useful, but WITHOUT
--  ANY  WARRANTY; without  even  the implied  warranty  of MERCHANTABILITY  or
--  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
--  for more details.

--  You should  have received a copy  of the GNU Lesser  General Public License
--  along with this library. If not, see <http://www.gnu.org/licenses/>.

separate (Main)
procedure RIPEMD160_Tests is
   Ctx      : LSC.RIPEMD160.Context_Type;
   Hash     : LSC.RIPEMD160.Hash_Type;
   Message  : LSC.RIPEMD160.Block_Type;
begin

   LSC.Test.Suite ("RIPEMD160 tests");

   -- RIPEMD-160: A Strengthened Version of RIPEMD , Appendix B: Test values

   --  "" (empty string)
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'(others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 0);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 (empty string)",
                 Hash = LSC.RIPEMD160.Hash_Type'(N (16#9c1185a5#),
                                                 N (16#c5e9fc54#),
                                                 N (16#61280897#),
                                                 N (16#7ee8f548#),
                                                 N (16#b2258d31#)));

   --  "a"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'(N (16#61000000#), others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 8);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 ('a')",
                 Hash = LSC.RIPEMD160.Hash_Type'(N (16#0bdc9d2d#),
                                                 N (16#256b3ee9#),
                                                 N (16#daae347b#),
                                                 N (16#e6f4dc83#),
                                                 N (16#5a467ffe#)));

   --  "abc"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'(N (16#61626300#), others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 24);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 ('abc')",
                 Hash = LSC.RIPEMD160.Hash_Type'(N (16#8eb208f7#),
                                                 N (16#e05d987a#),
                                                 N (16#9b044a8e#),
                                                 N (16#98c6b087#),
                                                 N (16#f15a0bfc#)));

   --  "message digest"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'
      (N (16#6d657373#), N (16#20656761#), N (16#65676964#), N (16#00007473#),
       others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 112);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 ('message digest')",
                 Hash = LSC.RIPEMD160.Hash_Type'(N (16#5d0689ef#),
                                                 N (16#49d2fae5#),
                                                 N (16#72b881b1#),
                                                 N (16#23a85ffa#),
                                                 N (16#21595f36#)));

   --  "abcdefghijklmnopqrstuvwxyz"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'
      (N (16#61626364#), N (16#68676665#), N (16#6c6b6a69#), N (16#706f6e6d#),
       N (16#71727374#), N (16#78777675#), N (16#00007a79#), others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 208);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 ('a...z')",
                 Hash = LSC.RIPEMD160.Hash_Type'(N (16#f71c2710#),
                                                 N (16#9c692c1b#),
                                                 N (16#56bbdceb#),
                                                 N (16#5b9d2865#),
                                                 N (16#b3708dbc#)));

   --  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'
      (N (16#61626364#), N (16#65646362#), N (16#66656463#), N (16#67666564#),
       N (16#65666768#), N (16#69686766#), N (16#6a696867#), N (16#6b6a6968#),
       N (16#696a6b6c#), N (16#6d6c6b6a#), N (16#6e6d6c6b#), N (16#6f6e6d6c#),
       N (16#6d6e6f70#), 16#71706f6e#, others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 448);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 ('abcdbcdecdefdefgefgh...')",
                 Hash = LSC.RIPEMD160.Hash_Type'(N (16#12a05338#),
                                                 N (16#4a9c0c88#),
                                                 N (16#e405a06c#),
                                                 N (16#27dcf49a#),
                                                 N (16#da62eb2b#)));

   --  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'
      (N (16#41424344#), N (16#48474645#), N (16#4c4b4a49#), N (16#504f4e4d#),
       N (16#51525354#), N (16#58575655#), N (16#62615a59#), N (16#66656463#),
       N (16#6768696a#), N (16#6e6d6c6b#), N (16#7271706f#), N (16#76757473#),
       N (16#7778797a#), N (16#33323130#), N (16#37363534#), N (16#000a3938#));
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 496);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 ('A...Za...z0...9')",
                 Hash = LSC.RIPEMD160.Hash_Type'(N (16#b0e20b6e#),
                                                 N (16#31166402#),
                                                 N (16#86ed3a87#),
                                                 N (16#a5713079#),
                                                 N (16#b21f5189#)));

   --  8 times "1234567890"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'
      (N (16#31323334#), N (16#38373635#), N (16#32313039#), N (16#36353433#),
       N (16#37383930#), N (16#34333231#), N (16#38373635#), N (16#32313039#),
       N (16#33343536#), N (16#30393837#), N (16#34333231#), N (16#38373635#),
       N (16#39303132#), N (16#36353433#), N (16#30393837#), N (16#34333231#));
   LSC.RIPEMD160.Context_Update (Ctx, Message);

   Message := LSC.RIPEMD160.Block_Type'
      (N (16#35363738#), N (16#32313039#), N (16#36353433#), N (16#30393837#),
       others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 128);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 (8 times '1234567890')",
                 Hash = LSC.RIPEMD160.Hash_Type'(N (16#9b752e45#),
                                                 N (16#573d4b39#),
                                                 N (16#f4dbd332#),
                                                 N (16#3cab82bf#),
                                                 N (16#63326bfb#)));

   --  1 million times "a"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'(others => N (16#61616161#));

   for I in Natural range 1 .. 15625
   --# assert I in 1 .. 15625;
   loop
      LSC.RIPEMD160.Context_Update (Ctx, Message);
   end loop;

   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 0);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 (one million times 'a')",
                 Hash = LSC.RIPEMD160.Hash_Type'(N (16#52783243#),
                                                 N (16#c1697bdb#),
                                                 N (16#e16d37f9#),
                                                 N (16#7f68f083#),
                                                 N (16#25dc1528#)));
end RIPEMD160_Tests;
