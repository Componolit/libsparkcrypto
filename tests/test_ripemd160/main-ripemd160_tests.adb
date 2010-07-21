-------------------------------------------------------------------------------
--  This file is part of the sparkcrypto library.
--
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>
--  Copyright (C) 2010  secunet Security Networks AG
--
--  This program is free software: you can redistribute it and/or modify it
--  under the terms of the GNU General Public License as published by the Free
--  Software Foundation, either version 3 of the License, or (at your option)
--  any later version.
--
--  This program is distributed in the hope that it will be useful, but WITHOUT
--  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
--  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
--  more details.
--  
--  You should have received a copy of the GNU General Public License along
--  with this program.  If not, see <http://www.gnu.org/licenses/>.
--  
--  As a special exception, if other files instantiate generics from this unit,
--  or you link this unit with other files to produce an executable, this unit
--  does not by itself cause the resulting executable to be covered by the GNU
--  General Public License. This exception does not however invalidate any
--  other reasons why the executable file might be covered by the GNU Public
--  License.
-------------------------------------------------------------------------------

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
   Message := LSC.RIPEMD160.Block_Type'(N (16#6d657373#),
                                        N (16#61676520#),
                                        N (16#64696765#),
                                        N (16#73740000#),
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
   Message := LSC.RIPEMD160.Block_Type'(N (16#61626364#),
                                        N (16#65666768#),
                                        N (16#696a6b6c#),
                                        N (16#6d6e6f70#),
                                        N (16#74737271#),
                                        N (16#75767778#),
                                        N (16#797a0000#),
                                        others => 0);

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
   Message := LSC.RIPEMD160.Block_Type'(N (16#61626364#),
                                        N (16#62636465#),
                                        N (16#63646566#),
                                        N (16#64656667#),
                                        N (16#65666768#),
                                        N (16#66676869#),
                                        N (16#6768696a#),
                                        N (16#68696a6b#),
                                        N (16#696a6b6c#),
                                        N (16#6a6b6c6d#),
                                        N (16#6b6c6d6e#),
                                        N (16#6c6d6e6f#),
                                        N (16#6d6e6f70#),
                                        N (16#6e6f7071#),
                                        others => 0);
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
   Message := LSC.RIPEMD160.Block_Type'(N (16#41424344#),
                                        N (16#45464748#),
                                        N (16#494a4b4c#),
                                        N (16#4d4e4f50#),
                                        N (16#51525354#),
                                        N (16#55565758#),
                                        N (16#595a6162#),
                                        N (16#63646566#),
                                        N (16#6768696a#),
                                        N (16#6b6c6d6e#),
                                        N (16#6f707172#),
                                        N (16#73747576#),
                                        N (16#7778797a#),
                                        N (16#30313233#),
                                        N (16#34353637#),
                                        N (16#38390000#));
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
   Message := LSC.RIPEMD160.Block_Type'(N (16#31323334#),
                                        N (16#35363738#),
                                        N (16#39303132#),
                                        N (16#33343536#),
                                        N (16#37383930#),
                                        N (16#31323334#),
                                        N (16#35363738#),
                                        N (16#39303132#),
                                        N (16#33343536#),
                                        N (16#37383930#),
                                        N (16#31323334#),
                                        N (16#35363738#),
                                        N (16#39303132#),
                                        N (16#33343536#),
                                        N (16#37383930#),
                                        N (16#31323334#));
   LSC.RIPEMD160.Context_Update (Ctx, Message);

   Message := LSC.RIPEMD160.Block_Type'(N (16#35363738#),
                                        N (16#39303132#),
                                        N (16#33343536#),
                                        N (16#37383930#),
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
