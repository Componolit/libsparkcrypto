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
                 Hash = LSC.RIPEMD160.Hash_Type'(16#a585119c#,
                                                 16#54fce9c5#,
                                                 16#97082861#,
                                                 16#48f5e87e#,
                                                 16#318d25b2#));

   --  "a"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'(16#00000061#, others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 8);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 ('a')",
                 Hash = LSC.RIPEMD160.Hash_Type'(16#2d9ddc0b#,
                                                 16#e93e6b25#,
                                                 16#7b34aeda#,
                                                 16#83dcf4e6#,
                                                 16#fe7f465a#));

   --  "abc"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'(16#00636261#, others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 24);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 ('abc')",
                 Hash = LSC.RIPEMD160.Hash_Type'(16#f708b28e#,
                                                 16#7a985de0#,
                                                 16#8e4a049b#,
                                                 16#87b0c698#,
                                                 16#fc0b5af1#));

   --  "message digest"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'
      (16#7373656d#, 16#20656761#, 16#65676964#, 16#00007473#,
       others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 112);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 ('message digest')",
                 Hash = LSC.RIPEMD160.Hash_Type'(16#ef89065d#,
                                                 16#e5fad249#,
                                                 16#b181b872#,
                                                 16#fa5fa823#,
                                                 16#365f5921#));

   --  "abcdefghijklmnopqrstuvwxyz"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'
      (16#64636261#, 16#68676665#, 16#6c6b6a69#, 16#706f6e6d#,
       16#74737271#, 16#78777675#, 16#00007a79#, others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 208);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 ('a...z')",
                 Hash = LSC.RIPEMD160.Hash_Type'(16#10271cf7#,
                                                 16#1b2c699c#,
                                                 16#ebdcbb56#,
                                                 16#65289d5b#,
                                                 16#bc8d70b3#));

   --  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'
      (16#64636261#, 16#65646362#, 16#66656463#, 16#67666564#,
       16#68676665#, 16#69686766#, 16#6a696867#, 16#6b6a6968#,
       16#6c6b6a69#, 16#6d6c6b6a#, 16#6e6d6c6b#, 16#6f6e6d6c#,
       16#706f6e6d#, 16#71706f6e#, others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 448);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 ('abcdbcdecdefdefgefgh...')",
                 Hash = LSC.RIPEMD160.Hash_Type'(16#3853a012#,
                                                 16#880c9c4a#,
                                                 16#6ca005e4#,
                                                 16#9af4dc27#,
                                                 16#2beb62da#));

   --  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'
      (16#44434241#, 16#48474645#, 16#4c4b4a49#, 16#504f4e4d#,
       16#54535251#, 16#58575655#, 16#62615a59#, 16#66656463#,
       16#6a696867#, 16#6e6d6c6b#, 16#7271706f#, 16#76757473#,
       16#7a797877#, 16#33323130#, 16#37363534#, 16#000a3938#);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 496);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 ('A...Za...z0...9')",
                 Hash = LSC.RIPEMD160.Hash_Type'(16#6e0be2b0#,
                                                 16#02641631#,
                                                 16#873aed86#,
                                                 16#793071a5#,
                                                 16#89511fb2#));

   --  8 times "1234567890"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'
      (16#34333231#, 16#38373635#, 16#32313039#, 16#36353433#,
       16#30393837#, 16#34333231#, 16#38373635#, 16#32313039#,
       16#36353433#, 16#30393837#, 16#34333231#, 16#38373635#,
       16#32313039#, 16#36353433#, 16#30393837#, 16#34333231#);
   LSC.RIPEMD160.Context_Update (Ctx, Message);

   Message := LSC.RIPEMD160.Block_Type'
      (16#38373635#, 16#32313039#, 16#36353433#, 16#30393837#,
       others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 128);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 (8 times '1234567890')",
                 Hash = LSC.RIPEMD160.Hash_Type'(16#452e759b#,
                                                 16#394b3d57#,
                                                 16#32d3dbf4#,
                                                 16#bf82ab3c#,
                                                 16#fb6b3263#));

   --  1 million times "a"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'(others => 16#61616161#);

   for I in Natural range 1 .. 15625
   loop
      LSC.RIPEMD160.Context_Update (Ctx, Message);
   end loop;

   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 0);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 (one million times 'a')",
                 Hash = LSC.RIPEMD160.Hash_Type'(16#43327852#,
                                                 16#db7b69c1#,
                                                 16#f9376de1#,
                                                 16#83f0687f#,
                                                 16#2815dc25#));
end RIPEMD160_Tests;
