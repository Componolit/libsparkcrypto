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

   LSC.Test.Run ("RIPEMD-160 Example (empty string)",
                 Hash = LSC.RIPEMD160.Hash_Type'(16#a585119c#,
                                                 16#54fce9c5#,
                                                 16#97082861#,
                                                 16#48f5e87e#,
                                                 16#318d25b2#));

   --  "a"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'(16#61000000#, others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 8);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 Example ('a')",
                 Hash = LSC.RIPEMD160.Hash_Type'(16#2d9ddc0b#,
                                                 16#e93e6b25#,
                                                 16#7b34aeda#,
                                                 16#83dcf4e6#,
                                                 16#fe7f465a#));

   --  "abc"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'(16#61626300#, others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 24);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 Example ('abc')",
                 Hash = LSC.RIPEMD160.Hash_Type'(16#8eb208f7#,
                                                 16#e05d987a#,
                                                 16#9b044a8e#,
                                                 16#98c6b087#,
                                                 16#f15a0bfc#));

   --  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'
      (16#42414443#, 16#46454847#, 16#4a494c4b#, 16#4e4d504f#,
       16#52515453#, 16#56555857#, 16#5a596261#, 16#64636665#,
       16#68676a69#, 16#6c6b6e6d#, 16#706f7271#, 16#74737675#,
       16#78777a79#, 16#31303332#, 16#35343736#, 16#3938000a#);
   LSC.RIPEMD160.Context_Update (Ctx, Message);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 0);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 Example ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')",
                 Hash = LSC.RIPEMD160.Hash_Type'(16#b0e20b6e#,
                                                 16#31166402#,
                                                 16#86ed3a87#,
                                                 16#a5713079#,
                                                 16#b21f5189#));
end RIPEMD160_Tests;
