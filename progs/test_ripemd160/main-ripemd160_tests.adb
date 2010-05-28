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
   Message := LSC.RIPEMD160.Block_Type'(16#00000061#, others => 0);
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
   Message := LSC.RIPEMD160.Block_Type'(16#00636261#, others => 0);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 24);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 Example ('abc')",
                 Hash = LSC.RIPEMD160.Hash_Type'(16#f708b28e#,
                                                 16#7a985de0#,
                                                 16#8e4a049b#,
                                                 16#87b0c698#,
                                                 16#fc0b5af1#));

   --  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
   Ctx := LSC.RIPEMD160.Context_Init;
   Message := LSC.RIPEMD160.Block_Type'
      (16#44434241#, 16#48474645#, 16#4c4b4a49#, 16#504f4e4d#,
       16#54535251#, 16#58575655#, 16#62615a59#, 16#66656463#,
       16#6a696867#, 16#6e6d6c6b#, 16#7271706f#, 16#76757473#,
       16#7a797877#, 16#33323130#, 16#37363534#, 16#000a3938#);
   LSC.RIPEMD160.Context_Finalize (Ctx, Message, 496);
   Hash := LSC.RIPEMD160.Get_Hash (Ctx);

   LSC.Test.Run ("RIPEMD-160 Example ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')",
                 Hash = LSC.RIPEMD160.Hash_Type'(16#6e0be2b0#,
                                                 16#02641631#,
                                                 16#873aed86#,
                                                 16#793071a5#,
                                                 16#89511fb2#));
end RIPEMD160_Tests;
