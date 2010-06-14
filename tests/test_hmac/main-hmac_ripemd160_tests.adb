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
procedure HMAC_RIPEMD160_Tests is

   HMAC_Ctx    : LSC.HMAC.RIPEMD.Context_Type;
   Key         : LSC.RIPEMD160.Block_Type;
   Block       : LSC.RIPEMD160.Block_Type;
   MAC         : LSC.RIPEMD160.Hash_Type;

begin

   LSC.Test.Suite ("HMAC-RIPEMD160 tests");

   --  RIPEMD160 Test Vectors (RFC 2286, 2.)

   -----------------------
   --  Test Case AUTH-1 --
   -----------------------

   Key := LSC.RIPEMD160.Block_Type'
      (M (16#0b0b0b0b#), M (16#0b0b0b0b#), M (16#0b0b0b0b#),
       M (16#0b0b0b0b#), M (16#0b0b0b0b#), others => 0);

   -- "Hi There"
   Block := LSC.RIPEMD160.Block_Type'
      (M (16#48692054#), M (16#68657265#), others => 0);

   HMAC_Ctx := LSC.HMAC.RIPEMD.Context_Init (Key);
   LSC.HMAC.RIPEMD.Context_Finalize (HMAC_Ctx, Block, 64);
   MAC := LSC.HMAC.RIPEMD.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-RIPEMD160-1",
      MAC = LSC.RIPEMD160.Hash_Type'
      (M (16#24cb4bd6#), M (16#7d20fc1a#), M (16#5d2ed773#),
       M (16#2dcc3937#), M (16#7f0a5668#), others => 0));

   -----------------------
   --  Test Case AUTH-2 --
   -----------------------

   --  "Jefe"
   Key   := LSC.RIPEMD160.Block_Type'
      (M (16#4a656665#), others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Block := LSC.RIPEMD160.Block_Type'
      (M (16#77686174#), M (16#20646f20#), M (16#79612077#), M (16#616e7420#),
       M (16#666f7220#), M (16#6e6f7468#), M (16#696e673f#), others => 0);

   HMAC_Ctx := LSC.HMAC.RIPEMD.Context_Init (Key);
   LSC.HMAC.RIPEMD.Context_Finalize (HMAC_Ctx, Block, 224);
   MAC := LSC.HMAC.RIPEMD.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-RIPEMD160-2",
      MAC = LSC.RIPEMD160.Hash_Type'
               (M (16#dda6c021#), M (16#3a485a9e#), M (16#24f47420#),
                M (16#64a7f033#), M (16#b43c4069#)));

   -----------------------
   --  Test Case AUTH-3 --
   -----------------------

   --  20 times 16#aa#
   Key   := LSC.RIPEMD160.Block_Type'
      (M (16#aaaaaaaa#), M (16#aaaaaaaa#), M (16#aaaaaaaa#),
       M (16#aaaaaaaa#), M (16#aaaaaaaa#), others => 0);

   --  50 times 16#dd#
   Block := LSC.RIPEMD160.Block_Type'
      (M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
       M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
       M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
       M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
       M (16#dddd0000#), others => 0);

   HMAC_Ctx := LSC.HMAC.RIPEMD.Context_Init (Key);
   LSC.HMAC.RIPEMD.Context_Finalize (HMAC_Ctx, Block, 400);
   MAC := LSC.HMAC.RIPEMD.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-RIPEMD160-3",
      MAC = LSC.RIPEMD160.Hash_Type'
      (M (16#b0b10536#), M (16#0de75996#), M (16#0ab4f352#),
       M (16#98e116e2#), M (16#95d8e7c1#)));

   -----------------------
   --  Test Case AUTH-4 --
   -----------------------

   Key := LSC.RIPEMD160.Block_Type'
      (M (16#01020304#), M (16#05060708#), M (16#090a0b0c#),
       M (16#0d0e0f10#), M (16#11121314#), M (16#15161718#),
       M (16#19000000#), others => 0);

   --  50 times 16#cd#
   Block := LSC.RIPEMD160.Block_Type'
      (M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
       M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
       M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
       M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
       M (16#cdcd0000#), others => 0);

   HMAC_Ctx := LSC.HMAC.RIPEMD.Context_Init (Key);
   LSC.HMAC.RIPEMD.Context_Finalize (HMAC_Ctx, Block, 400);
   MAC := LSC.HMAC.RIPEMD.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-RIPEMD160-4",
      MAC = LSC.RIPEMD160.Hash_Type'
      (M (16#d5ca862f#), M (16#4d21d5e6#), M (16#10e18b4c#),
       M (16#f1beb97a#), M (16#4365ecf4#)));

end HMAC_RIPEMD160_Tests;
