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

   Key := LSC.RIPEMD160.Block_Type'(16#0b0b0b0b#,
                                    16#0b0b0b0b#,
                                    16#0b0b0b0b#,
                                    16#0b0b0b0b#,
                                    16#0b0b0b0b#,
                                    others => 0);

   -- "Hi There"
   Block := LSC.RIPEMD160.Block_Type'(16#54206948#,
                                      16#65726568#,
                                      others => 0);

   HMAC_Ctx := LSC.HMAC.RIPEMD.Context_Init (Key);
   LSC.HMAC.RIPEMD.Context_Finalize (HMAC_Ctx, Block, 64);
   MAC := LSC.HMAC.RIPEMD.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-RIPEMD160-1",
      MAC = LSC.RIPEMD160.Hash_Type'(16#d64bcb24#,
                                     16#1afc207d#,
                                     16#73d72e5d#,
                                     16#3739cc2d#,
                                     16#68560a7f#,
                                     others => 0));

   -----------------------
   --  Test Case AUTH-2 --
   -----------------------

   --  "Jefe"
   Key   := LSC.RIPEMD160.Block_Type'(16#6566654a#,
                                      others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Block := LSC.RIPEMD160.Block_Type'(16#74616877#,
                                      16#206f6420#,
                                      16#77206179#,
                                      16#20746e61#,
                                      16#20726f66#,
                                      16#68746f6e#,
                                      16#3f676e69#,
                                      others => 0);

   HMAC_Ctx := LSC.HMAC.RIPEMD.Context_Init (Key);
   LSC.HMAC.RIPEMD.Context_Finalize (HMAC_Ctx, Block, 224);
   MAC := LSC.HMAC.RIPEMD.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-RIPEMD160-2",
      MAC = LSC.RIPEMD160.Hash_Type'(16#21c0a6dd#,
                                     16#9e5a483a#,
                                     16#2074f424#,
                                     16#33f0a764#,
                                     16#69403cb4#));

   -----------------------
   --  Test Case AUTH-3 --
   -----------------------

   --  20 times 16#aa#
   Key   := LSC.RIPEMD160.Block_Type'(16#aaaaaaaa#,
                                      16#aaaaaaaa#,
                                      16#aaaaaaaa#,
                                      16#aaaaaaaa#,
                                      16#aaaaaaaa#,
                                      others => 0);

   --  50 times 16#dd#
   Block := LSC.RIPEMD160.Block_Type'(16#dddddddd#,
                                      16#dddddddd#,
                                      16#dddddddd#,
                                      16#dddddddd#,
                                      16#dddddddd#,
                                      16#dddddddd#,
                                      16#0000dddd#,
                                      others => 0);

   HMAC_Ctx := LSC.HMAC.RIPEMD.Context_Init (Key);
   LSC.HMAC.RIPEMD.Context_Finalize (HMAC_Ctx, Block, 400);
   MAC := LSC.HMAC.RIPEMD.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-RIPEMD160-3",
      MAC = LSC.RIPEMD160.Hash_Type'(16#3605b1b0#,
                                     16#9659e70d#,
                                     16#52f3b40a#,
                                     16#e216e198#,
                                     16#c1e7d895#));

   -----------------------
   --  Test Case AUTH-4 --
   -----------------------

   Key := LSC.RIPEMD160.Block_Type'(16#04030201#,
                                    16#08070605#,
                                    16#0c0b0a09#,
                                    16#100f0e0d#,
                                    16#14131211#,
                                    16#18171615#,
                                    16#00000019#,
                                    others => 0);

   --  50 times 16#cd#
   Block := LSC.RIPEMD160.Block_Type'(16#cdcdcdcd#,
                                      16#cdcdcdcd#,
                                      16#cdcdcdcd#,
                                      16#cdcdcdcd#,
                                      16#cdcdcdcd#,
                                      16#cdcdcdcd#,
                                      16#0000cdcd#,
                                      others => 0);

   HMAC_Ctx := LSC.HMAC.RIPEMD.Context_Init (Key);
   LSC.HMAC.RIPEMD.Context_Finalize (HMAC_Ctx, Block, 400);
   MAC := LSC.HMAC.RIPEMD.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-RIPEMD160-4",
      MAC = LSC.RIPEMD160.Hash_Type'(16#2f86cad5#,
                                     16#e6d5214d#,
                                     16#4c8be110#,
                                     16#7ab9bef1#,
                                     16#f4ec6543#));
end HMAC_RIPEMD160_Tests;
