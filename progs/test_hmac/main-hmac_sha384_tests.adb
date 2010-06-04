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
procedure HMAC_SHA384_Tests is

   HMAC_Ctx                         : LSC.HMAC.SHA384.Context_Type;
   Key                              : LSC.SHA2.Block_Type;
   Block                            : LSC.SHA2.Block_Type;
   PRF_HMAC_SHA_384                 : LSC.SHA2.SHA384_Hash_Type;
   AUTH_HMAC_SHA_384                : LSC.HMAC.SHA384.Auth_Type;

begin

   LSC.Test.Suite ("HMAC-SHA384 tests");

   --  SHA384 PRF Test Vectors (RFC 4868, 2.7.1.)

   ----------------------
   --  Test Case PRF-1 --
   ----------------------

   Key   := LSC.SHA2.Block_Type'(16#0b0b0b0b0b0b0b0b#,
                                 16#0b0b0b0b0b0b0b0b#,
                                 16#0b0b0b0b00000000#,
                                 others => 0);

   -- "Hi There"
   Block := LSC.SHA2.Block_Type'(16#48_69_20_54_68_65_72_65#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 64);
   PRF_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-PRF-1",
      PRF_HMAC_SHA_384 =
      LSC.SHA2.SHA384_Hash_Type'(16#afd03944d8489562#,
                                 16#6b0825f4ab46907f#,
                                 16#15f9dadbe4101ec6#,
                                 16#82aa034c7cebc59c#,
                                 16#faea9ea9076ede7f#,
                                 16#4af152e8b2fa9cb6#));

   ----------------------
   --  Test Case PRF-2 --
   ----------------------

   --  "Jefe"
   Key   := LSC.SHA2.Block_Type'(16#4a_65_66_65_00_00_00_00#,
                                 others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Block := LSC.SHA2.Block_Type'(16#7768617420646f20#,
                                 16#79612077616e7420#,
                                 16#666f72206e6f7468#,
                                 16#696e673f00000000#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 224);
   PRF_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-PRF-2",
      PRF_HMAC_SHA_384 =
      LSC.SHA2.SHA384_Hash_Type'(16#af45d2e376484031#,
                                 16#617f78d2b58a6b1b#,
                                 16#9c7ef464f5a01b47#,
                                 16#e42ec3736322445e#,
                                 16#8e2240ca5e69e2c7#,
                                 16#8b3239ecfab21649#));

   ----------------------
   --  Test Case PRF-3 --
   ----------------------

   --  20 times 16#aa#
   Key   := LSC.SHA2.Block_Type'(16#aaaaaaaaaaaaaaaa#,
                                 16#aaaaaaaaaaaaaaaa#,
                                 16#aaaaaaaa00000000#,
                                 others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA2.Block_Type'(16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddd000000000000#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 400);
   PRF_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-PRF-3",
      PRF_HMAC_SHA_384 =
      LSC.SHA2.SHA384_Hash_Type'(16#88062608d3e6ad8a#,
                                 16#0aa2ace014c8a86f#,
                                 16#0aa635d947ac9feb#,
                                 16#e83ef4e55966144b#,
                                 16#2a5ab39dc13814b9#,
                                 16#4e3ab6e101a34f27#));

   ----------------------
   --  Test Case PRF-4 --
   ----------------------

   --  25 bytes
   Key   := LSC.SHA2.Block_Type'(16#0102030405060708#,
                                 16#090a0b0c0d0e0f10#,
                                 16#1112131415161718#,
                                 16#1900000000000000#,
                                 others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA2.Block_Type'(16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcd000000000000#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 400);
   PRF_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-PRF-4",
      PRF_HMAC_SHA_384 =
      LSC.SHA2.SHA384_Hash_Type'(16#3e8a69b7783c2585#,
                                 16#1933ab6290af6ca7#,
                                 16#7a9981480850009c#,
                                 16#c5577c6e1f573b4e#,
                                 16#6801dd23c4a7d679#,
                                 16#ccf8a386c674cffb#));

   -----------------------
   --  Test Case AUTH-1 --
   -----------------------

   --  48 bytes
   Key   := LSC.SHA2.Block_Type'(16#0b0b0b0b0b0b0b0b#,
                                 16#0b0b0b0b0b0b0b0b#,
                                 16#0b0b0b0b0b0b0b0b#,
                                 16#0b0b0b0b0b0b0b0b#,
                                 16#0b0b0b0b0b0b0b0b#,
                                 16#0b0b0b0b0b0b0b0b#,
                                 others => 0);

   -- "Hi There"
   Block := LSC.SHA2.Block_Type'(0 => 16#48_69_20_54_68_65_72_65#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 64);
   AUTH_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-AUTH-1",
      AUTH_HMAC_SHA_384 =
      LSC.HMAC.SHA384.Auth_Type'(16#b6a8d5636f5c6a72#,
                                 16#24f9977dcf7ee6c7#,
                                 16#fb6d0c48cbdee973#));

   -----------------------
   --  Test Case AUTH-2 --
   -----------------------

   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   Key   := LSC.SHA2.Block_Type'(16#4a6566654a656665#,
                                 16#4a6566654a656665#,
                                 16#4a6566654a656665#,
                                 16#4a6566654a656665#,
                                 16#4a6566654a656665#,
                                 16#4a6566654a656665#,
                                 others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Block := LSC.SHA2.Block_Type'(16#7768617420646f20#,
                                 16#79612077616e7420#,
                                 16#666f72206e6f7468#,
                                 16#696e673f00000000#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 224);
   AUTH_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-AUTH-2",
      AUTH_HMAC_SHA_384 =
      LSC.HMAC.SHA384.Auth_Type'(16#2c7353974f1842fd#,
                                 16#66d53c452ca42122#,
                                 16#b28c0b594cfb184d#));

   -----------------------
   --  Test Case AUTH-3 --
   -----------------------

   --  48 times 16#aa#
   Key   := LSC.SHA2.Block_Type'(16#aaaaaaaaaaaaaaaa#,
                                 16#aaaaaaaaaaaaaaaa#,
                                 16#aaaaaaaaaaaaaaaa#,
                                 16#aaaaaaaaaaaaaaaa#,
                                 16#aaaaaaaaaaaaaaaa#,
                                 16#aaaaaaaaaaaaaaaa#,
                                 others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA2.Block_Type'(16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddd000000000000#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 400);
   AUTH_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-AUTH-3",
      AUTH_HMAC_SHA_384 =
      LSC.HMAC.SHA384.Auth_Type'(16#809f439be0027432#,
                                 16#1d4a538652164b53#,
                                 16#554a508184a0c316#));

   -----------------------
   --  Test Case AUTH-4 --
   -----------------------

   Key   := LSC.SHA2.Block_Type'(16#0102030405060708#,
                                 16#090a0b0c0d0e0f10#,
                                 16#1112131415161718#,
                                 16#191a1b1c1d1e1f20#,
                                 16#0a0b0c0d0e0f1011#,
                                 16#1213141516171819#,
                                 others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA2.Block_Type'(16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcd000000000000#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 400);
   AUTH_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-AUTH-4",
      AUTH_HMAC_SHA_384 =
      LSC.HMAC.SHA384.Auth_Type'(16#5b540085c6e63580#,
                                 16#96532b2493609ed1#,
                                 16#cb298f774f87bb5c#));
end HMAC_SHA384_Tests;
