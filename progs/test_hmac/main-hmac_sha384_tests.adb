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

   Key   := LSC.SHA2.Block_Type'(0 => 16#0b0b0b0b0b0b0b0b#,
                                 1 => 16#0b0b0b0b0b0b0b0b#,
                                 2 => 16#0b0b0b0b00000000#,
                                 others => 0);

   -- "Hi There"
   Block := LSC.SHA2.Block_Type'(0 => 16#48_69_20_54_68_65_72_65#,
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
   Key   := LSC.SHA2.Block_Type'(0 => 16#4a_65_66_65_00_00_00_00#,
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
   Key   := LSC.SHA2.Block_Type'(0 => 16#aaaaaaaaaaaaaaaa#,
                                 1 => 16#aaaaaaaaaaaaaaaa#,
                                 2 => 16#aaaaaaaa00000000#,
                                 others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA2.Block_Type'(0 => 16#dddddddddddddddd#,
                                 1 => 16#dddddddddddddddd#,
                                 2 => 16#dddddddddddddddd#,
                                 3 => 16#dddddddddddddddd#,
                                 4 => 16#dddddddddddddddd#,
                                 5 => 16#dddddddddddddddd#,
                                 6 => 16#dddd000000000000#,
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
   Key   := LSC.SHA2.Block_Type'(0 => 16#0102030405060708#,
                                 1 => 16#090a0b0c0d0e0f10#,
                                 2 => 16#1112131415161718#,
                                 3 => 16#1900000000000000#,
                                 others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA2.Block_Type'(0 => 16#cdcdcdcdcdcdcdcd#,
                                 1 => 16#cdcdcdcdcdcdcdcd#,
                                 2 => 16#cdcdcdcdcdcdcdcd#,
                                 3 => 16#cdcdcdcdcdcdcdcd#,
                                 4 => 16#cdcdcdcdcdcdcdcd#,
                                 5 => 16#cdcdcdcdcdcdcdcd#,
                                 6 => 16#cdcd000000000000#,
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

   --  64 bytes
   Key   := LSC.SHA2.Block_Type'(0 => 16#0b0b0b0b0b0b0b0b#,
                                 1 => 16#0b0b0b0b0b0b0b0b#,
                                 2 => 16#0b0b0b0b0b0b0b0b#,
                                 3 => 16#0b0b0b0b0b0b0b0b#,
                                 4 => 16#0b0b0b0b0b0b0b0b#,
                                 5 => 16#0b0b0b0b0b0b0b0b#,
                                 6 => 16#0b0b0b0b0b0b0b0b#,
                                 7 => 16#0b0b0b0b0b0b0b0b#,
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
   Key   := LSC.SHA2.Block_Type'(0 => 16#4a6566654a656665#,
                                 1 => 16#4a6566654a656665#,
                                 2 => 16#4a6566654a656665#,
                                 3 => 16#4a6566654a656665#,
                                 4 => 16#4a6566654a656665#,
                                 5 => 16#4a6566654a656665#,
                                 6 => 16#4a6566654a656665#,
                                 7 => 16#4a6566654a656665#,
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

   --  64 times 16#aa#
   Key   := LSC.SHA2.Block_Type'(0 => 16#aaaaaaaaaaaaaaaa#,
                                 1 => 16#aaaaaaaaaaaaaaaa#,
                                 2 => 16#aaaaaaaaaaaaaaaa#,
                                 3 => 16#aaaaaaaaaaaaaaaa#,
                                 4 => 16#aaaaaaaaaaaaaaaa#,
                                 5 => 16#aaaaaaaaaaaaaaaa#,
                                 6 => 16#aaaaaaaaaaaaaaaa#,
                                 7 => 16#aaaaaaaaaaaaaaaa#,
                                 others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA2.Block_Type'(0 => 16#dddddddddddddddd#,
                                 1 => 16#dddddddddddddddd#,
                                 2 => 16#dddddddddddddddd#,
                                 3 => 16#dddddddddddddddd#,
                                 4 => 16#dddddddddddddddd#,
                                 5 => 16#dddddddddddddddd#,
                                 6 => 16#dddd000000000000#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 400);
   AUTH_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-AUTH-3",
      AUTH_HMAC_SHA_384 =
      LSC.HMAC.SHA384.Auth_Type'(0 => 16#2ee7acd783624ca9#,
                                 1 => 16#398710f3ee05ae41#,
                                 2 => 16#b9f9b0510c87e49e#));

   -----------------------
   --  Test Case AUTH-4 --
   -----------------------

   --  64 bytes
   --  NB: The test vector in RCF 4868 seem to be bogus! Though stating
   --      this to be a 64 bytes key, 80 bytes are presented. However,
   --      leaving out the first 16 bytes of the bogus key results in
   --      the presented MAC.
   Key   := LSC.SHA2.Block_Type'(-- 16#0a0b0c0d0e0f1011#,
                                 -- 16#1213141516171819#,
                                 16#0102030405060708#,
                                 16#090a0b0c0d0e0f10#,
                                 16#1112131415161718#,
                                 16#191a1b1c1d1e1f20#,
                                 16#2122232425262728#,
                                 16#292a2b2c2d2e2f30#,
                                 16#3132333435363738#,
                                 16#393a3b3c3d3e3f40#,
                                 others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA2.Block_Type'(0 => 16#cdcdcdcdcdcdcdcd#,
                                 1 => 16#cdcdcdcdcdcdcdcd#,
                                 2 => 16#cdcdcdcdcdcdcdcd#,
                                 3 => 16#cdcdcdcdcdcdcdcd#,
                                 4 => 16#cdcdcdcdcdcdcdcd#,
                                 5 => 16#cdcdcdcdcdcdcdcd#,
                                 6 => 16#cdcd000000000000#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 400);
   AUTH_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-AUTH-4",
      AUTH_HMAC_SHA_384 =
      LSC.HMAC.SHA384.Auth_Type'(0 => 16#5e6688e5a3daec82#,
                                 1 => 16#6ca32eaea224eff5#,
                                 2 => 16#e700628947470e13#));
end HMAC_SHA384_Tests;
