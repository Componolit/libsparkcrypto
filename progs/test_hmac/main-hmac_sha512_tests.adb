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
procedure HMAC_SHA512_Tests is

   HMAC_Ctx                         : LSC.HMAC.SHA512.Context_Type;
   Key                              : LSC.SHA2.Block_Type;
   Block                            : LSC.SHA2.Block_Type;
   PRF_HMAC_SHA_512                 : LSC.SHA2.SHA512_Hash_Type;
   AUTH_HMAC_SHA_512                : LSC.HMAC.SHA512.Auth_Type;

begin

   LSC.Test.Suite ("HMAC-SHA512 tests");

   --  SHA512 PRF Test Vectors (RFC 4868, 2.7.1.)

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

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 64);
   PRF_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-PRF-1",
      PRF_HMAC_SHA_512 =
      LSC.SHA2.SHA512_Hash_Type'(16#87aa7cdea5ef619d#,
                                 16#4ff0b4241a1d6cb0#,
                                 16#2379f4e2ce4ec278#,
                                 16#7ad0b30545e17cde#,
                                 16#daa833b7d6b8a702#,
                                 16#038b274eaea3f4e4#,
                                 16#be9d914eeb61f170#,
                                 16#2e696c203a126854#));

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

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 224);
   PRF_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-PRF-2",
      PRF_HMAC_SHA_512 =
      LSC.SHA2.SHA512_Hash_Type'(16#164b7a7bfcf819e2#,
                                 16#e395fbe73b56e0a3#,
                                 16#87bd64222e831fd6#,
                                 16#10270cd7ea250554#,
                                 16#9758bf75c05a994a#,
                                 16#6d034f65f8f0e6fd#,
                                 16#caeab1a34d4a6b4b#,
                                 16#636e070a38bce737#));

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

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 400);
   PRF_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-PRF-3",
      PRF_HMAC_SHA_512 =
      LSC.SHA2.SHA512_Hash_Type'(16#fa73b0089d56a284#,
                                 16#efb0f0756c890be9#,
                                 16#b1b5dbdd8ee81a36#,
                                 16#55f83e33b2279d39#,
                                 16#bf3e848279a722c8#,
                                 16#06b485a47e67c807#,
                                 16#b946a337bee89426#,
                                 16#74278859e13292fb#));

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

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 400);
   PRF_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-PRF-4",
      PRF_HMAC_SHA_512 =
      LSC.SHA2.SHA512_Hash_Type'(16#b0ba465637458c69#,
                                 16#90e5a8c5f61d4af7#,
                                 16#e576d97ff94b872d#,
                                 16#e76f8050361ee3db#,
                                 16#a91ca5c11aa25eb4#,
                                 16#d679275cc5788063#,
                                 16#a5f19741120c4f2d#,
                                 16#e2adebeb10a298dd#));

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

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 64);
   AUTH_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-AUTH-1",
      AUTH_HMAC_SHA_512 =
      LSC.HMAC.SHA512.Auth_Type'(0 => 16#637edc6e01dce7e6#,
                                 1 => 16#742a99451aae82df#,
                                 2 => 16#23da3e92439e590e#,
                                 3 => 16#43e761b33e910fb8#));

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

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 224);
   AUTH_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-AUTH-2",
      AUTH_HMAC_SHA_512 =
      LSC.HMAC.SHA512.Auth_Type'(16#cb370917ae8a7ce2#,
                                 16#8cfd1d8f4705d614#,
                                 16#1c173b2a9362c15d#,
                                 16#f235dfb251b15454#));

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

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 400);
   AUTH_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-AUTH-3",
      AUTH_HMAC_SHA_512 =
      LSC.HMAC.SHA512.Auth_Type'(0 => 16#2ee7acd783624ca9#,
                                 1 => 16#398710f3ee05ae41#,
                                 2 => 16#b9f9b0510c87e49e#,
                                 3 => 16#586cc9bf961733d8#));

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

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 400);
   AUTH_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-AUTH-4",
      AUTH_HMAC_SHA_512 =
      LSC.HMAC.SHA512.Auth_Type'(0 => 16#5e6688e5a3daec82#,
                                 1 => 16#6ca32eaea224eff5#,
                                 2 => 16#e700628947470e13#,
                                 3 => 16#ad01302561bab108#));
end HMAC_SHA512_Tests;
