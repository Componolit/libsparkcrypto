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
procedure HMAC_SHA512_Tests is

   HMAC_Ctx                         : LSC.HMAC_SHA512.Context_Type;
   Key                              : LSC.SHA512.Block_Type;
   Block                            : LSC.SHA512.Block_Type;
   PRF_HMAC_SHA_512                 : LSC.SHA512.SHA512_Hash_Type;

   subtype Message1_Index is LSC.Types.Word64 range 1 .. 1;
   subtype Message1_Type is LSC.SHA512.Message_Type (Message1_Index);

   Message1 : Message1_Type;

begin

   LSC.Test.Suite ("HMAC-SHA512 tests");

   --  SHA512 PRF Test Vectors (RFC 4868, 2.7.1.)

   ----------------------
   --  Test Case PRF-1 --
   ----------------------

   Key   := LSC.SHA512.Block_Type'
      (N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#),
       N (16#0b0b0b0b00000000#), others => 0);

   -- "Hi There"
   Block := LSC.SHA512.Block_Type'
      (N (16#4869205468657265#), others => 0);

   HMAC_Ctx := LSC.HMAC_SHA512.Context_Init (Key);
   LSC.HMAC_SHA512.Context_Finalize (HMAC_Ctx, Block, 64);
   PRF_HMAC_SHA_512 := LSC.HMAC_SHA512.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-PRF-1",
      PRF_HMAC_SHA_512 =
      LSC.SHA512.SHA512_Hash_Type'
         (N (16#87aa7cdea5ef619d#), N (16#4ff0b4241a1d6cb0#), N (16#2379f4e2ce4ec278#),
          N (16#7ad0b30545e17cde#), N (16#daa833b7d6b8a702#), N (16#038b274eaea3f4e4#),
          N (16#be9d914eeb61f170#), N (16#2e696c203a126854#)));

   ----------------------
   --  Test Case PRF-2 --
   ----------------------

   --  "Jefe"
   Key   := LSC.SHA512.Block_Type'
      (0 => N (16#4a65666500000000#), others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Block := LSC.SHA512.Block_Type'
      (N (16#7768617420646f20#), N (16#79612077616e7420#), N (16#666f72206e6f7468#),
       N (16#696e673f00000000#), others => 0);

   HMAC_Ctx := LSC.HMAC_SHA512.Context_Init (Key);
   LSC.HMAC_SHA512.Context_Finalize (HMAC_Ctx, Block, 224);
   PRF_HMAC_SHA_512 := LSC.HMAC_SHA512.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-PRF-2",
      PRF_HMAC_SHA_512 =
      LSC.SHA512.SHA512_Hash_Type'
         (N (16#164b7a7bfcf819e2#), N (16#e395fbe73b56e0a3#), N (16#87bd64222e831fd6#),
          N (16#10270cd7ea250554#), N (16#9758bf75c05a994a#), N (16#6d034f65f8f0e6fd#),
          N (16#caeab1a34d4a6b4b#), N (16#636e070a38bce737#)));

   ----------------------
   --  Test Case PRF-3 --
   ----------------------

   --  20 times 16#aa#
   Key   := LSC.SHA512.Block_Type'
      (N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaa00000000#),
       others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA512.Block_Type'
      (N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
       N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
       N (16#dddd000000000000#), others => 0);

   HMAC_Ctx := LSC.HMAC_SHA512.Context_Init (Key);
   LSC.HMAC_SHA512.Context_Finalize (HMAC_Ctx, Block, 400);
   PRF_HMAC_SHA_512 := LSC.HMAC_SHA512.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-PRF-3",
      PRF_HMAC_SHA_512 =
      LSC.SHA512.SHA512_Hash_Type'
         (N (16#fa73b0089d56a284#), N (16#efb0f0756c890be9#), N (16#b1b5dbdd8ee81a36#),
          N (16#55f83e33b2279d39#), N (16#bf3e848279a722c8#), N (16#06b485a47e67c807#),
          N (16#b946a337bee89426#), N (16#74278859e13292fb#)));

   ----------------------
   --  Test Case PRF-4 --
   ----------------------

   --  25 bytes
   Key   := LSC.SHA512.Block_Type'
         (N (16#0102030405060708#), N (16#090a0b0c0d0e0f10#), N (16#1112131415161718#),
          N (16#1900000000000000#), others => 0);

   --  50 times 16#cd#
   Block := LSC.SHA512.Block_Type'
      (N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
       N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
       N (16#cdcd000000000000#), others => 0);

   HMAC_Ctx := LSC.HMAC_SHA512.Context_Init (Key);
   LSC.HMAC_SHA512.Context_Finalize (HMAC_Ctx, Block, 400);
   PRF_HMAC_SHA_512 := LSC.HMAC_SHA512.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-PRF-4",
      PRF_HMAC_SHA_512 =
      LSC.SHA512.SHA512_Hash_Type'
         (N (16#b0ba465637458c69#), N (16#90e5a8c5f61d4af7#), N (16#e576d97ff94b872d#),
          N (16#e76f8050361ee3db#), N (16#a91ca5c11aa25eb4#), N (16#d679275cc5788063#),
          N (16#a5f19741120c4f2d#), N (16#e2adebeb10a298dd#)));

   -----------------------
   --  Test Case AUTH-1 --
   -----------------------

   --  64 bytes
   Key   := LSC.SHA512.Block_Type'
         (N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#),
          N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#),
          N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#), others => 0);

   -- "Hi There"
   Message1 := Message1_Type'(1 => LSC.SHA512.Block_Type'(N (16#4869205468657265#), others => 0));

   LSC.Test.Run
     ("HMAC-SHA512-AUTH-1",
      LSC.HMAC_SHA512.Authenticate (Key, Message1, 64) =
      LSC.HMAC_SHA512.Auth_Type'
         (N (16#637edc6e01dce7e6#), N (16#742a99451aae82df#), N (16#23da3e92439e590e#),
          N (16#43e761b33e910fb8#)));

   -----------------------
   --  Test Case AUTH-2 --
   -----------------------

   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   Key   := LSC.SHA512.Block_Type'
      (N (16#4a6566654a656665#), N (16#4a6566654a656665#), N (16#4a6566654a656665#),
       N (16#4a6566654a656665#), N (16#4a6566654a656665#), N (16#4a6566654a656665#),
       N (16#4a6566654a656665#), N (16#4a6566654a656665#), others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Message1 := Message1_Type'(1 => LSC.SHA512.Block_Type'
      (N (16#7768617420646f20#), N (16#79612077616e7420#), N (16#666f72206e6f7468#),
       N (16#696e673f00000000#), others => 0));

   LSC.Test.Run
     ("HMAC-SHA512-AUTH-2",
      LSC.HMAC_SHA512.Authenticate (Key, Message1, 224) =
      LSC.HMAC_SHA512.Auth_Type'
         (N (16#cb370917ae8a7ce2#), N (16#8cfd1d8f4705d614#), N (16#1c173b2a9362c15d#),
          N (16#f235dfb251b15454#)));

   -----------------------
   --  Test Case AUTH-3 --
   -----------------------

   --  64 times 16#aa#
   Key   := LSC.SHA512.Block_Type'
         (N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#),
          N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#),
          N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#), others => 0);

   --  50 times 16#dd#
   Message1 := Message1_Type'(1 => LSC.SHA512.Block_Type'
         (N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
          N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
          N (16#dddd000000000000#), others => 0));

   LSC.Test.Run
     ("HMAC-SHA512-AUTH-3",
      LSC.HMAC_SHA512.Authenticate (Key, Message1, 400) =
      LSC.HMAC_SHA512.Auth_Type'
         (N (16#2ee7acd783624ca9#), N (16#398710f3ee05ae41#), N (16#b9f9b0510c87e49e#),
          N (16#586cc9bf961733d8#)));

   -----------------------
   --  Test Case AUTH-4 --
   -----------------------

   --  64 bytes
   --  NB: The test vector in RCF 4868 seem to be bogus! Though stating
   --      this to be a 64 bytes key, 80 bytes are presented. However,
   --      leaving out the first 16 bytes of the bogus key results in
   --      the presented MAC.
   Key   := LSC.SHA512.Block_Type'
      (-- N (16#0a0b0c0d0e0f1011#), N (16#1213141516171819#),
       N (16#0102030405060708#), N (16#090a0b0c0d0e0f10#), N (16#1112131415161718#),
       N (16#191a1b1c1d1e1f20#), N (16#2122232425262728#), N (16#292a2b2c2d2e2f30#),
       N (16#3132333435363738#), N (16#393a3b3c3d3e3f40#), others => 0);

   --  50 times 16#dd#
   Message1 := Message1_Type'(1 => LSC.SHA512.Block_Type'
      (N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
       N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
       N (16#cdcd000000000000#), others => 0));

   LSC.Test.Run
     ("HMAC-SHA512-AUTH-4",
      LSC.HMAC_SHA512.Authenticate (Key, Message1, 400) =
      LSC.HMAC_SHA512.Auth_Type'
         (N (16#5e6688e5a3daec82#), N (16#6ca32eaea224eff5#), N (16#e700628947470e13#),
          N (16#ad01302561bab108#)));

end HMAC_SHA512_Tests;
