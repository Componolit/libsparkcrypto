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
procedure HMAC_SHA384_Tests is

   HMAC_Ctx                         : LSC.HMAC_SHA384.Context_Type;
   Key                              : LSC.SHA512.Block_Type;
   Block                            : LSC.SHA512.Block_Type;
   PRF_HMAC_SHA_384                 : LSC.SHA512.SHA384_Hash_Type;

   subtype Message1_Index is LSC.Types.Word64 range 1 .. 1;
   subtype Message1_Type is LSC.SHA512.Message_Type (Message1_Index);

   subtype Message2_Index is LSC.Types.Word64 range 1 .. 2;
   subtype Message2_Type is LSC.SHA512.Message_Type (Message2_Index);

   subtype Message3_Index is LSC.Types.Word64 range 1 .. 3;
   subtype Message3_Type is LSC.SHA512.Message_Type (Message3_Index);

   Message1  : Message1_Type;
   Message2  : Message2_Type;
   Message3  : Message3_Type;

begin

   LSC.Test.Suite ("HMAC-SHA384 tests");

   --  SHA384 PRF Test Vectors (RFC 4868, 2.7.1.)

   ----------------------
   --  Test Case PRF-1 --
   ----------------------

   Key   := LSC.SHA512.Block_Type'
      (N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#),
       N (16#0b0b0b0b00000000#), others => 0);

   -- "Hi There"
   Block := LSC.SHA512.Block_Type'
      (N (16#4869205468657265#), others => 0);

   HMAC_Ctx := LSC.HMAC_SHA384.Context_Init (Key);
   LSC.HMAC_SHA384.Context_Finalize (HMAC_Ctx, Block, 64);
   PRF_HMAC_SHA_384 := LSC.HMAC_SHA384.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-PRF-1",
      PRF_HMAC_SHA_384 =
      LSC.SHA512.SHA384_Hash_Type'
         (N (16#afd03944d8489562#), N (16#6b0825f4ab46907f#),
          N (16#15f9dadbe4101ec6#), N (16#82aa034c7cebc59c#),
          N (16#faea9ea9076ede7f#), N (16#4af152e8b2fa9cb6#)));

   ----------------------
   --  Test Case PRF-2 --
   ----------------------

   --  "Jefe"
   Key   := LSC.SHA512.Block_Type'
      (N (16#4a65666500000000#), others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Block := LSC.SHA512.Block_Type'
      (N (16#7768617420646f20#), N (16#79612077616e7420#),
       N (16#666f72206e6f7468#), N (16#696e673f00000000#),
       others => 0);

   HMAC_Ctx := LSC.HMAC_SHA384.Context_Init (Key);
   LSC.HMAC_SHA384.Context_Finalize (HMAC_Ctx, Block, 224);
   PRF_HMAC_SHA_384 := LSC.HMAC_SHA384.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-PRF-2",
      PRF_HMAC_SHA_384 =
      LSC.SHA512.SHA384_Hash_Type'
      (N (16#af45d2e376484031#), N (16#617f78d2b58a6b1b#), N (16#9c7ef464f5a01b47#),
       N (16#e42ec3736322445e#), N (16#8e2240ca5e69e2c7#), N (16#8b3239ecfab21649#)));

   ----------------------
   --  Test Case PRF-3 --
   ----------------------

   --  20 times 16#aa#
   Key   := LSC.SHA512.Block_Type'
      (N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#),
       N (16#aaaaaaaa00000000#), others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA512.Block_Type'
      (N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
       N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
       N (16#dddd000000000000#), others => 0);

   HMAC_Ctx := LSC.HMAC_SHA384.Context_Init (Key);
   LSC.HMAC_SHA384.Context_Finalize (HMAC_Ctx, Block, 400);
   PRF_HMAC_SHA_384 := LSC.HMAC_SHA384.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-PRF-3",
      PRF_HMAC_SHA_384 =
      LSC.SHA512.SHA384_Hash_Type'
      (N (16#88062608d3e6ad8a#), N (16#0aa2ace014c8a86f#), N (16#0aa635d947ac9feb#),
       N (16#e83ef4e55966144b#), N (16#2a5ab39dc13814b9#), N (16#4e3ab6e101a34f27#)));

   ----------------------
   --  Test Case PRF-4 --
   ----------------------

   --  25 bytes
   Key   := LSC.SHA512.Block_Type'
      (N (16#0102030405060708#), N (16#090a0b0c0d0e0f10#), N (16#1112131415161718#),
       N (16#1900000000000000#), others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA512.Block_Type'
      (N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
       N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
       N (16#cdcd000000000000#), others => 0);

   HMAC_Ctx := LSC.HMAC_SHA384.Context_Init (Key);
   LSC.HMAC_SHA384.Context_Finalize (HMAC_Ctx, Block, 400);
   PRF_HMAC_SHA_384 := LSC.HMAC_SHA384.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-PRF-4",
      PRF_HMAC_SHA_384 =
      LSC.SHA512.SHA384_Hash_Type'
      (N (16#3e8a69b7783c2585#), N (16#1933ab6290af6ca7#), N (16#7a9981480850009c#),
       N (16#c5577c6e1f573b4e#), N (16#6801dd23c4a7d679#), N (16#ccf8a386c674cffb#)));

   -----------------------
   --  Test Case AUTH-1 --
   -----------------------

   --  48 bytes
   Key   := LSC.SHA512.Block_Type'
      (N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#),
       N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#),
       others => 0);

   -- "Hi There"
   Message1 := Message1_Type'(1 => LSC.SHA512.Block_Type'
      (N (16#4869205468657265#), others => 0));

   LSC.Test.Run
     ("HMAC-SHA384-AUTH-1",
      LSC.HMAC_SHA384.Authenticate (Key, Message1, 64) =
      LSC.HMAC_SHA384.Auth_Type'
      (N (16#b6a8d5636f5c6a72#), N (16#24f9977dcf7ee6c7#), N (16#fb6d0c48cbdee973#)));

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
       others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Message1 := Message1_Type'(1 => LSC.SHA512.Block_Type'
      (N (16#7768617420646f20#), N (16#79612077616e7420#), N (16#666f72206e6f7468#),
       N (16#696e673f00000000#), others => 0));

   LSC.Test.Run
     ("HMAC-SHA384-AUTH-2",
      LSC.HMAC_SHA384.Authenticate (Key, Message1, 224) =
      LSC.HMAC_SHA384.Auth_Type'
      (N (16#2c7353974f1842fd#), N (16#66d53c452ca42122#), N (16#b28c0b594cfb184d#)));

   -----------------------
   --  Test Case AUTH-3 --
   -----------------------

   --  48 times 16#aa#
   Key   := LSC.SHA512.Block_Type'
      (N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#),
       N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#),
       others => 0);

   --  50 times 16#dd#
   Message1 := Message1_Type'(1 => LSC.SHA512.Block_Type'
      (N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
       N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
       N (16#dddd000000000000#), others => 0));

   LSC.Test.Run
     ("HMAC-SHA384-AUTH-3",
      LSC.HMAC_SHA384.Authenticate (Key, Message1, 400) =
      LSC.HMAC_SHA384.Auth_Type'
      (N (16#809f439be0027432#), N (16#1d4a538652164b53#), N (16#554a508184a0c316#)));

   -----------------------
   --  Test Case AUTH-4 --
   -----------------------

   Key   := LSC.SHA512.Block_Type'
      (N (16#0102030405060708#), N (16#090a0b0c0d0e0f10#), N (16#1112131415161718#),
       N (16#191a1b1c1d1e1f20#), N (16#0a0b0c0d0e0f1011#), N (16#1213141516171819#),
       others => 0);

   --  50 times 16#dd#
   Message1 := Message1_Type'(1 => LSC.SHA512.Block_Type'
      (N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
       N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
       N (16#cdcd000000000000#), others => 0));

   LSC.Test.Run
     ("HMAC-SHA384-AUTH-4",
      LSC.HMAC_SHA384.Authenticate (Key, Message1, 400) =
      LSC.HMAC_SHA384.Auth_Type'
      (N (16#5b540085c6e63580#), N (16#96532b2493609ed1#), N (16#cb298f774f87bb5c#)));

   ------------------------
   --  Test Case MULTI-1 --
   ------------------------

   --  Hexdump of hmac_sha384-key-1.dat
   Key   := LSC.SHA512.Block_Type'(
      N (16#2cad6b4b0b01b5b4#), N (16#a4de252f2b594736#), N (16#68e85fdc40de1d25#), N (16#c25d4ecc2a7dfec4#),
      N (16#53334b6ee5b4a4fb#), N (16#33cf52a70f23a351#), N (16#e7e124dc78b56c76#), N (16#18c14c301ef0452a#),
      N (16#29b8cdb0821d774a#), N (16#d0e55480530bd091#), N (16#0f92dcb33037cded#), N (16#d8fabd1bcd519cba#),
      N (16#8dc8cd68bbd33d5e#), N (16#2e22a320d6a71a60#), N (16#ba16964831e0e8e6#), N (16#b5527d657d6a9daa#)
   );

   --  Hexdump of hmac_sha384-message-1.dat
   Message2 := Message2_Type'(
   LSC.SHA512.Block_Type'(
      N (16#c7e3ae3df95ca9a8#), N (16#13242d4052700304#), N (16#fc8dab7c4bffff62#), N (16#de0b364b87a1f8c7#),
      N (16#5e9b3f6b31f552ec#), N (16#f8a53724b01ff176#), N (16#eb9922a221b0003a#), N (16#682dca9fdfa49e59#),
      N (16#b652f8c834c89936#), N (16#486df5779f720734#), N (16#77e912b3568cd483#), N (16#7059267c1d013521#),
      N (16#b6c763924fea7e17#), N (16#58591d2a1781fcac#), N (16#072e963f2a02e23a#), N (16#831344b9c9ddc17e#)),
   LSC.SHA512.Block_Type'(
      N (16#68d70a8125e29904#), N (16#00aa442072ea6d52#), N (16#f890ce20e7fff07a#), N (16#ffb79d3c294fba57#),
      N (16#1546abc37b2071ca#), N (16#cffd731e25232350#), N (16#635e8e8a3693a8f2#), N (16#d13ec3505e6912d5#),
      N (16#c8855484eb251327#), N (16#2c42eaa8afa3d8ea#), N (16#82546d44da4e8553#), N (16#6844ec16107925a7#),
      N (16#8d3449f3c6cbff01#), N (16#b304d133a118c1d7#), N (16#2e0b4f754b38fa9e#), N (16#0a082fd37ca98c56#))
   );

   --  Hexdump of hmac_sha384-hash-1.dat
   LSC.Test.Run
     ("HMAC-SHA384-MULTI-1",
      LSC.HMAC_SHA384.Authenticate (Key, Message2, 2048) =
      LSC.HMAC_SHA384.Auth_Type'(
         N (16#89869091210b3653#), N (16#21f60d6409b9ab5e#), N (16#fd8eea749f22dce3#)));

   ------------------------
   --  Test Case MULTI-2 --
   ------------------------

   --  Hexdump of hmac_sha384-key-2.dat
   Key   := LSC.SHA512.Block_Type'(
      N (16#2466663d3e7bedcd#), N (16#e4c229484312440f#), N (16#954849019d214069#), N (16#759fdd03f6af0f1b#),
      N (16#4c6c4a0b78380f75#), N (16#12802b15ed72cf2d#), N (16#b82984e56921b813#), N (16#ffbc70abcf9aaa27#),
      N (16#042d2484d803ca23#), N (16#65830c9094ac5f3e#), N (16#fe810d7c628cd67d#), N (16#2e0acc568cd94862#),
      N (16#d45e471822988e27#), N (16#9d51cc4502a919bc#), N (16#3038d2e9c3336935#), N (16#eafcb8c2a0ac3878#)
   );

   --  Hexdump of hmac_sha384-message-2.dat
   Message3 := Message3_Type'(
   LSC.SHA512.Block_Type'(
      N (16#225832edcff4d97b#), N (16#6d6d9329fe9f7eff#), N (16#f3311f03f6168ca7#), N (16#493eadbafb66bff2#),
      N (16#9c106683539a0193#), N (16#88444e2f7be708b3#), N (16#eb736e77d15339e8#), N (16#978839ef2d4afc9d#),
      N (16#1b2eb2501b9a0f8b#), N (16#41ed05fb650f52a2#), N (16#c8440f9f214ce15e#), N (16#07f811255328e5f6#),
      N (16#c7bcedaf34271920#), N (16#ab24105256cace3e#), N (16#aca191607991c49a#), N (16#bce83199afee2786#)),
   LSC.SHA512.Block_Type'(
      N (16#70b6f46c918f88df#), N (16#5f2a3ddcaef7cc29#), N (16#0134f34d30012e18#), N (16#bab3ac55fe992b34#),
      N (16#763d72beb784ea0e#), N (16#51fea85641166183#), N (16#f2c8d745c128e374#), N (16#4d85f98ce6500504#),
      N (16#6e4e29023d97146e#), N (16#491c2f043406fde8#), N (16#8e387a86ab56ada2#), N (16#46a28e21298790b6#),
      N (16#d6dc2d1b8f582696#), N (16#e9eda4cc3779af1d#), N (16#310a961c1619328d#), N (16#d44f8da9f1d547e1#)),
   LSC.SHA512.Block_Type'(
      N (16#41e7558b1f771b63#), N (16#73ca7b8ea99afefa#), N (16#1423e9fb847a0f57#), N (16#1a848c52b9424d2e#),
      N (16#b9effba7b7063973#), N (16#f56bf7b52116cb7f#), N (16#3974bb7d3bc0be6a#), others => 0)
   );

   --  Compare with hexdump of hmac_sha384-hash-2.dat
   LSC.Test.Run
     ("HMAC-SHA384-MULTI-2",
      LSC.HMAC_SHA384.Authenticate (Key, Message3, 2048 + 448) =
      LSC.HMAC_SHA384.Auth_Type'(
         N (16#144cd21ae50bfb0f#), N (16#ed473b88e7b33470#), N (16#5c59fecda5f978c8#)));

end HMAC_SHA384_Tests;
