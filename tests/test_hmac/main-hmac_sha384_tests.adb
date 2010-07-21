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

   Message1 : Message1_Type;

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

end HMAC_SHA384_Tests;
