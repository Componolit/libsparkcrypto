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
procedure HMAC_SHA256_Tests is

   HMAC_Ctx                         : LSC.HMAC_SHA256.Context_Type;
   Key                              : LSC.SHA256.Block_Type;
   Block                            : LSC.SHA256.Block_Type;
   PRF_HMAC_SHA_256                 : LSC.SHA256.SHA256_Hash_Type;

   subtype Message1_Index is LSC.Types.Word64 range 1 .. 1;
   subtype Message1_Type is LSC.SHA256.Message_Type (Message1_Index);

   Message1 : Message1_Type;

begin

   LSC.Test.Suite ("HMAC-SHA256 tests");

   --  SHA256 PRF Test Vectors (RFC 4868, 2.7.1.)

   ----------------------
   --  Test Case PRF-1 --
   ----------------------

   Key   := LSC.SHA256.Block_Type'
      (M (16#0b0b0b0b#), M (16#0b0b0b0b#), M (16#0b0b0b0b#),
       M (16#0b0b0b0b#), M (16#0b0b0b0b#), others => 0);

   -- "Hi There"
   Block := LSC.SHA256.Block_Type'(M (16#48692054#),
                                   M (16#68657265#),
                                   others => 0);

   HMAC_Ctx := LSC.HMAC_SHA256.Context_Init (Key);
   LSC.HMAC_SHA256.Context_Finalize (HMAC_Ctx, Block, 64);
   PRF_HMAC_SHA_256 := LSC.HMAC_SHA256.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA256-PRF-1",
      PRF_HMAC_SHA_256 =
      LSC.SHA256.SHA256_Hash_Type'
         (M (16#b0344c61#),
          M (16#d8db3853#),
          M (16#5ca8afce#),
          M (16#af0bf12b#),
          M (16#881dc200#),
          M (16#c9833da7#),
          M (16#26e9376c#),
          M (16#2e32cff7#)));

   ----------------------
   --  Test Case PRF-2 --
   ----------------------

   --  "Jefe"
   Key   := LSC.SHA256.Block_Type'
      (M (16#4a656665#), others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Block := LSC.SHA256.Block_Type'
      (M (16#77686174#), M (16#20646f20#), M (16#79612077#), M (16#616e7420#),
       M (16#666f7220#), M (16#6e6f7468#), M (16#696e673f#), others => 0);

   HMAC_Ctx := LSC.HMAC_SHA256.Context_Init (Key);
   LSC.HMAC_SHA256.Context_Finalize (HMAC_Ctx, Block, 224);
   PRF_HMAC_SHA_256 := LSC.HMAC_SHA256.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA256-PRF-2",
      PRF_HMAC_SHA_256 =
      LSC.SHA256.SHA256_Hash_Type'(M (16#5bdcc146#),
                                   M (16#bf60754e#),
                                   M (16#6a042426#),
                                   M (16#089575c7#),
                                   M (16#5a003f08#),
                                   M (16#9d273983#),
                                   M (16#9dec58b9#),
                                   M (16#64ec3843#)));

   ----------------------
   --  Test Case PRF-3 --
   ----------------------

   --  20 times 16#aa#
   Key   := LSC.SHA256.Block_Type'
      (M (16#aaaaaaaa#), M (16#aaaaaaaa#), M (16#aaaaaaaa#),
       M (16#aaaaaaaa#), M (16#aaaaaaaa#), others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA256.Block_Type'
      (M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
       M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
       M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
       M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
       M (16#dddd0000#), others => 0);

   HMAC_Ctx := LSC.HMAC_SHA256.Context_Init (Key);
   LSC.HMAC_SHA256.Context_Finalize (HMAC_Ctx, Block, 400);
   PRF_HMAC_SHA_256 := LSC.HMAC_SHA256.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA256-PRF-3",
      PRF_HMAC_SHA_256 =
      LSC.SHA256.SHA256_Hash_Type'(M (16#773ea91e#),
                                   M (16#36800e46#),
                                   M (16#854db8eb#),
                                   M (16#d09181a7#),
                                   M (16#2959098b#),
                                   M (16#3ef8c122#),
                                   M (16#d9635514#),
                                   M (16#ced565fe#)));

   ----------------------
   --  Test Case PRF-4 --
   ----------------------

   --  25 bytes
   Key   := LSC.SHA256.Block_Type'(M (16#01020304#),
                                   M (16#05060708#),
                                   M (16#090a0b0c#),
                                   M (16#0d0e0f10#),
                                   M (16#11121314#),
                                   M (16#15161718#),
                                   M (16#19000000#),
                                   others => 0);
   --  50 times 16#dd#
   Block := LSC.SHA256.Block_Type'(M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcd0000#),
                                   others => 0);

   HMAC_Ctx := LSC.HMAC_SHA256.Context_Init (Key);
   LSC.HMAC_SHA256.Context_Finalize (HMAC_Ctx, Block, 400);
   PRF_HMAC_SHA_256 := LSC.HMAC_SHA256.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA256-PRF-4",
      PRF_HMAC_SHA_256 =
      LSC.SHA256.SHA256_Hash_Type'(M (16#82558a38#),
                                   M (16#9a443c0e#),
                                   M (16#a4cc8198#),
                                   M (16#99f2083a#),
                                   M (16#85f0faa3#),
                                   M (16#e578f807#),
                                   M (16#7a2e3ff4#),
                                   M (16#6729665b#)));

   -----------------------
   --  Test Case AUTH-1 --
   -----------------------

   --  32 bytes
   Key   := LSC.SHA256.Block_Type'(M (16#0b0b0b0b#),
                                   M (16#0b0b0b0b#),
                                   M (16#0b0b0b0b#),
                                   M (16#0b0b0b0b#),
                                   M (16#0b0b0b0b#),
                                   M (16#0b0b0b0b#),
                                   M (16#0b0b0b0b#),
                                   M (16#0b0b0b0b#),
                                   others => 0);

   -- "Hi There"
   Message1 := Message1_Type'(1 => LSC.SHA256.Block_Type'
      (M (16#48692054#), M (16#68657265#), others => 0));

   LSC.Test.Run
     ("HMAC-SHA256-AUTH-1",
      LSC.HMAC_SHA256.Authenticate (Key, Message1, 64) =
      LSC.HMAC_SHA256.Auth_Type'(M (16#198a607e#),
                                 M (16#b44bfbc6#),
                                 M (16#9903a0f1#),
                                 M (16#cf2bbdc5#)));

   -----------------------
   --  Test Case AUTH-2 --
   -----------------------

   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   Key   := LSC.SHA256.Block_Type'(M (16#4a656665#),
                                   M (16#4a656665#),
                                   M (16#4a656665#),
                                   M (16#4a656665#),
                                   M (16#4a656665#),
                                   M (16#4a656665#),
                                   M (16#4a656665#),
                                   M (16#4a656665#),
                                   others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Message1 := Message1_Type'(1 => LSC.SHA256.Block_Type'
                                  (M (16#77686174#),
                                   M (16#20646f20#),
                                   M (16#79612077#),
                                   M (16#616e7420#),
                                   M (16#666f7220#),
                                   M (16#6e6f7468#),
                                   M (16#696e673f#),
                                   others => 0));

   LSC.Test.Run
     ("HMAC-SHA256-AUTH-2",
      LSC.HMAC_SHA256.Authenticate (Key, Message1, 224) =
      LSC.HMAC_SHA256.Auth_Type'(M (16#167f9285#),
                                 M (16#88c5cc2e#),
                                 M (16#ef8e3093#),
                                 M (16#caa0e87c#)));

   -----------------------
   --  Test Case AUTH-3 --
   -----------------------

   --  32 times 16#aa#
   Key   := LSC.SHA256.Block_Type'(M (16#aaaaaaaa#),
                                   M (16#aaaaaaaa#),
                                   M (16#aaaaaaaa#),
                                   M (16#aaaaaaaa#),
                                   M (16#aaaaaaaa#),
                                   M (16#aaaaaaaa#),
                                   M (16#aaaaaaaa#),
                                   M (16#aaaaaaaa#),
                                   others => 0);

   --  50 times 16#dd#
   Message1 := Message1_Type'(1 => LSC.SHA256.Block_Type'
                                  (M (16#dddddddd#),
                                   M (16#dddddddd#),
                                   M (16#dddddddd#),
                                   M (16#dddddddd#),
                                   M (16#dddddddd#),
                                   M (16#dddddddd#),
                                   M (16#dddddddd#),
                                   M (16#dddddddd#),
                                   M (16#dddddddd#),
                                   M (16#dddddddd#),
                                   M (16#dddddddd#),
                                   M (16#dddddddd#),
                                   M (16#dddd0000#),
                                   others => 0));

   LSC.Test.Run
     ("HMAC-SHA256-AUTH-3",
      LSC.HMAC_SHA256.Authenticate (Key, Message1, 400) =
      LSC.HMAC_SHA256.Auth_Type'(M (16#cdcb1220#),
                                 M (16#d1ecccea#),
                                 M (16#91e53aba#),
                                 M (16#3092f962#)));

   -----------------------
   --  Test Case AUTH-4 --
   -----------------------

   --  32 byte
   Key   := LSC.SHA256.Block_Type'(M (16#01020304#),
                                   M (16#05060708#),
                                   M (16#090a0b0c#),
                                   M (16#0d0e0f10#),
                                   M (16#11121314#),
                                   M (16#15161718#),
                                   M (16#191a1b1c#),
                                   M (16#1d1e1f20#),
                                   others => 0);

   --  50 times 16#cd#
   Message1 := Message1_Type'(1 => LSC.SHA256.Block_Type'
                                  (M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcdcdcd#),
                                   M (16#cdcd0000#),
                                   others => 0));

   LSC.Test.Run
     ("HMAC-SHA256-AUTH-4",
      LSC.HMAC_SHA256.Authenticate (Key, Message1, 400) =
      LSC.HMAC_SHA256.Auth_Type'(M (16#372efcf9#),
                                 M (16#b40b35c2#),
                                 M (16#115b1346#),
                                 M (16#903d2ef4#)));

end HMAC_SHA256_Tests;
