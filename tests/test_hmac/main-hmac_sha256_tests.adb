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

   subtype Message4_Index is LSC.Types.Word64 range 1 .. 4;
   subtype Message4_Type is LSC.SHA256.Message_Type (Message4_Index);

   subtype Message5_Index is LSC.Types.Word64 range 1 .. 5;
   subtype Message5_Type is LSC.SHA256.Message_Type (Message5_Index);

   Message1 : Message1_Type;
   Message4 : Message4_Type;
   Message5 : Message5_Type;

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

   ------------------------
   --  Test Case MULTI-1 --
   ------------------------

   -- hmac_sha256-key-1.dat
   Key := LSC.SHA256.Block_Type'(
      M (16#e94f399e#), M (16#6451ce39#), M (16#7b49d580#), M (16#bafdf532#),
      M (16#ee24aa25#), M (16#6b0721bf#), M (16#c7f67939#), M (16#903fc021#),
      M (16#ca3c517c#), M (16#1ce00fa3#), M (16#ed0a5ff2#), M (16#a2c32049#),
      M (16#d3452f2b#), M (16#cdba563a#), M (16#3edf4f0d#), M (16#6bd26dad#)
   );

   -- hmac_sha256-message-1.dat
   Message4 := Message4_Type'(
   LSC.SHA256.Block_Type'(
      M (16#1d68a3cd#), M (16#6b07a7e3#), M (16#3ce93a05#), M (16#f89defe5#),
      M (16#0142fe91#), M (16#8508e319#), M (16#b283d17c#), M (16#1423afc0#),
      M (16#86508665#), M (16#b34c6d13#), M (16#777da272#), M (16#d202d291#),
      M (16#91c89d4b#), M (16#f2852209#), M (16#a4241e91#), M (16#2e4c9b6e#)),
   LSC.SHA256.Block_Type'(
      M (16#8342da56#), M (16#5fa7bbb0#), M (16#0e5541f7#), M (16#11ac4f01#),
      M (16#69bd4113#), M (16#a51388fc#), M (16#f57aac73#), M (16#95d774eb#),
      M (16#07eb51e1#), M (16#526efaa3#), M (16#c589f223#), M (16#89adaf4d#),
      M (16#48d01d42#), M (16#99a16171#), M (16#7a84a41c#), M (16#5cabe95b#)),
   LSC.SHA256.Block_Type'(
      M (16#d056a140#), M (16#25e4da39#), M (16#54251a17#), M (16#288bbf71#),
      M (16#7040f900#), M (16#e6b3eeb9#), M (16#b4c7337e#), M (16#59c946c0#),
      M (16#d72b53b2#), M (16#04e16a4a#), M (16#bb00aa33#), M (16#fc674d6a#),
      M (16#cdb821d9#), M (16#b1d2a1ca#), M (16#0d286937#), M (16#81ef2acf#)),
   LSC.SHA256.Block_Type'(
      M (16#e908e006#), M (16#815853a2#), M (16#d6100b5d#), M (16#a81ce416#),
      M (16#d98ba37d#), M (16#36e3c68b#), M (16#52cf0c1c#), M (16#aa9805b9#),
      M (16#3b7e68b7#), M (16#2c56511d#), M (16#711336b8#), M (16#eb1fe87f#),
      M (16#88b5870c#), M (16#697807fd#), M (16#dd1d1028#), M (16#87d5777f#))
      );

   -- hmac_sha256-hash-1.dat
   LSC.Test.Run
     ("HMAC-SHA256-MULTI-1",
      LSC.HMAC_SHA256.Authenticate (Key, Message4, 512) =
      LSC.SHA256.SHA256_Hash_Type'(
      M (16#15667870#), M (16#c4957c0f#), M (16#46de0f26#), M (16#c19804ae#),
      M (16#d1169bdf#), M (16#fd8beeb3#), M (16#c5e04706#), M (16#a59f3094#)));

   ------------------------
   --  Test Case MULTI-2 --
   ------------------------

   -- hmac_sha256-key-2.dat
   Key := LSC.SHA256.Block_Type'(
      M (16#f9bce67a#), M (16#4d76ff6d#), M (16#d14b0371#), M (16#7b63696c#),
      M (16#563ff8ee#), M (16#1825343e#), M (16#3732b7ff#), M (16#d881d8c1#),
      M (16#f5e75c76#), M (16#0fab3418#), M (16#8281a08b#), M (16#dbdf6264#),
      M (16#27566d34#), M (16#a61c20cf#), M (16#41db3611#), M (16#4d8d63f9#)
   );

   -- hmac_sha256-message-2.dat
   Message5 := Message5_Type'(
   LSC.SHA256.Block_Type'(
      M (16#05b4583b#), M (16#e4dabc55#), M (16#2d3ec9bb#), M (16#d9a36cfc#),
      M (16#ec9cd70a#), M (16#c28326e3#), M (16#55fa0488#), M (16#963c2dae#),
      M (16#c8046861#), M (16#27944daa#), M (16#7c9935a3#), M (16#7a15387e#),
      M (16#724669bd#), M (16#3ee51c80#), M (16#f01dd16e#), M (16#d6eaae5d#)),
   LSC.SHA256.Block_Type'(
      M (16#031d4365#), M (16#aecd1468#), M (16#623ecfef#), M (16#8bc48e96#),
      M (16#d14fd471#), M (16#adec193a#), M (16#2d803593#), M (16#876083a6#),
      M (16#771684e6#), M (16#022d917e#), M (16#b96c6472#), M (16#5e3d3c25#),
      M (16#cbf3b94b#), M (16#290f30dd#), M (16#ae3be915#), M (16#bbf215fa#)),
   LSC.SHA256.Block_Type'(
      M (16#a362659b#), M (16#7ba390a6#), M (16#fe4ccb96#), M (16#3d7a9efa#),
      M (16#634edd9a#), M (16#e977235b#), M (16#b061da25#), M (16#871d5ec4#),
      M (16#96591090#), M (16#03e8d9bd#), M (16#b8b570b2#), M (16#8a55eea2#),
      M (16#41654ead#), M (16#a305eca9#), M (16#27183dc4#), M (16#0fccbeac#)),
   LSC.SHA256.Block_Type'(
      M (16#9d99311c#), M (16#c8cee41e#), M (16#e165b132#), M (16#d0907f42#),
      M (16#ba829b85#), M (16#6ac8cc7b#), M (16#32c158ed#), M (16#8ae5efbd#),
      M (16#c8c47c0a#), M (16#11f6e3de#), M (16#ca9425d1#), M (16#d560ff15#),
      M (16#42724497#), M (16#07ded7a7#), M (16#87721d7c#), M (16#ab2cb568#)),
   LSC.SHA256.Block_Type'(
      M (16#29ac3372#), M (16#bbae6449#), M (16#8e48ce3d#), M (16#2f18bca7#),
      M (16#8b019337#), M (16#dad8763d#), M (16#dcef1b86#), M (16#e8e729c7#),
      M (16#f4966f48#), M (16#2537e29a#), M (16#6861c3b6#), M (16#1b8ad2a7#),
      M (16#2d07d0fd#), M (16#db70f339#), others => 0)
   );

   -- hmac_sha256-hash-2.dat
   LSC.Test.Run
     ("HMAC-SHA256-MULTI-2",
      LSC.HMAC_SHA256.Authenticate (Key, Message5, 448) =
      LSC.SHA256.SHA256_Hash_Type'(
      M (16#a3735482#), M (16#3897bec4#), M (16#a017cefc#), M (16#608852a6#),
      M (16#375aab7d#), M (16#966619d4#), M (16#f2243e00#), M (16#babc4d4c#)));

end HMAC_SHA256_Tests;
