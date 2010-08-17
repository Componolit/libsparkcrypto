-------------------------------------------------------------------------------
-- This file is part of the sparkcrypto library.
--
-- Copyright (C) 2010  Alexander Senier <mail@senier.net>
-- Copyright (C) 2010  secunet Security Networks AG
--
-- libsparkcrypto is  free software; you  can redistribute it and/or  modify it
-- under  terms of  the GNU  General Public  License as  published by  the Free
-- Software  Foundation;  either version  3,  or  (at  your option)  any  later
-- version.  libsparkcrypto  is  distributed  in  the  hope  that  it  will  be
-- useful,  but WITHOUT  ANY WARRANTY;  without  even the  implied warranty  of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
--
-- As a  special exception under  Section 7 of GPL  version 3, you  are granted
-- additional  permissions  described in  the  GCC  Runtime Library  Exception,
-- version 3.1, as published by the Free Software Foundation.
--
-- You should  have received  a copy of  the GNU General  Public License  and a
-- copy  of  the  GCC  Runtime  Library  Exception  along  with  this  program;
-- see  the  files  COPYING3  and COPYING.RUNTIME  respectively.  If  not,  see
-- <http://www.gnu.org/licenses/>.
-------------------------------------------------------------------------------

separate (Main)
procedure HMAC_RIPEMD160_Tests is

   Key         : LSC.RIPEMD160.Block_Type;

   subtype Message1_Index is LSC.Types.Word64 range 1 .. 1;
   subtype Message1_Type is LSC.RIPEMD160.Message_Type (Message1_Index);

   subtype Message4_Index is LSC.Types.Word64 range 1 .. 4;
   subtype Message4_Type is LSC.RIPEMD160.Message_Type (Message4_Index);

   subtype Message5_Index is LSC.Types.Word64 range 1 .. 5;
   subtype Message5_Type is LSC.RIPEMD160.Message_Type (Message5_Index);

   Message1 : Message1_Type;
   Message4 : Message4_Type;
   Message5 : Message5_Type;

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
   Message1 := Message1_Type'(1 => LSC.RIPEMD160.Block_Type'
      (M (16#48692054#), M (16#68657265#), others => 0));

   LSC.Test.Run
     ("HMAC-RIPEMD160-1",
      LSC.HMAC_RIPEMD160.Authenticate (Key, Message1, 64) =
      LSC.RIPEMD160.Hash_Type'
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
   Message1 := Message1_Type'(1 => LSC.RIPEMD160.Block_Type'
      (M (16#77686174#), M (16#20646f20#), M (16#79612077#), M (16#616e7420#),
       M (16#666f7220#), M (16#6e6f7468#), M (16#696e673f#), others => 0));

   LSC.Test.Run
     ("HMAC-RIPEMD160-2",
      LSC.HMAC_RIPEMD160.Authenticate (Key, Message1, 224) =
      LSC.RIPEMD160.Hash_Type'
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
   Message1 := Message1_Type'(1 => LSC.RIPEMD160.Block_Type'
      (M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
       M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
       M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
       M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
       M (16#dddd0000#), others => 0));

   LSC.Test.Run
     ("HMAC-RIPEMD160-3",
      LSC.HMAC_RIPEMD160.Authenticate (Key, Message1, 400) =
      LSC.RIPEMD160.Hash_Type'
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
   Message1 := Message1_Type'(1 => LSC.RIPEMD160.Block_Type'
      (M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
       M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
       M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
       M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
       M (16#cdcd0000#), others => 0));

   LSC.Test.Run
     ("HMAC-RIPEMD160-4",
      LSC.HMAC_RIPEMD160.Authenticate (Key, Message1, 400) =
      LSC.RIPEMD160.Hash_Type'
      (M (16#d5ca862f#), M (16#4d21d5e6#), M (16#10e18b4c#),
       M (16#f1beb97a#), M (16#4365ecf4#)));

   ------------------------
   --  Test Case MULTI-1 --
   ------------------------

   -- hmac_rmd160-key-1.dat
   Key := LSC.RIPEMD160.Block_Type'(
      M (16#eede4910#), M (16#ebbc6f5c#), M (16#13f5971b#), M (16#5466e1a6#),
      M (16#5b10e6d1#), M (16#f8c28abd#), M (16#77b061f0#), M (16#ac52cd4c#),
      M (16#77b9782d#), M (16#ddec2f46#), M (16#bcf2ab2b#), M (16#61713fc4#),
      M (16#2311c948#), M (16#41538d30#), M (16#6cb18b1f#), M (16#19a48dc5#)
   );

   -- hmac_rmd160-message-1.dat
   Message4 := Message4_Type'(
   LSC.RIPEMD160.Block_Type'(
      M (16#7ac96141#), M (16#3578af90#), M (16#342cbbf4#), M (16#b3c969cd#),
      M (16#5cc9ae0b#), M (16#6897d4b7#), M (16#611fb575#), M (16#ac5e772b#),
      M (16#95c35b19#), M (16#6ba0b47c#), M (16#4f890b07#), M (16#ceaa2938#),
      M (16#4d4a1b3e#), M (16#87b29344#), M (16#b4be72bc#), M (16#a89f215f#)),
   LSC.RIPEMD160.Block_Type'(
      M (16#074816cd#), M (16#dbaf41db#), M (16#163c5429#), M (16#d161b3a0#),
      M (16#0df99630#), M (16#e3e14ad2#), M (16#b78d1632#), M (16#2e203dfd#),
      M (16#f5c3dc40#), M (16#c5ded149#), M (16#7b5f13c3#), M (16#74e4877d#),
      M (16#33a7056a#), M (16#e5ce2e63#), M (16#24242f05#), M (16#e6608f12#)),
   LSC.RIPEMD160.Block_Type'(
      M (16#d49f4944#), M (16#e92d9d12#), M (16#0bdbdc9a#), M (16#66d9addf#),
      M (16#e070afdc#), M (16#45e785a8#), M (16#fbe7d19f#), M (16#613ec8ae#),
      M (16#caa2b668#), M (16#e9c16996#), M (16#07328ab7#), M (16#7bc64bf0#),
      M (16#c31f2d9a#), M (16#39325c03#), M (16#0c7dc101#), M (16#55217a05#)),
   LSC.RIPEMD160.Block_Type'(
      M (16#1ef4027e#), M (16#b6df5137#), M (16#4bc3915f#), M (16#417e78d3#),
      M (16#82d63ed8#), M (16#2350c1c3#), M (16#f424e6fe#), M (16#66c16737#),
      M (16#7630d2cc#), M (16#436f532d#), M (16#3c5d4716#), M (16#0e94a05f#),
      M (16#1941214e#), M (16#857fa0e9#), M (16#0e0e6855#), M (16#3afd24bc#))
      );

   -- hmac_rmd160-hash-1.dat
   LSC.Test.Run
     ("HMAC-RIPEMD160-MULTI-1",
      LSC.HMAC_RIPEMD160.Authenticate (Key, Message4, 2048) =
      LSC.RIPEMD160.Hash_Type'(
         M (16#34c25afc#), M (16#15a81bf8#), M (16#e48c2dce#), M (16#a1063014#), M (16#f49df262#)));

   ------------------------
   --  Test Case MULTI-2 --
   ------------------------

   -- hmac_rmd160-key-2.dat
   Key := LSC.RIPEMD160.Block_Type'(
      M (16#743c9034#), M (16#2c3a5238#), M (16#8644ea5c#), M (16#3f32e614#),
      M (16#f13e2e3f#), M (16#926810b0#), M (16#2dc2f006#), M (16#94c2cc93#),
      M (16#683bf052#), M (16#f738ad4d#), M (16#a9602089#), M (16#2e18dcdc#),
      M (16#03b04969#), M (16#6b9b0d1a#), M (16#5ce0dea4#), M (16#0f1b4e37#)
   );

   -- hmac_rmd160-message-2.dat
   Message5 := Message5_Type'(
   LSC.RIPEMD160.Block_Type'(
      M (16#ffe452a1#), M (16#0731bc87#), M (16#ac159b32#), M (16#5375a1a7#),
      M (16#05d2111d#), M (16#bf223453#), M (16#017fdc94#), M (16#8ce6e07d#),
      M (16#b736d511#), M (16#b3e01d21#), M (16#251776ed#), M (16#02930c5e#),
      M (16#96ef4c81#), M (16#c39826e9#), M (16#60f867e6#), M (16#5afb8b45#)),
   LSC.RIPEMD160.Block_Type'(
      M (16#4b6d4e48#), M (16#e55e9054#), M (16#935397fd#), M (16#d0fbbf89#),
      M (16#7ed6daba#), M (16#a7fc214a#), M (16#e4f1c189#), M (16#03c433bc#),
      M (16#f20c5b77#), M (16#2a8f56a4#), M (16#ca9e272b#), M (16#fe75f074#),
      M (16#dd39ab22#), M (16#9d944afd#), M (16#31b978e0#), M (16#4a6f6d42#)),
   LSC.RIPEMD160.Block_Type'(
      M (16#7cfc8649#), M (16#93b6ac91#), M (16#d8b683f7#), M (16#fad79a16#),
      M (16#2d419e85#), M (16#4e689a11#), M (16#9d607cc0#), M (16#2566375c#),
      M (16#e09ddd31#), M (16#2f050280#), M (16#ea5f5430#), M (16#cc3714d4#),
      M (16#9f069a44#), M (16#d7a2586d#), M (16#b16fce42#), M (16#fbc44cb6#)),
   LSC.RIPEMD160.Block_Type'(
      M (16#cf071d0b#), M (16#c1ce2727#), M (16#c44d8690#), M (16#60a75590#),
      M (16#d6036c1f#), M (16#c11bed8a#), M (16#537db307#), M (16#f05294ef#),
      M (16#c04807b0#), M (16#22f5b0a9#), M (16#dbb4bf72#), M (16#75483e79#),
      M (16#0d26bbb3#), M (16#ff7120ef#), M (16#224211e9#), M (16#686c8225#)),
   LSC.RIPEMD160.Block_Type'(
      M (16#dabc5b28#), M (16#7ce93ba1#), M (16#d67b9456#), M (16#91a651a3#),
      M (16#c3fe81ff#), M (16#db0334e6#), M (16#9863e388#), M (16#0ab3f5e0#),
      M (16#a90b747b#), M (16#724387d8#), M (16#8abd6511#), M (16#c689e47f#),
      M (16#c521396b#), M (16#9e21ed74#), others => 0)
      );

   -- hmac_rmd160-hash-2.dat
   LSC.Test.Run
     ("HMAC-RIPEMD160-MULTI-2",
      LSC.HMAC_RIPEMD160.Authenticate (Key, Message5, 2048 + 448) =
      LSC.RIPEMD160.Hash_Type'(
         M (16#8d6bf378#), M (16#22d7812d#), M (16#acc4aa1a#), M (16#86e280a0#), M (16#e43bbd38#)));

end HMAC_RIPEMD160_Tests;
