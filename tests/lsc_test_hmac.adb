-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2010, Alexander Senier
-- Copyright (C) 2010, secunet Security Networks AG
-- All rights reserved.
--
-- Redistribution  and  use  in  source  and  binary  forms,  with  or  without
-- modification, are permitted provided that the following conditions are met:
--
--    * Redistributions of source code must retain the above copyright notice,
--      this list of conditions and the following disclaimer.
--
--    * Redistributions in binary form must reproduce the above copyright
--      notice, this list of conditions and the following disclaimer in the
--      documentation and/or other materials provided with the distribution.
--
--    * Neither the name of the  nor the names of its contributors may be used
--      to endorse or promote products derived from this software without
--      specific prior written permission.
--
-- THIS SOFTWARE IS PROVIDED BY THE  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-- AND ANY  EXPRESS OR IMPLIED WARRANTIES,  INCLUDING, BUT NOT LIMITED  TO, THE
-- IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
-- ARE  DISCLAIMED. IN  NO EVENT  SHALL  THE COPYRIGHT  HOLDER OR  CONTRIBUTORS
-- BE  LIABLE FOR  ANY  DIRECT, INDIRECT,  INCIDENTAL,  SPECIAL, EXEMPLARY,  OR
-- CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT  LIMITED  TO,  PROCUREMENT  OF
-- SUBSTITUTE GOODS  OR SERVICES; LOSS  OF USE,  DATA, OR PROFITS;  OR BUSINESS
-- INTERRUPTION)  HOWEVER CAUSED  AND ON  ANY THEORY  OF LIABILITY,  WHETHER IN
-- CONTRACT,  STRICT LIABILITY,  OR  TORT (INCLUDING  NEGLIGENCE OR  OTHERWISE)
-- ARISING IN ANY WAY  OUT OF THE USE OF THIS SOFTWARE, EVEN  IF ADVISED OF THE
-- POSSIBILITY OF SUCH DAMAGE.
-------------------------------------------------------------------------------

with LSC.Types;
with LSC.RIPEMD160;
with LSC.HMAC_RIPEMD160;
with LSC.SHA1;
with LSC.HMAC_SHA1;
with AUnit.Assertions; use AUnit.Assertions;
with Util; use Util;
with Interfaces;

use type LSC.Types.Word32_Array_Type;
use type LSC.Types.Word64_Array_Type;
use type Interfaces.Unsigned_64;

package body LSC_Test_HMAC
is
   --  RIPEMD160 Test Vectors (RFC 2286, 2.)

   procedure Test_RIPEMD160_Auth_1 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.RIPEMD160.Message_Type (Message_Index);

      Key     : LSC.RIPEMD160.Block_Type;
      Message : Message_Type;
   begin
      Key := LSC.RIPEMD160.Block_Type'
         (M (16#0b0b0b0b#), M (16#0b0b0b0b#), M (16#0b0b0b0b#),
          M (16#0b0b0b0b#), M (16#0b0b0b0b#), others => 0);

      -- "Hi There"
      Message := Message_Type'(1 => LSC.RIPEMD160.Block_Type'
         (M (16#48692054#), M (16#68657265#), others => 0));

      Assert
        (LSC.HMAC_RIPEMD160.Authenticate (Key, Message, 64) =
         LSC.RIPEMD160.Hash_Type'
         (M (16#24cb4bd6#), M (16#7d20fc1a#), M (16#5d2ed773#),
          M (16#2dcc3937#), M (16#7f0a5668#), others => 0),
         "Invalid HMAC");

   end Test_RIPEMD160_Auth_1;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_Auth_2 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.RIPEMD160.Message_Type (Message_Index);

      Key     : LSC.RIPEMD160.Block_Type;
      Message : Message_Type;
   begin
      --  "Jefe"
      Key   := LSC.RIPEMD160.Block_Type'
         (M (16#4a656665#), others => 0);

      --  "what do ya want "
      --  "for nothing?"
      Message := Message_Type'(1 => LSC.RIPEMD160.Block_Type'
         (M (16#77686174#), M (16#20646f20#), M (16#79612077#), M (16#616e7420#),
          M (16#666f7220#), M (16#6e6f7468#), M (16#696e673f#), others => 0));

      Assert
        (LSC.HMAC_RIPEMD160.Authenticate (Key, Message, 224) =
         LSC.RIPEMD160.Hash_Type'
                  (M (16#dda6c021#), M (16#3a485a9e#), M (16#24f47420#),
                   M (16#64a7f033#), M (16#b43c4069#)),
         "Invalid HMAC");

   end Test_RIPEMD160_Auth_2;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_Auth_3 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.RIPEMD160.Message_Type (Message_Index);

      Key     : LSC.RIPEMD160.Block_Type;
      Message : Message_Type;
   begin

      --  20 times 16#aa#
      Key   := LSC.RIPEMD160.Block_Type'
         (M (16#aaaaaaaa#), M (16#aaaaaaaa#), M (16#aaaaaaaa#),
          M (16#aaaaaaaa#), M (16#aaaaaaaa#), others => 0);

      --  50 times 16#dd#
      Message := Message_Type'(1 => LSC.RIPEMD160.Block_Type'
         (M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
          M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
          M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
          M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
          M (16#dddd0000#), others => 0));

      Assert
        (LSC.HMAC_RIPEMD160.Authenticate (Key, Message, 400) =
         LSC.RIPEMD160.Hash_Type'
         (M (16#b0b10536#), M (16#0de75996#), M (16#0ab4f352#),
          M (16#98e116e2#), M (16#95d8e7c1#)),
         "Invalid HMAC");

   end Test_RIPEMD160_Auth_3;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_Auth_4 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.RIPEMD160.Message_Type (Message_Index);

      Key     : LSC.RIPEMD160.Block_Type;
      Message : Message_Type;
   begin

      Key := LSC.RIPEMD160.Block_Type'
         (M (16#01020304#), M (16#05060708#), M (16#090a0b0c#),
          M (16#0d0e0f10#), M (16#11121314#), M (16#15161718#),
          M (16#19000000#), others => 0);

      --  50 times 16#cd#
      Message := Message_Type'(1 => LSC.RIPEMD160.Block_Type'
         (M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
          M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
          M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
          M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
          M (16#cdcd0000#), others => 0));

      Assert
        (LSC.HMAC_RIPEMD160.Authenticate (Key, Message, 400) =
         LSC.RIPEMD160.Hash_Type'
         (M (16#d5ca862f#), M (16#4d21d5e6#), M (16#10e18b4c#),
          M (16#f1beb97a#), M (16#4365ecf4#)),
         "Invalid HMAC");

   end Test_RIPEMD160_Auth_4;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_Multi_1 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Types.Word64 range 1 .. 4;
      subtype Message_Type is LSC.RIPEMD160.Message_Type (Message_Index);

      Key     : LSC.RIPEMD160.Block_Type;
      Message : Message_Type;
   begin

      -- hmac_rmd160-key-1.dat
      Key := LSC.RIPEMD160.Block_Type'(
         M (16#eede4910#), M (16#ebbc6f5c#), M (16#13f5971b#), M (16#5466e1a6#),
         M (16#5b10e6d1#), M (16#f8c28abd#), M (16#77b061f0#), M (16#ac52cd4c#),
         M (16#77b9782d#), M (16#ddec2f46#), M (16#bcf2ab2b#), M (16#61713fc4#),
         M (16#2311c948#), M (16#41538d30#), M (16#6cb18b1f#), M (16#19a48dc5#)
      );

      -- hmac_rmd160-message-1.dat
      Message := Message_Type'(
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
      Assert
        (LSC.HMAC_RIPEMD160.Authenticate (Key, Message, 2048) =
         LSC.RIPEMD160.Hash_Type'(
            M (16#34c25afc#), M (16#15a81bf8#), M (16#e48c2dce#), M (16#a1063014#), M (16#f49df262#)),
         "Invalid HMAC");

   end Test_RIPEMD160_Multi_1;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_Multi_2 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Types.Word64 range 1 .. 5;
      subtype Message_Type is LSC.RIPEMD160.Message_Type (Message_Index);

      Key     : LSC.RIPEMD160.Block_Type;
      Message : Message_Type;
   begin
      -- hmac_rmd160-key-2.dat
      Key := LSC.RIPEMD160.Block_Type'(
         M (16#743c9034#), M (16#2c3a5238#), M (16#8644ea5c#), M (16#3f32e614#),
         M (16#f13e2e3f#), M (16#926810b0#), M (16#2dc2f006#), M (16#94c2cc93#),
         M (16#683bf052#), M (16#f738ad4d#), M (16#a9602089#), M (16#2e18dcdc#),
         M (16#03b04969#), M (16#6b9b0d1a#), M (16#5ce0dea4#), M (16#0f1b4e37#)
      );

      -- hmac_rmd160-message-2.dat
      Message := Message_Type'(
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
      Assert
        (LSC.HMAC_RIPEMD160.Authenticate (Key, Message, 2048 + 448) =
         LSC.RIPEMD160.Hash_Type'(
            M (16#8d6bf378#), M (16#22d7812d#), M (16#acc4aa1a#), M (16#86e280a0#), M (16#e43bbd38#)),
         "Invalid HMAC");

   end Test_RIPEMD160_Multi_2;

   ---------------------------------------------------------------------------

   --  SHA1 Test Vectors (RFC 2202, 3.)

   procedure Test_SHA1_Auth_1 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.SHA1.Message_Type (Message_Index);

      Key     : LSC.SHA1.Block_Type;
      Message : Message_Type;
   begin
      Key := LSC.SHA1.Block_Type'
        (M (16#0b0b0b0b#), M (16#0b0b0b0b#), M (16#0b0b0b0b#), M (16#0b0b0b0b#),
         M (16#0b0b0b0b#), others => 0);

      -- "Hi There"
      Message := Message_Type'
        (1 => LSC.SHA1.Block_Type'
           (M (16#48692054#), M (16#68657265#), others => 0));

      Assert
        (LSC.HMAC_SHA1.Authenticate (Key, Message, 64) =
           LSC.SHA1.Hash_Type'
             (M (16#b6173186#), M (16#55057264#), M (16#e28bc0b6#),
              M (16#fb378c8e#), M (16#f146be00#), others => 0),
         "Invalid HMAC");

   end Test_SHA1_Auth_1;

   ---------------------------------------------------------------------------

   procedure Test_SHA1_Auth_2 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.SHA1.Message_Type (Message_Index);

      Key     : LSC.SHA1.Block_Type;
      Message : Message_Type;
   begin
      --  "Jefe"
      Key := LSC.SHA1.Block_Type'(M (16#4a656665#), others => 0);

      --  "what do ya want for nothing?"
      Message := Message_Type'
        (1 => LSC.SHA1.Block_Type'
           (M (16#77686174#), M (16#20646f20#), M (16#79612077#), M (16#616e7420#),
            M (16#666f7220#), M (16#6e6f7468#), M (16#696e673f#), others => 0));

      Assert
        (LSC.HMAC_SHA1.Authenticate (Key, Message, 224) =
           LSC.SHA1.Hash_Type'
             (M (16#effcdf6a#), M (16#e5eb2fa2#), M (16#d27416d5#),
              M (16#f184df9c#), M (16#259a7c79#)),
         "Invalid HMAC");

   end Test_SHA1_Auth_2;

   ---------------------------------------------------------------------------

   procedure Test_SHA1_Auth_3 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.SHA1.Message_Type (Message_Index);

      Key     : LSC.SHA1.Block_Type;
      Message : Message_Type;
   begin
      --  20 times 16#aa#
      Key := LSC.SHA1.Block_Type'
        (M (16#aaaaaaaa#), M (16#aaaaaaaa#), M (16#aaaaaaaa#), M (16#aaaaaaaa#),
         M (16#aaaaaaaa#), others => 0);

      --  50 times 16#dd#
      Message := Message_Type'
        (1 => LSC.SHA1.Block_Type'
           (M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
            M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
            M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
            M (16#dddd0000#), others => 0));

      Assert
        (LSC.HMAC_SHA1.Authenticate (Key, Message, 400) =
           LSC.SHA1.Hash_Type'
             (M (16#125d7342#), M (16#b9ac11cd#), M (16#91a39af4#),
              M (16#8aa17b4f#), M (16#63f175d3#)),
         "Invalid Hash");

   end Test_SHA1_Auth_3;

   ---------------------------------------------------------------------------

   procedure Test_SHA1_Auth_4 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.SHA1.Message_Type (Message_Index);

      Key     : LSC.SHA1.Block_Type;
      Message : Message_Type;
   begin
      --  0x0102030405060708090a0b0c0d0e0f10111213141516171819
      Key := LSC.SHA1.Block_Type'
        (M (16#01020304#), M (16#05060708#), M (16#090a0b0c#), M (16#0d0e0f10#),
         M (16#11121314#), M (16#15161718#), M (16#19000000#), others => 0);

      --  50 times 16#cd#
      Message := Message_Type'
        (1 => LSC.SHA1.Block_Type'
           (M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
            M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
            M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
            M (16#cdcd0000#), others => 0));

      Assert
        (LSC.HMAC_SHA1.Authenticate (Key, Message, 400) =
           LSC.SHA1.Hash_Type'
             (M (16#4c9007f4#), M (16#026250c6#), M (16#bc8414f9#),
              M (16#bf50c86c#), M (16#2d7235da#)),
         "Invalid HMAC");

   end Test_SHA1_Auth_4;

   ---------------------------------------------------------------------------

   procedure Test_SHA1_Auth_5 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.SHA1.Message_Type (Message_Index);

      Key     : LSC.SHA1.Block_Type;
      Message : Message_Type;
   begin

      --  0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
      Key := LSC.SHA1.Block_Type'
        (M (16#0c0c0c0c#), M (16#0c0c0c0c#), M (16#0c0c0c0c#), M (16#0c0c0c0c#),
         M (16#0c0c0c0c#), others => 0);

      --  "Test With Truncation"
      Message := Message_Type'
        (1 => LSC.SHA1.Block_Type'
           (M (16#54657374#), M (16#20576974#), M (16#68205472#), M (16#756e6361#),
            M (16#74696f6e#), others => 0));

      Assert
        (LSC.HMAC_SHA1.Authenticate (Key, Message, 160) =
           LSC.SHA1.Hash_Type'
             (M (16#4c1a0342#), M (16#4b55e07f#), M (16#e7f27be1#),
              M (16#d58bb932#), M (16#4a9a5a04#)),
         "Invalid HMAC");

   end Test_SHA1_Auth_5;

   ---------------------------------------------------------------------------

   procedure Test_SHA1_Multi_1 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Types.Word64 range 1 .. 4;
      subtype Message_Type is LSC.SHA1.Message_Type (Message_Index);

      Key     : LSC.SHA1.Block_Type;
      Message : Message_Type;
   begin
      -- hmac_sha1-key-1.dat
      Key := LSC.sha1.Block_Type'
        (M (16#07a55659#), M (16#e5e382f2#), M (16#a12610e0#), M (16#8926b665#),
         M (16#43122a4e#), M (16#c2dc3c09#), M (16#8261de1f#), M (16#3f2ae412#),
         M (16#7e19048e#), M (16#7cee69bc#), M (16#43f8283e#), M (16#86b48781#),
         M (16#ca18e81c#), M (16#422f70e3#), M (16#52062553#), M (16#ff11c406#));

      -- hmac_sha1-message-1.dat
      Message := Message_Type'
        (LSC.SHA1.Block_Type'
           (M (16#b88457a3#), M (16#9d9346c9#), M (16#9698c202#), M (16#c45572f7#),
            M (16#4ccff08d#), M (16#c311f906#), M (16#c8dbfa88#), M (16#57f2220b#),
            M (16#70d29fb8#), M (16#689ca8c1#), M (16#7a907974#), M (16#c7c09dcf#),
            M (16#15357d16#), M (16#36103db1#), M (16#0618739c#), M (16#cddcd890#)),
         LSC.SHA1.Block_Type'
           (M (16#6946c864#), M (16#b3bae1f4#), M (16#60d1e64f#), M (16#ee07a9c7#),
            M (16#119e06ed#), M (16#d5ff9753#), M (16#b237b06a#), M (16#4ecc8000#),
            M (16#430389cc#), M (16#0114af02#), M (16#2ed4714e#), M (16#5ba051de#),
            M (16#c852b7aa#), M (16#5799d4d0#), M (16#52121b4e#), M (16#67325a2f#)),
         LSC.SHA1.Block_Type'
           (M (16#7bb838f5#), M (16#2f3cbff1#), M (16#ae723f2d#), M (16#35abc721#),
            M (16#74503c67#), M (16#9be8d95c#), M (16#60a7308f#), M (16#b21a0347#),
            M (16#e099d848#), M (16#15a46a22#), M (16#a78112d1#), M (16#c5cbc2a4#),
            M (16#376934e0#), M (16#337c8770#), M (16#24a440e3#), M (16#5e3a7349#)),
         LSC.SHA1.Block_Type'
           (M (16#a6232f33#), M (16#48130619#), M (16#30aba014#), M (16#c6400194#),
            M (16#1546e5ab#), M (16#50d98fe5#), M (16#3700f966#), M (16#982eaf6a#),
            M (16#65ef70de#), M (16#6b5f9d6c#), M (16#ec8c7a7e#), M (16#ff37f2ec#),
            M (16#5cafcc39#), M (16#646132f3#), M (16#240e4811#), M (16#7f4db108#))
        );

      -- hmac_sha1-hash-1.dat
      Assert
        (LSC.HMAC_SHA1.Authenticate (Key, Message, 2048) =
           LSC.SHA1.Hash_Type'(M (16#ec3b225b#), M (16#f28c53dc#),
             M (16#e8bd8722#), M (16#f325d5b1#), M (16#691114c7#)),
         "Invalid HMAC");

   end Test_SHA1_Multi_1;

   ---------------------------------------------------------------------------

   procedure Test_SHA1_Multi_2 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Types.Word64 range 1 .. 5;
      subtype Message_Type is LSC.SHA1.Message_Type (Message_Index);

      Key     : LSC.SHA1.Block_Type;
      Message : Message_Type;
   begin
      -- hmac_sha1-key-2.dat
      Key := LSC.SHA1.Block_Type'
        (M (16#f05821b9#), M (16#94ab6613#), M (16#f7c5773f#), M (16#b2a2184f#),
         M (16#9659daf3#), M (16#856a4a69#), M (16#245ba5f9#), M (16#7431d93f#),
         M (16#697a494d#), M (16#8da7131b#), M (16#1a995683#), M (16#4b4592d0#),
         M (16#c10b076b#), M (16#989278bc#), M (16#91fe184c#), M (16#84046614#));

      -- hmac_sha1-message-2.dat
      Message := Message_Type'
        (LSC.SHA1.Block_Type'
           (M (16#503ab855#), M (16#d8a04186#), M (16#484637e5#), M (16#38dd715f#),
            M (16#ca6026bd#), M (16#a01a90d4#), M (16#3ac281e4#), M (16#cf626d63#),
            M (16#cc6c49f0#), M (16#397cdc76#), M (16#db96736f#), M (16#4e0fd1e7#),
            M (16#24b765e7#), M (16#83d7bd3b#), M (16#f20ebc24#), M (16#8e1c0eef#)),
         LSC.SHA1.Block_Type'
           (M (16#cc9b450e#), M (16#481ed2f3#), M (16#13c26f80#), M (16#57ae2910#),
            M (16#b316e6ae#), M (16#580250b6#), M (16#57857881#), M (16#eb7e25e4#),
            M (16#b7e64116#), M (16#ad0bb1d5#), M (16#b720b390#), M (16#8f1e47a1#),
            M (16#65461c23#), M (16#46e282c8#), M (16#b4948e3e#), M (16#6c70c980#)),
         LSC.SHA1.Block_Type'
           (M (16#f7464750#), M (16#d18db4c2#), M (16#9a7db515#), M (16#e6212696#),
            M (16#bf47e1e5#), M (16#3d1b5887#), M (16#82610dd8#), M (16#39e60cbf#),
            M (16#efe360f8#), M (16#374b922d#), M (16#cae8bcee#), M (16#8eb7db21#),
            M (16#cb13bccd#), M (16#d98284ec#), M (16#95896c3b#), M (16#30173471#)),
         LSC.SHA1.Block_Type'
           (M (16#64aa3093#), M (16#cacca160#), M (16#543e4b66#), M (16#f2dda6a2#),
            M (16#4ed9d501#), M (16#5f60f27f#), M (16#7e966bb3#), M (16#df799512#),
            M (16#cb379c89#), M (16#225e92b7#), M (16#54fc317e#), M (16#c6ee8ebe#),
            M (16#ac522ea6#), M (16#2e89fa10#), M (16#40008689#), M (16#a375735f#)),
         LSC.SHA1.Block_Type'
           (M (16#c9c7e5e0#), M (16#1ec278ff#), M (16#d86271e4#), M (16#1ec69d9a#),
            M (16#b94945db#), M (16#0efb7362#), M (16#2a6c72a6#), M (16#3e5f3880#),
            M (16#7df8aa81#), M (16#c7393cc8#), M (16#4077af9a#), M (16#01c0adc4#),
            M (16#3543e821#), M (16#f1dbd0a1#), others => 0)
        );

      -- hmac_sha1-hash-2.dat
      Assert
        (LSC.HMAC_SHA1.Authenticate (Key, Message, 2048 + 448) =
           LSC.SHA1.Hash_Type'(M (16#f87e3f76#), M (16#92b5f83c#),
             M (16#8f2f20bf#), M (16#8027d87e#), M (16#8b4cf783#)),
         "Invalid HMAC");
   end Test_SHA1_Multi_2;

   ---------------------------------------------------------------------------

   procedure Register_Tests (T: in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (T, Test_RIPEMD160_Auth_1'Access, "RIPEMD160 (AUTH-1)");
      Register_Routine (T, Test_RIPEMD160_Auth_2'Access, "RIPEMD160 (AUTH-2)");
      Register_Routine (T, Test_RIPEMD160_Auth_3'Access, "RIPEMD160 (AUTH-3)");
      Register_Routine (T, Test_RIPEMD160_Auth_4'Access, "RIPEMD160 (AUTH-4)");
      Register_Routine (T, Test_RIPEMD160_Multi_1'Access, "RIPEMD160 (MULTI-1)");
      Register_Routine (T, Test_RIPEMD160_Multi_2'Access, "RIPEMD160 (MULTI-2)");
      Register_Routine (T, Test_SHA1_Auth_1'Access, "SHA1 (AUTH-1)");
      Register_Routine (T, Test_SHA1_Auth_2'Access, "SHA1 (AUTH-2)");
      Register_Routine (T, Test_SHA1_Auth_3'Access, "SHA1 (AUTH-3)");
      Register_Routine (T, Test_SHA1_Auth_4'Access, "SHA1 (AUTH-4)");
      Register_Routine (T, Test_SHA1_Auth_5'Access, "SHA1 (AUTH-5)");
      Register_Routine (T, Test_SHA1_Multi_1'Access, "SHA1 (MULTI-1)");
      Register_Routine (T, Test_SHA1_Multi_2'Access, "SHA1 (MULTI-2)");
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("HMAC");
   end Name;

end LSC_Test_HMAC;
