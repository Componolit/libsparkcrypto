-------------------------------------------------------------------------------
--  This file is part of libsparkcrypto.
--
--  Copyright (C) 2010, Alexander Senier
--  Copyright (C) 2010, secunet Security Networks AG
--  All rights reserved.
--
--  Redistribution  and  use  in  source  and  binary  forms,  with  or  without
--  modification, are permitted provided that the following conditions are met:
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
--  THIS SOFTWARE IS PROVIDED BY THE  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
--  AND ANY  EXPRESS OR IMPLIED WARRANTIES,  INCLUDING, BUT NOT LIMITED  TO, THE
--  IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
--  ARE  DISCLAIMED. IN  NO EVENT  SHALL  THE COPYRIGHT  HOLDER OR  CONTRIBUTORS
--  BE  LIABLE FOR  ANY  DIRECT, INDIRECT,  INCIDENTAL,  SPECIAL, EXEMPLARY,  OR
--  CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT  LIMITED  TO,  PROCUREMENT  OF
--  SUBSTITUTE GOODS  OR SERVICES; LOSS  OF USE,  DATA, OR PROFITS;  OR BUSINESS
--  INTERRUPTION)  HOWEVER CAUSED  AND ON  ANY THEORY  OF LIABILITY,  WHETHER IN
--  CONTRACT,  STRICT LIABILITY,  OR  TORT (INCLUDING  NEGLIGENCE OR  OTHERWISE)
--  ARISING IN ANY WAY  OUT OF THE USE OF THIS SOFTWARE, EVEN  IF ADVISED OF THE
--  POSSIBILITY OF SUCH DAMAGE.
-------------------------------------------------------------------------------

with LSC.Internal.Types;
with LSC.Internal.RIPEMD160;
with LSC.Internal.HMAC_RIPEMD160;
with LSC.Internal.SHA1;
with LSC.Internal.HMAC_SHA1;
with LSC.Internal.SHA256;
with LSC.Internal.HMAC_SHA256;
with LSC.Internal.SHA512;
with LSC.Internal.HMAC_SHA384;
with LSC.Internal.HMAC_SHA512;
with AUnit.Assertions; use AUnit.Assertions;
with Util; use Util;
with Interfaces;

use type LSC.Internal.Types.Word32_Array_Type;
use type LSC.Internal.Types.Word64_Array_Type;
use type Interfaces.Unsigned_64;
use type LSC.Internal.SHA256.Message_Index;
use type LSC.Internal.SHA512.Message_Index;

pragma Style_Checks ("-s");
pragma Warnings (Off, "formal parameter ""T"" is not referenced");

package body LSC_Internal_Test_HMAC
is
   --  RIPEMD160 Test Vectors (RFC 2286, 2.)

   procedure Test_RIPEMD160_Auth_1 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.Internal.RIPEMD160.Message_Type (Message_Index);

      Key     : LSC.Internal.RIPEMD160.Block_Type;
      Message : Message_Type;
   begin
      Key := LSC.Internal.RIPEMD160.Block_Type'
         (M (16#0b0b0b0b#), M (16#0b0b0b0b#), M (16#0b0b0b0b#),
          M (16#0b0b0b0b#), M (16#0b0b0b0b#), others => 0);

      --  "Hi There"
      Message := Message_Type'(1 => LSC.Internal.RIPEMD160.Block_Type'
         (M (16#48692054#), M (16#68657265#), others => 0));

      Assert
        (LSC.Internal.HMAC_RIPEMD160.Authenticate (Key, Message, 64) =
         LSC.Internal.RIPEMD160.Hash_Type'
         (M (16#24cb4bd6#), M (16#7d20fc1a#), M (16#5d2ed773#),
          M (16#2dcc3937#), M (16#7f0a5668#)),
         "Invalid HMAC");

   end Test_RIPEMD160_Auth_1;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_Auth_2 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.Internal.RIPEMD160.Message_Type (Message_Index);

      Key     : LSC.Internal.RIPEMD160.Block_Type;
      Message : Message_Type;
   begin
      --  "Jefe"
      Key   := LSC.Internal.RIPEMD160.Block_Type'
         (M (16#4a656665#), others => 0);

      --  "what do ya want "
      --  "for nothing?"
      Message := Message_Type'(1 => LSC.Internal.RIPEMD160.Block_Type'
         (M (16#77686174#), M (16#20646f20#), M (16#79612077#), M (16#616e7420#),
          M (16#666f7220#), M (16#6e6f7468#), M (16#696e673f#), others => 0));

      Assert
        (LSC.Internal.HMAC_RIPEMD160.Authenticate (Key, Message, 224) =
         LSC.Internal.RIPEMD160.Hash_Type'
                  (M (16#dda6c021#), M (16#3a485a9e#), M (16#24f47420#),
                   M (16#64a7f033#), M (16#b43c4069#)),
         "Invalid HMAC");

   end Test_RIPEMD160_Auth_2;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_Auth_3 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.Internal.RIPEMD160.Message_Type (Message_Index);

      Key     : LSC.Internal.RIPEMD160.Block_Type;
      Message : Message_Type;
   begin

      --  20 times 16#aa#
      Key   := LSC.Internal.RIPEMD160.Block_Type'
         (M (16#aaaaaaaa#), M (16#aaaaaaaa#), M (16#aaaaaaaa#),
          M (16#aaaaaaaa#), M (16#aaaaaaaa#), others => 0);

      --  50 times 16#dd#
      Message := Message_Type'(1 => LSC.Internal.RIPEMD160.Block_Type'
         (M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
          M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
          M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
          M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
          M (16#dddd0000#), others => 0));

      Assert
        (LSC.Internal.HMAC_RIPEMD160.Authenticate (Key, Message, 400) =
         LSC.Internal.RIPEMD160.Hash_Type'
         (M (16#b0b10536#), M (16#0de75996#), M (16#0ab4f352#),
          M (16#98e116e2#), M (16#95d8e7c1#)),
         "Invalid HMAC");

   end Test_RIPEMD160_Auth_3;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_Auth_4 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.Internal.RIPEMD160.Message_Type (Message_Index);

      Key     : LSC.Internal.RIPEMD160.Block_Type;
      Message : Message_Type;
   begin

      Key := LSC.Internal.RIPEMD160.Block_Type'
         (M (16#01020304#), M (16#05060708#), M (16#090a0b0c#),
          M (16#0d0e0f10#), M (16#11121314#), M (16#15161718#),
          M (16#19000000#), others => 0);

      --  50 times 16#cd#
      Message := Message_Type'(1 => LSC.Internal.RIPEMD160.Block_Type'
         (M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
          M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
          M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
          M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
          M (16#cdcd0000#), others => 0));

      Assert
        (LSC.Internal.HMAC_RIPEMD160.Authenticate (Key, Message, 400) =
         LSC.Internal.RIPEMD160.Hash_Type'
         (M (16#d5ca862f#), M (16#4d21d5e6#), M (16#10e18b4c#),
          M (16#f1beb97a#), M (16#4365ecf4#)),
         "Invalid HMAC");

   end Test_RIPEMD160_Auth_4;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_Multi_1 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.Types.Word64 range 1 .. 4;
      subtype Message_Type is LSC.Internal.RIPEMD160.Message_Type (Message_Index);

      Key     : LSC.Internal.RIPEMD160.Block_Type;
      Message : Message_Type;
   begin

      --  hmac_rmd160-key-1.dat
      Key := LSC.Internal.RIPEMD160.Block_Type'(
         M (16#eede4910#), M (16#ebbc6f5c#), M (16#13f5971b#), M (16#5466e1a6#),
         M (16#5b10e6d1#), M (16#f8c28abd#), M (16#77b061f0#), M (16#ac52cd4c#),
         M (16#77b9782d#), M (16#ddec2f46#), M (16#bcf2ab2b#), M (16#61713fc4#),
         M (16#2311c948#), M (16#41538d30#), M (16#6cb18b1f#), M (16#19a48dc5#)
      );

      --  hmac_rmd160-message-1.dat
      Message := Message_Type'(
      LSC.Internal.RIPEMD160.Block_Type'(
         M (16#7ac96141#), M (16#3578af90#), M (16#342cbbf4#), M (16#b3c969cd#),
         M (16#5cc9ae0b#), M (16#6897d4b7#), M (16#611fb575#), M (16#ac5e772b#),
         M (16#95c35b19#), M (16#6ba0b47c#), M (16#4f890b07#), M (16#ceaa2938#),
         M (16#4d4a1b3e#), M (16#87b29344#), M (16#b4be72bc#), M (16#a89f215f#)),
      LSC.Internal.RIPEMD160.Block_Type'(
         M (16#074816cd#), M (16#dbaf41db#), M (16#163c5429#), M (16#d161b3a0#),
         M (16#0df99630#), M (16#e3e14ad2#), M (16#b78d1632#), M (16#2e203dfd#),
         M (16#f5c3dc40#), M (16#c5ded149#), M (16#7b5f13c3#), M (16#74e4877d#),
         M (16#33a7056a#), M (16#e5ce2e63#), M (16#24242f05#), M (16#e6608f12#)),
      LSC.Internal.RIPEMD160.Block_Type'(
         M (16#d49f4944#), M (16#e92d9d12#), M (16#0bdbdc9a#), M (16#66d9addf#),
         M (16#e070afdc#), M (16#45e785a8#), M (16#fbe7d19f#), M (16#613ec8ae#),
         M (16#caa2b668#), M (16#e9c16996#), M (16#07328ab7#), M (16#7bc64bf0#),
         M (16#c31f2d9a#), M (16#39325c03#), M (16#0c7dc101#), M (16#55217a05#)),
      LSC.Internal.RIPEMD160.Block_Type'(
         M (16#1ef4027e#), M (16#b6df5137#), M (16#4bc3915f#), M (16#417e78d3#),
         M (16#82d63ed8#), M (16#2350c1c3#), M (16#f424e6fe#), M (16#66c16737#),
         M (16#7630d2cc#), M (16#436f532d#), M (16#3c5d4716#), M (16#0e94a05f#),
         M (16#1941214e#), M (16#857fa0e9#), M (16#0e0e6855#), M (16#3afd24bc#))
         );

      --  hmac_rmd160-hash-1.dat
      Assert
        (LSC.Internal.HMAC_RIPEMD160.Authenticate (Key, Message, 2048) =
         LSC.Internal.RIPEMD160.Hash_Type'(
            M (16#34c25afc#), M (16#15a81bf8#), M (16#e48c2dce#), M (16#a1063014#), M (16#f49df262#)),
         "Invalid HMAC");

   end Test_RIPEMD160_Multi_1;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_Multi_2 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.Types.Word64 range 1 .. 5;
      subtype Message_Type is LSC.Internal.RIPEMD160.Message_Type (Message_Index);

      Key     : LSC.Internal.RIPEMD160.Block_Type;
      Message : Message_Type;
   begin
      --  hmac_rmd160-key-2.dat
      Key := LSC.Internal.RIPEMD160.Block_Type'(
         M (16#743c9034#), M (16#2c3a5238#), M (16#8644ea5c#), M (16#3f32e614#),
         M (16#f13e2e3f#), M (16#926810b0#), M (16#2dc2f006#), M (16#94c2cc93#),
         M (16#683bf052#), M (16#f738ad4d#), M (16#a9602089#), M (16#2e18dcdc#),
         M (16#03b04969#), M (16#6b9b0d1a#), M (16#5ce0dea4#), M (16#0f1b4e37#)
      );

      --  hmac_rmd160-message-2.dat
      Message := Message_Type'(
      LSC.Internal.RIPEMD160.Block_Type'(
         M (16#ffe452a1#), M (16#0731bc87#), M (16#ac159b32#), M (16#5375a1a7#),
         M (16#05d2111d#), M (16#bf223453#), M (16#017fdc94#), M (16#8ce6e07d#),
         M (16#b736d511#), M (16#b3e01d21#), M (16#251776ed#), M (16#02930c5e#),
         M (16#96ef4c81#), M (16#c39826e9#), M (16#60f867e6#), M (16#5afb8b45#)),
      LSC.Internal.RIPEMD160.Block_Type'(
         M (16#4b6d4e48#), M (16#e55e9054#), M (16#935397fd#), M (16#d0fbbf89#),
         M (16#7ed6daba#), M (16#a7fc214a#), M (16#e4f1c189#), M (16#03c433bc#),
         M (16#f20c5b77#), M (16#2a8f56a4#), M (16#ca9e272b#), M (16#fe75f074#),
         M (16#dd39ab22#), M (16#9d944afd#), M (16#31b978e0#), M (16#4a6f6d42#)),
      LSC.Internal.RIPEMD160.Block_Type'(
         M (16#7cfc8649#), M (16#93b6ac91#), M (16#d8b683f7#), M (16#fad79a16#),
         M (16#2d419e85#), M (16#4e689a11#), M (16#9d607cc0#), M (16#2566375c#),
         M (16#e09ddd31#), M (16#2f050280#), M (16#ea5f5430#), M (16#cc3714d4#),
         M (16#9f069a44#), M (16#d7a2586d#), M (16#b16fce42#), M (16#fbc44cb6#)),
      LSC.Internal.RIPEMD160.Block_Type'(
         M (16#cf071d0b#), M (16#c1ce2727#), M (16#c44d8690#), M (16#60a75590#),
         M (16#d6036c1f#), M (16#c11bed8a#), M (16#537db307#), M (16#f05294ef#),
         M (16#c04807b0#), M (16#22f5b0a9#), M (16#dbb4bf72#), M (16#75483e79#),
         M (16#0d26bbb3#), M (16#ff7120ef#), M (16#224211e9#), M (16#686c8225#)),
      LSC.Internal.RIPEMD160.Block_Type'(
         M (16#dabc5b28#), M (16#7ce93ba1#), M (16#d67b9456#), M (16#91a651a3#),
         M (16#c3fe81ff#), M (16#db0334e6#), M (16#9863e388#), M (16#0ab3f5e0#),
         M (16#a90b747b#), M (16#724387d8#), M (16#8abd6511#), M (16#c689e47f#),
         M (16#c521396b#), M (16#9e21ed74#), others => 0)
         );

      --  hmac_rmd160-hash-2.dat
      Assert
        (LSC.Internal.HMAC_RIPEMD160.Authenticate (Key, Message, 2048 + 448) =
         LSC.Internal.RIPEMD160.Hash_Type'(
            M (16#8d6bf378#), M (16#22d7812d#), M (16#acc4aa1a#), M (16#86e280a0#), M (16#e43bbd38#)),
         "Invalid HMAC");

   end Test_RIPEMD160_Multi_2;

   ---------------------------------------------------------------------------

   --  SHA1 Test Vectors (RFC 2202, 3.)

   procedure Test_SHA1_Auth_1 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA1.Message_Type (Message_Index);

      Key     : LSC.Internal.SHA1.Block_Type;
      Message : Message_Type;
   begin
      Key := LSC.Internal.SHA1.Block_Type'
        (M (16#0b0b0b0b#), M (16#0b0b0b0b#), M (16#0b0b0b0b#), M (16#0b0b0b0b#),
         M (16#0b0b0b0b#), others => 0);

      --  "Hi There"
      Message := Message_Type'
        (1 => LSC.Internal.SHA1.Block_Type'
           (M (16#48692054#), M (16#68657265#), others => 0));

      Assert
        (LSC.Internal.HMAC_SHA1.Authenticate (Key, Message, 64) =
           LSC.Internal.SHA1.Hash_Type'
             (M (16#b6173186#), M (16#55057264#), M (16#e28bc0b6#),
              M (16#fb378c8e#), M (16#f146be00#)),
         "Invalid HMAC");

   end Test_SHA1_Auth_1;

   ---------------------------------------------------------------------------

   procedure Test_SHA1_Auth_2 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA1.Message_Type (Message_Index);

      Key     : LSC.Internal.SHA1.Block_Type;
      Message : Message_Type;
   begin
      --  "Jefe"
      Key := LSC.Internal.SHA1.Block_Type'(M (16#4a656665#), others => 0);

      --  "what do ya want for nothing?"
      Message := Message_Type'
        (1 => LSC.Internal.SHA1.Block_Type'
           (M (16#77686174#), M (16#20646f20#), M (16#79612077#), M (16#616e7420#),
            M (16#666f7220#), M (16#6e6f7468#), M (16#696e673f#), others => 0));

      Assert
        (LSC.Internal.HMAC_SHA1.Authenticate (Key, Message, 224) =
           LSC.Internal.SHA1.Hash_Type'
             (M (16#effcdf6a#), M (16#e5eb2fa2#), M (16#d27416d5#),
              M (16#f184df9c#), M (16#259a7c79#)),
         "Invalid HMAC");

   end Test_SHA1_Auth_2;

   ---------------------------------------------------------------------------

   procedure Test_SHA1_Auth_3 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA1.Message_Type (Message_Index);

      Key     : LSC.Internal.SHA1.Block_Type;
      Message : Message_Type;
   begin
      --  20 times 16#aa#
      Key := LSC.Internal.SHA1.Block_Type'
        (M (16#aaaaaaaa#), M (16#aaaaaaaa#), M (16#aaaaaaaa#), M (16#aaaaaaaa#),
         M (16#aaaaaaaa#), others => 0);

      --  50 times 16#dd#
      Message := Message_Type'
        (1 => LSC.Internal.SHA1.Block_Type'
           (M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
            M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
            M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
            M (16#dddd0000#), others => 0));

      Assert
        (LSC.Internal.HMAC_SHA1.Authenticate (Key, Message, 400) =
           LSC.Internal.SHA1.Hash_Type'
             (M (16#125d7342#), M (16#b9ac11cd#), M (16#91a39af4#),
              M (16#8aa17b4f#), M (16#63f175d3#)),
         "Invalid Hash");

   end Test_SHA1_Auth_3;

   ---------------------------------------------------------------------------

   procedure Test_SHA1_Auth_4 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA1.Message_Type (Message_Index);

      Key     : LSC.Internal.SHA1.Block_Type;
      Message : Message_Type;
   begin
      --  0x0102030405060708090a0b0c0d0e0f10111213141516171819
      Key := LSC.Internal.SHA1.Block_Type'
        (M (16#01020304#), M (16#05060708#), M (16#090a0b0c#), M (16#0d0e0f10#),
         M (16#11121314#), M (16#15161718#), M (16#19000000#), others => 0);

      --  50 times 16#cd#
      Message := Message_Type'
        (1 => LSC.Internal.SHA1.Block_Type'
           (M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
            M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
            M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
            M (16#cdcd0000#), others => 0));

      Assert
        (LSC.Internal.HMAC_SHA1.Authenticate (Key, Message, 400) =
           LSC.Internal.SHA1.Hash_Type'
             (M (16#4c9007f4#), M (16#026250c6#), M (16#bc8414f9#),
              M (16#bf50c86c#), M (16#2d7235da#)),
         "Invalid HMAC");

   end Test_SHA1_Auth_4;

   ---------------------------------------------------------------------------

   procedure Test_SHA1_Auth_5 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.Types.Word64 range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA1.Message_Type (Message_Index);

      Key     : LSC.Internal.SHA1.Block_Type;
      Message : Message_Type;
   begin

      --  0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
      Key := LSC.Internal.SHA1.Block_Type'
        (M (16#0c0c0c0c#), M (16#0c0c0c0c#), M (16#0c0c0c0c#), M (16#0c0c0c0c#),
         M (16#0c0c0c0c#), others => 0);

      --  "Test With Truncation"
      Message := Message_Type'
        (1 => LSC.Internal.SHA1.Block_Type'
           (M (16#54657374#), M (16#20576974#), M (16#68205472#), M (16#756e6361#),
            M (16#74696f6e#), others => 0));

      Assert
        (LSC.Internal.HMAC_SHA1.Authenticate (Key, Message, 160) =
           LSC.Internal.SHA1.Hash_Type'
             (M (16#4c1a0342#), M (16#4b55e07f#), M (16#e7f27be1#),
              M (16#d58bb932#), M (16#4a9a5a04#)),
         "Invalid HMAC");

   end Test_SHA1_Auth_5;

   ---------------------------------------------------------------------------

   procedure Test_SHA1_Multi_1 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.Types.Word64 range 1 .. 4;
      subtype Message_Type is LSC.Internal.SHA1.Message_Type (Message_Index);

      Key     : LSC.Internal.SHA1.Block_Type;
      Message : Message_Type;
   begin
      --  hmac_sha1-key-1.dat
      Key := LSC.Internal.SHA1.Block_Type'
        (M (16#07a55659#), M (16#e5e382f2#), M (16#a12610e0#), M (16#8926b665#),
         M (16#43122a4e#), M (16#c2dc3c09#), M (16#8261de1f#), M (16#3f2ae412#),
         M (16#7e19048e#), M (16#7cee69bc#), M (16#43f8283e#), M (16#86b48781#),
         M (16#ca18e81c#), M (16#422f70e3#), M (16#52062553#), M (16#ff11c406#));

      --  hmac_sha1-message-1.dat
      Message := Message_Type'
        (LSC.Internal.SHA1.Block_Type'
           (M (16#b88457a3#), M (16#9d9346c9#), M (16#9698c202#), M (16#c45572f7#),
            M (16#4ccff08d#), M (16#c311f906#), M (16#c8dbfa88#), M (16#57f2220b#),
            M (16#70d29fb8#), M (16#689ca8c1#), M (16#7a907974#), M (16#c7c09dcf#),
            M (16#15357d16#), M (16#36103db1#), M (16#0618739c#), M (16#cddcd890#)),
         LSC.Internal.SHA1.Block_Type'
           (M (16#6946c864#), M (16#b3bae1f4#), M (16#60d1e64f#), M (16#ee07a9c7#),
            M (16#119e06ed#), M (16#d5ff9753#), M (16#b237b06a#), M (16#4ecc8000#),
            M (16#430389cc#), M (16#0114af02#), M (16#2ed4714e#), M (16#5ba051de#),
            M (16#c852b7aa#), M (16#5799d4d0#), M (16#52121b4e#), M (16#67325a2f#)),
         LSC.Internal.SHA1.Block_Type'
           (M (16#7bb838f5#), M (16#2f3cbff1#), M (16#ae723f2d#), M (16#35abc721#),
            M (16#74503c67#), M (16#9be8d95c#), M (16#60a7308f#), M (16#b21a0347#),
            M (16#e099d848#), M (16#15a46a22#), M (16#a78112d1#), M (16#c5cbc2a4#),
            M (16#376934e0#), M (16#337c8770#), M (16#24a440e3#), M (16#5e3a7349#)),
         LSC.Internal.SHA1.Block_Type'
           (M (16#a6232f33#), M (16#48130619#), M (16#30aba014#), M (16#c6400194#),
            M (16#1546e5ab#), M (16#50d98fe5#), M (16#3700f966#), M (16#982eaf6a#),
            M (16#65ef70de#), M (16#6b5f9d6c#), M (16#ec8c7a7e#), M (16#ff37f2ec#),
            M (16#5cafcc39#), M (16#646132f3#), M (16#240e4811#), M (16#7f4db108#))
        );

      --  hmac_sha1-hash-1.dat
      Assert
        (LSC.Internal.HMAC_SHA1.Authenticate (Key, Message, 2048) =
           LSC.Internal.SHA1.Hash_Type'(M (16#ec3b225b#), M (16#f28c53dc#),
             M (16#e8bd8722#), M (16#f325d5b1#), M (16#691114c7#)),
         "Invalid HMAC");

   end Test_SHA1_Multi_1;

   ---------------------------------------------------------------------------

   procedure Test_SHA1_Multi_2 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.Types.Word64 range 1 .. 5;
      subtype Message_Type is LSC.Internal.SHA1.Message_Type (Message_Index);

      Key     : LSC.Internal.SHA1.Block_Type;
      Message : Message_Type;
   begin
      --  hmac_sha1-key-2.dat
      Key := LSC.Internal.SHA1.Block_Type'
        (M (16#f05821b9#), M (16#94ab6613#), M (16#f7c5773f#), M (16#b2a2184f#),
         M (16#9659daf3#), M (16#856a4a69#), M (16#245ba5f9#), M (16#7431d93f#),
         M (16#697a494d#), M (16#8da7131b#), M (16#1a995683#), M (16#4b4592d0#),
         M (16#c10b076b#), M (16#989278bc#), M (16#91fe184c#), M (16#84046614#));

      --  hmac_sha1-message-2.dat
      Message := Message_Type'
        (LSC.Internal.SHA1.Block_Type'
           (M (16#503ab855#), M (16#d8a04186#), M (16#484637e5#), M (16#38dd715f#),
            M (16#ca6026bd#), M (16#a01a90d4#), M (16#3ac281e4#), M (16#cf626d63#),
            M (16#cc6c49f0#), M (16#397cdc76#), M (16#db96736f#), M (16#4e0fd1e7#),
            M (16#24b765e7#), M (16#83d7bd3b#), M (16#f20ebc24#), M (16#8e1c0eef#)),
         LSC.Internal.SHA1.Block_Type'
           (M (16#cc9b450e#), M (16#481ed2f3#), M (16#13c26f80#), M (16#57ae2910#),
            M (16#b316e6ae#), M (16#580250b6#), M (16#57857881#), M (16#eb7e25e4#),
            M (16#b7e64116#), M (16#ad0bb1d5#), M (16#b720b390#), M (16#8f1e47a1#),
            M (16#65461c23#), M (16#46e282c8#), M (16#b4948e3e#), M (16#6c70c980#)),
         LSC.Internal.SHA1.Block_Type'
           (M (16#f7464750#), M (16#d18db4c2#), M (16#9a7db515#), M (16#e6212696#),
            M (16#bf47e1e5#), M (16#3d1b5887#), M (16#82610dd8#), M (16#39e60cbf#),
            M (16#efe360f8#), M (16#374b922d#), M (16#cae8bcee#), M (16#8eb7db21#),
            M (16#cb13bccd#), M (16#d98284ec#), M (16#95896c3b#), M (16#30173471#)),
         LSC.Internal.SHA1.Block_Type'
           (M (16#64aa3093#), M (16#cacca160#), M (16#543e4b66#), M (16#f2dda6a2#),
            M (16#4ed9d501#), M (16#5f60f27f#), M (16#7e966bb3#), M (16#df799512#),
            M (16#cb379c89#), M (16#225e92b7#), M (16#54fc317e#), M (16#c6ee8ebe#),
            M (16#ac522ea6#), M (16#2e89fa10#), M (16#40008689#), M (16#a375735f#)),
         LSC.Internal.SHA1.Block_Type'
           (M (16#c9c7e5e0#), M (16#1ec278ff#), M (16#d86271e4#), M (16#1ec69d9a#),
            M (16#b94945db#), M (16#0efb7362#), M (16#2a6c72a6#), M (16#3e5f3880#),
            M (16#7df8aa81#), M (16#c7393cc8#), M (16#4077af9a#), M (16#01c0adc4#),
            M (16#3543e821#), M (16#f1dbd0a1#), others => 0)
        );

      --  hmac_sha1-hash-2.dat
      Assert
        (LSC.Internal.HMAC_SHA1.Authenticate (Key, Message, 2048 + 448) =
           LSC.Internal.SHA1.Hash_Type'(M (16#f87e3f76#), M (16#92b5f83c#),
             M (16#8f2f20bf#), M (16#8027d87e#), M (16#8b4cf783#)),
         "Invalid HMAC");
   end Test_SHA1_Multi_2;

   ---------------------------------------------------------------------------

   procedure Test_SHA256_Prf_1 (T : in out Test_Cases.Test_Case'Class)
   is
      HMAC_Ctx          : LSC.Internal.HMAC_SHA256.Context_Type;
      Key               : LSC.Internal.SHA256.Block_Type;
      Block             : LSC.Internal.SHA256.Block_Type;
      PRF_HMAC_SHA_256  : LSC.Internal.SHA256.SHA256_Hash_Type;
   begin
      Key   := LSC.Internal.SHA256.Block_Type'
        (M (16#0b0b0b0b#), M (16#0b0b0b0b#), M (16#0b0b0b0b#),
         M (16#0b0b0b0b#), M (16#0b0b0b0b#), others => 0);

      --  "Hi There"
      Block := LSC.Internal.SHA256.Block_Type'(M (16#48692054#),
                                      M (16#68657265#),
                                      others => 0);

      HMAC_Ctx := LSC.Internal.HMAC_SHA256.Context_Init (Key);
      LSC.Internal.HMAC_SHA256.Context_Finalize (HMAC_Ctx, Block, 64);
      PRF_HMAC_SHA_256 := LSC.Internal.HMAC_SHA256.Get_Prf (HMAC_Ctx);

      Assert
        (PRF_HMAC_SHA_256 = LSC.Internal.SHA256.SHA256_Hash_Type'
                              (M (16#b0344c61#),
                               M (16#d8db3853#),
                               M (16#5ca8afce#),
                               M (16#af0bf12b#),
                               M (16#881dc200#),
                               M (16#c9833da7#),
                               M (16#26e9376c#),
                               M (16#2e32cff7#)),
         "Invalid PRF");
   end Test_SHA256_Prf_1;

   ---------------------------------------------------------------------------

   procedure Test_SHA256_Prf_2 (T : in out Test_Cases.Test_Case'Class)
   is
      HMAC_Ctx          : LSC.Internal.HMAC_SHA256.Context_Type;
      Key               : LSC.Internal.SHA256.Block_Type;
      Block             : LSC.Internal.SHA256.Block_Type;
      PRF_HMAC_SHA_256  : LSC.Internal.SHA256.SHA256_Hash_Type;
   begin
      --  "Jefe"
      Key   := LSC.Internal.SHA256.Block_Type'
        (M (16#4a656665#), others => 0);

      --  "what do ya want "
      --  "for nothing?"
      Block := LSC.Internal.SHA256.Block_Type'
        (M (16#77686174#), M (16#20646f20#), M (16#79612077#), M (16#616e7420#),
         M (16#666f7220#), M (16#6e6f7468#), M (16#696e673f#), others => 0);

      HMAC_Ctx := LSC.Internal.HMAC_SHA256.Context_Init (Key);
      LSC.Internal.HMAC_SHA256.Context_Finalize (HMAC_Ctx, Block, 224);
      PRF_HMAC_SHA_256 := LSC.Internal.HMAC_SHA256.Get_Prf (HMAC_Ctx);

      Assert
        (PRF_HMAC_SHA_256 =
         LSC.Internal.SHA256.SHA256_Hash_Type'(M (16#5bdcc146#),
                                      M (16#bf60754e#),
                                      M (16#6a042426#),
                                      M (16#089575c7#),
                                      M (16#5a003f08#),
                                      M (16#9d273983#),
                                      M (16#9dec58b9#),
                                      M (16#64ec3843#)),
         "Invalid HMAC");
   end Test_SHA256_Prf_2;

   ---------------------------------------------------------------------------

   procedure Test_SHA256_Prf_3 (T : in out Test_Cases.Test_Case'Class)
   is
      HMAC_Ctx          : LSC.Internal.HMAC_SHA256.Context_Type;
      Key               : LSC.Internal.SHA256.Block_Type;
      Block             : LSC.Internal.SHA256.Block_Type;
      PRF_HMAC_SHA_256  : LSC.Internal.SHA256.SHA256_Hash_Type;
   begin
      --  20 times 16#aa#
      Key   := LSC.Internal.SHA256.Block_Type'
        (M (16#aaaaaaaa#), M (16#aaaaaaaa#), M (16#aaaaaaaa#),
         M (16#aaaaaaaa#), M (16#aaaaaaaa#), others => 0);

      --  50 times 16#dd#
      Block := LSC.Internal.SHA256.Block_Type'
        (M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
         M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
         M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
         M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
         M (16#dddd0000#), others => 0);

      HMAC_Ctx := LSC.Internal.HMAC_SHA256.Context_Init (Key);
      LSC.Internal.HMAC_SHA256.Context_Finalize (HMAC_Ctx, Block, 400);
      PRF_HMAC_SHA_256 := LSC.Internal.HMAC_SHA256.Get_Prf (HMAC_Ctx);

      Assert
        (PRF_HMAC_SHA_256 =
         LSC.Internal.SHA256.SHA256_Hash_Type'(M (16#773ea91e#),
                                      M (16#36800e46#),
                                      M (16#854db8eb#),
                                      M (16#d09181a7#),
                                      M (16#2959098b#),
                                      M (16#3ef8c122#),
                                      M (16#d9635514#),
                                      M (16#ced565fe#)),
         "Invalid HMAC");
   end Test_SHA256_Prf_3;

   ---------------------------------------------------------------------------

   procedure Test_SHA256_Prf_4 (T : in out Test_Cases.Test_Case'Class)
   is
      HMAC_Ctx          : LSC.Internal.HMAC_SHA256.Context_Type;
      Key               : LSC.Internal.SHA256.Block_Type;
      Block             : LSC.Internal.SHA256.Block_Type;
      PRF_HMAC_SHA_256  : LSC.Internal.SHA256.SHA256_Hash_Type;
   begin
      --  25 bytes
      Key   := LSC.Internal.SHA256.Block_Type'(M (16#01020304#),
                                      M (16#05060708#),
                                      M (16#090a0b0c#),
                                      M (16#0d0e0f10#),
                                      M (16#11121314#),
                                      M (16#15161718#),
                                      M (16#19000000#),
                                      others => 0);
      --  50 times 16#dd#
      Block := LSC.Internal.SHA256.Block_Type'(M (16#cdcdcdcd#),
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

      HMAC_Ctx := LSC.Internal.HMAC_SHA256.Context_Init (Key);
      LSC.Internal.HMAC_SHA256.Context_Finalize (HMAC_Ctx, Block, 400);
      PRF_HMAC_SHA_256 := LSC.Internal.HMAC_SHA256.Get_Prf (HMAC_Ctx);

      Assert
        (PRF_HMAC_SHA_256 =
         LSC.Internal.SHA256.SHA256_Hash_Type'(M (16#82558a38#),
                                      M (16#9a443c0e#),
                                      M (16#a4cc8198#),
                                      M (16#99f2083a#),
                                      M (16#85f0faa3#),
                                      M (16#e578f807#),
                                      M (16#7a2e3ff4#),
                                      M (16#6729665b#)),
         "Invalid HMAC");
   end Test_SHA256_Prf_4;

   ---------------------------------------------------------------------------

   procedure Test_SHA256_Auth_1 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA256.Message_Index range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA256.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA256.Block_Type;
      Message : Message_Type;
   begin
      --  32 bytes
      Key   := LSC.Internal.SHA256.Block_Type'(M (16#0b0b0b0b#),
                                      M (16#0b0b0b0b#),
                                      M (16#0b0b0b0b#),
                                      M (16#0b0b0b0b#),
                                      M (16#0b0b0b0b#),
                                      M (16#0b0b0b0b#),
                                      M (16#0b0b0b0b#),
                                      M (16#0b0b0b0b#),
                                      others => 0);

      --  "Hi There"
      Message := Message_Type'(1 => LSC.Internal.SHA256.Block_Type'
         (M (16#48692054#), M (16#68657265#), others => 0));

      Assert
        (LSC.Internal.HMAC_SHA256.Authenticate (Key, Message, 64) =
         LSC.Internal.HMAC_SHA256.Auth_Type'(M (16#198a607e#),
                                    M (16#b44bfbc6#),
                                    M (16#9903a0f1#),
                                    M (16#cf2bbdc5#)),
         "Invalid HMAC");
   end Test_SHA256_Auth_1;

   ---------------------------------------------------------------------------

   procedure Test_SHA256_Auth_2 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA256.Message_Index range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA256.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA256.Block_Type;
      Message : Message_Type;
   begin
      --  "JefeJefeJefeJefe"
      --  "JefeJefeJefeJefe"
      Key   := LSC.Internal.SHA256.Block_Type'(M (16#4a656665#),
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
      Message := Message_Type'(1 => LSC.Internal.SHA256.Block_Type'
                                   (M (16#77686174#),
                                    M (16#20646f20#),
                                    M (16#79612077#),
                                    M (16#616e7420#),
                                    M (16#666f7220#),
                                    M (16#6e6f7468#),
                                    M (16#696e673f#),
                                    others => 0));

      Assert
        (LSC.Internal.HMAC_SHA256.Authenticate (Key, Message, 224) =
         LSC.Internal.HMAC_SHA256.Auth_Type'(M (16#167f9285#),
                                    M (16#88c5cc2e#),
                                    M (16#ef8e3093#),
                                    M (16#caa0e87c#)),
         "Invalid HMAC");
   end Test_SHA256_Auth_2;

   ---------------------------------------------------------------------------

   procedure Test_SHA256_Auth_3 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA256.Message_Index range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA256.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA256.Block_Type;
      Message : Message_Type;
   begin
      --  32 times 16#aa#
      Key   := LSC.Internal.SHA256.Block_Type'(M (16#aaaaaaaa#),
                                      M (16#aaaaaaaa#),
                                      M (16#aaaaaaaa#),
                                      M (16#aaaaaaaa#),
                                      M (16#aaaaaaaa#),
                                      M (16#aaaaaaaa#),
                                      M (16#aaaaaaaa#),
                                      M (16#aaaaaaaa#),
                                      others => 0);

      --  50 times 16#dd#
      Message := Message_Type'(1 => LSC.Internal.SHA256.Block_Type'
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

      Assert
        (LSC.Internal.HMAC_SHA256.Authenticate (Key, Message, 400) =
         LSC.Internal.HMAC_SHA256.Auth_Type'(M (16#cdcb1220#),
                                    M (16#d1ecccea#),
                                    M (16#91e53aba#),
                                    M (16#3092f962#)),
         "Invalid HMAC");
   end Test_SHA256_Auth_3;

   ---------------------------------------------------------------------------

   procedure Test_SHA256_Auth_4 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA256.Message_Index range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA256.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA256.Block_Type;
      Message : Message_Type;
   begin
      --  32 byte
      Key   := LSC.Internal.SHA256.Block_Type'(M (16#01020304#),
                                      M (16#05060708#),
                                      M (16#090a0b0c#),
                                      M (16#0d0e0f10#),
                                      M (16#11121314#),
                                      M (16#15161718#),
                                      M (16#191a1b1c#),
                                      M (16#1d1e1f20#),
                                      others => 0);

      --  50 times 16#cd#
      Message := Message_Type'(1 => LSC.Internal.SHA256.Block_Type'
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

      Assert
        (LSC.Internal.HMAC_SHA256.Authenticate (Key, Message, 400) =
         LSC.Internal.HMAC_SHA256.Auth_Type'(M (16#372efcf9#),
                                    M (16#b40b35c2#),
                                    M (16#115b1346#),
                                    M (16#903d2ef4#)),
         "Invalid HMAC");
   end Test_SHA256_Auth_4;

   ---------------------------------------------------------------------------

   procedure Test_SHA256_Multi_1 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA256.Message_Index range 1 .. 4;
      subtype Message_Type is LSC.Internal.SHA256.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA256.Block_Type;
      Message : Message_Type;
   begin
      --  hmac_sha256-key-1.dat
      Key := LSC.Internal.SHA256.Block_Type'(
         M (16#e94f399e#), M (16#6451ce39#), M (16#7b49d580#), M (16#bafdf532#),
         M (16#ee24aa25#), M (16#6b0721bf#), M (16#c7f67939#), M (16#903fc021#),
         M (16#ca3c517c#), M (16#1ce00fa3#), M (16#ed0a5ff2#), M (16#a2c32049#),
         M (16#d3452f2b#), M (16#cdba563a#), M (16#3edf4f0d#), M (16#6bd26dad#)
      );

      --  hmac_sha256-message-1.dat
      Message := Message_Type'(
      LSC.Internal.SHA256.Block_Type'(
         M (16#1d68a3cd#), M (16#6b07a7e3#), M (16#3ce93a05#), M (16#f89defe5#),
         M (16#0142fe91#), M (16#8508e319#), M (16#b283d17c#), M (16#1423afc0#),
         M (16#86508665#), M (16#b34c6d13#), M (16#777da272#), M (16#d202d291#),
         M (16#91c89d4b#), M (16#f2852209#), M (16#a4241e91#), M (16#2e4c9b6e#)),
      LSC.Internal.SHA256.Block_Type'(
         M (16#8342da56#), M (16#5fa7bbb0#), M (16#0e5541f7#), M (16#11ac4f01#),
         M (16#69bd4113#), M (16#a51388fc#), M (16#f57aac73#), M (16#95d774eb#),
         M (16#07eb51e1#), M (16#526efaa3#), M (16#c589f223#), M (16#89adaf4d#),
         M (16#48d01d42#), M (16#99a16171#), M (16#7a84a41c#), M (16#5cabe95b#)),
      LSC.Internal.SHA256.Block_Type'(
         M (16#d056a140#), M (16#25e4da39#), M (16#54251a17#), M (16#288bbf71#),
         M (16#7040f900#), M (16#e6b3eeb9#), M (16#b4c7337e#), M (16#59c946c0#),
         M (16#d72b53b2#), M (16#04e16a4a#), M (16#bb00aa33#), M (16#fc674d6a#),
         M (16#cdb821d9#), M (16#b1d2a1ca#), M (16#0d286937#), M (16#81ef2acf#)),
      LSC.Internal.SHA256.Block_Type'(
         M (16#e908e006#), M (16#815853a2#), M (16#d6100b5d#), M (16#a81ce416#),
         M (16#d98ba37d#), M (16#36e3c68b#), M (16#52cf0c1c#), M (16#aa9805b9#),
         M (16#3b7e68b7#), M (16#2c56511d#), M (16#711336b8#), M (16#eb1fe87f#),
         M (16#88b5870c#), M (16#697807fd#), M (16#dd1d1028#), M (16#87d5777f#))
      );

      --  hmac_sha256-hash-1.dat
      Assert
        (LSC.Internal.HMAC_SHA256.Authenticate (Key, Message, 2048) =
         LSC.Internal.HMAC_SHA256.Auth_Type'(
         M (16#15667870#), M (16#c4957c0f#), M (16#46de0f26#), M (16#c19804ae#)),
         "Invalid HMAC");
   end Test_SHA256_Multi_1;

   ---------------------------------------------------------------------------

   procedure Test_SHA256_Multi_2 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA256.Message_Index range 1 .. 5;
      subtype Message_Type is LSC.Internal.SHA256.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA256.Block_Type;
      Message : Message_Type;
   begin
      --  hmac_sha256-key-2.dat
      Key := LSC.Internal.SHA256.Block_Type'(
         M (16#f9bce67a#), M (16#4d76ff6d#), M (16#d14b0371#), M (16#7b63696c#),
         M (16#563ff8ee#), M (16#1825343e#), M (16#3732b7ff#), M (16#d881d8c1#),
         M (16#f5e75c76#), M (16#0fab3418#), M (16#8281a08b#), M (16#dbdf6264#),
         M (16#27566d34#), M (16#a61c20cf#), M (16#41db3611#), M (16#4d8d63f9#)
      );

      --  hmac_sha256-message-2.dat
      Message := Message_Type'(
      LSC.Internal.SHA256.Block_Type'(
         M (16#05b4583b#), M (16#e4dabc55#), M (16#2d3ec9bb#), M (16#d9a36cfc#),
         M (16#ec9cd70a#), M (16#c28326e3#), M (16#55fa0488#), M (16#963c2dae#),
         M (16#c8046861#), M (16#27944daa#), M (16#7c9935a3#), M (16#7a15387e#),
         M (16#724669bd#), M (16#3ee51c80#), M (16#f01dd16e#), M (16#d6eaae5d#)),
      LSC.Internal.SHA256.Block_Type'(
         M (16#031d4365#), M (16#aecd1468#), M (16#623ecfef#), M (16#8bc48e96#),
         M (16#d14fd471#), M (16#adec193a#), M (16#2d803593#), M (16#876083a6#),
         M (16#771684e6#), M (16#022d917e#), M (16#b96c6472#), M (16#5e3d3c25#),
         M (16#cbf3b94b#), M (16#290f30dd#), M (16#ae3be915#), M (16#bbf215fa#)),
      LSC.Internal.SHA256.Block_Type'(
         M (16#a362659b#), M (16#7ba390a6#), M (16#fe4ccb96#), M (16#3d7a9efa#),
         M (16#634edd9a#), M (16#e977235b#), M (16#b061da25#), M (16#871d5ec4#),
         M (16#96591090#), M (16#03e8d9bd#), M (16#b8b570b2#), M (16#8a55eea2#),
         M (16#41654ead#), M (16#a305eca9#), M (16#27183dc4#), M (16#0fccbeac#)),
      LSC.Internal.SHA256.Block_Type'(
         M (16#9d99311c#), M (16#c8cee41e#), M (16#e165b132#), M (16#d0907f42#),
         M (16#ba829b85#), M (16#6ac8cc7b#), M (16#32c158ed#), M (16#8ae5efbd#),
         M (16#c8c47c0a#), M (16#11f6e3de#), M (16#ca9425d1#), M (16#d560ff15#),
         M (16#42724497#), M (16#07ded7a7#), M (16#87721d7c#), M (16#ab2cb568#)),
      LSC.Internal.SHA256.Block_Type'(
         M (16#29ac3372#), M (16#bbae6449#), M (16#8e48ce3d#), M (16#2f18bca7#),
         M (16#8b019337#), M (16#dad8763d#), M (16#dcef1b86#), M (16#e8e729c7#),
         M (16#f4966f48#), M (16#2537e29a#), M (16#6861c3b6#), M (16#1b8ad2a7#),
         M (16#2d07d0fd#), M (16#db70f339#), others => 0)
      );

      --  hmac_sha256-hash-2.dat
      Assert
        (LSC.Internal.HMAC_SHA256.Authenticate (Key, Message, 2048 + 448) =
         LSC.Internal.HMAC_SHA256.Auth_Type'(
         M (16#a3735482#), M (16#3897bec4#), M (16#a017cefc#), M (16#608852a6#)),
         "Invalid HMAC");
   end Test_SHA256_Multi_2;

   ---------------------------------------------------------------------------

   procedure Test_SHA384_Prf_1 (T : in out Test_Cases.Test_Case'Class)
   is
      HMAC_Ctx          : LSC.Internal.HMAC_SHA384.Context_Type;
      Key               : LSC.Internal.SHA512.Block_Type;
      Block             : LSC.Internal.SHA512.Block_Type;
      PRF_HMAC_SHA_384  : LSC.Internal.SHA512.SHA384_Hash_Type;
   begin
      Key   := LSC.Internal.SHA512.Block_Type'
         (N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#),
          N (16#0b0b0b0b00000000#), others => 0);

      --  "Hi There"
      Block := LSC.Internal.SHA512.Block_Type'
         (N (16#4869205468657265#), others => 0);

      HMAC_Ctx := LSC.Internal.HMAC_SHA384.Context_Init (Key);
      LSC.Internal.HMAC_SHA384.Context_Finalize (HMAC_Ctx, Block, 64);
      PRF_HMAC_SHA_384 := LSC.Internal.HMAC_SHA384.Get_Prf (HMAC_Ctx);

      Assert
        (PRF_HMAC_SHA_384 =
         LSC.Internal.SHA512.SHA384_Hash_Type'
            (N (16#afd03944d8489562#), N (16#6b0825f4ab46907f#),
             N (16#15f9dadbe4101ec6#), N (16#82aa034c7cebc59c#),
             N (16#faea9ea9076ede7f#), N (16#4af152e8b2fa9cb6#)),
         "Invalid PRF");
   end Test_SHA384_Prf_1;

   ---------------------------------------------------------------------------

   procedure Test_SHA384_Prf_2 (T : in out Test_Cases.Test_Case'Class)
   is
      HMAC_Ctx          : LSC.Internal.HMAC_SHA384.Context_Type;
      Key               : LSC.Internal.SHA512.Block_Type;
      Block             : LSC.Internal.SHA512.Block_Type;
      PRF_HMAC_SHA_384  : LSC.Internal.SHA512.SHA384_Hash_Type;
   begin
      --  "Jefe"
      Key   := LSC.Internal.SHA512.Block_Type'
         (N (16#4a65666500000000#), others => 0);

      --  "what do ya want "
      --  "for nothing?"
      Block := LSC.Internal.SHA512.Block_Type'
         (N (16#7768617420646f20#), N (16#79612077616e7420#),
          N (16#666f72206e6f7468#), N (16#696e673f00000000#),
          others => 0);

      HMAC_Ctx := LSC.Internal.HMAC_SHA384.Context_Init (Key);
      LSC.Internal.HMAC_SHA384.Context_Finalize (HMAC_Ctx, Block, 224);
      PRF_HMAC_SHA_384 := LSC.Internal.HMAC_SHA384.Get_Prf (HMAC_Ctx);

      Assert
        (PRF_HMAC_SHA_384 =
         LSC.Internal.SHA512.SHA384_Hash_Type'
         (N (16#af45d2e376484031#), N (16#617f78d2b58a6b1b#), N (16#9c7ef464f5a01b47#),
          N (16#e42ec3736322445e#), N (16#8e2240ca5e69e2c7#), N (16#8b3239ecfab21649#)),
         "Invalid PRF");

   end Test_SHA384_Prf_2;

   ---------------------------------------------------------------------------

   procedure Test_SHA384_Prf_3 (T : in out Test_Cases.Test_Case'Class)
   is
      HMAC_Ctx          : LSC.Internal.HMAC_SHA384.Context_Type;
      Key               : LSC.Internal.SHA512.Block_Type;
      Block             : LSC.Internal.SHA512.Block_Type;
      PRF_HMAC_SHA_384  : LSC.Internal.SHA512.SHA384_Hash_Type;
   begin
      --  20 times 16#aa#
      Key   := LSC.Internal.SHA512.Block_Type'
         (N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#),
          N (16#aaaaaaaa00000000#), others => 0);

      --  50 times 16#dd#
      Block := LSC.Internal.SHA512.Block_Type'
         (N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
          N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
          N (16#dddd000000000000#), others => 0);

      HMAC_Ctx := LSC.Internal.HMAC_SHA384.Context_Init (Key);
      LSC.Internal.HMAC_SHA384.Context_Finalize (HMAC_Ctx, Block, 400);
      PRF_HMAC_SHA_384 := LSC.Internal.HMAC_SHA384.Get_Prf (HMAC_Ctx);

      Assert
        (PRF_HMAC_SHA_384 =
         LSC.Internal.SHA512.SHA384_Hash_Type'
         (N (16#88062608d3e6ad8a#), N (16#0aa2ace014c8a86f#), N (16#0aa635d947ac9feb#),
          N (16#e83ef4e55966144b#), N (16#2a5ab39dc13814b9#), N (16#4e3ab6e101a34f27#)),
         "Invalid PRF");
   end Test_SHA384_Prf_3;

   ---------------------------------------------------------------------------

   procedure Test_SHA384_Prf_4 (T : in out Test_Cases.Test_Case'Class)
   is
      HMAC_Ctx          : LSC.Internal.HMAC_SHA384.Context_Type;
      Key               : LSC.Internal.SHA512.Block_Type;
      Block             : LSC.Internal.SHA512.Block_Type;
      PRF_HMAC_SHA_384  : LSC.Internal.SHA512.SHA384_Hash_Type;
   begin
      --  25 bytes
      Key   := LSC.Internal.SHA512.Block_Type'
         (N (16#0102030405060708#), N (16#090a0b0c0d0e0f10#), N (16#1112131415161718#),
          N (16#1900000000000000#), others => 0);

      --  50 times 16#dd#
      Block := LSC.Internal.SHA512.Block_Type'
         (N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
          N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
          N (16#cdcd000000000000#), others => 0);

      HMAC_Ctx := LSC.Internal.HMAC_SHA384.Context_Init (Key);
      LSC.Internal.HMAC_SHA384.Context_Finalize (HMAC_Ctx, Block, 400);
      PRF_HMAC_SHA_384 := LSC.Internal.HMAC_SHA384.Get_Prf (HMAC_Ctx);

      Assert
        (PRF_HMAC_SHA_384 =
         LSC.Internal.SHA512.SHA384_Hash_Type'
         (N (16#3e8a69b7783c2585#), N (16#1933ab6290af6ca7#), N (16#7a9981480850009c#),
          N (16#c5577c6e1f573b4e#), N (16#6801dd23c4a7d679#), N (16#ccf8a386c674cffb#)),
         "Invalid PRF");
   end Test_SHA384_Prf_4;

   ---------------------------------------------------------------------------

   procedure Test_SHA384_Auth_1 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA512.Message_Index range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA512.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA512.Block_Type;
      Message : Message_Type;
   begin
      --  48 bytes
      Key   := LSC.Internal.SHA512.Block_Type'
         (N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#),
          N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#),
          others => 0);

      --  "Hi There"
      Message := Message_Type'(1 => LSC.Internal.SHA512.Block_Type'
         (N (16#4869205468657265#), others => 0));

      Assert
        (LSC.Internal.HMAC_SHA384.Authenticate (Key, Message, 64) =
         LSC.Internal.HMAC_SHA384.Auth_Type'
         (N (16#b6a8d5636f5c6a72#), N (16#24f9977dcf7ee6c7#), N (16#fb6d0c48cbdee973#)),
         "Invalid HMAC");
   end Test_SHA384_Auth_1;

   ---------------------------------------------------------------------------

   procedure Test_SHA384_Auth_2 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA512.Message_Index range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA512.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA512.Block_Type;
      Message : Message_Type;
   begin
      --  "JefeJefeJefeJefe"
      --  "JefeJefeJefeJefe"
      --  "JefeJefeJefeJefe"
      --  "JefeJefeJefeJefe"
      Key   := LSC.Internal.SHA512.Block_Type'
         (N (16#4a6566654a656665#), N (16#4a6566654a656665#), N (16#4a6566654a656665#),
          N (16#4a6566654a656665#), N (16#4a6566654a656665#), N (16#4a6566654a656665#),
          others => 0);

      --  "what do ya want "
      --  "for nothing?"
      Message := Message_Type'(1 => LSC.Internal.SHA512.Block_Type'
         (N (16#7768617420646f20#), N (16#79612077616e7420#), N (16#666f72206e6f7468#),
          N (16#696e673f00000000#), others => 0));

      Assert
        (LSC.Internal.HMAC_SHA384.Authenticate (Key, Message, 224) =
         LSC.Internal.HMAC_SHA384.Auth_Type'
         (N (16#2c7353974f1842fd#), N (16#66d53c452ca42122#), N (16#b28c0b594cfb184d#)),
         "Invalid HMAC");
   end Test_SHA384_Auth_2;

   ---------------------------------------------------------------------------

   procedure Test_SHA384_Auth_3 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA512.Message_Index range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA512.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA512.Block_Type;
      Message : Message_Type;
   begin
      --  48 times 16#aa#
      Key   := LSC.Internal.SHA512.Block_Type'
         (N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#),
          N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#),
          others => 0);

      --  50 times 16#dd#
      Message := Message_Type'(1 => LSC.Internal.SHA512.Block_Type'
         (N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
          N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
          N (16#dddd000000000000#), others => 0));

      Assert
        (LSC.Internal.HMAC_SHA384.Authenticate (Key, Message, 400) =
         LSC.Internal.HMAC_SHA384.Auth_Type'
         (N (16#809f439be0027432#), N (16#1d4a538652164b53#), N (16#554a508184a0c316#)),
         "Invalid HMAC");
   end Test_SHA384_Auth_3;

   ---------------------------------------------------------------------------

   procedure Test_SHA384_Auth_4 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA512.Message_Index range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA512.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA512.Block_Type;
      Message : Message_Type;
   begin
      Key   := LSC.Internal.SHA512.Block_Type'
         (N (16#0102030405060708#), N (16#090a0b0c0d0e0f10#), N (16#1112131415161718#),
          N (16#191a1b1c1d1e1f20#), N (16#0a0b0c0d0e0f1011#), N (16#1213141516171819#),
          others => 0);

      --  50 times 16#dd#
      Message := Message_Type'(1 => LSC.Internal.SHA512.Block_Type'
         (N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
          N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
          N (16#cdcd000000000000#), others => 0));

      Assert
        (LSC.Internal.HMAC_SHA384.Authenticate (Key, Message, 400) =
         LSC.Internal.HMAC_SHA384.Auth_Type'
         (N (16#5b540085c6e63580#), N (16#96532b2493609ed1#), N (16#cb298f774f87bb5c#)),
         "Invalid HMAC");

   end Test_SHA384_Auth_4;

   ---------------------------------------------------------------------------

   procedure Test_SHA384_Multi_1 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA512.Message_Index range 1 .. 2;
      subtype Message_Type is LSC.Internal.SHA512.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA512.Block_Type;
      Message : Message_Type;
   begin
      --  Hexdump of HMAC_SHA384-key-1.dat
      Key   := LSC.Internal.SHA512.Block_Type'(
         N (16#2cad6b4b0b01b5b4#), N (16#a4de252f2b594736#), N (16#68e85fdc40de1d25#), N (16#c25d4ecc2a7dfec4#),
         N (16#53334b6ee5b4a4fb#), N (16#33cf52a70f23a351#), N (16#e7e124dc78b56c76#), N (16#18c14c301ef0452a#),
         N (16#29b8cdb0821d774a#), N (16#d0e55480530bd091#), N (16#0f92dcb33037cded#), N (16#d8fabd1bcd519cba#),
         N (16#8dc8cd68bbd33d5e#), N (16#2e22a320d6a71a60#), N (16#ba16964831e0e8e6#), N (16#b5527d657d6a9daa#)
      );

      --  Hexdump of HMAC_SHA384-message-1.dat
      Message := Message_Type'(
      LSC.Internal.SHA512.Block_Type'(
         N (16#c7e3ae3df95ca9a8#), N (16#13242d4052700304#), N (16#fc8dab7c4bffff62#), N (16#de0b364b87a1f8c7#),
         N (16#5e9b3f6b31f552ec#), N (16#f8a53724b01ff176#), N (16#eb9922a221b0003a#), N (16#682dca9fdfa49e59#),
         N (16#b652f8c834c89936#), N (16#486df5779f720734#), N (16#77e912b3568cd483#), N (16#7059267c1d013521#),
         N (16#b6c763924fea7e17#), N (16#58591d2a1781fcac#), N (16#072e963f2a02e23a#), N (16#831344b9c9ddc17e#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#68d70a8125e29904#), N (16#00aa442072ea6d52#), N (16#f890ce20e7fff07a#), N (16#ffb79d3c294fba57#),
         N (16#1546abc37b2071ca#), N (16#cffd731e25232350#), N (16#635e8e8a3693a8f2#), N (16#d13ec3505e6912d5#),
         N (16#c8855484eb251327#), N (16#2c42eaa8afa3d8ea#), N (16#82546d44da4e8553#), N (16#6844ec16107925a7#),
         N (16#8d3449f3c6cbff01#), N (16#b304d133a118c1d7#), N (16#2e0b4f754b38fa9e#), N (16#0a082fd37ca98c56#))
      );

      --  Hexdump of HMAC_SHA384-hash-1.dat
      Assert
        (LSC.Internal.HMAC_SHA384.Authenticate (Key, Message, 2048) =
         LSC.Internal.HMAC_SHA384.Auth_Type'(
            N (16#89869091210b3653#), N (16#21f60d6409b9ab5e#), N (16#fd8eea749f22dce3#)),
         "Invalid HMAC");

   end Test_SHA384_Multi_1;

   ---------------------------------------------------------------------------

   procedure Test_SHA384_Multi_2 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA512.Message_Index range 1 .. 3;
      subtype Message_Type is LSC.Internal.SHA512.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA512.Block_Type;
      Message : Message_Type;
   begin
      --  Hexdump of HMAC_SHA384-key-2.dat
      Key   := LSC.Internal.SHA512.Block_Type'(
         N (16#2466663d3e7bedcd#), N (16#e4c229484312440f#), N (16#954849019d214069#), N (16#759fdd03f6af0f1b#),
         N (16#4c6c4a0b78380f75#), N (16#12802b15ed72cf2d#), N (16#b82984e56921b813#), N (16#ffbc70abcf9aaa27#),
         N (16#042d2484d803ca23#), N (16#65830c9094ac5f3e#), N (16#fe810d7c628cd67d#), N (16#2e0acc568cd94862#),
         N (16#d45e471822988e27#), N (16#9d51cc4502a919bc#), N (16#3038d2e9c3336935#), N (16#eafcb8c2a0ac3878#)
      );

      --  Hexdump of HMAC_SHA384-message-2.dat
      Message := Message_Type'(
      LSC.Internal.SHA512.Block_Type'(
         N (16#225832edcff4d97b#), N (16#6d6d9329fe9f7eff#), N (16#f3311f03f6168ca7#), N (16#493eadbafb66bff2#),
         N (16#9c106683539a0193#), N (16#88444e2f7be708b3#), N (16#eb736e77d15339e8#), N (16#978839ef2d4afc9d#),
         N (16#1b2eb2501b9a0f8b#), N (16#41ed05fb650f52a2#), N (16#c8440f9f214ce15e#), N (16#07f811255328e5f6#),
         N (16#c7bcedaf34271920#), N (16#ab24105256cace3e#), N (16#aca191607991c49a#), N (16#bce83199afee2786#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#70b6f46c918f88df#), N (16#5f2a3ddcaef7cc29#), N (16#0134f34d30012e18#), N (16#bab3ac55fe992b34#),
         N (16#763d72beb784ea0e#), N (16#51fea85641166183#), N (16#f2c8d745c128e374#), N (16#4d85f98ce6500504#),
         N (16#6e4e29023d97146e#), N (16#491c2f043406fde8#), N (16#8e387a86ab56ada2#), N (16#46a28e21298790b6#),
         N (16#d6dc2d1b8f582696#), N (16#e9eda4cc3779af1d#), N (16#310a961c1619328d#), N (16#d44f8da9f1d547e1#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#41e7558b1f771b63#), N (16#73ca7b8ea99afefa#), N (16#1423e9fb847a0f57#), N (16#1a848c52b9424d2e#),
         N (16#b9effba7b7063973#), N (16#f56bf7b52116cb7f#), N (16#3974bb7d3bc0be6a#), others => 0)
      );

      --  Compare with hexdump of HMAC_SHA384-hash-2.dat
      Assert
        (LSC.Internal.HMAC_SHA384.Authenticate (Key, Message, 2048 + 448) =
         LSC.Internal.HMAC_SHA384.Auth_Type'(
            N (16#144cd21ae50bfb0f#), N (16#ed473b88e7b33470#), N (16#5c59fecda5f978c8#)),
         "Invalid HMAC");
   end Test_SHA384_Multi_2;

   ---------------------------------------------------------------------------

   --  SHA512 PRF Test Vectors (RFC 4868, 2.7.1.)

   procedure Test_SHA512_Prf_1 (T : in out Test_Cases.Test_Case'Class)
   is
      HMAC_Ctx          : LSC.Internal.HMAC_SHA512.Context_Type;
      Key               : LSC.Internal.SHA512.Block_Type;
      Block             : LSC.Internal.SHA512.Block_Type;
      PRF_HMAC_SHA_512  : LSC.Internal.SHA512.SHA512_Hash_Type;
   begin
      Key   := LSC.Internal.SHA512.Block_Type'
        (N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#),
         N (16#0b0b0b0b00000000#), others => 0);

      --  "Hi There"
      Block := LSC.Internal.SHA512.Block_Type'
        (N (16#4869205468657265#), others => 0);

      HMAC_Ctx := LSC.Internal.HMAC_SHA512.Context_Init (Key);
      LSC.Internal.HMAC_SHA512.Context_Finalize (HMAC_Ctx, Block, 64);
      PRF_HMAC_SHA_512 := LSC.Internal.HMAC_SHA512.Get_Prf (HMAC_Ctx);

      Assert
        (PRF_HMAC_SHA_512 =
         LSC.Internal.SHA512.SHA512_Hash_Type'
           (N (16#87aa7cdea5ef619d#), N (16#4ff0b4241a1d6cb0#), N (16#2379f4e2ce4ec278#),
            N (16#7ad0b30545e17cde#), N (16#daa833b7d6b8a702#), N (16#038b274eaea3f4e4#),
            N (16#be9d914eeb61f170#), N (16#2e696c203a126854#)),
         "Invalid PRF");
   end Test_SHA512_Prf_1;

   ---------------------------------------------------------------------------

   procedure Test_SHA512_Prf_2 (T : in out Test_Cases.Test_Case'Class)
   is
      HMAC_Ctx          : LSC.Internal.HMAC_SHA512.Context_Type;
      Key               : LSC.Internal.SHA512.Block_Type;
      Block             : LSC.Internal.SHA512.Block_Type;
      PRF_HMAC_SHA_512  : LSC.Internal.SHA512.SHA512_Hash_Type;
   begin
      --  "Jefe"
      Key   := LSC.Internal.SHA512.Block_Type'
        (0 => N (16#4a65666500000000#), others => 0);

      --  "what do ya want "
      --  "for nothing?"
      Block := LSC.Internal.SHA512.Block_Type'
        (N (16#7768617420646f20#), N (16#79612077616e7420#), N (16#666f72206e6f7468#),
         N (16#696e673f00000000#), others => 0);

      HMAC_Ctx := LSC.Internal.HMAC_SHA512.Context_Init (Key);
      LSC.Internal.HMAC_SHA512.Context_Finalize (HMAC_Ctx, Block, 224);
      PRF_HMAC_SHA_512 := LSC.Internal.HMAC_SHA512.Get_Prf (HMAC_Ctx);

      Assert
        (PRF_HMAC_SHA_512 =
         LSC.Internal.SHA512.SHA512_Hash_Type'
           (N (16#164b7a7bfcf819e2#), N (16#e395fbe73b56e0a3#), N (16#87bd64222e831fd6#),
            N (16#10270cd7ea250554#), N (16#9758bf75c05a994a#), N (16#6d034f65f8f0e6fd#),
            N (16#caeab1a34d4a6b4b#), N (16#636e070a38bce737#)),
         "Invalid PRF");
   end Test_SHA512_Prf_2;

   ---------------------------------------------------------------------------

   procedure Test_SHA512_Prf_3 (T : in out Test_Cases.Test_Case'Class)
   is
      HMAC_Ctx          : LSC.Internal.HMAC_SHA512.Context_Type;
      Key               : LSC.Internal.SHA512.Block_Type;
      Block             : LSC.Internal.SHA512.Block_Type;
      PRF_HMAC_SHA_512  : LSC.Internal.SHA512.SHA512_Hash_Type;
   begin
      --  20 times 16#aa#
      Key   := LSC.Internal.SHA512.Block_Type'
        (N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaa00000000#),
         others => 0);

      --  50 times 16#dd#
      Block := LSC.Internal.SHA512.Block_Type'
        (N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
         N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
         N (16#dddd000000000000#), others => 0);

      HMAC_Ctx := LSC.Internal.HMAC_SHA512.Context_Init (Key);
      LSC.Internal.HMAC_SHA512.Context_Finalize (HMAC_Ctx, Block, 400);
      PRF_HMAC_SHA_512 := LSC.Internal.HMAC_SHA512.Get_Prf (HMAC_Ctx);

      Assert
        (PRF_HMAC_SHA_512 =
         LSC.Internal.SHA512.SHA512_Hash_Type'
           (N (16#fa73b0089d56a284#), N (16#efb0f0756c890be9#), N (16#b1b5dbdd8ee81a36#),
            N (16#55f83e33b2279d39#), N (16#bf3e848279a722c8#), N (16#06b485a47e67c807#),
            N (16#b946a337bee89426#), N (16#74278859e13292fb#)),
         "Invalid PRF");
   end Test_SHA512_Prf_3;

   ---------------------------------------------------------------------------

   procedure Test_SHA512_Prf_4 (T : in out Test_Cases.Test_Case'Class)
   is
      HMAC_Ctx          : LSC.Internal.HMAC_SHA512.Context_Type;
      Key               : LSC.Internal.SHA512.Block_Type;
      Block             : LSC.Internal.SHA512.Block_Type;
      PRF_HMAC_SHA_512  : LSC.Internal.SHA512.SHA512_Hash_Type;
   begin
      --  25 bytes
      Key   := LSC.Internal.SHA512.Block_Type'
        (N (16#0102030405060708#), N (16#090a0b0c0d0e0f10#), N (16#1112131415161718#),
         N (16#1900000000000000#), others => 0);

      --  50 times 16#cd#
      Block := LSC.Internal.SHA512.Block_Type'
        (N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
         N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
         N (16#cdcd000000000000#), others => 0);

      HMAC_Ctx := LSC.Internal.HMAC_SHA512.Context_Init (Key);
      LSC.Internal.HMAC_SHA512.Context_Finalize (HMAC_Ctx, Block, 400);
      PRF_HMAC_SHA_512 := LSC.Internal.HMAC_SHA512.Get_Prf (HMAC_Ctx);

      Assert
        (PRF_HMAC_SHA_512 =
         LSC.Internal.SHA512.SHA512_Hash_Type'
           (N (16#b0ba465637458c69#), N (16#90e5a8c5f61d4af7#), N (16#e576d97ff94b872d#),
            N (16#e76f8050361ee3db#), N (16#a91ca5c11aa25eb4#), N (16#d679275cc5788063#),
            N (16#a5f19741120c4f2d#), N (16#e2adebeb10a298dd#)),
         "Invalid PRF");
   end Test_SHA512_Prf_4;

   ---------------------------------------------------------------------------

   procedure Test_SHA512_Auth_1 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA512.Message_Index range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA512.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA512.Block_Type;
      Message : Message_Type;
   begin
      --  64 bytes
      Key   := LSC.Internal.SHA512.Block_Type'
        (N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#),
         N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#),
         N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#), others => 0);

      --  "Hi There"
      Message := Message_Type'(1 => LSC.Internal.SHA512.Block_Type'(N (16#4869205468657265#), others => 0));

      Assert
        (LSC.Internal.HMAC_SHA512.Authenticate (Key, Message, 64) =
         LSC.Internal.HMAC_SHA512.Auth_Type'
           (N (16#637edc6e01dce7e6#), N (16#742a99451aae82df#), N (16#23da3e92439e590e#),
            N (16#43e761b33e910fb8#)),
         "Invalid HMAC");
   end Test_SHA512_Auth_1;

   ---------------------------------------------------------------------------

   procedure Test_SHA512_Auth_2 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA512.Message_Index range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA512.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA512.Block_Type;
      Message : Message_Type;
   begin
      --  "JefeJefeJefeJefe"
      --  "JefeJefeJefeJefe"
      --  "JefeJefeJefeJefe"
      --  "JefeJefeJefeJefe"
      Key   := LSC.Internal.SHA512.Block_Type'
        (N (16#4a6566654a656665#), N (16#4a6566654a656665#), N (16#4a6566654a656665#),
         N (16#4a6566654a656665#), N (16#4a6566654a656665#), N (16#4a6566654a656665#),
         N (16#4a6566654a656665#), N (16#4a6566654a656665#), others => 0);

      --  "what do ya want "
      --  "for nothing?"
      Message := Message_Type'(1 => LSC.Internal.SHA512.Block_Type'
         (N (16#7768617420646f20#), N (16#79612077616e7420#), N (16#666f72206e6f7468#),
          N (16#696e673f00000000#), others => 0));

      Assert
        (LSC.Internal.HMAC_SHA512.Authenticate (Key, Message, 224) =
         LSC.Internal.HMAC_SHA512.Auth_Type'
           (N (16#cb370917ae8a7ce2#), N (16#8cfd1d8f4705d614#), N (16#1c173b2a9362c15d#),
            N (16#f235dfb251b15454#)),
         "Invalid HMAC");
   end Test_SHA512_Auth_2;

   ---------------------------------------------------------------------------

   procedure Test_SHA512_Auth_3 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA512.Message_Index range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA512.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA512.Block_Type;
      Message : Message_Type;
   begin
      --  64 times 16#aa#
      Key   := LSC.Internal.SHA512.Block_Type'
        (N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#),
         N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#),
         N (16#aaaaaaaaaaaaaaaa#), N (16#aaaaaaaaaaaaaaaa#), others => 0);

      --  50 times 16#dd#
      Message := Message_Type'(1 => LSC.Internal.SHA512.Block_Type'
         (N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
          N (16#dddddddddddddddd#), N (16#dddddddddddddddd#), N (16#dddddddddddddddd#),
          N (16#dddd000000000000#), others => 0));

      Assert
        (LSC.Internal.HMAC_SHA512.Authenticate (Key, Message, 400) =
         LSC.Internal.HMAC_SHA512.Auth_Type'
           (N (16#2ee7acd783624ca9#), N (16#398710f3ee05ae41#), N (16#b9f9b0510c87e49e#),
            N (16#586cc9bf961733d8#)),
         "Invalid HMAC");
   end Test_SHA512_Auth_3;

   ---------------------------------------------------------------------------

   procedure Test_SHA512_Auth_4 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA512.Message_Index range 1 .. 1;
      subtype Message_Type is LSC.Internal.SHA512.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA512.Block_Type;
      Message : Message_Type;
   begin
      --  64 bytes
      --  NB: The test vector in RCF 4868 seem to be bogus! Though stating
      --      this to be a 64 bytes key, 80 bytes are presented. However,
      --      leaving out the first 16 bytes of the bogus key results in
      --      the presented MAC.
      Key   := LSC.Internal.SHA512.Block_Type'
        ( --  N (16#0a0b0c0d0e0f1011#), N (16#1213141516171819#),
         N (16#0102030405060708#), N (16#090a0b0c0d0e0f10#), N (16#1112131415161718#),
         N (16#191a1b1c1d1e1f20#), N (16#2122232425262728#), N (16#292a2b2c2d2e2f30#),
         N (16#3132333435363738#), N (16#393a3b3c3d3e3f40#), others => 0);

      --  50 times 16#dd#
      Message := Message_Type'(1 => LSC.Internal.SHA512.Block_Type'
         (N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
          N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#), N (16#cdcdcdcdcdcdcdcd#),
          N (16#cdcd000000000000#), others => 0));

      Assert
        (LSC.Internal.HMAC_SHA512.Authenticate (Key, Message, 400) =
         LSC.Internal.HMAC_SHA512.Auth_Type'
           (N (16#5e6688e5a3daec82#), N (16#6ca32eaea224eff5#), N (16#e700628947470e13#),
            N (16#ad01302561bab108#)),
         "Invalid HMAC");
   end Test_SHA512_Auth_4;

   ---------------------------------------------------------------------------

   procedure Test_SHA512_Multi_1 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA512.Message_Index range 1 .. 12;
      subtype Message_Type is LSC.Internal.SHA512.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA512.Block_Type;
      Message : Message_Type;
   begin
      --  Hexdump of key.dat
      Key   := LSC.Internal.SHA512.Block_Type'(
         N (16#2577888a5d567bf2#), N (16#01507064342a1670#), N (16#287ff1ea2ecabf96#), N (16#1542002cac690b68#),
         N (16#b647126442106e6f#), N (16#13eeffc56b4c8145#), N (16#6018bccffc00013d#), N (16#6d793f222e51d1a1#),
         others => 0
      );

      --  Hexdump of message.dat
      Message := Message_Type'(
      LSC.Internal.SHA512.Block_Type'(
         N (16#ab52393074a225f3#), N (16#9e432a58f6e977b2#), N (16#300df239a618518b#), N (16#44658572f2172571#),
         N (16#ed255db96276107d#), N (16#51ffe2d224398e6c#), N (16#7a5f28ba944234ca#), N (16#5cda9e919906d5db#),
         N (16#1e68ffb46c4502ce#), N (16#681b244934461c0e#), N (16#1f6f46215a687437#), N (16#6af97fc972980ed2#),
         N (16#37da280ca151a62e#), N (16#76e1061d9e66853b#), N (16#4cc431b1914bb77b#), N (16#9b0e872f70f5a6da#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#280fff785f74b695#), N (16#8723a46af87be8de#), N (16#a58295d9096e1d4d#), N (16#6de4955f179584b9#),
         N (16#d12c2197019f99cd#), N (16#f67a9ab6bb73e3e0#), N (16#952a99e77f97e389#), N (16#4944a6186960d1e2#),
         N (16#3945955700b078d5#), N (16#21f5eaa1e8fa3791#), N (16#61c5365d9b171afa#), N (16#6959a0a4ac566c8b#),
         N (16#f1b255ac75303a77#), N (16#02166e025c1b39d2#), N (16#9d172035de6c4bc0#), N (16#6a6d97b1f459f4e9#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#ddfb8d14678d2a56#), N (16#f3bf4ac6f70c913c#), N (16#c420c90214aea24a#), N (16#6f4e5ed1353ef80c#),
         N (16#39d45af77f92333a#), N (16#ee5cd1ff4266203d#), N (16#beaacf3b2400d092#), N (16#92fe1686f94d9905#),
         N (16#ba54a4f4c4e15fe2#), N (16#f61822552b9636f9#), N (16#ade3a60d895c6f99#), N (16#cdafd8c314b80b52#),
         N (16#f3f60ee9bc532185#), N (16#9ac0b0af2cb2064c#), N (16#d4592461e4149a38#), N (16#87db711d6780b9a3#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#a89663fb54e7af26#), N (16#35281105c9c11702#), N (16#fd66c7a66bdfd487#), N (16#64feb3305d99f2d8#),
         N (16#84f9f8df9cbc3ac2#), N (16#e1a05a67eefa2715#), N (16#c5a0a400e7b08951#), N (16#c6881b94a8e2e19c#),
         N (16#73a1210f9d8fcae6#), N (16#eaee91d6c355c7c5#), N (16#0af0f7c9c2a9a8b7#), N (16#d2bbd2021e005870#),
         N (16#80906028c4a857ab#), N (16#bc0193203ca904ce#), N (16#780496b634da331a#), N (16#94cb8f7ef900ea35#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#4c6ea0b588ba5a3b#), N (16#f5308bcbdaf41f69#), N (16#7879c816da391ec7#), N (16#18183bccca912d13#),
         N (16#2eb014b30ef8fb31#), N (16#9b3fece27dc8087b#), N (16#b9d0d874b03ad882#), N (16#46c840958d259c8c#),
         N (16#f7b86c7eff93d87e#), N (16#07a439d6e87bf8be#), N (16#885bfb0070d0f7e7#), N (16#5c81dd103552275b#),
         N (16#1113bf54d87e7945#), N (16#2a84246d2d0edf99#), N (16#34d99bfe79fadd79#), N (16#d2a883c2d1e3a6b7#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#b6efeb711954eeaf#), N (16#5b257ae378d44add#), N (16#00337d3e3e4e3fc6#), N (16#096fa66cc9385a96#),
         N (16#684240906b088744#), N (16#3525643b8fbfb874#), N (16#93d035d083b14f75#), N (16#0de86e83870cb487#),
         N (16#09b07dd08a1144c6#), N (16#95dc3e748e66d261#), N (16#a5f13b1ec903b475#), N (16#ff8a9c98671eab2e#),
         N (16#ea97255a3299b203#), N (16#421b44e9053c081c#), N (16#506565a5adf13767#), N (16#1c9ae758c435518c#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#d5c3482a45658905#), N (16#dfae0e6e94cc646f#), N (16#11c36c6187f78bd0#), N (16#635c86d782b11e84#),
         N (16#9c1ae165732b92cb#), N (16#1b45a1d981d62057#), N (16#fcf247d8950ee240#), N (16#cf559512489df8a8#),
         N (16#5c840eedbc0f5d67#), N (16#0c5a63ec4b11553c#), N (16#bf289c06f83df6f7#), N (16#02f5e058d1dd9cdb#),
         N (16#696c3c041621d2ee#), N (16#6bc8dee7876c3e98#), N (16#3a77599403f3e08f#), N (16#21324fcb2d26cbd9#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#80aa24c723ea9063#), N (16#d9c0b48219dca5b9#), N (16#8201966dbd3820f9#), N (16#8ac84c52996019b5#),
         N (16#2ca4061e2eb8bea3#), N (16#8df523b70a99c5c7#), N (16#5f158e0d9abd58f3#), N (16#e0ba3b57f978d073#),
         N (16#08def6f29fde7ea9#), N (16#27e610db52819093#), N (16#7a49ce664eba82d6#), N (16#06a123b78fe958c9#),
         N (16#f9da05acf8e1ac6b#), N (16#5dbb990a59c14f32#), N (16#81a1516e381ad030#), N (16#94a0f83a55671922#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#363705d530942cee#), N (16#5437b2d1c82e3f9e#), N (16#4d7d212e205897fb#), N (16#1054c868ee54242a#),
         N (16#11fa648d61e51532#), N (16#6e84e935d1501fa2#), N (16#9bd183c72634af64#), N (16#c00811f08c54f089#),
         N (16#d974b54634244cbe#), N (16#f4e3ec1ecf613c4d#), N (16#00e7f5964f309cde#), N (16#79eec10ffe95ddcb#),
         N (16#e674cb032d076161#), N (16#1bdd8d74f1d15380#), N (16#2b4c1a6bb54cf881#), N (16#1229c73ab0f8ff3d#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#20f2d3ceab7612f3#), N (16#0775082bf3789777#), N (16#ad9c987e3bde871d#), N (16#933cae9355261d4c#),
         N (16#30f51fa7fde7c0b8#), N (16#fa8339acfb41a410#), N (16#e91b3ae4c9f79673#), N (16#f662297f88006fb3#),
         N (16#8dec35294af146fa#), N (16#3eee676346eb829a#), N (16#4a87448f9bb9055b#), N (16#67905373649fe386#),
         N (16#aabb9100a44c9da5#), N (16#ee42636675d58d7a#), N (16#9d568b65b76de7e4#), N (16#8b2c622cbfce55fb#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#a33f71994974e81c#), N (16#b08d987b2e0dffd5#), N (16#a2effbe4a4b9ff87#), N (16#e65e6b3be44bbada#),
         N (16#dfacfe9e697aaf93#), N (16#12ebc6e5e00db862#), N (16#16831a85e41bbce0#), N (16#4f15d06d60007d84#),
         N (16#c4cab768ae890ef9#), N (16#0c4f25ec47f99c49#), N (16#50b4ab73f086e65e#), N (16#46f20022fd99fc66#),
         N (16#45c922af1a0ecf47#), N (16#cf1feb451e43cab0#), N (16#1f31a235d4c7ec89#), N (16#580538b645dd6d5b#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#046308d4f812f66d#), N (16#73eb9b6611570e2c#), N (16#0fadd394f4921f5e#), N (16#9468553cabfe6154#),
         N (16#e962e1b4fe9dc931#), N (16#6908fae29f3d749f#), N (16#26452b105084ef42#), N (16#4b0d8027feb7f5d3#),
         N (16#f56a39e873f7dfa4#), N (16#afe5a389c3739e78#), N (16#8293199341348a57#), N (16#00355cc900000000#),
         others => 0)
      );

      --  Compare with hexdump of hash.dat
      Assert
        (LSC.Internal.HMAC_SHA512.Authenticate (Key, Message, 12_000) =
         LSC.Internal.HMAC_SHA512.Auth_Type'(
            N (16#24b3907ac82497a4#), N (16#d7e0db7c317b93a7#), N (16#f2c35ce153913d86#), N (16#608068d30ce4ef0a#)),
         "Invalid HMAC");
   end Test_SHA512_Multi_1;

   ---------------------------------------------------------------------------

   --  Multiple message blocks, block aligned. This test was generated using
   --  dd, the genhmac command line tool (based on OpenSSL) and xxd:
   --
   --  $ dd if=/dev/urandom bs=1 count=128 of=HMAC_SHA512-KEY-2.dat
   --  $ dd if=/dev/urandom bs=1 count=640 of=HMAC_SHA512-MESSAGE-2.dat
   --  $ ./out/genhmac \
   --       HMAC_SHA512-KEY-2.dat \
   --       HMAC_SHA512-MESSAGE-2.dat \
   --       HMAC_SHA512-HASH-2.dat
   --  $ xxd -c32 -g8 HMAC_SHA512-KEY-2.dat
   --  $ xxd -c32 -g8 HMAC_SHA512-MESSAGE-2.dat
   --  $ xxd -c32 -g8 HMAC_SHA512-HASH-2.dat

   procedure Test_SHA512_Multi_2 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA512.Message_Index range 1 .. 7;
      subtype Message_Type is LSC.Internal.SHA512.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA512.Block_Type;
      Message : Message_Type;
   begin
      --  Hexdump of HMAC_SHA512-KEY-2.dat
      Key   := LSC.Internal.SHA512.Block_Type'(
         N (16#e3a86aea63f58fac#), N (16#a858ef8a994605e4#), N (16#e8da8502cf68ca6b#), N (16#dba3651502c3fd38#),
         N (16#9f360e30f13b4658#), N (16#522d6584e290197e#), N (16#8938f191c9bf6467#), N (16#7220a5df9da19d85#),
         N (16#fbfe98bbe1acb251#), N (16#2f0bb1957c8e5cc9#), N (16#872a2687d13ef45f#), N (16#3346616d0cf7eed0#),
         N (16#bdf8c89926a895aa#), N (16#591415eb888342f5#), N (16#10547d8796a606e5#), N (16#543edfda43c9b8f7#)
      );

      --  Hexdump of HMAC_SHA512-MESSAGE-2.dat
      Message := Message_Type'(
      LSC.Internal.SHA512.Block_Type'(
         N (16#18da28d1fd3f10b6#), N (16#547fd81ae9e64dc0#), N (16#1cd015147e8d92e9#), N (16#9ceec40b8279c4df#),
         N (16#69964480f23e6630#), N (16#b735e934879e7264#), N (16#a16f36b520565543#), N (16#0f965fbf99ea62ce#),
         N (16#c3bf473481537028#), N (16#6d8a3014dc3bf8dc#), N (16#1c4484168ec39393#), N (16#7f89f6f1c0107484#),
         N (16#cd1d23d75d1f8b8e#), N (16#4622dc6c8ada84b9#), N (16#267b341999f75146#), N (16#896721a3d977d6bc#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#eb91ced1c0574314#), N (16#ea03bb202fb7064d#), N (16#75108edcc8b4790f#), N (16#59a5ecf6c9524198#),
         N (16#e5b47305fce4e4aa#), N (16#f91f8315bffdaa45#), N (16#463287010beea839#), N (16#203056994db783e6#),
         N (16#9ad1bc202f4a7b77#), N (16#f7f33e3a9af3d096#), N (16#5718eca50e70198a#), N (16#493b35dfd0b7d04f#),
         N (16#a50195ab13130324#), N (16#ee875c16be090345#), N (16#d5e43684fcd678b7#), N (16#77401f45d85b63c3#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#c02b855d3bd13445#), N (16#14740c3cdf873d2d#), N (16#f811a72883b6a0a3#), N (16#58771622c1cc5c07#),
         N (16#223f0ccfec5f90a8#), N (16#50d1d552a7d8f178#), N (16#88024175e377e21e#), N (16#c78eaf843f81baab#),
         N (16#c62d5a390b760849#), N (16#62aa63307c0959e6#), N (16#abc001d49773a782#), N (16#4147840acb1bd02e#),
         N (16#784b5aa724d9b218#), N (16#cf5d53115f4acd2c#), N (16#88a42a14af3b2f77#), N (16#43b9f144e044f6f4#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#5e79ce696409e5f1#), N (16#9d61a5af2412ae08#), N (16#3ef6d62fd3af2fbb#), N (16#e8328d99517e6aaf#),
         N (16#5fba0969fa2cd91e#), N (16#c9f58450f3fa2378#), N (16#cf5bafc2ae702d23#), N (16#9028b457ff93bef3#),
         N (16#0985b6f4f0387ff7#), N (16#c04bf5d9a67d9216#), N (16#2d8c32f5805f5125#), N (16#c5db4a90600b7a20#),
         N (16#ac51ec5414fd9394#), N (16#07d05d456ea3d04b#), N (16#de50ee63274ad6d6#), N (16#74d24549bb0b95a5#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#7c11d824625f1080#), N (16#b46895271e8547f1#), N (16#440df9c275bc4578#), N (16#979905e940683d18#),
         N (16#87d089c49b91fdfc#), N (16#a31cffc297d3e156#), N (16#d06360c9695a2914#), N (16#aa10cfe1c90ff89e#),
         N (16#9a75f63eed5fdca7#), N (16#a11bee9a01246a17#), N (16#76aba38f962a1cf7#), N (16#e1df2e5834d8b4c5#),
         N (16#23dcdae23ce5de10#), N (16#a23ea0978a51ea7b#), N (16#76df2b1631741fe4#), N (16#510dc8cc08dcabf2#)),
      others => LSC.Internal.SHA512.Block_Type'(others => 0)
      );

      --  Compare with hexdump of HMAC_SHA512-HASH-2.dat
      Assert
        (LSC.Internal.HMAC_SHA512.Authenticate (Key, Message, 5120) =
         LSC.Internal.HMAC_SHA512.Auth_Type'(
            N (16#412015d264458463#), N (16#0c23f0685dce9e06#), N (16#d790cd4af47e70b7#), N (16#4809daea24ebdcd4#)),
         "Invalid HMAC");
   end Test_SHA512_Multi_2;

   ---------------------------------------------------------------------------

   procedure Test_SHA512_Multi_3 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA512.Message_Index range 1 .. 11;
      subtype Message_Type is LSC.Internal.SHA512.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA512.Block_Type;
      Message : Message_Type;
   begin
      Key := LSC.Internal.SHA512.Block_Type'(
         N (16#f1bcc392d8719db7#), N (16#e2e3203e0ebd53b2#), N (16#147de675accd7087#), N (16#1950385efcda6037#),
         N (16#d3f6a21d97768626#), N (16#7274ff83def9538a#), N (16#9ccc7d7bfa48f464#), N (16#ec2d522d05e62c8b#),
         N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#),
         N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#)
      );

      Message := Message_Type'(
      LSC.Internal.SHA512.Block_Type'(
         N (16#f92a476300000005#), N (16#4242424242424242#), N (16#4242424242424242#), N (16#5ff43fd476a405d4#),
         N (16#d4938bbfaa6b5910#), N (16#232828fe4048276a#), N (16#0f92b99bac0a36e9#), N (16#5e410224a875a63a#),
         N (16#e032760b769970e0#), N (16#334776bf31223842#), N (16#c70c5e58a3ad72ad#), N (16#a007112a8378e6c9#),
         N (16#64964368933b7cca#), N (16#32080e54cd38e9fd#), N (16#4f863df05078ea29#), others => 0),
      others => LSC.Internal.SHA512.Block_Type'(others => 0)
      );

      Assert
        (LSC.Internal.HMAC_SHA512.Authenticate (Key, Message, 16#3c0#) =
         LSC.Internal.HMAC_SHA512.Auth_Type'(
            N (16#dc3081d890ce1209#), N (16#ca7c0618f35c7da8#), N (16#6ca43d462ce7a92e#), N (16#157e2b8865381a6f#)),
         "Invalid HMAC");
   end Test_SHA512_Multi_3;

   ---------------------------------------------------------------------------

   procedure Test_SHA512_Multi_4 (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is LSC.Internal.SHA512.Message_Index range 1 .. 11;
      subtype Message_Type is LSC.Internal.SHA512.Message_Type (Message_Index);
      Key     : LSC.Internal.SHA512.Block_Type;
      Message : Message_Type;
   begin
      Key := LSC.Internal.SHA512.Block_Type'(
        N (16#f1bcc392d8719db7#), N (16#e2e3203e0ebd53b2#), N (16#147de675accd7087#), N (16#1950385efcda6037#),
        N (16#d3f6a21d97768626#), N (16#7274ff83def9538a#), N (16#9ccc7d7bfa48f464#), N (16#ec2d522d05e62c8b#),
        N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#),
        N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#)
      );

      Message := Message_Type'(
      LSC.Internal.SHA512.Block_Type'(
         N (16#f92a476300000005#), N (16#4242424242424242#), N (16#4242424242424242#), N (16#5ff43fd476a405d4#),
         N (16#d4938bbfaa6b5910#), N (16#232828fe4048276a#), N (16#0f92b99bac0a36e9#), N (16#5e410224a875a63a#),
         N (16#e032760b769970e0#), N (16#334776bf31223842#), N (16#c70c5e58a3ad72ad#), N (16#a007112a8378e6c9#),
         N (16#64964368933b7cca#), N (16#32080e54cd38e9fd#), N (16#4f863df05078ea29#), N (16#dc3081d890ce1209#)),
      LSC.Internal.SHA512.Block_Type'(
         N (16#ca7c0618f35c7da8#), N (16#6ca43d462ce7a92e#), N (16#157e2b8865381a6f#), others => 0),
      others => LSC.Internal.SHA512.Block_Type'(others => 0)
      );

      --  Note that we hash only part of the message (leaving out the last 4 64-bit values).
      --  This should result in the same authentication value as MULTI-3!
      Assert
        (LSC.Internal.HMAC_SHA512.Authenticate (Key, Message, 16#3c0#) =
         LSC.Internal.HMAC_SHA512.Auth_Type'(
            N (16#dc3081d890ce1209#), N (16#ca7c0618f35c7da8#), N (16#6ca43d462ce7a92e#), N (16#157e2b8865381a6f#)),
            "Invalid HMAC");
   end Test_SHA512_Multi_4;

   ---------------------------------------------------------------------------

   procedure Register_Tests (T : in out Test_Case) is
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
      Register_Routine (T, Test_SHA256_Prf_1'Access, "SHA256 (PRF-1)");
      Register_Routine (T, Test_SHA256_Prf_2'Access, "SHA256 (PRF-2)");
      Register_Routine (T, Test_SHA256_Prf_3'Access, "SHA256 (PRF-3)");
      Register_Routine (T, Test_SHA256_Prf_4'Access, "SHA256 (PRF-4)");
      Register_Routine (T, Test_SHA256_Auth_1'Access, "SHA256 (AUTH-1)");
      Register_Routine (T, Test_SHA256_Auth_2'Access, "SHA256 (AUTH-2)");
      Register_Routine (T, Test_SHA256_Auth_3'Access, "SHA256 (AUTH-3)");
      Register_Routine (T, Test_SHA256_Auth_4'Access, "SHA256 (AUTH-4)");
      Register_Routine (T, Test_SHA256_Multi_1'Access, "SHA256 (MULTI-1)");
      Register_Routine (T, Test_SHA256_Multi_2'Access, "SHA256 (MULTI-2)");
      Register_Routine (T, Test_SHA384_Prf_1'Access, "SHA384 (PRF-1)");
      Register_Routine (T, Test_SHA384_Prf_2'Access, "SHA384 (PRF-2)");
      Register_Routine (T, Test_SHA384_Prf_3'Access, "SHA384 (PRF-3)");
      Register_Routine (T, Test_SHA384_Prf_4'Access, "SHA384 (PRF-4)");
      Register_Routine (T, Test_SHA384_Auth_1'Access, "SHA384 (AUTH-1)");
      Register_Routine (T, Test_SHA384_Auth_2'Access, "SHA384 (AUTH-2)");
      Register_Routine (T, Test_SHA384_Auth_3'Access, "SHA384 (AUTH-3)");
      Register_Routine (T, Test_SHA384_Auth_4'Access, "SHA384 (AUTH-4)");
      Register_Routine (T, Test_SHA384_Multi_1'Access, "SHA384 (MULTI-1)");
      Register_Routine (T, Test_SHA384_Multi_2'Access, "SHA384 (MULTI-2)");
      Register_Routine (T, Test_SHA512_Prf_1'Access, "SHA512 (PRF-1)");
      Register_Routine (T, Test_SHA512_Prf_2'Access, "SHA512 (PRF-2)");
      Register_Routine (T, Test_SHA512_Prf_3'Access, "SHA512 (PRF-3)");
      Register_Routine (T, Test_SHA512_Prf_4'Access, "SHA512 (PRF-4)");
      Register_Routine (T, Test_SHA512_Auth_1'Access, "SHA512 (AUTH-1)");
      Register_Routine (T, Test_SHA512_Auth_2'Access, "SHA512 (AUTH-2)");
      Register_Routine (T, Test_SHA512_Auth_3'Access, "SHA512 (AUTH-3)");
      Register_Routine (T, Test_SHA512_Auth_4'Access, "SHA512 (AUTH-4)");
      Register_Routine (T, Test_SHA512_Multi_1'Access, "SHA512 (MULTI-1)");
      Register_Routine (T, Test_SHA512_Multi_2'Access, "SHA512 (MULTI-2)");
      Register_Routine (T, Test_SHA512_Multi_3'Access, "SHA512 (MULTI-3)");
      Register_Routine (T, Test_SHA512_Multi_4'Access, "SHA512 (MULTI-4)");
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("HMAC");
   end Name;

end LSC_Internal_Test_HMAC;
