-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2011, Adrian-Ken Rueegsegger
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

separate (Main)
procedure HMAC_SHA1_Tests is

   Key             : LSC.SHA1.Block_Type;
   HMAC_SHA1_Suite : SPARKUnit.Index_Type;

   subtype Message1_Index is LSC.Types.Word64 range 1 .. 1;
   subtype Message1_Type is LSC.SHA1.Message_Type (Message1_Index);

   Message1 : Message1_Type;

begin

   SPARKUnit.Create_Suite (Harness, "HMAC-SHA1 tests", HMAC_SHA1_Suite);

   --  SHA1 Test Vectors (RFC 2202, 3.)

   -----------------------
   --  Test Case AUTH-1 --
   -----------------------

   Key := LSC.SHA1.Block_Type'
     (M (16#0b0b0b0b#), M (16#0b0b0b0b#), M (16#0b0b0b0b#), M (16#0b0b0b0b#),
      M (16#0b0b0b0b#), others => 0);

   -- "Hi There"
   Message1 := Message1_Type'
     (1 => LSC.SHA1.Block_Type'
        (M (16#48692054#), M (16#68657265#), others => 0));

   SPARKUnit.Create_Test
     (Harness,
      HMAC_SHA1_Suite,
      "HMAC-SHA1-1",
      LSC.HMAC_SHA1.Authenticate (Key, Message1, 64) =
        LSC.SHA1.Hash_Type'
          (M (16#b6173186#), M (16#55057264#), M (16#e28bc0b6#),
           M (16#fb378c8e#), M (16#f146be00#), others => 0));

   -----------------------
   --  Test Case AUTH-2 --
   -----------------------

   --  "Jefe"
   Key := LSC.SHA1.Block_Type'(M (16#4a656665#), others => 0);

   --  "what do ya want for nothing?"
   Message1 := Message1_Type'
     (1 => LSC.SHA1.Block_Type'
        (M (16#77686174#), M (16#20646f20#), M (16#79612077#), M (16#616e7420#),
         M (16#666f7220#), M (16#6e6f7468#), M (16#696e673f#), others => 0));

   SPARKUnit.Create_Test
     (Harness,
      HMAC_SHA1_Suite,
      "HMAC-SHA1-2",
      LSC.HMAC_SHA1.Authenticate (Key, Message1, 224) =
        LSC.SHA1.Hash_Type'
          (M (16#effcdf6a#), M (16#e5eb2fa2#), M (16#d27416d5#),
           M (16#f184df9c#), M (16#259a7c79#)));

   -----------------------
   --  Test Case AUTH-3 --
   -----------------------

   --  20 times 16#aa#
   Key := LSC.SHA1.Block_Type'
     (M (16#aaaaaaaa#), M (16#aaaaaaaa#), M (16#aaaaaaaa#), M (16#aaaaaaaa#),
      M (16#aaaaaaaa#), others => 0);

   --  50 times 16#dd#
   Message1 := Message1_Type'
     (1 => LSC.SHA1.Block_Type'
        (M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
         M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
         M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#), M (16#dddddddd#),
         M (16#dddd0000#), others => 0));

   SPARKUnit.Create_Test
     (Harness,
      HMAC_SHA1_Suite,
      "HMAC-SHA1-3",
      LSC.HMAC_SHA1.Authenticate (Key, Message1, 400) =
        LSC.SHA1.Hash_Type'
          (M (16#125d7342#), M (16#b9ac11cd#), M (16#91a39af4#),
           M (16#8aa17b4f#), M (16#63f175d3#)));

   -----------------------
   --  Test Case AUTH-4 --
   -----------------------

   --  0x0102030405060708090a0b0c0d0e0f10111213141516171819
   Key := LSC.SHA1.Block_Type'
     (M (16#01020304#), M (16#05060708#), M (16#090a0b0c#), M (16#0d0e0f10#),
      M (16#11121314#), M (16#15161718#), M (16#19000000#), others => 0);

   --  50 times 16#cd#
   Message1 := Message1_Type'
     (1 => LSC.SHA1.Block_Type'
        (M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
         M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
         M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#), M (16#cdcdcdcd#),
         M (16#cdcd0000#), others => 0));

   SPARKUnit.Create_Test
     (Harness,
      HMAC_SHA1_Suite,
      "HMAC-SHA1-4",
      LSC.HMAC_SHA1.Authenticate (Key, Message1, 400) =
        LSC.SHA1.Hash_Type'
          (M (16#4c9007f4#), M (16#026250c6#), M (16#bc8414f9#),
           M (16#bf50c86c#), M (16#2d7235da#)));

   -----------------------
   --  Test Case AUTH-5 --
   -----------------------

   --  0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
   Key := LSC.SHA1.Block_Type'
     (M (16#0c0c0c0c#), M (16#0c0c0c0c#), M (16#0c0c0c0c#), M (16#0c0c0c0c#),
      M (16#0c0c0c0c#), others => 0);

   --  "Test With Truncation"
   Message1 := Message1_Type'
     (1 => LSC.SHA1.Block_Type'
        (M (16#54657374#), M (16#20576974#), M (16#68205472#), M (16#756e6361#),
         M (16#74696f6e#), others => 0));

   SPARKUnit.Create_Test
     (Harness,
      HMAC_SHA1_Suite,
      "HMAC-SHA1-5",
      LSC.HMAC_SHA1.Authenticate (Key, Message1, 160) =
        LSC.SHA1.Hash_Type'
          (M (16#4c1a0342#), M (16#4b55e07f#), M (16#e7f27be1#),
           M (16#d58bb932#), M (16#4a9a5a04#)));

end HMAC_SHA1_Tests;

