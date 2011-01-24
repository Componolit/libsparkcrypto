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

   subtype Message4_Index is LSC.Types.Word64 range 1 .. 4;
   subtype Message4_Type is LSC.SHA1.Message_Type (Message4_Index);

   subtype Message5_Index is LSC.Types.Word64 range 1 .. 5;
   subtype Message5_Type is LSC.SHA1.Message_Type (Message5_Index);

   Message1 : Message1_Type;
   Message4 : Message4_Type;
   Message5 : Message5_Type;

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

   ------------------------
   --  Test Case MULTI-1 --
   ------------------------

   -- hmac_sha1-key-1.dat
   Key := LSC.sha1.Block_Type'
     (M (16#07a55659#), M (16#e5e382f2#), M (16#a12610e0#), M (16#8926b665#),
      M (16#43122a4e#), M (16#c2dc3c09#), M (16#8261de1f#), M (16#3f2ae412#),
      M (16#7e19048e#), M (16#7cee69bc#), M (16#43f8283e#), M (16#86b48781#),
      M (16#ca18e81c#), M (16#422f70e3#), M (16#52062553#), M (16#ff11c406#));

   -- hmac_sha1-message-1.dat
   Message4 := Message4_Type'
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
   SPARKUnit.Create_Test
     (Harness,
      HMAC_SHA1_Suite,
      "HMAC-SHA1-MULTI-1",
      LSC.HMAC_SHA1.Authenticate (Key, Message4, 2048) =
        LSC.SHA1.Hash_Type'(M (16#ec3b225b#), M (16#f28c53dc#),
          M (16#e8bd8722#), M (16#f325d5b1#), M (16#691114c7#)));

   ------------------------
   --  Test Case MULTI-2 --
   ------------------------

   -- hmac_sha1-key-2.dat
   Key := LSC.SHA1.Block_Type'
     (M (16#f05821b9#), M (16#94ab6613#), M (16#f7c5773f#), M (16#b2a2184f#),
      M (16#9659daf3#), M (16#856a4a69#), M (16#245ba5f9#), M (16#7431d93f#),
      M (16#697a494d#), M (16#8da7131b#), M (16#1a995683#), M (16#4b4592d0#),
      M (16#c10b076b#), M (16#989278bc#), M (16#91fe184c#), M (16#84046614#));

   -- hmac_sha1-message-2.dat
   Message5 := Message5_Type'
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
   SPARKUnit.Create_Test
     (Harness,
      HMAC_SHA1_Suite,
      "HMAC-SHA1-MULTI-2",
      LSC.HMAC_SHA1.Authenticate (Key, Message5, 2048 + 448) =
        LSC.SHA1.Hash_Type'(M (16#f87e3f76#), M (16#92b5f83c#),
          M (16#8f2f20bf#), M (16#8027d87e#), M (16#8b4cf783#)));

end HMAC_SHA1_Tests;

