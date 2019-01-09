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

separate (Main)
procedure HMAC_SHA512_Tests is

   HMAC_SHA512_Suite : SPARKUnit.Index_Type;

   subtype Message1_Index is LSC.SHA512.Message_Index range 1 .. 1;
   subtype Message1_Type  is LSC.SHA512.Message_Type (Message1_Index);

   subtype Message7_Index is LSC.SHA512.Message_Index range 1 .. 7;
   subtype Message7_Type  is LSC.SHA512.Message_Type (Message7_Index);

   subtype Message11_Index is LSC.SHA512.Message_Index range 1 .. 11;
   subtype Message11_Type  is LSC.SHA512.Message_Type (Message11_Index);

   subtype Message12_Index is LSC.SHA512.Message_Index range 1 .. 12;
   subtype Message12_Type  is LSC.SHA512.Message_Type (Message12_Index);

   ----------------------
   --  Test Case PRF-1 --
   ----------------------

   procedure PRF1
   --# global Harness, HMAC_SHA512_Suite;
   --# derives Harness from Harness, HMAC_SHA512_Suite;
   is
      HMAC_Ctx          : LSC.HMAC_SHA512.Context_Type;
      Key               : LSC.SHA512.Block_Type;
      Block             : LSC.SHA512.Block_Type;
      PRF_HMAC_SHA_512  : LSC.SHA512.SHA512_Hash_Type;
   begin
      Key   := LSC.SHA512.Block_Type'
        (N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#),
         N (16#0b0b0b0b00000000#), others => 0);

      -- "Hi There"
      Block := LSC.SHA512.Block_Type'
        (N (16#4869205468657265#), others => 0);

      HMAC_Ctx := LSC.HMAC_SHA512.Context_Init (Key);
      LSC.HMAC_SHA512.Context_Finalize (HMAC_Ctx, Block, 64);
      PRF_HMAC_SHA_512 := LSC.HMAC_SHA512.Get_Prf (HMAC_Ctx);

      SPARKUnit.Create_Test
        (Harness,
         HMAC_SHA512_Suite,
         "HMAC-SHA512-PRF-1",
         PRF_HMAC_SHA_512 =
         LSC.SHA512.SHA512_Hash_Type'
           (N (16#87aa7cdea5ef619d#), N (16#4ff0b4241a1d6cb0#), N (16#2379f4e2ce4ec278#),
            N (16#7ad0b30545e17cde#), N (16#daa833b7d6b8a702#), N (16#038b274eaea3f4e4#),
            N (16#be9d914eeb61f170#), N (16#2e696c203a126854#)));
   end PRF1;

   ----------------------
   --  Test Case PRF-2 --
   ----------------------

   procedure PRF2
   --# global Harness, HMAC_SHA512_Suite;
   --# derives Harness from Harness, HMAC_SHA512_Suite;
   is
      HMAC_Ctx          : LSC.HMAC_SHA512.Context_Type;
      Key               : LSC.SHA512.Block_Type;
      Block             : LSC.SHA512.Block_Type;
      PRF_HMAC_SHA_512  : LSC.SHA512.SHA512_Hash_Type;
   begin
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

      SPARKUnit.Create_Test
        (Harness,
         HMAC_SHA512_Suite,
         "HMAC-SHA512-PRF-2",
         PRF_HMAC_SHA_512 =
         LSC.SHA512.SHA512_Hash_Type'
           (N (16#164b7a7bfcf819e2#), N (16#e395fbe73b56e0a3#), N (16#87bd64222e831fd6#),
            N (16#10270cd7ea250554#), N (16#9758bf75c05a994a#), N (16#6d034f65f8f0e6fd#),
            N (16#caeab1a34d4a6b4b#), N (16#636e070a38bce737#)));
   end PRF2;

   ----------------------
   --  Test Case PRF-3 --
   ----------------------

   procedure PRF3
   --# global Harness, HMAC_SHA512_Suite;
   --# derives Harness from Harness, HMAC_SHA512_Suite;
   is
      HMAC_Ctx          : LSC.HMAC_SHA512.Context_Type;
      Key               : LSC.SHA512.Block_Type;
      Block             : LSC.SHA512.Block_Type;
      PRF_HMAC_SHA_512  : LSC.SHA512.SHA512_Hash_Type;
   begin
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

      SPARKUnit.Create_Test
        (Harness,
         HMAC_SHA512_Suite,
         "HMAC-SHA512-PRF-3",
         PRF_HMAC_SHA_512 =
         LSC.SHA512.SHA512_Hash_Type'
           (N (16#fa73b0089d56a284#), N (16#efb0f0756c890be9#), N (16#b1b5dbdd8ee81a36#),
            N (16#55f83e33b2279d39#), N (16#bf3e848279a722c8#), N (16#06b485a47e67c807#),
            N (16#b946a337bee89426#), N (16#74278859e13292fb#)));
   end PRF3;

   ----------------------
   --  Test Case PRF-4 --
   ----------------------

   procedure PRF4
   --# global Harness, HMAC_SHA512_Suite;
   --# derives Harness from Harness, HMAC_SHA512_Suite;
   is
      HMAC_Ctx          : LSC.HMAC_SHA512.Context_Type;
      Key               : LSC.SHA512.Block_Type;
      Block             : LSC.SHA512.Block_Type;
      PRF_HMAC_SHA_512  : LSC.SHA512.SHA512_Hash_Type;
   begin
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

      SPARKUnit.Create_Test
        (Harness,
         HMAC_SHA512_Suite,
         "HMAC-SHA512-PRF-4",
         PRF_HMAC_SHA_512 =
         LSC.SHA512.SHA512_Hash_Type'
           (N (16#b0ba465637458c69#), N (16#90e5a8c5f61d4af7#), N (16#e576d97ff94b872d#),
            N (16#e76f8050361ee3db#), N (16#a91ca5c11aa25eb4#), N (16#d679275cc5788063#),
            N (16#a5f19741120c4f2d#), N (16#e2adebeb10a298dd#)));
   end PRF4;

   -----------------------
   --  Test Case AUTH-1 --
   -----------------------

   procedure AUTH1
   --# global Harness, HMAC_SHA512_Suite;
   --# derives Harness from Harness, HMAC_SHA512_Suite;
   is
      Key       : LSC.SHA512.Block_Type;
      Message1  : Message1_Type;
   begin
      --  64 bytes
      Key   := LSC.SHA512.Block_Type'
        (N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#),
         N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#),
         N (16#0b0b0b0b0b0b0b0b#), N (16#0b0b0b0b0b0b0b0b#), others => 0);

      -- "Hi There"
      Message1 := Message1_Type'(1 => LSC.SHA512.Block_Type'(N (16#4869205468657265#), others => 0));

      SPARKUnit.Create_Test
        (Harness,
         HMAC_SHA512_Suite,
         "HMAC-SHA512-AUTH-1",
         LSC.HMAC_SHA512.Authenticate (Key, Message1, 64) =
         LSC.HMAC_SHA512.Auth_Type'
           (N (16#637edc6e01dce7e6#), N (16#742a99451aae82df#), N (16#23da3e92439e590e#),
            N (16#43e761b33e910fb8#)));
   end AUTH1;

   -----------------------
   --  Test Case AUTH-2 --
   -----------------------

   procedure AUTH2
   --# global Harness, HMAC_SHA512_Suite;
   --# derives Harness from Harness, HMAC_SHA512_Suite;
   is
      Key       : LSC.SHA512.Block_Type;
      Message1  : Message1_Type;
   begin
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

      SPARKUnit.Create_Test
        (Harness,
         HMAC_SHA512_Suite,
         "HMAC-SHA512-AUTH-2",
         LSC.HMAC_SHA512.Authenticate (Key, Message1, 224) =
         LSC.HMAC_SHA512.Auth_Type'
           (N (16#cb370917ae8a7ce2#), N (16#8cfd1d8f4705d614#), N (16#1c173b2a9362c15d#),
            N (16#f235dfb251b15454#)));
   end AUTH2;

   -----------------------
   --  Test Case AUTH-3 --
   -----------------------

   procedure AUTH3
   --# global Harness, HMAC_SHA512_Suite;
   --# derives Harness from Harness, HMAC_SHA512_Suite;
   is
      Key       : LSC.SHA512.Block_Type;
      Message1  : Message1_Type;
   begin
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

      SPARKUnit.Create_Test
        (Harness,
         HMAC_SHA512_Suite,
         "HMAC-SHA512-AUTH-3",
         LSC.HMAC_SHA512.Authenticate (Key, Message1, 400) =
         LSC.HMAC_SHA512.Auth_Type'
           (N (16#2ee7acd783624ca9#), N (16#398710f3ee05ae41#), N (16#b9f9b0510c87e49e#),
            N (16#586cc9bf961733d8#)));
   end AUTH3;

   -----------------------
   --  Test Case AUTH-4 --
   -----------------------

   procedure AUTH4
   --# global Harness, HMAC_SHA512_Suite;
   --# derives Harness from Harness, HMAC_SHA512_Suite;
   is
      Key       : LSC.SHA512.Block_Type;
      Message1  : Message1_Type;
   begin
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

      SPARKUnit.Create_Test
        (Harness,
         HMAC_SHA512_Suite,
         "HMAC-SHA512-AUTH-4",
         LSC.HMAC_SHA512.Authenticate (Key, Message1, 400) =
         LSC.HMAC_SHA512.Auth_Type'
           (N (16#5e6688e5a3daec82#), N (16#6ca32eaea224eff5#), N (16#e700628947470e13#),
            N (16#ad01302561bab108#)));
   end AUTH4;

   ------------------------
   --  Test Case MULTI-1 --
   ------------------------

   --  Multiple message blocks, not block aligned. This test was generated using
   --  dd, the genhmac command line tool (based on OpenSSL) and xxd:
   --
   --  $ dd if=/dev/urandom bs=1 count=64 of=HMAC_SHA512-KEY-1.dat
   --  $ dd if=/dev/urandom bs=1 count=1500 of=HMAC_SHA512-MESSAGE-1.dat
   --  $ ./out/genhmac \
   --       HMAC_SHA512-KEY-1.dat \
   --       HMAC_SHA512-MESSAGE-1.dat \
   --       HMAC_SHA512-HASH-1.dat
   --  $ xxd -c32 -g8 HMAC_SHA512-KEY-1.dat
   --  $ xxd -c32 -g8 HMAC_SHA512-MESSAGE-1.dat
   --  $ xxd -c32 -g8 HMAC_SHA512-HASH-1.dat

   procedure MULTI1
   --# global Harness, HMAC_SHA512_Suite;
   --# derives Harness from Harness, HMAC_SHA512_Suite;
   is
      Key       : LSC.SHA512.Block_Type;
      Message12 : Message12_Type;
   begin
      --  Hexdump of key.dat
      Key   := LSC.SHA512.Block_Type'(
         N (16#2577888a5d567bf2#), N (16#01507064342a1670#), N (16#287ff1ea2ecabf96#), N (16#1542002cac690b68#),
         N (16#b647126442106e6f#), N (16#13eeffc56b4c8145#), N (16#6018bccffc00013d#), N (16#6d793f222e51d1a1#),
         others => 0
      );

      --  Hexdump of message.dat
      Message12 := Message12_Type'(
      LSC.SHA512.Block_Type'(
         N (16#ab52393074a225f3#), N (16#9e432a58f6e977b2#), N (16#300df239a618518b#), N (16#44658572f2172571#),
         N (16#ed255db96276107d#), N (16#51ffe2d224398e6c#), N (16#7a5f28ba944234ca#), N (16#5cda9e919906d5db#),
         N (16#1e68ffb46c4502ce#), N (16#681b244934461c0e#), N (16#1f6f46215a687437#), N (16#6af97fc972980ed2#),
         N (16#37da280ca151a62e#), N (16#76e1061d9e66853b#), N (16#4cc431b1914bb77b#), N (16#9b0e872f70f5a6da#)),
      LSC.SHA512.Block_Type'(
         N (16#280fff785f74b695#), N (16#8723a46af87be8de#), N (16#a58295d9096e1d4d#), N (16#6de4955f179584b9#),
         N (16#d12c2197019f99cd#), N (16#f67a9ab6bb73e3e0#), N (16#952a99e77f97e389#), N (16#4944a6186960d1e2#),
         N (16#3945955700b078d5#), N (16#21f5eaa1e8fa3791#), N (16#61c5365d9b171afa#), N (16#6959a0a4ac566c8b#),
         N (16#f1b255ac75303a77#), N (16#02166e025c1b39d2#), N (16#9d172035de6c4bc0#), N (16#6a6d97b1f459f4e9#)),
      LSC.SHA512.Block_Type'(
         N (16#ddfb8d14678d2a56#), N (16#f3bf4ac6f70c913c#), N (16#c420c90214aea24a#), N (16#6f4e5ed1353ef80c#),
         N (16#39d45af77f92333a#), N (16#ee5cd1ff4266203d#), N (16#beaacf3b2400d092#), N (16#92fe1686f94d9905#),
         N (16#ba54a4f4c4e15fe2#), N (16#f61822552b9636f9#), N (16#ade3a60d895c6f99#), N (16#cdafd8c314b80b52#),
         N (16#f3f60ee9bc532185#), N (16#9ac0b0af2cb2064c#), N (16#d4592461e4149a38#), N (16#87db711d6780b9a3#)),
      LSC.SHA512.Block_Type'(
         N (16#a89663fb54e7af26#), N (16#35281105c9c11702#), N (16#fd66c7a66bdfd487#), N (16#64feb3305d99f2d8#),
         N (16#84f9f8df9cbc3ac2#), N (16#e1a05a67eefa2715#), N (16#c5a0a400e7b08951#), N (16#c6881b94a8e2e19c#),
         N (16#73a1210f9d8fcae6#), N (16#eaee91d6c355c7c5#), N (16#0af0f7c9c2a9a8b7#), N (16#d2bbd2021e005870#),
         N (16#80906028c4a857ab#), N (16#bc0193203ca904ce#), N (16#780496b634da331a#), N (16#94cb8f7ef900ea35#)),
      LSC.SHA512.Block_Type'(
         N (16#4c6ea0b588ba5a3b#), N (16#f5308bcbdaf41f69#), N (16#7879c816da391ec7#), N (16#18183bccca912d13#),
         N (16#2eb014b30ef8fb31#), N (16#9b3fece27dc8087b#), N (16#b9d0d874b03ad882#), N (16#46c840958d259c8c#),
         N (16#f7b86c7eff93d87e#), N (16#07a439d6e87bf8be#), N (16#885bfb0070d0f7e7#), N (16#5c81dd103552275b#),
         N (16#1113bf54d87e7945#), N (16#2a84246d2d0edf99#), N (16#34d99bfe79fadd79#), N (16#d2a883c2d1e3a6b7#)),
      LSC.SHA512.Block_Type'(
         N (16#b6efeb711954eeaf#), N (16#5b257ae378d44add#), N (16#00337d3e3e4e3fc6#), N (16#096fa66cc9385a96#),
         N (16#684240906b088744#), N (16#3525643b8fbfb874#), N (16#93d035d083b14f75#), N (16#0de86e83870cb487#),
         N (16#09b07dd08a1144c6#), N (16#95dc3e748e66d261#), N (16#a5f13b1ec903b475#), N (16#ff8a9c98671eab2e#),
         N (16#ea97255a3299b203#), N (16#421b44e9053c081c#), N (16#506565a5adf13767#), N (16#1c9ae758c435518c#)),
      LSC.SHA512.Block_Type'(
         N (16#d5c3482a45658905#), N (16#dfae0e6e94cc646f#), N (16#11c36c6187f78bd0#), N (16#635c86d782b11e84#),
         N (16#9c1ae165732b92cb#), N (16#1b45a1d981d62057#), N (16#fcf247d8950ee240#), N (16#cf559512489df8a8#),
         N (16#5c840eedbc0f5d67#), N (16#0c5a63ec4b11553c#), N (16#bf289c06f83df6f7#), N (16#02f5e058d1dd9cdb#),
         N (16#696c3c041621d2ee#), N (16#6bc8dee7876c3e98#), N (16#3a77599403f3e08f#), N (16#21324fcb2d26cbd9#)),
      LSC.SHA512.Block_Type'(
         N (16#80aa24c723ea9063#), N (16#d9c0b48219dca5b9#), N (16#8201966dbd3820f9#), N (16#8ac84c52996019b5#),
         N (16#2ca4061e2eb8bea3#), N (16#8df523b70a99c5c7#), N (16#5f158e0d9abd58f3#), N (16#e0ba3b57f978d073#),
         N (16#08def6f29fde7ea9#), N (16#27e610db52819093#), N (16#7a49ce664eba82d6#), N (16#06a123b78fe958c9#),
         N (16#f9da05acf8e1ac6b#), N (16#5dbb990a59c14f32#), N (16#81a1516e381ad030#), N (16#94a0f83a55671922#)),
      LSC.SHA512.Block_Type'(
         N (16#363705d530942cee#), N (16#5437b2d1c82e3f9e#), N (16#4d7d212e205897fb#), N (16#1054c868ee54242a#),
         N (16#11fa648d61e51532#), N (16#6e84e935d1501fa2#), N (16#9bd183c72634af64#), N (16#c00811f08c54f089#),
         N (16#d974b54634244cbe#), N (16#f4e3ec1ecf613c4d#), N (16#00e7f5964f309cde#), N (16#79eec10ffe95ddcb#),
         N (16#e674cb032d076161#), N (16#1bdd8d74f1d15380#), N (16#2b4c1a6bb54cf881#), N (16#1229c73ab0f8ff3d#)),
      LSC.SHA512.Block_Type'(
         N (16#20f2d3ceab7612f3#), N (16#0775082bf3789777#), N (16#ad9c987e3bde871d#), N (16#933cae9355261d4c#),
         N (16#30f51fa7fde7c0b8#), N (16#fa8339acfb41a410#), N (16#e91b3ae4c9f79673#), N (16#f662297f88006fb3#),
         N (16#8dec35294af146fa#), N (16#3eee676346eb829a#), N (16#4a87448f9bb9055b#), N (16#67905373649fe386#),
         N (16#aabb9100a44c9da5#), N (16#ee42636675d58d7a#), N (16#9d568b65b76de7e4#), N (16#8b2c622cbfce55fb#)),
      LSC.SHA512.Block_Type'(
         N (16#a33f71994974e81c#), N (16#b08d987b2e0dffd5#), N (16#a2effbe4a4b9ff87#), N (16#e65e6b3be44bbada#),
         N (16#dfacfe9e697aaf93#), N (16#12ebc6e5e00db862#), N (16#16831a85e41bbce0#), N (16#4f15d06d60007d84#),
         N (16#c4cab768ae890ef9#), N (16#0c4f25ec47f99c49#), N (16#50b4ab73f086e65e#), N (16#46f20022fd99fc66#),
         N (16#45c922af1a0ecf47#), N (16#cf1feb451e43cab0#), N (16#1f31a235d4c7ec89#), N (16#580538b645dd6d5b#)),
      LSC.SHA512.Block_Type'(
         N (16#046308d4f812f66d#), N (16#73eb9b6611570e2c#), N (16#0fadd394f4921f5e#), N (16#9468553cabfe6154#),
         N (16#e962e1b4fe9dc931#), N (16#6908fae29f3d749f#), N (16#26452b105084ef42#), N (16#4b0d8027feb7f5d3#),
         N (16#f56a39e873f7dfa4#), N (16#afe5a389c3739e78#), N (16#8293199341348a57#), N (16#00355cc900000000#),
         others => 0)
      );

      --  Compare with hexdump of hash.dat
      SPARKUnit.Create_Test
        (Harness,
         HMAC_SHA512_Suite,
         "HMAC-SHA512-MULTI-1",
         LSC.HMAC_SHA512.Authenticate (Key, Message12, 12_000) =
         LSC.HMAC_SHA512.Auth_Type'(
            N (16#24b3907ac82497a4#), N (16#d7e0db7c317b93a7#), N (16#f2c35ce153913d86#), N (16#608068d30ce4ef0a#)));
   end MULTI1;

   ------------------------
   --  Test Case MULTI-2 --
   ------------------------

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

   procedure MULTI2
   --# global Harness, HMAC_SHA512_Suite;
   --# derives Harness from Harness, HMAC_SHA512_Suite;
   is
      Key       : LSC.SHA512.Block_Type;
      Message7  : Message7_Type;
   begin
      --  Hexdump of HMAC_SHA512-KEY-2.dat
      Key   := LSC.SHA512.Block_Type'(
         N (16#e3a86aea63f58fac#), N (16#a858ef8a994605e4#), N (16#e8da8502cf68ca6b#), N (16#dba3651502c3fd38#),
         N (16#9f360e30f13b4658#), N (16#522d6584e290197e#), N (16#8938f191c9bf6467#), N (16#7220a5df9da19d85#),
         N (16#fbfe98bbe1acb251#), N (16#2f0bb1957c8e5cc9#), N (16#872a2687d13ef45f#), N (16#3346616d0cf7eed0#),
         N (16#bdf8c89926a895aa#), N (16#591415eb888342f5#), N (16#10547d8796a606e5#), N (16#543edfda43c9b8f7#)
      );

      --  Hexdump of HMAC_SHA512-MESSAGE-2.dat
      Message7 := Message7_Type'(
      LSC.SHA512.Block_Type'(
         N (16#18da28d1fd3f10b6#), N (16#547fd81ae9e64dc0#), N (16#1cd015147e8d92e9#), N (16#9ceec40b8279c4df#),
         N (16#69964480f23e6630#), N (16#b735e934879e7264#), N (16#a16f36b520565543#), N (16#0f965fbf99ea62ce#),
         N (16#c3bf473481537028#), N (16#6d8a3014dc3bf8dc#), N (16#1c4484168ec39393#), N (16#7f89f6f1c0107484#),
         N (16#cd1d23d75d1f8b8e#), N (16#4622dc6c8ada84b9#), N (16#267b341999f75146#), N (16#896721a3d977d6bc#)),
      LSC.SHA512.Block_Type'(
         N (16#eb91ced1c0574314#), N (16#ea03bb202fb7064d#), N (16#75108edcc8b4790f#), N (16#59a5ecf6c9524198#),
         N (16#e5b47305fce4e4aa#), N (16#f91f8315bffdaa45#), N (16#463287010beea839#), N (16#203056994db783e6#),
         N (16#9ad1bc202f4a7b77#), N (16#f7f33e3a9af3d096#), N (16#5718eca50e70198a#), N (16#493b35dfd0b7d04f#),
         N (16#a50195ab13130324#), N (16#ee875c16be090345#), N (16#d5e43684fcd678b7#), N (16#77401f45d85b63c3#)),
      LSC.SHA512.Block_Type'(
         N (16#c02b855d3bd13445#), N (16#14740c3cdf873d2d#), N (16#f811a72883b6a0a3#), N (16#58771622c1cc5c07#),
         N (16#223f0ccfec5f90a8#), N (16#50d1d552a7d8f178#), N (16#88024175e377e21e#), N (16#c78eaf843f81baab#),
         N (16#c62d5a390b760849#), N (16#62aa63307c0959e6#), N (16#abc001d49773a782#), N (16#4147840acb1bd02e#),
         N (16#784b5aa724d9b218#), N (16#cf5d53115f4acd2c#), N (16#88a42a14af3b2f77#), N (16#43b9f144e044f6f4#)),
      LSC.SHA512.Block_Type'(
         N (16#5e79ce696409e5f1#), N (16#9d61a5af2412ae08#), N (16#3ef6d62fd3af2fbb#), N (16#e8328d99517e6aaf#),
         N (16#5fba0969fa2cd91e#), N (16#c9f58450f3fa2378#), N (16#cf5bafc2ae702d23#), N (16#9028b457ff93bef3#),
         N (16#0985b6f4f0387ff7#), N (16#c04bf5d9a67d9216#), N (16#2d8c32f5805f5125#), N (16#c5db4a90600b7a20#),
         N (16#ac51ec5414fd9394#), N (16#07d05d456ea3d04b#), N (16#de50ee63274ad6d6#), N (16#74d24549bb0b95a5#)),
      LSC.SHA512.Block_Type'(
         N (16#7c11d824625f1080#), N (16#b46895271e8547f1#), N (16#440df9c275bc4578#), N (16#979905e940683d18#),
         N (16#87d089c49b91fdfc#), N (16#a31cffc297d3e156#), N (16#d06360c9695a2914#), N (16#aa10cfe1c90ff89e#),
         N (16#9a75f63eed5fdca7#), N (16#a11bee9a01246a17#), N (16#76aba38f962a1cf7#), N (16#e1df2e5834d8b4c5#),
         N (16#23dcdae23ce5de10#), N (16#a23ea0978a51ea7b#), N (16#76df2b1631741fe4#), N (16#510dc8cc08dcabf2#)),
      others => LSC.SHA512.Block_Type'(others => 0)
      );

      --  Compare with hexdump of HMAC_SHA512-HASH-2.dat
      SPARKUnit.Create_Test
        (Harness,
         HMAC_SHA512_Suite,
         "HMAC-SHA512-MULTI-2",
         LSC.HMAC_SHA512.Authenticate (Key, Message7, 5120) =
         LSC.HMAC_SHA512.Auth_Type'(
            N (16#412015d264458463#), N (16#0c23f0685dce9e06#), N (16#d790cd4af47e70b7#), N (16#4809daea24ebdcd4#)));
   end MULTI2;

   ------------------------
   --  Test Case MULTI-3 --
   ------------------------

   procedure MULTI3
   --# global Harness, HMAC_SHA512_Suite;
   --# derives Harness from Harness, HMAC_SHA512_Suite;
   is
      Key       : LSC.SHA512.Block_Type;
      Message11 : Message11_Type;
   begin
      Key := LSC.SHA512.Block_Type'(
         N (16#f1bcc392d8719db7#), N (16#e2e3203e0ebd53b2#), N (16#147de675accd7087#), N (16#1950385efcda6037#),
         N (16#d3f6a21d97768626#), N (16#7274ff83def9538a#), N (16#9ccc7d7bfa48f464#), N (16#ec2d522d05e62c8b#),
         N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#),
         N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#)
      );

      Message11 := Message11_Type'(
      LSC.SHA512.Block_Type'(
         N (16#f92a476300000005#), N (16#4242424242424242#), N (16#4242424242424242#), N (16#5ff43fd476a405d4#),
         N (16#d4938bbfaa6b5910#), N (16#232828fe4048276a#), N (16#0f92b99bac0a36e9#), N (16#5e410224a875a63a#),
         N (16#e032760b769970e0#), N (16#334776bf31223842#), N (16#c70c5e58a3ad72ad#), N (16#a007112a8378e6c9#),
         N (16#64964368933b7cca#), N (16#32080e54cd38e9fd#), N (16#4f863df05078ea29#), others => 0),
      others => LSC.SHA512.Block_Type'(others => 0)
      );

      SPARKUnit.Create_Test
        (Harness,
         HMAC_SHA512_Suite,
         "HMAC-SHA512-MULTI-3",
         LSC.HMAC_SHA512.Authenticate (Key, Message11, 16#3c0#) =
         LSC.HMAC_SHA512.Auth_Type'(
            N (16#dc3081d890ce1209#), N (16#ca7c0618f35c7da8#), N (16#6ca43d462ce7a92e#), N (16#157e2b8865381a6f#)));
   end MULTI3;

   ------------------------
   --  Test Case MULTI-4 --
   ------------------------

   procedure MULTI4
   --# global Harness, HMAC_SHA512_Suite;
   --# derives Harness from Harness, HMAC_SHA512_Suite;
   is
      Key       : LSC.SHA512.Block_Type;
      Message11 : Message11_Type;
   begin
      Key := LSC.SHA512.Block_Type'(
        N (16#f1bcc392d8719db7#), N (16#e2e3203e0ebd53b2#), N (16#147de675accd7087#), N (16#1950385efcda6037#),
        N (16#d3f6a21d97768626#), N (16#7274ff83def9538a#), N (16#9ccc7d7bfa48f464#), N (16#ec2d522d05e62c8b#),
        N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#),
        N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#), N (16#0000000000000000#)
      );

      Message11 := Message11_Type'(
      LSC.SHA512.Block_Type'(
         N (16#f92a476300000005#), N (16#4242424242424242#), N (16#4242424242424242#), N (16#5ff43fd476a405d4#),
         N (16#d4938bbfaa6b5910#), N (16#232828fe4048276a#), N (16#0f92b99bac0a36e9#), N (16#5e410224a875a63a#),
         N (16#e032760b769970e0#), N (16#334776bf31223842#), N (16#c70c5e58a3ad72ad#), N (16#a007112a8378e6c9#),
         N (16#64964368933b7cca#), N (16#32080e54cd38e9fd#), N (16#4f863df05078ea29#), N (16#dc3081d890ce1209#)),
      LSC.SHA512.Block_Type'(
         N (16#ca7c0618f35c7da8#), N (16#6ca43d462ce7a92e#), N (16#157e2b8865381a6f#), others => 0),
      others => LSC.SHA512.Block_Type'(others => 0)
      );

      -- Note that we hash only part of the message (leaving out the last 4 64-bit values).
      -- This should result in the same authentication value as MULTI-3!
      SPARKUnit.Create_Test
        (Harness,
         HMAC_SHA512_Suite,
         "HMAC-SHA512-MULTI-4",
         LSC.HMAC_SHA512.Authenticate (Key, Message11, 16#3c0#) =
         LSC.HMAC_SHA512.Auth_Type'(
            N (16#dc3081d890ce1209#), N (16#ca7c0618f35c7da8#), N (16#6ca43d462ce7a92e#), N (16#157e2b8865381a6f#)));
   end MULTI4;

begin

   SPARKUnit.Create_Suite (Harness, "HMAC-SHA512 tests", HMAC_SHA512_Suite);


   --  SHA512 PRF Test Vectors (RFC 4868, 2.7.1.)

   PRF1;
   PRF2;
   PRF3;
   PRF4;

   AUTH1;
   AUTH2;
   AUTH3;
   AUTH4;

   MULTI1;
   MULTI2;
   MULTI3;
   MULTI4;

end HMAC_SHA512_Tests;