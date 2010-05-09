--  This file is part of the sparkcrypto library.
--
--  Copyright (C) 2010  secunet Security Networks AG
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>

--  This library  is free software:  you can  redistribute it and/or  modify it
--  under the  terms of the GNU  Lesser General Public License  as published by
--  the Free Software Foundation, either version  3 of the License, or (at your
--  option) any later version.

--  This library is distributed in the hope that it will be useful, but WITHOUT
--  ANY  WARRANTY; without  even  the implied  warranty  of MERCHANTABILITY  or
--  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
--  for more details.

--  You should  have received a copy  of the GNU Lesser  General Public License
--  along with this library. If not, see <http://www.gnu.org/licenses/>.

with SHA2, HMAC.SHA512, AES256, IO, Test;
use type SHA2.Hash_Type;

--# inherit IO,
--#         SHA2,
--#         HMAC.SHA512,
--#         AES256,
--#         Test;

--# main_program;
procedure Main
   --# derives ;
is
   Ctx1, Ctx2, Ctx3              : SHA2.Context_Type;
   Hash1, Hash2, Hash3           : SHA2.Hash_Type;
   Message1, Message2, Message3  : SHA2.Block_Type;

   Context                       : HMAC.SHA512.Context_Type;
   Key                           : SHA2.Block_Type;
   Block                         : SHA2.Block_Type;
   PRF_HMAC_SHA_512              : SHA2.Hash_Type;
   AUTH_HMAC_SHA_512             : HMAC.SHA512.Auth_Type;

   AES_Ctx                       : AES256.Context;
begin

   --  FIPS 180-2, Appendix C: SHA-512 Examples

   --  C.1 SHA-512 Example (One-Block Message)
   Ctx1     := SHA2.Context_Init;
   Message1 := SHA2.Block_Type'(0 => 16#6162630000000000#, others => 0);
   SHA2.Context_Finalize (Ctx1, Message1, 24);
   Hash1 := SHA2.Get_Hash (Ctx1);

   Test.Run
     ("SHA-512 Example (One-Block Message)",
      Hash1 =
      SHA2.Hash_Type'(16#DDAF35A193617ABA#,
                      16#CC417349AE204131#,
                      16#12E6FA4E89A97EA2#,
                      16#0A9EEEE64B55D39A#,
                      16#2192992A274FC1A8#,
                      16#36BA3C23A3FEEBBD#,
                      16#454D4423643CE80E#,
                      16#2A9AC94FA54CA49F#));

   --  C.2 SHA-512 Example (Multi-Block Message)
   Ctx2     := SHA2.Context_Init;
   Message2 :=
     SHA2.Block_Type'
     (16#6162636465666768#,
      16#6263646566676869#,
      16#636465666768696a#,
      16#6465666768696a6b#,
      16#65666768696a6b6c#,
      16#666768696a6b6c6d#,
      16#6768696a6b6c6d6e#,
      16#68696a6b6c6d6e6f#,
      16#696a6b6c6d6e6f70#,
      16#6a6b6c6d6e6f7071#,
      16#6b6c6d6e6f707172#,
      16#6c6d6e6f70717273#,
      16#6d6e6f7071727374#,
      16#6e6f707172737475#,
      16#0000000000000000#,
      16#0000000000000000#);
   SHA2.Context_Finalize (Ctx2, Message2, 896);
   Hash2 := SHA2.Get_Hash (Ctx2);

   Test.Run
     ("SHA-512 Example (Multi-Block Message)",
      Hash2 =
      SHA2.Hash_Type'(16#8e959b75dae313da#,
                      16#8cf4f72814fc143f#,
                      16#8f7779c6eb9f7fa1#,
                      16#7299aeadb6889018#,
                      16#501d289e4900f7e4#,
                      16#331b99dec4b5433a#,
                      16#c7d329eeb6dd2654#,
                      16#5e96e55b874be909#));

   --  C.3 SHA-512 Example (Long Message)
   Message3 := SHA2.Block_Type'(others => 16#61_61_61_61_61_61_61_61#);

   Ctx3 := SHA2.Context_Init;
   for I in Natural range 1 .. 7812
      --#  assert I in Natural;
   loop
      SHA2.Context_Update (Ctx3, Message3);
   end loop;
   SHA2.Context_Finalize (Ctx3, Message3, 512);
   Hash3 := SHA2.Get_Hash (Ctx3);

   Test.Run
     ("SHA-512 Example (Long Message)",
      Hash3 =
      SHA2.Hash_Type'(16#e718483d0ce76964#,
                      16#4e2e42c7bc15b463#,
                      16#8e1f98b13b204428#,
                      16#5632a803afa973eb#,
                      16#de0ff244877ea60a#,
                      16#4cb0432ce577c31b#,
                      16#eb009c5c2c49aa2e#,
                      16#4eadb217ad8cc09b#));


   --  SHA512 PRF Test Vectors (RFC 4868, 2.7.1.)

   ----------------------
   --  Test Case PRF-1 --
   ----------------------

   Key   := SHA2.Block_Type'(0 => 16#0b0b0b0b0b0b0b0b#,
                             1 => 16#0b0b0b0b0b0b0b0b#,
                             2 => 16#0b0b0b0b00000000#,
                             others => 0);

   -- "Hi There"
   Block := SHA2.Block_Type'(0 => 16#48_69_20_54_68_65_72_65#,
                             others => 0);

   Context := HMAC.SHA512.Context_Init (Key);
   HMAC.SHA512.Context_Finalize (Context, Block, 64);
   PRF_HMAC_SHA_512 := HMAC.SHA512.Get_Prf (Context);

   Test.Run
     ("PRF-1",
      PRF_HMAC_SHA_512 =
      SHA2.Hash_Type'(16#87aa7cdea5ef619d#,
                      16#4ff0b4241a1d6cb0#,
                      16#2379f4e2ce4ec278#,
                      16#7ad0b30545e17cde#,
                      16#daa833b7d6b8a702#,
                      16#038b274eaea3f4e4#,
                      16#be9d914eeb61f170#,
                      16#2e696c203a126854#));

   ----------------------
   --  Test Case PRF-2 --
   ----------------------

   --  "Jefe"
   Key   := SHA2.Block_Type'(0 => 16#4a_65_66_65_00_00_00_00#,
                             others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Block := SHA2.Block_Type'(16#7768617420646f20#,
                             16#79612077616e7420#,
                             16#666f72206e6f7468#,
                             16#696e673f00000000#,
                             others => 0);

   Context := HMAC.SHA512.Context_Init (Key);
   HMAC.SHA512.Context_Finalize (Context, Block, 224);
   PRF_HMAC_SHA_512 := HMAC.SHA512.Get_Prf (Context);

   Test.Run
     ("PRF-2",
      PRF_HMAC_SHA_512 =
      SHA2.Hash_Type'(16#164b7a7bfcf819e2#,
                      16#e395fbe73b56e0a3#,
                      16#87bd64222e831fd6#,
                      16#10270cd7ea250554#,
                      16#9758bf75c05a994a#,
                      16#6d034f65f8f0e6fd#,
                      16#caeab1a34d4a6b4b#,
                      16#636e070a38bce737#));

   ----------------------
   --  Test Case PRF-3 --
   ----------------------

   --  20 times 16#aa#
   Key   := SHA2.Block_Type'(0 => 16#aaaaaaaaaaaaaaaa#,
                             1 => 16#aaaaaaaaaaaaaaaa#,
                             2 => 16#aaaaaaaa00000000#,
                             others => 0);

   --  50 times 16#dd#
   Block := SHA2.Block_Type'(0 => 16#dddddddddddddddd#,
                             1 => 16#dddddddddddddddd#,
                             2 => 16#dddddddddddddddd#,
                             3 => 16#dddddddddddddddd#,
                             4 => 16#dddddddddddddddd#,
                             5 => 16#dddddddddddddddd#,
                             6 => 16#dddd000000000000#,
                             others => 0);

   Context := HMAC.SHA512.Context_Init (Key);
   HMAC.SHA512.Context_Finalize (Context, Block, 400);
   PRF_HMAC_SHA_512 := HMAC.SHA512.Get_Prf (Context);

   Test.Run
     ("PRF-3",
      PRF_HMAC_SHA_512 =
      SHA2.Hash_Type'(16#fa73b0089d56a284#,
                      16#efb0f0756c890be9#,
                      16#b1b5dbdd8ee81a36#,
                      16#55f83e33b2279d39#,
                      16#bf3e848279a722c8#,
                      16#06b485a47e67c807#,
                      16#b946a337bee89426#,
                      16#74278859e13292fb#));

   ----------------------
   --  Test Case PRF-4 --
   ----------------------

   --  25 bytes
   Key   := SHA2.Block_Type'(0 => 16#0102030405060708#,
                             1 => 16#090a0b0c0d0e0f10#,
                             2 => 16#1112131415161718#,
                             3 => 16#1900000000000000#,
                             others => 0);

   --  50 times 16#dd#
   Block := SHA2.Block_Type'(0 => 16#cdcdcdcdcdcdcdcd#,
                             1 => 16#cdcdcdcdcdcdcdcd#,
                             2 => 16#cdcdcdcdcdcdcdcd#,
                             3 => 16#cdcdcdcdcdcdcdcd#,
                             4 => 16#cdcdcdcdcdcdcdcd#,
                             5 => 16#cdcdcdcdcdcdcdcd#,
                             6 => 16#cdcd000000000000#,
                             others => 0);

   Context := HMAC.SHA512.Context_Init (Key);
   HMAC.SHA512.Context_Finalize (Context, Block, 400);
   PRF_HMAC_SHA_512 := HMAC.SHA512.Get_Prf (Context);

   Test.Run
     ("PRF-4",
      PRF_HMAC_SHA_512 =
      SHA2.Hash_Type'(16#b0ba465637458c69#,
                      16#90e5a8c5f61d4af7#,
                      16#e576d97ff94b872d#,
                      16#e76f8050361ee3db#,
                      16#a91ca5c11aa25eb4#,
                      16#d679275cc5788063#,
                      16#a5f19741120c4f2d#,
                      16#e2adebeb10a298dd#));

   -----------------------
   --  Test Case AUTH-1 --
   -----------------------

   --  64 bytes
   Key   := SHA2.Block_Type'(0 => 16#0b0b0b0b0b0b0b0b#,
                             1 => 16#0b0b0b0b0b0b0b0b#,
                             2 => 16#0b0b0b0b0b0b0b0b#,
                             3 => 16#0b0b0b0b0b0b0b0b#,
                             4 => 16#0b0b0b0b0b0b0b0b#,
                             5 => 16#0b0b0b0b0b0b0b0b#,
                             6 => 16#0b0b0b0b0b0b0b0b#,
                             7 => 16#0b0b0b0b0b0b0b0b#,
                             others => 0);

   -- "Hi There"
   Block := SHA2.Block_Type'(0 => 16#48_69_20_54_68_65_72_65#,
                             others => 0);

   Context := HMAC.SHA512.Context_Init (Key);
   HMAC.SHA512.Context_Finalize (Context, Block, 64);
   AUTH_HMAC_SHA_512 := HMAC.SHA512.Get_Auth (Context);

   Test.Run
     ("AUTH-1",
      AUTH_HMAC_SHA_512 =
      HMAC.SHA512.Auth_Type'(0 => 16#637edc6e01dce7e6#,
                             1 => 16#742a99451aae82df#,
                             2 => 16#23da3e92439e590e#,
                             3 => 16#43e761b33e910fb8#));

   -----------------------
   --  Test Case AUTH-2 --
   -----------------------

   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   Key   := SHA2.Block_Type'(0 => 16#4a6566654a656665#,
                             1 => 16#4a6566654a656665#,
                             2 => 16#4a6566654a656665#,
                             3 => 16#4a6566654a656665#,
                             4 => 16#4a6566654a656665#,
                             5 => 16#4a6566654a656665#,
                             6 => 16#4a6566654a656665#,
                             7 => 16#4a6566654a656665#,
                             others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Block := SHA2.Block_Type'(16#7768617420646f20#,
                             16#79612077616e7420#,
                             16#666f72206e6f7468#,
                             16#696e673f00000000#,
                             others => 0);

   Context := HMAC.SHA512.Context_Init (Key);
   HMAC.SHA512.Context_Finalize (Context, Block, 224);
   AUTH_HMAC_SHA_512 := HMAC.SHA512.Get_Auth (Context);

   Test.Run
     ("AUTH-2",
      AUTH_HMAC_SHA_512 =
      HMAC.SHA512.Auth_Type'(16#cb370917ae8a7ce2#,
                             16#8cfd1d8f4705d614#,
                             16#1c173b2a9362c15d#,
                             16#f235dfb251b15454#));

   -----------------------
   --  Test Case AUTH-3 --
   -----------------------

   --  64 times 16#aa#
   Key   := SHA2.Block_Type'(0 => 16#aaaaaaaaaaaaaaaa#,
                             1 => 16#aaaaaaaaaaaaaaaa#,
                             2 => 16#aaaaaaaaaaaaaaaa#,
                             3 => 16#aaaaaaaaaaaaaaaa#,
                             4 => 16#aaaaaaaaaaaaaaaa#,
                             5 => 16#aaaaaaaaaaaaaaaa#,
                             6 => 16#aaaaaaaaaaaaaaaa#,
                             7 => 16#aaaaaaaaaaaaaaaa#,
                             others => 0);

   --  50 times 16#dd#
   Block := SHA2.Block_Type'(0 => 16#dddddddddddddddd#,
                             1 => 16#dddddddddddddddd#,
                             2 => 16#dddddddddddddddd#,
                             3 => 16#dddddddddddddddd#,
                             4 => 16#dddddddddddddddd#,
                             5 => 16#dddddddddddddddd#,
                             6 => 16#dddd000000000000#,
                             others => 0);

   Context := HMAC.SHA512.Context_Init (Key);
   HMAC.SHA512.Context_Finalize (Context, Block, 400);
   AUTH_HMAC_SHA_512 := HMAC.SHA512.Get_Auth (Context);

   Test.Run
     ("AUTH-3",
      AUTH_HMAC_SHA_512 =
      HMAC.SHA512.Auth_Type'(0 => 16#2ee7acd783624ca9#,
                             1 => 16#398710f3ee05ae41#,
                             2 => 16#b9f9b0510c87e49e#,
                             3 => 16#586cc9bf961733d8#));

   -----------------------
   --  Test Case AUTH-4 --
   -----------------------

   --  64 bytes
   --  NB: The test vector in RCF 4868 seem to be bogus! Though stating
   --      this to be a 64 bytes key, 80 bytes are presented. However,
   --      leaving out the first 16 bytes of the bogus key results in
   --      the presented MAC.
   Key   := SHA2.Block_Type'(-- 16#0a0b0c0d0e0f1011#,
                             -- 16#1213141516171819#,
                             16#0102030405060708#,
                             16#090a0b0c0d0e0f10#,
                             16#1112131415161718#,
                             16#191a1b1c1d1e1f20#,
                             16#2122232425262728#,
                             16#292a2b2c2d2e2f30#,
                             16#3132333435363738#,
                             16#393a3b3c3d3e3f40#,
                             others => 0);

   --  50 times 16#dd#
   Block := SHA2.Block_Type'(0 => 16#cdcdcdcdcdcdcdcd#,
                             1 => 16#cdcdcdcdcdcdcdcd#,
                             2 => 16#cdcdcdcdcdcdcdcd#,
                             3 => 16#cdcdcdcdcdcdcdcd#,
                             4 => 16#cdcdcdcdcdcdcdcd#,
                             5 => 16#cdcdcdcdcdcdcdcd#,
                             6 => 16#cdcd000000000000#,
                             others => 0);

   Context := HMAC.SHA512.Context_Init (Key);
   HMAC.SHA512.Context_Finalize (Context, Block, 400);
   AUTH_HMAC_SHA_512 := HMAC.SHA512.Get_Auth (Context);

   Test.Run
     ("AUTH-4",
      AUTH_HMAC_SHA_512 =
      HMAC.SHA512.Auth_Type'(0 => 16#5e6688e5a3daec82#,
                             1 => 16#6ca32eaea224eff5#,
                             2 => 16#e700628947470e13#,
                             3 => 16#ad01302561bab108#));

   --# accept Flow, 10, "Test not yet finished";
   --# accept Flow, 33, AES_Ctx, "Test not yet finished";
   AES_Ctx := AES256.Context_Init (Key => AES256.Key_Type'(16#60_3d_eb_10#,
                                                           16#15_ca_71_be#,
                                                           16#2b_73_ae_f0#,
                                                           16#85_7d_77_81#,
                                                           16#1f_35_2c_07#,
                                                           16#3b_61_08_d7#,
                                                           16#2d_98_10_a3#,
                                                           16#09_14_df_f4#));
end Main;
