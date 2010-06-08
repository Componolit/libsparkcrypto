--  This file is part of the sparkcrypto library.

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

separate (Main)
procedure HMAC_SHA512_Tests is

   HMAC_Ctx                         : LSC.HMAC.SHA512.Context_Type;
   Key                              : LSC.SHA2.Block_Type;
   Block                            : LSC.SHA2.Block_Type;
   PRF_HMAC_SHA_512                 : LSC.SHA2.SHA512_Hash_Type;
   AUTH_HMAC_SHA_512                : LSC.HMAC.SHA512.Auth_Type;

begin

   LSC.Test.Suite ("HMAC-SHA512 tests");

   --  SHA512 PRF Test Vectors (RFC 4868, 2.7.1.)

   ----------------------
   --  Test Case PRF-1 --
   ----------------------

   Key   := LSC.SHA2.Block_Type'(16#0b0b0b0b0b0b0b0b#,
                                 16#0b0b0b0b0b0b0b0b#,
                                 16#000000000b0b0b0b#,
                                 others => 0);

   -- "Hi There"
   Block := LSC.SHA2.Block_Type'(16#6572656854206948#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 64);
   PRF_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-PRF-1",
      PRF_HMAC_SHA_512 =
      LSC.SHA2.SHA512_Hash_Type'(16#9d61efa5de7caa87#,
                                 16#b06c1d1a24b4f04f#,
                                 16#78c24ecee2f47923#,
                                 16#de7ce14505b3d07a#,
                                 16#02a7b8d6b733a8da#,
                                 16#e4f4a3ae4e278b03#,
                                 16#70f161eb4e919dbe#,
                                 16#5468123a206c692e#));

   ----------------------
   --  Test Case PRF-2 --
   ----------------------

   --  "Jefe"
   Key   := LSC.SHA2.Block_Type'(0 => 16#000000006566654a#,
                                 others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Block := LSC.SHA2.Block_Type'(16#206f642074616877#,
                                 16#20746e6177206179#,
                                 16#68746f6e20726f66#,
                                 16#000000003f676e69#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 224);
   PRF_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-PRF-2",
      PRF_HMAC_SHA_512 =
      LSC.SHA2.SHA512_Hash_Type'(16#e219f8fc7b7a4b16#,
                                 16#a3e0563be7fb95e3#,
                                 16#d61f832e2264bd87#,
                                 16#540525ead70c2710#,
                                 16#4a995ac075bf5897#,
                                 16#fde6f0f8654f036d#,
                                 16#4b6b4a4da3b1eaca#,
                                 16#37e7bc380a076e63#));

   ----------------------
   --  Test Case PRF-3 --
   ----------------------

   --  20 times 16#aa#
   Key   := LSC.SHA2.Block_Type'(0 => 16#aaaaaaaaaaaaaaaa#,
                                 1 => 16#aaaaaaaaaaaaaaaa#,
                                 2 => 16#00000000aaaaaaaa#,
                                 others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA2.Block_Type'(0 => 16#dddddddddddddddd#,
                                 1 => 16#dddddddddddddddd#,
                                 2 => 16#dddddddddddddddd#,
                                 3 => 16#dddddddddddddddd#,
                                 4 => 16#dddddddddddddddd#,
                                 5 => 16#dddddddddddddddd#,
                                 6 => 16#000000000000dddd#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 400);
   PRF_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-PRF-3",
      PRF_HMAC_SHA_512 =
      LSC.SHA2.SHA512_Hash_Type'(16#84a2569d08b073fa#,
                                 16#e90b896c75f0b0ef#,
                                 16#361ae88edddbb5b1#,
                                 16#399d27b2333ef855#,
                                 16#c822a77982843ebf#,
                                 16#07c8677ea485b406#,
                                 16#2694e8be37a346b9#,
                                 16#fb9232e159882774#));

   ----------------------
   --  Test Case PRF-4 --
   ----------------------

   --  25 bytes
   Key   := LSC.SHA2.Block_Type'(0 => 16#0807060504030201#,
                                 1 => 16#100f0e0d0c0b0a09#,
                                 2 => 16#1817161514131211#,
                                 3 => 16#0000000000000019#,
                                 others => 0);

   --  50 times 16#cd#
   Block := LSC.SHA2.Block_Type'(0 => 16#cdcdcdcdcdcdcdcd#,
                                 1 => 16#cdcdcdcdcdcdcdcd#,
                                 2 => 16#cdcdcdcdcdcdcdcd#,
                                 3 => 16#cdcdcdcdcdcdcdcd#,
                                 4 => 16#cdcdcdcdcdcdcdcd#,
                                 5 => 16#cdcdcdcdcdcdcdcd#,
                                 6 => 16#000000000000cdcd#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 400);
   PRF_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-PRF-4",
      PRF_HMAC_SHA_512 =
      LSC.SHA2.SHA512_Hash_Type'(16#698c45375646bab0#,
                                 16#f74a1df6c5a8e590#,
                                 16#2d874bf97fd976e5#,
                                 16#dbe31e3650806fe7#,
                                 16#b45ea21ac1a51ca9#,
                                 16#638078c55c2779d6#,
                                 16#2d4f0c124197f1a5#,
                                 16#dd98a210ebebade2#));

   -----------------------
   --  Test Case AUTH-1 --
   -----------------------

   --  64 bytes
   Key   := LSC.SHA2.Block_Type'(0 => 16#0b0b0b0b0b0b0b0b#,
                                 1 => 16#0b0b0b0b0b0b0b0b#,
                                 2 => 16#0b0b0b0b0b0b0b0b#,
                                 3 => 16#0b0b0b0b0b0b0b0b#,
                                 4 => 16#0b0b0b0b0b0b0b0b#,
                                 5 => 16#0b0b0b0b0b0b0b0b#,
                                 6 => 16#0b0b0b0b0b0b0b0b#,
                                 7 => 16#0b0b0b0b0b0b0b0b#,
                                 others => 0);

   -- "Hi There"
   Block := LSC.SHA2.Block_Type'(0 => 16#6572656854206948#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 64);
   AUTH_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-AUTH-1",
      AUTH_HMAC_SHA_512 =
      LSC.HMAC.SHA512.Auth_Type'(0 => 16#e6e7dc016edc7e63#,
                                 1 => 16#df82ae1a45992a74#,
                                 2 => 16#0e599e43923eda23#,
                                 3 => 16#b80f913eb361e743#));

   -----------------------
   --  Test Case AUTH-2 --
   -----------------------

   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   Key   := LSC.SHA2.Block_Type'(0 => 16#6566654a6566654a#,
                                 1 => 16#6566654a6566654a#,
                                 2 => 16#6566654a6566654a#,
                                 3 => 16#6566654a6566654a#,
                                 4 => 16#6566654a6566654a#,
                                 5 => 16#6566654a6566654a#,
                                 6 => 16#6566654a6566654a#,
                                 7 => 16#6566654a6566654a#,
                                 others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Block := LSC.SHA2.Block_Type'(16#206f642074616877#,
                                 16#20746e6177206179#,
                                 16#68746f6e20726f66#,
                                 16#000000003f676e69#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 224);
   AUTH_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-AUTH-2",
      AUTH_HMAC_SHA_512 =
      LSC.HMAC.SHA512.Auth_Type'(16#e27c8aae170937cb#,
                                 16#14d605478f1dfd8c#,
                                 16#5dc162932a3b171c#,
                                 16#5454b151b2df35f2#));

   -----------------------
   --  Test Case AUTH-3 --
   -----------------------

   --  64 times 16#aa#
   Key   := LSC.SHA2.Block_Type'(0 => 16#aaaaaaaaaaaaaaaa#,
                                 1 => 16#aaaaaaaaaaaaaaaa#,
                                 2 => 16#aaaaaaaaaaaaaaaa#,
                                 3 => 16#aaaaaaaaaaaaaaaa#,
                                 4 => 16#aaaaaaaaaaaaaaaa#,
                                 5 => 16#aaaaaaaaaaaaaaaa#,
                                 6 => 16#aaaaaaaaaaaaaaaa#,
                                 7 => 16#aaaaaaaaaaaaaaaa#,
                                 others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA2.Block_Type'(0 => 16#dddddddddddddddd#,
                                 1 => 16#dddddddddddddddd#,
                                 2 => 16#dddddddddddddddd#,
                                 3 => 16#dddddddddddddddd#,
                                 4 => 16#dddddddddddddddd#,
                                 5 => 16#dddddddddddddddd#,
                                 6 => 16#000000000000dddd#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 400);
   AUTH_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-AUTH-3",
      AUTH_HMAC_SHA_512 =
      LSC.HMAC.SHA512.Auth_Type'(0 => 16#a94c6283d7ace72e#,
                                 1 => 16#41ae05eef3108739#,
                                 2 => 16#9ee4870c51b0f9b9#,
                                 3 => 16#d8331796bfc96c58#));

   -----------------------
   --  Test Case AUTH-4 --
   -----------------------

   --  64 bytes
   --  NB: The test vector in RCF 4868 seem to be bogus! Though stating
   --      this to be a 64 bytes key, 80 bytes are presented. However,
   --      leaving out the first 16 bytes of the bogus key results in
   --      the presented MAC.
   Key   := LSC.SHA2.Block_Type'(-- 16#11100f0e0d0c0b0a#,
                                 -- 16#1918171615141312#,
                                 16#0807060504030201#,
                                 16#100f0e0d0c0b0a09#,
                                 16#1817161514131211#,
                                 16#201f1e1d1c1b1a19#,
                                 16#2827262524232221#,
                                 16#302f2e2d2c2b2a29#,
                                 16#3837363534333231#,
                                 16#403f3e3d3c3b3a39#,
                                 others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA2.Block_Type'(0 => 16#cdcdcdcdcdcdcdcd#,
                                 1 => 16#cdcdcdcdcdcdcdcd#,
                                 2 => 16#cdcdcdcdcdcdcdcd#,
                                 3 => 16#cdcdcdcdcdcdcdcd#,
                                 4 => 16#cdcdcdcdcdcdcdcd#,
                                 5 => 16#cdcdcdcdcdcdcdcd#,
                                 6 => 16#000000000000cdcd#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA512.Context_Init (Key);
   LSC.HMAC.SHA512.Context_Finalize (HMAC_Ctx, Block, 400);
   AUTH_HMAC_SHA_512 := LSC.HMAC.SHA512.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA512-AUTH-4",
      AUTH_HMAC_SHA_512 =
      LSC.HMAC.SHA512.Auth_Type'(0 => 16#82ecdaa3e588665e#,
                                 1 => 16#f5ef24a2ae2ea36c#,
                                 2 => 16#130e4747896200e7#,
                                 3 => 16#08b1ba61253001ad#));
end HMAC_SHA512_Tests;
