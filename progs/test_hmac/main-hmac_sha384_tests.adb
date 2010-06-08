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
procedure HMAC_SHA384_Tests is

   HMAC_Ctx                         : LSC.HMAC.SHA384.Context_Type;
   Key                              : LSC.SHA2.Block_Type;
   Block                            : LSC.SHA2.Block_Type;
   PRF_HMAC_SHA_384                 : LSC.SHA2.SHA384_Hash_Type;
   AUTH_HMAC_SHA_384                : LSC.HMAC.SHA384.Auth_Type;

begin

   LSC.Test.Suite ("HMAC-SHA384 tests");

   --  SHA384 PRF Test Vectors (RFC 4868, 2.7.1.)

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

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 64);
   PRF_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-PRF-1",
      PRF_HMAC_SHA_384 =
      LSC.SHA2.SHA384_Hash_Type'(16#629548d84439d0af#,
                                 16#7f9046abf425086b#,
                                 16#c61e10e4dbdaf915#,
                                 16#9cc5eb7c4c03aa82#,
                                 16#7fde6e07a99eeafa#,
                                 16#b69cfab2e852f14a#));

   ----------------------
   --  Test Case PRF-2 --
   ----------------------

   --  "Jefe"
   Key   := LSC.SHA2.Block_Type'(16#000000006566654a#,
                                 others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Block := LSC.SHA2.Block_Type'(16#206f642074616877#,
                                 16#20746e6177206179#,
                                 16#68746f6e20726f66#,
                                 16#000000003f676e69#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 224);
   PRF_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-PRF-2",
      PRF_HMAC_SHA_384 =
      LSC.SHA2.SHA384_Hash_Type'(16#31404876e3d245af#,
                                 16#1b6b8ab5d2787f61#,
                                 16#471ba0f564f47e9c#,
                                 16#5e44226373c32ee4#,
                                 16#c7e2695eca40228e#,
                                 16#4916b2faec39328b#));

   ----------------------
   --  Test Case PRF-3 --
   ----------------------

   --  20 times 16#aa#
   Key   := LSC.SHA2.Block_Type'(16#aaaaaaaaaaaaaaaa#,
                                 16#aaaaaaaaaaaaaaaa#,
                                 16#00000000aaaaaaaa#,
                                 others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA2.Block_Type'(16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#000000000000dddd#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 400);
   PRF_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-PRF-3",
      PRF_HMAC_SHA_384 =
      LSC.SHA2.SHA384_Hash_Type'(16#8aade6d308260688#,
                                 16#6fa8c814e0aca20a#,
                                 16#eb9fac47d935a60a#,
                                 16#4b146659e5f43ee8#,
                                 16#b91438c19db35a2a#,
                                 16#274fa301e1b63a4e#));

   ----------------------
   --  Test Case PRF-4 --
   ----------------------

   --  25 bytes
   Key   := LSC.SHA2.Block_Type'(16#0807060504030201#,
                                 16#100f0e0d0c0b0a09#,
                                 16#1817161514131211#,
                                 16#0000000000000019#,
                                 others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA2.Block_Type'(16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#000000000000cdcd#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 400);
   PRF_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Prf (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-PRF-4",
      PRF_HMAC_SHA_384 =
      LSC.SHA2.SHA384_Hash_Type'(16#85253c78b7698a3e#,
                                 16#a76caf9062ab3319#,
                                 16#9c0050084881997a#,
                                 16#4e3b571f6e7c57c5#,
                                 16#79d6a7c423dd0168#,
                                 16#fbcf74c686a3f8cc#));

   -----------------------
   --  Test Case AUTH-1 --
   -----------------------

   --  48 bytes
   Key   := LSC.SHA2.Block_Type'(16#0b0b0b0b0b0b0b0b#,
                                 16#0b0b0b0b0b0b0b0b#,
                                 16#0b0b0b0b0b0b0b0b#,
                                 16#0b0b0b0b0b0b0b0b#,
                                 16#0b0b0b0b0b0b0b0b#,
                                 16#0b0b0b0b0b0b0b0b#,
                                 others => 0);

   -- "Hi There"
   Block := LSC.SHA2.Block_Type'(0 => 16#6572656854206948#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 64);
   AUTH_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-AUTH-1",
      AUTH_HMAC_SHA_384 =
      LSC.HMAC.SHA384.Auth_Type'(16#726a5c6f63d5a8b6#,
                                 16#c7e67ecf7d97f924#,
                                 16#73e9decb480c6dfb#));

   -----------------------
   --  Test Case AUTH-2 --
   -----------------------

   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   --  "JefeJefeJefeJefe"
   Key   := LSC.SHA2.Block_Type'(16#6566654a6566654a#,
                                 16#6566654a6566654a#,
                                 16#6566654a6566654a#,
                                 16#6566654a6566654a#,
                                 16#6566654a6566654a#,
                                 16#6566654a6566654a#,
                                 others => 0);

   --  "what do ya want "
   --  "for nothing?"
   Block := LSC.SHA2.Block_Type'(16#206f642074616877#,
                                 16#20746e6177206179#,
                                 16#68746f6e20726f66#,
                                 16#000000003f676e69#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 224);
   AUTH_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-AUTH-2",
      AUTH_HMAC_SHA_384 =
      LSC.HMAC.SHA384.Auth_Type'(16#fd42184f9753732c#,
                                 16#2221a42c453cd566#,
                                 16#4d18fb4c590b8cb2#));

   -----------------------
   --  Test Case AUTH-3 --
   -----------------------

   --  48 times 16#aa#
   Key   := LSC.SHA2.Block_Type'(16#aaaaaaaaaaaaaaaa#,
                                 16#aaaaaaaaaaaaaaaa#,
                                 16#aaaaaaaaaaaaaaaa#,
                                 16#aaaaaaaaaaaaaaaa#,
                                 16#aaaaaaaaaaaaaaaa#,
                                 16#aaaaaaaaaaaaaaaa#,
                                 others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA2.Block_Type'(16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#dddddddddddddddd#,
                                 16#000000000000dddd#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 400);
   AUTH_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-AUTH-3",
      AUTH_HMAC_SHA_384 =
      LSC.HMAC.SHA384.Auth_Type'(16#327402e09b439f80#,
                                 16#534b165286534a1d#,
                                 16#16c3a08481504a55#));

   -----------------------
   --  Test Case AUTH-4 --
   -----------------------

   Key   := LSC.SHA2.Block_Type'(16#0807060504030201#,
                                 16#100f0e0d0c0b0a09#,
                                 16#1817161514131211#,
                                 16#201f1e1d1c1b1a19#,
                                 16#11100f0e0d0c0b0a#,
                                 16#1918171615141312#,
                                 others => 0);

   --  50 times 16#dd#
   Block := LSC.SHA2.Block_Type'(16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#cdcdcdcdcdcdcdcd#,
                                 16#000000000000cdcd#,
                                 others => 0);

   HMAC_Ctx := LSC.HMAC.SHA384.Context_Init (Key);
   LSC.HMAC.SHA384.Context_Finalize (HMAC_Ctx, Block, 400);
   AUTH_HMAC_SHA_384 := LSC.HMAC.SHA384.Get_Auth (HMAC_Ctx);

   LSC.Test.Run
     ("HMAC-SHA384-AUTH-4",
      AUTH_HMAC_SHA_384 =
      LSC.HMAC.SHA384.Auth_Type'(16#8035e6c68500545b#,
                                 16#d19e6093242b5396#,
                                 16#5cbb874f778f29cb#));
end HMAC_SHA384_Tests;
