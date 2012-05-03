-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2011, Alexander Senier and Stefan Berghofer
-- Copyright (C) 2011, secunet Security Networks AG
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
--    * Neither the name of the author nor the names of its contributors may be
--      used to endorse or promote products derived from this software without
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
procedure Test_Bignum
is
   subtype Mod_Range is Natural range 0 .. 63;
   subtype Pub_Exp_Range is Natural range 0 .. 0;

   subtype LInt is LSC.Bignum.Big_Int (Mod_Range);
   subtype SInt is LSC.Bignum.Big_Int (Pub_Exp_Range);

   Modulus : constant LInt := LInt'
     (16#e3855b7b#, 16#695e1d0c#, 16#2f3a389f#, 16#e4e8cfbc#, 16#366c3c0b#,
      16#07f34b0d#, 16#a92ff519#, 16#566a909a#, 16#d79ecc36#, 16#e392c334#,
      16#dbbb737f#, 16#80c97ddd#, 16#812a798c#, 16#0fdf31b2#, 16#c9c3978b#,
      16#f526906b#, 16#cf23d190#, 16#ea1e08a2#, 16#08cf9c02#, 16#b3b794fb#,
      16#7855c403#, 16#49b10dd8#, 16#6ca17d12#, 16#b069b1ab#, 16#b8d28b35#,
      16#a08d0a13#, 16#1a1bf74d#, 16#30ca19b3#, 16#29e5abd7#, 16#4ccb0a06#,
      16#7bae2533#, 16#fc040833#, 16#2c1c80c5#, 16#ea729a13#, 16#ac5ffd04#,
      16#a2dcc2f9#, 16#c1f9c72c#, 16#f466adf6#, 16#ea152c47#, 16#42d76640#,
      16#8b5c067a#, 16#8c870d16#, 16#d3dacf2f#, 16#df33c327#, 16#fdddf873#,
      16#592c3110#, 16#a94e6415#, 16#6b0f63f4#, 16#84919783#, 16#da1672d1#,
      16#6d2b736e#, 16#3c02711d#, 16#eba01b1d#, 16#04463ba8#, 16#a8f0f41b#,
      16#d41c9a16#, 16#2e0a1c54#, 16#e8340e9b#, 16#0194cdee#, 16#4beacec6#,
      16#e23ee4a4#, 16#ec602901#, 16#079751bd#, 16#Dad31766#);

   Pub_Exp : constant SInt := SInt'(0 => 16#00010001#);

   Priv_Exp : constant LInt := LInt'
     (16#3fd9f299#, 16#64a02913#, 16#780db9d7#, 16#164c83cd#, 16#70ac88cc#,
      16#14e9bfcc#, 16#bff4fa46#, 16#a2956db0#, 16#d5952d92#, 16#d8e23b1b#,
      16#d252925c#, 16#f63f2570#, 16#1232a957#, 16#0ecdf6fc#, 16#23356dd5#,
      16#6dfd8463#, 16#b88e9193#, 16#3e337443#, 16#c30bd004#, 16#f86471bc#,
      16#26836b1f#, 16#36792ee7#, 16#fd7774c3#, 16#e947afe5#, 16#403e454e#,
      16#60886c2f#, 16#7da04cab#, 16#0006c1c8#, 16#87bfa8cc#, 16#c644e026#,
      16#8eea8cce#, 16#beca39f9#, 16#60c3808d#, 16#2faf499f#, 16#c81d0c50#,
      16#ef2e6e1b#, 16#ae3dbc3f#, 16#54a6e7b8#, 16#efdc4e55#, 16#e0ed4e41#,
      16#6ddee985#, 16#2c988959#, 16#2bdbffad#, 16#ec9c5635#, 16#a6ad3fef#,
      16#5df1f2a6#, 16#e4ec57d3#, 16#1c823145#, 16#eecff08e#, 16#51b9f682#,
      16#c8ec37a1#, 16#1212a615#, 16#9265aeed#, 16#4b4e2491#, 16#2b29d53a#,
      16#2bd57be9#, 16#ffd21ce0#, 16#bccc6401#, 16#e2d6c019#, 16#c98b2771#,
      16#4d4cde01#, 16#d507d875#, 16#886bab53#, 16#7cac4629#);

   Aux1, Aux2, Aux3, Plain1, Plain2, Cipher, R : LInt;
   M_Inv        : LSC.Types.Word32;
   Bignum_Suite : SPARKUnit.Index_Type;
begin
   SPARKUnit.Create_Suite (Harness, "Bignum tests", Bignum_Suite);

   -- Precompute R^2 mod m
   LSC.Bignum.Size_Square_Mod
     (M       => Modulus,
      M_First => Modulus'First,
      M_Last  => Modulus'Last,
      R       => R,
      R_First => R'First);

   -- Precomputing inverse
   M_Inv := LSC.Bignum.Word_Inverse (Modulus (Modulus'First));

   -- create original data
   for I in Natural range Modulus'Range
   loop
      Plain1 (I) := LSC.Types.Word32 (I);
   end loop;

   -- Encrypt
   LSC.Bignum.Mont_Exp
     (A          => Cipher,
      A_First    => Cipher'First,
      A_Last     => Cipher'Last,
      X          => Plain1,
      X_First    => Plain1'First,
      E          => Pub_Exp,
      E_First    => Pub_Exp'First,
      E_Last     => Pub_Exp'Last,
      M          => Modulus,
      M_First    => Modulus'First,
      Aux1       => Aux1,
      Aux1_First => Aux1'First,
      Aux2       => Aux2,
      Aux2_First => Aux2'First,
      Aux3       => Aux3,
      Aux3_First => Aux3'First,
      R          => R,
      R_First    => R'First,
      M_Inv      => M_Inv);

   -- Decrypting
   LSC.Bignum.Mont_Exp
     (A          => Plain2,
      A_First    => Plain2'First,
      A_Last     => Plain2'Last,
      X          => Cipher,
      X_First    => Cipher'First,
      E          => Priv_Exp,
      E_First    => Priv_Exp'First,
      E_Last     => Priv_Exp'Last,
      M          => Modulus,
      M_First    => Modulus'First,
      Aux1       => Aux1,
      Aux1_First => Aux1'First,
      Aux2       => Aux2,
      Aux2_First => Aux2'First,
      Aux3       => Aux3,
      Aux3_First => Aux3'First,
      R          => R,
      R_First    => R'First,
      M_Inv      => M_Inv);

   SPARKUnit.Create_Test
     (Harness,
      Bignum_Suite,
      "Encrypt/Decrypt",
      Plain1 = Plain2);

end Test_Bignum;
