-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2012, Stefan Berghofer
-- Copyright (C) 2012, secunet Security Networks AG
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
procedure EC_Tests
is
   EC_Suite : SPARKUnit.Index_Type;

   -- brainpoolP320r1 curve, see RFC 5639

   P : constant LSC.EC.Coord := LSC.EC.Coord'
     (16#F1B32E27#, 16#FCD412B1#, 16#7893EC28#, 16#4F92B9EC#, 16#F6F40DEF#,
      16#F98FCFA6#, 16#D201E065#, 16#E13C785E#, 16#36BC4FB7#, 16#D35E4720#);
   --# for P declare Rule;

   A : constant LSC.EC.Coord := LSC.EC.Coord'
     (16#7D860EB4#, 16#92F375A9#, 16#85FFA9F4#, 16#66190EB0#, 16#F5EB79DA#,
      16#A2A73513#, 16#6D3F3BB8#, 16#83CCEBD4#, 16#8FBAB0F8#, 16#3EE30B56#);
   --# for A declare Rule;

   B : constant LSC.EC.Coord := LSC.EC.Coord'
     (16#8FB1F1A6#, 16#6F5EB4AC#, 16#88453981#, 16#CC31DCCD#, 16#9554B49A#,
      16#E13F4134#, 16#40688A6F#, 16#D3AD1986#, 16#9DFDBC42#, 16#52088394#);
   --# for B declare Rule;

   Base_X : constant LSC.EC.Coord := LSC.EC.Coord'
     (16#39E20611#, 16#10AF8D0D#, 16#10A599C7#, 16#E7871E2A#, 16#0A087EB6#,
      16#F20137D1#, 16#8EE5BFE6#, 16#5289BCC4#, 16#FB53D8B8#, 16#43BD7E9A#);
   --# for Base_X declare Rule;

   Base_Y : constant LSC.EC.Coord := LSC.EC.Coord'
     (16#692E8EE1#, 16#D35245D1#, 16#AAAC6AC7#, 16#A9C77877#, 16#117182EA#,
      16#0743FFED#, 16#7F77275E#, 16#AB409324#, 16#45EC1CC8#, 16#14FDD055#);
   --# for Base_Y declare Rule;

   Q : constant LSC.EC.Coord := LSC.EC.Coord'
     (16#44C59311#, 16#8691555B#, 16#EE8658E9#, 16#2D482EC7#, 16#B68F12A3#,
      16#F98FCFA5#, 16#D201E065#, 16#E13C785E#, 16#36BC4FB7#, 16#D35E4720#);
   --# for Q declare Rule;

   RP, AM, BM, RQ : LSC.EC.Coord;

   P_Inv, Q_Inv : LSC.Types.Word32;

   procedure Precompute_Values
     --# global RP, AM, BM, RQ, P_Inv, Q_Inv;
     --# derives RP, AM, BM, RQ, P_Inv, Q_Inv from ;
     --# post
     --#   LSC.Bignum.Num_Of_Big_Int (RP, RP'First, P'Last - P'First + 1) =
     --#   LSC.Bignum.Base ** (2 * (P'Last - P'First + 1)) mod
     --#   LSC.Bignum.Num_Of_Big_Int (P, P'First, P'Last - P'First + 1) and
     --#   LSC.Bignum.Num_Of_Big_Int (AM, AM'First, P'Last - P'First + 1) <
     --#   LSC.Bignum.Num_Of_Big_Int (P, P'First, P'Last - P'First + 1) and
     --#   LSC.Bignum.Num_Of_Big_Int (BM, BM'First, P'Last - P'First + 1) <
     --#   LSC.Bignum.Num_Of_Big_Int (P, P'First, P'Last - P'First + 1) and
     --#   LSC.Bignum.Num_Of_Big_Int (RQ, RQ'First, Q'Last - Q'First + 1) =
     --#   LSC.Bignum.Base ** (2 * (Q'Last - Q'First + 1)) mod
     --#   LSC.Bignum.Num_Of_Big_Int (Q, Q'First, Q'Last - Q'First + 1) and
     --#   1 + P_Inv * P (P'First) = 0 and
     --#   1 + Q_Inv * Q (Q'First) = 0;
   is
   begin
      LSC.Bignum.Size_Square_Mod (P, P'First, P'Last, RP, RP'First);
      P_Inv := LSC.Bignum.Word_Inverse (P (P'First));

      LSC.Bignum.Size_Square_Mod (Q, Q'First, Q'Last, RQ, RQ'First);
      Q_Inv := LSC.Bignum.Word_Inverse (Q (Q'First));

      LSC.Bignum.Mont_Mult
        (AM, AM'First, AM'Last, A, A'First, RP, RP'First,
         P, P'First, P_Inv);

      LSC.Bignum.Mont_Mult
        (BM, BM'First, BM'Last, B, B'First, RP, RP'First,
         P, P'First, P_Inv);
   end Precompute_Values;

   function Test_ECDH return Boolean
     --# global RP, AM, P_Inv;
     --# pre
     --#   LSC.Bignum.Num_Of_Big_Int (RP, RP'First, P'Last - P'First + 1) =
     --#   LSC.Bignum.Base ** (2 * (P'Last - P'First + 1)) mod
     --#   LSC.Bignum.Num_Of_Big_Int (P, P'First, P'Last - P'First + 1) and
     --#   LSC.Bignum.Num_Of_Big_Int (AM, AM'First, P'Last - P'First + 1) <
     --#   LSC.Bignum.Num_Of_Big_Int (P, P'First, P'Last - P'First + 1) and
     --#   1 + P_Inv * P (P'First) = 0;
   is
      Priv : constant LSC.EC.Coord := LSC.EC.Coord'
        (16#A5D0E7B7#, 16#AD14B697#, 16#8EF3F5F4#, 16#4BEA7AF1#, 16#E772756D#,
         16#EAD256BE#, 16#5F344272#, 16#751B292C#, 16#26EF6D7A#, 16#2A246489#);

      Priv_Other : constant LSC.EC.Coord := LSC.EC.Coord'
        (16#F070603C#, 16#AFCD48B7#, 16#F0AE9E9D#, 16#7A7301D8#, 16#BE35942D#,
         16#59BF3301#, 16#3666553B#, 16#A18BF603#, 16#04E60104#, 16#0E584D8A#);

      Pub_X, Pub_Y, Pub_Other_X, Pub_Other_Y : LSC.EC.Coord;
      Shared_X, Shared_Y, Shared_Other_X, Shared_Other_Y : LSC.EC.Coord;

      X, Y, Z : LSC.EC.Coord;

   begin
      -- Compute public values from secrets

      LSC.EC.Point_Mult
        (X1       => Base_X,
         Y1       => Base_Y,
         Z1       => LSC.EC.One,
         E        => Priv,
         E_First  => Priv'First,
         E_Last   => Priv'Last,
         X2       => X,
         Y2       => Y,
         Z2       => Z,
         A        => AM,
         M        => P,
         M_Inv    => P_Inv);

      LSC.EC.Make_Affine (X, Y, Z, Pub_X, Pub_Y, RP, P, P_Inv);

      LSC.EC.Point_Mult
        (X1       => Base_X,
         Y1       => Base_Y,
         Z1       => LSC.EC.One,
         E        => Priv_Other,
         E_First  => Priv_Other'First,
         E_Last   => Priv_Other'Last,
         X2       => X,
         Y2       => Y,
         Z2       => Z,
         A        => AM,
         M        => P,
         M_Inv    => P_Inv);

      LSC.EC.Make_Affine (X, Y, Z, Pub_Other_X, Pub_Other_Y, RP, P, P_Inv);

      -- Now compute shared secret

      LSC.EC.Point_Mult
        (X1       => Pub_Other_X,
         Y1       => Pub_Other_Y,
         Z1       => LSC.EC.One,
         E        => Priv,
         E_First  => Priv'First,
         E_Last   => Priv'Last,
         X2       => X,
         Y2       => Y,
         Z2       => Z,
         A        => AM,
         M        => P,
         M_Inv    => P_Inv);

      LSC.EC.Make_Affine (X, Y, Z, Shared_X, Shared_Y, RP, P, P_Inv);

      LSC.EC.Point_Mult
        (X1       => Pub_X,
         Y1       => Pub_Y,
         Z1       => LSC.EC.One,
         E        => Priv_Other,
         E_First  => Priv_Other'First,
         E_Last   => Priv_Other'Last,
         X2       => X,
         Y2       => Y,
         Z2       => Z,
         A        => AM,
         M        => P,
         M_Inv    => P_Inv);

      LSC.EC.Make_Affine (X, Y, Z, Shared_Other_X, Shared_Other_Y, RP, P, P_Inv);

      -- Check if shared secrets are equal

      return Shared_X = Shared_Other_X and then Shared_Y = Shared_Other_Y;
   end Test_ECDH;

   function Test_Sign
     (T   : LSC.EC.Signature.Signature_Type;
      Bad : Boolean)
     return Boolean
     --# global RP, AM, RQ, P_Inv, Q_Inv;
     --# pre
     --#   LSC.Bignum.Num_Of_Big_Int (RP, RP'First, P'Last - P'First + 1) =
     --#   LSC.Bignum.Base ** (2 * (P'Last - P'First + 1)) mod
     --#   LSC.Bignum.Num_Of_Big_Int (P, P'First, P'Last - P'First + 1) and
     --#   LSC.Bignum.Num_Of_Big_Int (AM, AM'First, P'Last - P'First + 1) <
     --#   LSC.Bignum.Num_Of_Big_Int (P, P'First, P'Last - P'First + 1) and
     --#   LSC.Bignum.Num_Of_Big_Int (RQ, RQ'First, Q'Last - Q'First + 1) =
     --#   LSC.Bignum.Base ** (2 * (Q'Last - Q'First + 1)) mod
     --#   LSC.Bignum.Num_Of_Big_Int (Q, Q'First, Q'Last - Q'First + 1) and
     --#   1 + P_Inv * P (P'First) = 0 and
     --#   1 + Q_Inv * Q (Q'First) = 0;
   is
      Hash : constant LSC.EC.Coord := LSC.EC.Coord'
        (16#23242526#, 16#1F202122#, 16#1B1C1D1E#, 16#1718191A#, 16#13141516#,
         16#0F101112#, 16#0B0C0D0E#, 16#0708090A#, 16#03040506#, 16#00000102#);
      --# for Hash declare Rule;

      Priv : constant LSC.EC.Coord := LSC.EC.Coord'
        (16#DEADBEEF#, 16#CAFEBABE#, 16#AFFEAFFE#, 16#F000B000#, 16#AFFEAFFE#,
         16#CAFEBABE#, 16#DEADBEEF#, 16#BAFBAFBA#, 16#BABBABBA#, 16#A0000000#);

      Rand : constant LSC.EC.Coord := LSC.EC.Coord'
        (16#2A903BE9#, 16#DDF3DBCF#, 16#97B066DD#, 16#3EFDEF2F#, 16#DE51A1B0#,
         16#9CAF863D#, 16#C8B5C5E7#, 16#B1D0426A#, 16#6624EF2C#, 16#77277D9B#);

      Inv_Priv, PubX, PubY, Sign1, Sign2, X, Y, Z, H : LSC.EC.Coord;

      Success : Boolean;

   begin
      case T is
         when LSC.EC.Signature.ECGDSA =>
            LSC.EC.Invert (Priv, H, RQ, Q, Q_Inv);
            LSC.Bignum.Mont_Mult
              (Inv_Priv, Inv_Priv'First, Inv_Priv'Last,
               H, H'First, LSC.EC.One, LSC.EC.One'First,
               Q, Q'First, Q_Inv);

            LSC.EC.Point_Mult
              (X1       => Base_X,
               Y1       => Base_Y,
               Z1       => LSC.EC.One,
               E        => Inv_Priv,
               E_First  => Inv_Priv'First,
               E_Last   => Inv_Priv'Last,
               X2       => X,
               Y2       => Y,
               Z2       => Z,
               A        => AM,
               M        => P,
               M_Inv    => P_Inv);

         when LSC.EC.Signature.ECDSA =>
            LSC.EC.Point_Mult
              (X1       => Base_X,
               Y1       => Base_Y,
               Z1       => LSC.EC.One,
               E        => Priv,
               E_First  => Priv'First,
               E_Last   => Priv'Last,
               X2       => X,
               Y2       => Y,
               Z2       => Z,
               A        => AM,
               M        => P,
               M_Inv    => P_Inv);
      end case;

      LSC.EC.Make_Affine (X, Y, Z, PubX, PubY, RP, P, P_Inv);

      LSC.EC.Signature.Sign
        (Sign1   => Sign1,
         Sign2   => Sign2,
         Hash    => Hash,
         Rand    => Rand,
         T       => T,
         Priv    => Priv,
         BX      => Base_X,
         BY      => Base_Y,
         A       => AM,
         M       => P,
         M_Inv   => P_Inv,
         RM      => RP,
         N       => Q,
         N_Inv   => Q_Inv,
         RN      => RQ,
         Success => Success);

      -- Check if signature manipulation is detected

      if Bad then
         Sign1 (5) := 12345;
      end if;

      return Success and then
        (LSC.EC.Signature.Verify
           (Sign1 => Sign1,
            Sign2 => Sign2,
            Hash  => Hash,
            T     => T,
            PubX  => PubX,
            PubY  => PubY,
            BX    => Base_X,
            BY    => Base_Y,
            A     => AM,
            M     => P,
            M_Inv => P_Inv,
            RM    => RP,
            N     => Q,
            N_Inv => Q_Inv,
            RN    => RQ) xor Bad);
   end Test_Sign;

begin
   SPARKUnit.Create_Suite (Harness, "EC tests", EC_Suite);

   Precompute_Values;

   SPARKUnit.Create_Test
     (Harness,
      EC_Suite,
      "Check if base point is on curve",
      LSC.EC.On_Curve (Base_X, Base_Y, AM, BM, RP, P, P_Inv));

   SPARKUnit.Create_Test
     (Harness,
      EC_Suite,
      "ECDH key agreement",
      Test_ECDH);

   SPARKUnit.Create_Test
     (Harness,
      EC_Suite,
      "Good ECDSA signature",
      Test_Sign (LSC.EC.Signature.ECDSA, False));

   SPARKUnit.Create_Test
     (Harness,
      EC_Suite,
      "Bad ECDSA signature",
      Test_Sign (LSC.EC.Signature.ECDSA, True));

   SPARKUnit.Create_Test
     (Harness,
      EC_Suite,
      "Good ECGDSA signature",
      Test_Sign (LSC.EC.Signature.ECGDSA, False));

   SPARKUnit.Create_Test
     (Harness,
      EC_Suite,
      "Bad ECGDSA signature",
      Test_Sign (LSC.EC.Signature.ECGDSA, True));
end EC_Tests;
