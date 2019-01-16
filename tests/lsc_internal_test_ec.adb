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

with LSC.Internal.Types;
with LSC.Internal.Bignum;
with LSC.Internal.EC;
with LSC.Internal.EC_Signature;
with AUnit.Assertions; use AUnit.Assertions;
with Interfaces;

use type LSC.Internal.Bignum.Big_Int;
use type LSC.Internal.EC_Signature.Signature_Type;

package body LSC_Internal_Test_EC
is
   subtype Coord_Index is Natural range 0 .. 16;
   subtype Coord is LSC.Internal.Bignum.Big_Int (Coord_Index);

   ---------------------------------------------------------------------------

   procedure Precompute_Values (P, A, B, Q     : Coord;
                                RP, AM, BM, RQ : out Coord;
                                P_Inv, Q_Inv   : out LSC.Internal.Types.Word32)
   is
   begin
      LSC.Internal.Bignum.Size_Square_Mod (P, P'First, P'Last, RP, RP'First);
      P_Inv := LSC.Internal.Bignum.Word_Inverse (P (P'First));

      LSC.Internal.Bignum.Size_Square_Mod (Q, Q'First, Q'Last, RQ, RQ'First);
      Q_Inv := LSC.Internal.Bignum.Word_Inverse (Q (Q'First));

      LSC.Internal.Bignum.Mont_Mult
        (AM, AM'First, AM'Last, A, A'First, RP, RP'First,
         P, P'First, P_Inv);

      LSC.Internal.Bignum.Mont_Mult
        (BM, BM'First, BM'Last, B, B'First, RP, RP'First,
         P, P'First, P_Inv);
   end Precompute_Values;

   ---------------------------------------------------------------------------

   -- 521-bit elliptic curve, see RFC 4753 / 4754

   P : constant Coord := Coord'
     (16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#,
      16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#,
      16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#,
      16#FFFFFFFF#, 16#000001FF#);

   A : constant Coord := Coord'
     (16#FFFFFFFC#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#,
      16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#,
      16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#,
      16#FFFFFFFF#, 16#000001FF#);

   B : constant Coord := Coord'
     (16#6B503F00#, 16#EF451FD4#, 16#3D2C34F1#, 16#3573DF88#, 16#3BB1BF07#,
      16#1652C0BD#, 16#EC7E937B#, 16#56193951#, 16#8EF109E1#, 16#B8B48991#,
      16#99B315F3#, 16#A2DA725B#, 16#B68540EE#, 16#929A21A0#, 16#8E1C9A1F#,
      16#953EB961#, 16#00000051#);

   Base_X : constant Coord := Coord'
     (16#C2E5BD66#, 16#F97E7E31#, 16#856A429B#, 16#3348B3C1#, 16#A2FFA8DE#,
      16#FE1DC127#, 16#EFE75928#, 16#A14B5E77#, 16#6B4D3DBA#, 16#F828AF60#,
      16#053FB521#, 16#9C648139#, 16#2395B442#, 16#9E3ECB66#, 16#0404E9CD#,
      16#858E06B7#, 16#000000C6#);

   Base_Y : constant Coord := Coord'
     (16#9FD16650#, 16#88BE9476#, 16#A272C240#, 16#353C7086#, 16#3FAD0761#,
      16#C550B901#, 16#5EF42640#, 16#97EE7299#, 16#273E662C#, 16#17AFBD17#,
      16#579B4468#, 16#98F54449#, 16#2C7D1BD9#, 16#5C8A5FB4#, 16#9A3BC004#,
      16#39296A78#, 16#00000118#);

   Q : constant Coord := Coord'
     (16#91386409#, 16#BB6FB71E#, 16#899C47AE#, 16#3BB5C9B8#, 16#F709A5D0#,
      16#7FCC0148#, 16#BF2F966B#, 16#51868783#, 16#FFFFFFFA#, 16#FFFFFFFF#,
      16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#,
      16#FFFFFFFF#, 16#000001FF#);

   ---------------------------------------------------------------------------

   -- See RFC 4753 (section 8.3) for test values

   procedure Test_ECDH (T : in out Test_Cases.Test_Case'Class)
   is
      Priv : constant Coord := Coord'
        (16#382D4A52#, 16#68C27A57#, 16#B072462F#, 16#7B2639BA#, 16#9777F595#,
         16#71D937BA#, 16#C2952C67#, 16#85A30FE1#, 16#72A095AA#, 16#CE476081#,
         16#57B5393D#, 16#3C61ACAB#, 16#ACCCA512#, 16#B3EF411A#, 16#89F4DABD#,
         16#ADE9319A#, 16#00000037#);

      Priv_Other : constant Coord := Coord'
        (16#51685EB9#, 16#311F5CB1#, 16#A4A4EFFC#, 16#CCA7458A#, 16#E4C2F869#,
         16#BF2A3163#, 16#3757A3BD#, 16#7D600B34#, 16#201E9C67#, 16#3F078380#,
         16#0F97BCCC#, 16#E30FDC78#, 16#7CDFA16B#, 16#DD0E872E#, 16#AF43793F#,
         16#BA99A847#, 16#00000145#);

      Shared_Expected_X : constant Coord := Coord'
        (16#19F3DDEA#, 16#E417996D#, 16#3151F2BE#, 16#15A3A8CC#, 16#0C06B3C7#,
         16#78685981#, 16#AA240A34#, 16#7E73CA4B#, 16#9B04D142#, 16#E5E6B2D7#,
         16#07F97894#, 16#086FA644#, 16#7C4521CB#, 16#DB8E7C78#, 16#6956BC8E#,
         16#4C7D79AE#, 16#00000114#);

      Shared_Expected_Y : constant Coord := Coord'
        (16#9BAFFA43#, 16#8569D6C9#, 16#E0BDD1F8#, 16#E8DA1B38#, 16#0C3EB622#,
         16#E5B3A8E5#, 16#EDB1E13C#, 16#3C63EA05#, 16#ADAA9FFC#, 16#5D1B5242#,
         16#18D078E0#, 16#CFE59CDA#, 16#1C1674E5#, 16#17D853EF#, 16#B2947AC0#,
         16#01E6B17D#, 16#000001B9#);

      Pub_X, Pub_Y, Pub_Other_X, Pub_Other_Y : Coord;
      Shared_X, Shared_Y, Shared_Other_X, Shared_Other_Y : Coord;

      X, Y, Z : Coord;
      RP, AM, BM, RQ : Coord;
      P_Inv, Q_Inv : LSC.Internal.Types.Word32;

   begin
      Precompute_Values (P, A, B, Q, RP, AM, BM, RQ, P_Inv, Q_Inv);

      -- Compute public values from secrets

      LSC.Internal.EC.Point_Mult
        (X1       => Base_X,
         X1_First => Base_X'First,
         X1_Last  => Base_X'Last,
         Y1       => Base_Y,
         Y1_First => Base_Y'First,
         Z1       => LSC.Internal.EC.One,
         Z1_First => LSC.Internal.EC.One'First,
         E        => Priv,
         E_First  => Priv'First,
         E_Last   => Priv'Last,
         X2       => X,
         X2_First => X'First,
         Y2       => Y,
         Y2_First => Y'First,
         Z2       => Z,
         Z2_First => Z'First,
         A        => AM,
         A_First  => AM'First,
         M        => P,
         M_First  => P'First,
         M_Inv    => P_Inv);

      LSC.Internal.EC.Make_Affine
        (X, X'First, X'Last, Y, Y'First, Z, Z'First,
         Pub_X, Pub_X'First, Pub_Y, Pub_Y'First,
         RP, RP'First, P, P'First, P_Inv);

      LSC.Internal.EC.Point_Mult
        (X1       => Base_X,
         X1_First => Base_X'First,
         X1_Last  => Base_X'Last,
         Y1       => Base_Y,
         Y1_First => Base_Y'First,
         Z1       => LSC.Internal.EC.One,
         Z1_First => LSC.Internal.EC.One'First,
         E        => Priv_Other,
         E_First  => Priv_Other'First,
         E_Last   => Priv_Other'Last,
         X2       => X,
         X2_First => X'First,
         Y2       => Y,
         Y2_First => Y'First,
         Z2       => Z,
         Z2_First => Z'First,
         A        => AM,
         A_First  => AM'First,
         M        => P,
         M_First  => P'First,
         M_Inv    => P_Inv);

      LSC.Internal.EC.Make_Affine
        (X, X'First, X'Last, Y, Y'First, Z, Z'First,
         Pub_Other_X, Pub_Other_X'First, Pub_Other_Y, Pub_Other_Y'First,
         RP, RP'First, P, P'First, P_Inv);

      -- Now compute shared secret

      LSC.Internal.EC.Point_Mult
        (X1       => Pub_Other_X,
         X1_First => Pub_Other_X'First,
         X1_Last  => Pub_Other_X'Last,
         Y1       => Pub_Other_Y,
         Y1_First => Pub_Other_Y'First,
         Z1       => LSC.Internal.EC.One,
         Z1_First => LSC.Internal.EC.One'First,
         E        => Priv,
         E_First  => Priv'First,
         E_Last   => Priv'Last,
         X2       => X,
         X2_First => X'First,
         Y2       => Y,
         Y2_First => Y'First,
         Z2       => Z,
         Z2_First => Z'First,
         A        => AM,
         A_First  => AM'First,
         M        => P,
         M_First  => P'First,
         M_Inv    => P_Inv);

      LSC.Internal.EC.Make_Affine
        (X, X'First, X'Last, Y, Y'First, Z, Z'First,
         Shared_X, Shared_X'First, Shared_Y, Shared_Y'First,
         RP, RP'First, P, P'First, P_Inv);

      LSC.Internal.EC.Point_Mult
        (X1       => Pub_X,
         X1_First => Pub_X'First,
         X1_Last  => Pub_X'Last,
         Y1       => Pub_Y,
         Y1_First => Pub_Y'First,
         Z1       => LSC.Internal.EC.One,
         Z1_First => LSC.Internal.EC.One'First,
         E        => Priv_Other,
         E_First  => Priv_Other'First,
         E_Last   => Priv_Other'Last,
         X2       => X,
         X2_First => X'First,
         Y2       => Y,
         Y2_First => Y'First,
         Z2       => Z,
         Z2_First => Z'First,
         A        => AM,
         A_First  => AM'First,
         M        => P,
         M_First  => P'First,
         M_Inv    => P_Inv);

      LSC.Internal.EC.Make_Affine
        (X, X'First, X'Last, Y, Y'First, Z, Z'First,
         Shared_Other_X, Shared_Other_X'First, Shared_Other_Y, Shared_Other_Y'First,
         RP, RP'First, P, P'First, P_Inv);

      -- Check if shared secrets are equal

      Assert
        (Shared_X = Shared_Other_X and then Shared_Y = Shared_Other_Y and then
         Shared_X = Shared_Expected_X and then Shared_Y = Shared_Expected_Y,
         "Invalid ECDH operation");
   end Test_ECDH;

   ---------------------------------------------------------------------------

   -- See RFC 4754 (section 8.3) for test values

   function Test_Sign
     (T   : LSC.Internal.EC_Signature.Signature_Type;
      Bad : Boolean)
     return Boolean
   is
      Hash : constant Coord := Coord'
        (16#A54CA49F#, 16#2A9AC94F#, 16#643CE80E#, 16#454D4423#, 16#A3FEEBBD#,
         16#36BA3C23#, 16#274FC1A8#, 16#2192992A#, 16#4B55D39A#, 16#0A9EEEE6#,
         16#89A97EA2#, 16#12E6FA4E#, 16#AE204131#, 16#CC417349#, 16#93617ABA#,
         16#DDAF35A1#, 16#00000000#);

      Priv : constant Coord := Coord'
        (16#8B375FA1#, 16#C5B153B4#, 16#0C5D5481#, 16#62E95C7E#, 16#0FFAD6F0#,
         16#ADF78B57#, 16#7FF9D704#, 16#7779060A#, 16#84912059#, 16#209D7DF5#,
         16#34BDF8C1#, 16#13C17BFD#, 16#5112A3D8#, 16#0EAD4549#, 16#51DCAB0A#,
         16#FDA34094#, 16#00000065#);

      Rand : constant Coord := Coord'
        (16#1B956C2F#, 16#0B1B7F0C#, 16#C3378A54#, 16#BD7382CF#, 16#42F9B4A4#,
         16#825FF24F#, 16#6497B1EF#, 16#78F9DE6B#, 16#46F93737#, 16#42B8B62F#,
         16#7A9B2443#, 16#96F55619#, 16#933D7340#, 16#4D7E4359#, 16#9F5A4134#,
         16#C2B30541#, 16#000000C1#);

      -- RFC 4754 only specifies expected results for ECDSA

      Sign1_Expected : constant Coord := Coord'
        (16#20552251#, 16#ACEE5443#, 16#D9362CAE#, 16#0ED7DBB8#, 16#4A927888#,
         16#D93CF879#, 16#0B22C269#, 16#2F281A7E#, 16#4339B19F#, 16#B68E2E6F#,
         16#8FC6AAAA#, 16#34FDE831#, 16#30539885#, 16#7DD5341D#, 16#92D0DCA5#,
         16#FD3836AF#, 16#00000154#);

      Sign2_Expected : constant Coord := Coord'
        (16#66472660#, 16#C68D62F8#, 16#51AE01AA#, 16#9E70AAC8#, 16#9534FA50#,
         16#BF2F3D23#, 16#D1CF9BCC#, 16#67101F67#, 16#2DF49753#, 16#8C10C836#,
         16#96EC926C#, 16#521E87A6#, 16#03FF9CDD#, 16#05A9A1BB#, 16#90D1CEB6#,
         16#05A70302#, 16#00000177#);

      Inv_Priv, PubX, PubY, Sign1, Sign2, X, Y, Z, H : Coord;
      Success : Boolean;
      RP, AM, BM, RQ : Coord;
      P_Inv, Q_Inv : LSC.Internal.Types.Word32;

   begin

      Precompute_Values (P, A, B, Q, RP, AM, BM, RQ, P_Inv, Q_Inv);

      case T is
         when LSC.Internal.EC_Signature.ECGDSA =>
            LSC.Internal.EC.Invert
              (Priv, Priv'First, Priv'Last, H, H'First,
               RQ, RQ'First, Q, Q'First, Q_Inv);
            LSC.Internal.Bignum.Mont_Mult
              (Inv_Priv, Inv_Priv'First, Inv_Priv'Last,
               H, H'First, LSC.Internal.EC.One, LSC.Internal.EC.One'First,
               Q, Q'First, Q_Inv);

            LSC.Internal.EC.Point_Mult
              (X1       => Base_X,
               X1_First => Base_X'First,
               X1_Last  => Base_X'Last,
               Y1       => Base_Y,
               Y1_First => Base_Y'First,
               Z1       => LSC.Internal.EC.One,
               Z1_First => LSC.Internal.EC.One'First,
               E        => Inv_Priv,
               E_First  => Inv_Priv'First,
               E_Last   => Inv_Priv'Last,
               X2       => X,
               X2_First => X'First,
               Y2       => Y,
               Y2_First => Y'First,
               Z2       => Z,
               Z2_First => Z'First,
               A        => AM,
               A_First  => AM'First,
               M        => P,
               M_First  => P'First,
               M_Inv    => P_Inv);

         when LSC.Internal.EC_Signature.ECDSA =>
            LSC.Internal.EC.Point_Mult
              (X1       => Base_X,
               X1_First => Base_X'First,
               X1_Last  => Base_X'Last,
               Y1       => Base_Y,
               Y1_First => Base_Y'First,
               Z1       => LSC.Internal.EC.One,
               Z1_First => LSC.Internal.EC.One'First,
               E        => Priv,
               E_First  => Priv'First,
               E_Last   => Priv'Last,
               X2       => X,
               X2_First => X'First,
               Y2       => Y,
               Y2_First => Y'First,
               Z2       => Z,
               Z2_First => Z'First,
               A        => AM,
               A_First  => AM'First,
               M        => P,
               M_First  => P'First,
               M_Inv    => P_Inv);
      end case;

      LSC.Internal.EC.Make_Affine
        (X, X'First, X'Last, Y, Y'First, Z, Z'First,
         PubX, PubX'First, PubY, PubY'First,
         RP, RP'First, P, P'First, P_Inv);

      LSC.Internal.EC_Signature.Sign
        (Sign1       => Sign1,
         Sign1_First => Sign1'First,
         Sign1_Last  => Sign1'Last,
         Sign2       => Sign2,
         Sign2_First => Sign2'First,
         Hash        => Hash,
         Hash_First  => Hash'First,
         Rand        => Rand,
         Rand_First  => Rand'First,
         T           => T,
         Priv        => Priv,
         Priv_First  => Priv'First,
         BX          => Base_X,
         BX_First    => Base_X'First,
         BY          => Base_Y,
         BY_First    => Base_Y'First,
         A           => AM,
         A_First     => AM'First,
         M           => P,
         M_First     => P'First,
         M_Inv       => P_Inv,
         RM          => RP,
         RM_First    => RP'First,
         N           => Q,
         N_First     => Q'First,
         N_Inv       => Q_Inv,
         RN          => RQ,
         RN_First    => RQ'First,
         Success     => Success);

      -- Check if signature manipulation is detected

      if Bad then
         Sign1 (5) := 12345;
      end if;

      return
        Success and then
        (Bad or else T = LSC.Internal.EC_Signature.ECGDSA or else
           (Sign1 = Sign1_Expected and then Sign2 = Sign2_Expected)) and then
        (LSC.Internal.EC_Signature.Verify
           (Sign1       => Sign1,
            Sign1_First => Sign1'First,
            Sign1_Last  => Sign1'Last,
            Sign2       => Sign2,
            Sign2_First => Sign2'First,
            Hash        => Hash,
            Hash_First  => Hash'First,
            T           => T,
            PubX        => PubX,
            PubX_First  => PubX'First,
            PubY        => PubY,
            PubY_First  => PubY'First,
            BX          => Base_X,
            BX_First    => Base_X'First,
            BY          => Base_Y,
            BY_First    => Base_Y'First,
            A           => AM,
            A_First     => AM'First,
            M           => P,
            M_First     => P'First,
            M_Inv       => P_Inv,
            RM          => RP,
            RM_First    => RP'First,
            N           => Q,
            N_First     => Q'First,
            N_Inv       => Q_Inv,
            RN          => RQ,
            RN_First    => RQ'First) xor Bad);
   end Test_Sign;

   ---------------------------------------------------------------------------

   procedure Test_Uncompress_Point(T : in out Test_Cases.Test_Case'Class)
   is
      Y : Coord;
      Success : Boolean;
      RP, AM, BM, RQ : Coord;
      P_Inv, Q_Inv : LSC.Internal.Types.Word32;
   begin
      Precompute_Values (P, A, B, Q, RP, AM, BM, RQ, P_Inv, Q_Inv);

      LSC.Internal.EC.Uncompress_Point
        (X       => Base_X,
         X_First => Base_X'First,
         X_Last  => Base_X'Last,
         Even    => True,
         A       => AM,
         A_First => AM'First,
         B       => BM,
         B_First => BM'First,
         R       => RP,
         R_First => RP'First,
         M       => P,
         M_First => P'First,
         M_Inv   => P_Inv,
         Y       => Y,
         Y_First => Y'First,
         Success => Success);

      Assert (Success and then Y = Base_Y, "Invalid");

   end Test_Uncompress_Point;

   ---------------------------------------------------------------------------

   procedure Test_Bad_ECDSA_Signature (T : in out Test_Cases.Test_Case'Class)
   is
   begin
      Assert (Test_Sign (LSC.Internal.EC_Signature.ECDSA, True), "Invalid");
   end Test_Bad_ECDSA_Signature;

   ---------------------------------------------------------------------------

   procedure Test_Good_ECDSA_Signature (T : in out Test_Cases.Test_Case'Class)
   is
   begin
      Assert (Test_Sign (LSC.Internal.EC_Signature.ECDSA, False), "Invalid");
   end Test_Good_ECDSA_Signature;

   ---------------------------------------------------------------------------

   procedure Test_Bad_ECGDSA_Signature (T : in out Test_Cases.Test_Case'Class)
   is
   begin
      Assert (Test_Sign (LSC.Internal.EC_Signature.ECGDSA, True), "Invalid");
   end Test_Bad_ECGDSA_Signature;

   ---------------------------------------------------------------------------

   procedure Test_Good_ECGDSA_Signature (T : in out Test_Cases.Test_Case'Class)
   is
   begin
      Assert (Test_Sign (LSC.Internal.EC_Signature.ECGDSA, False), "Invalid");
   end Test_Good_ECGDSA_Signature;

   ---------------------------------------------------------------------------

   procedure Test_Base_Point_On_Curve (T : in out Test_Cases.Test_Case'Class)
   is
      RP, AM, BM, RQ : Coord;
      P_Inv, Q_Inv : LSC.Internal.Types.Word32;
   begin
      Precompute_Values (P, A, B, Q, RP, AM, BM, RQ, P_Inv, Q_Inv);

      Assert
         (LSC.Internal.EC.On_Curve
           (Base_X, Base_X'First, Base_X'Last, Base_Y, Base_Y'First,
            AM, AM'First, BM, BM'First, RP, RP'First, P, P'First, P_Inv), "Invalid");
   end Test_Base_Point_On_Curve;

   ---------------------------------------------------------------------------

   procedure Register_Tests (T: in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (T, Test_Base_Point_On_Curve'Access, "Base point on curve");
      Register_Routine (T, Test_ECDH'Access, "ECDH key agreement");
      Register_Routine (T, Test_Bad_ECDSA_Signature'Access, "ECDSA signature (bad)");
      Register_Routine (T, Test_Good_ECDSA_Signature'Access, "ECDSA signature (good)");
      Register_Routine (T, Test_Bad_ECGDSA_Signature'Access, "ECGDSA signature (bad)");
      Register_Routine (T, Test_Good_ECGDSA_Signature'Access, "ECGDSA signature (good)");
      Register_Routine (T, Test_Uncompress_Point'Access, "Uncompress point");
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("EC");
   end Name;

end LSC_Internal_Test_EC;
