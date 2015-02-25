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

package body LSC.EC_Signature
is

   pragma Warnings (Off, """V"" may be referenced before it has a value");
   procedure Extract
     (X        : in     Bignum.Big_Int;
      X_First  : in     Natural;
      X_Last   : in     Natural;
      Z        : in     Bignum.Big_Int;
      Z_First  : in     Natural;
      V        :    out Bignum.Big_Int;
      V_First  : in     Natural;
      M        : in     Bignum.Big_Int;
      M_First  : in     Natural;
      M_Inv    : in     Types.Word32;
      RM       : in     Bignum.Big_Int;
      RM_First : in     Natural;
      N        : in     Bignum.Big_Int;
      N_First  : in     Natural;
      N_Inv    : in     Types.Word32;
      RN       : in     Bignum.Big_Int;
      RN_First : in     Natural)
     with
       Depends =>
         (V =>+
            (V_First, X, X_First, X_Last, Z, Z_First,
             M, M_First, M_Inv, RM, RM_First,
             N, N_First, N_Inv, RN, RN_First)),
       Pre =>
         X_First in X'Range and then
         X_Last in X'Range and then
         X_First < X_Last and then
         X_Last - X_First < EC.Max_Coord_Length and then
         Z_First in Z'Range and then
         Z_First + (X_Last - X_First) in Z'Range and then
         V_First in V'Range and then
         V_First + (X_Last - X_First) in V'Range and then
         M_First in M'Range and then
         M_First + (X_Last - X_First) in M'Range and then
         RM_First in RM'Range and then
         RM_First + (X_Last - X_First) in RM'Range and then
         N_First in N'Range and then
         N_First + (X_Last - X_First) in N'Range and then
         RN_First in RN'Range and then
         RN_First + (X_Last - X_First) in RN'Range and then
         Bignum.Num_Of_Big_Int (X, X_First, X_Last - X_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X_Last - X_First + 1) and then
         Bignum.Num_Of_Big_Int (Z, Z_First, X_Last - X_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X_Last - X_First + 1) and then
         Math_Int.From_Word32 (1) <
         Bignum.Num_Of_Big_Int (M, M_First, X_Last - X_First + 1) and then
         1 + M_Inv * M (M_First) = 0 and then
         Math_Int.From_Word32 (1) <
         Bignum.Num_Of_Big_Int (N, N_First, X_Last - X_First + 1) and then
         1 + N_Inv * N (N_First) = 0 and then
         Bignum.Num_Of_Big_Int (RM, RM_First, X_Last - X_First + 1) =
         Bignum.Base ** (Math_Int.From_Integer (2) *
           Math_Int.From_Integer (X_Last - X_First + 1)) mod
         Bignum.Num_Of_Big_Int (M, M_First, X_Last - X_First + 1) and then
         Bignum.Num_Of_Big_Int (RN, RN_First, X_Last - X_First + 1) =
         Bignum.Base ** (Math_Int.From_Integer (2) *
           Math_Int.From_Integer (X_Last - X_First + 1)) mod
         Bignum.Num_Of_Big_Int (N, N_First, X_Last - X_First + 1),
       Post =>
         Bignum.Num_Of_Big_Int (V, V_First, X_Last - X_First + 1) <
         Bignum.Num_Of_Big_Int (N, N_First, X_Last - X_First + 1)
   is
      L : Natural;
      H : EC.Coord;
   begin
      L := X_Last - X_First;

      EC.Invert
        (Z, Z_First, Z_First + L, H, H'First,
         RM, RM_First, M, M_First, M_Inv);

      Bignum.Mont_Mult
        (V, V_First, V_First + L, X, X_First, H, H'First,
         M, M_First, M_Inv);

      Bignum.Mont_Mult
        (H, H'First, H'First + L, V, V_First, EC.One, EC.One'First,
         N, N_First, N_Inv);

      Bignum.Mont_Mult
        (V, V_First, V_First + L, H, H'First, RN, RN_First,
         N, N_First, N_Inv);
   end Extract;
   pragma Warnings (On, """V"" may be referenced before it has a value");

   ----------------------------------------------------------------------------

   procedure Sign
     (Sign1       :    out Bignum.Big_Int;
      Sign1_First : in     Natural;
      Sign1_Last  : in     Natural;
      Sign2       :    out Bignum.Big_Int;
      Sign2_First : in     Natural;
      Hash        : in     Bignum.Big_Int;
      Hash_First  : in     Natural;
      Rand        : in     Bignum.Big_Int;
      Rand_First  : in     Natural;
      T           : in     Signature_Type;
      Priv        : in     Bignum.Big_Int;
      Priv_First  : in     Natural;
      BX          : in     Bignum.Big_Int;
      BX_First    : in     Natural;
      BY          : in     Bignum.Big_Int;
      BY_First    : in     Natural;
      A           : in     Bignum.Big_Int;
      A_First     : in     Natural;
      M           : in     Bignum.Big_Int;
      M_First     : in     Natural;
      M_Inv       : in     Types.Word32;
      RM          : in     Bignum.Big_Int;
      RM_First    : in     Natural;
      N           : in     Bignum.Big_Int;
      N_First     : in     Natural;
      N_Inv       : in     Types.Word32;
      RN          : in     Bignum.Big_Int;
      RN_First    : in     Natural;
      Success     :    out Boolean)
   is
      L : Natural;
      X, Y, Z, PrivR, H1, H2, H3 : EC.Coord;
   begin
      L := Sign1_Last - Sign1_First;

      Bignum.Mont_Mult
        (H1, H1'First, H1'First + L, Hash, Hash_First, EC.One, EC.One'First,
         N, N_First, N_Inv);

      Bignum.Mont_Mult
        (H3, H3'First, H3'First + L, H1, H1'First, RN, RN_First,
         N, N_First, N_Inv);

      pragma Warnings (Off, "unused assignment to ""Y""");
      EC.Point_Mult
        (X1       => BX,
         X1_First => BX_First,
         X1_Last  => BX_First + L,
         Y1       => BY,
         Y1_First => BY_First,
         Z1       => EC.One,
         Z1_First => EC.One'First,
         E        => Rand,
         E_First  => Rand_First,
         E_Last   => Rand_First + L,
         X2       => X,
         X2_First => X'First,
         Y2       => Y,
         Y2_First => Y'First,
         Z2       => Z,
         Z2_First => Z'First,
         A        => A,
         A_First  => A_First,
         M        => M,
         M_First  => M_First,
         M_Inv    => M_Inv);
      pragma Warnings (On, "unused assignment to ""Y""");

      Extract
        (X, X'First, X'First + L, Z, Z'First, Sign1, Sign1_First,
         M, M_First, M_Inv, RM, RM_First,
         N, N_First, N_Inv, RN, RN_First);

      Bignum.Mont_Mult
        (PrivR, PrivR'First, PrivR'First + L, Priv, Priv_First, RN, RN_First,
         N, N_First, N_Inv);

      case T is
         when ECDSA =>
            Bignum.Mont_Mult
              (H1, H1'First, H1'First + L, PrivR, PrivR'First, Sign1, Sign1_First,
               N, N_First, N_Inv);

            Bignum.Mod_Add_Inplace
              (H1, H1'First, H1'First + L, H3, H3'First, N, N_First);

            EC.Invert
              (Rand, Rand_First, Rand_First + L, H2, H2'First,
               RN, RN_First, N, N_First, N_Inv);

            Bignum.Mont_Mult
              (Sign2, Sign2_First, Sign2_First + L, H1, H1'First, H2, H2'First,
               N, N_First, N_Inv);

         when ECGDSA =>
            Bignum.Mont_Mult
              (H1, H1'First, H1'First + L, Rand, Rand_First, RN, RN_First,
               N, N_First, N_Inv);

            Bignum.Mont_Mult
              (H2, H2'First, H2'First + L, H1, H1'First, Sign1, Sign1_First,
               N, N_First, N_Inv);

            Bignum.Mod_Sub_Inplace
              (H2, H2'First, H2'First + L, H3, H3'First, N, N_First);

            Bignum.Mont_Mult
              (Sign2, Sign2_First, Sign2_First + L, H2, H2'First, PrivR, PrivR'First,
               N, N_First, N_Inv);
      end case;

      Success :=
        not Bignum.Is_Zero (Sign1, Sign1_First, Sign1_Last) and then
        not Bignum.Is_Zero (Sign2, Sign2_First, Sign2_First + L);
   end Sign;

   ----------------------------------------------------------------------------

   function Verify
     (Sign1       : Bignum.Big_Int;
      Sign1_First : Natural;
      Sign1_Last  : Natural;
      Sign2       : Bignum.Big_Int;
      Sign2_First : Natural;
      Hash        : Bignum.Big_Int;
      Hash_First  : Natural;
      T           : Signature_Type;
      PubX        : Bignum.Big_Int;
      PubX_First  : Natural;
      PubY        : Bignum.Big_Int;
      PubY_First  : Natural;
      BX          : Bignum.Big_Int;
      BX_First    : Natural;
      BY          : Bignum.Big_Int;
      BY_First    : Natural;
      A           : Bignum.Big_Int;
      A_First     : Natural;
      M           : Bignum.Big_Int;
      M_First     : Natural;
      M_Inv       : Types.Word32;
      RM          : Bignum.Big_Int;
      RM_First    : Natural;
      N           : Bignum.Big_Int;
      N_First     : Natural;
      N_Inv       : Types.Word32;
      RN          : Bignum.Big_Int;
      RN_First    : Natural)
     return Boolean
   is
      L : Natural;
      Result : Boolean;
      H1, H2, H, X, Y, Z, V : EC.Coord;
   begin
      L := Sign1_Last - Sign1_First;

      if
        not Bignum.Is_Zero (Sign1, Sign1_First, Sign1_Last) and then
        Bignum.Less (Sign1, Sign1_First, Sign1_Last, N, N_First) and then
        not Bignum.Is_Zero (Sign2, Sign2_First, Sign2_First + L) and then
        Bignum.Less (Sign2, Sign2_First, Sign2_First + L, N, N_First)
      then
         case T is
            when ECDSA =>
               EC.Invert
                 (Sign2, Sign2_First, Sign2_First + L, H, H'First,
                  RN, RN_First, N, N_First, N_Inv);

               Bignum.Mont_Mult
                 (H2, H2'First, H2'First + L, Sign1, Sign1_First, H, H'First,
                  N, N_First, N_Inv);

            when ECGDSA =>
               EC.Invert
                 (Sign1, Sign1_First, Sign1_Last, H, H'First,
                  RN, RN_First, N, N_First, N_Inv);

               Bignum.Mont_Mult
                 (H2, H2'First, H2'First + L, Sign2, Sign2_First, H, H'First,
                  N, N_First, N_Inv);
         end case;

         Bignum.Mont_Mult
           (H1, H1'First, H1'First + L, Hash, Hash_First, H, H'First,
            N, N_First, N_Inv);

         pragma Warnings (Off, "unused assignment to ""Y""");
         EC.Two_Point_Mult
           (X1       => BX,
            X1_First => BX_First,
            X1_Last  => BX_First + L,
            Y1       => BY,
            Y1_First => BY_First,
            Z1       => EC.One,
            Z1_First => EC.One'First,
            E1       => H1,
            E1_First => H1'First,
            E1_Last  => H1'First + L,
            X2       => PubX,
            X2_First => PubX_First,
            Y2       => PubY,
            Y2_First => PubY_First,
            Z2       => EC.One,
            Z2_First => EC.One'First,
            E2       => H2,
            E2_First => H2'First,
            X3       => X,
            X3_First => X'First,
            Y3       => Y,
            Y3_First => Y'First,
            Z3       => Z,
            Z3_First => Z'First,
            A        => A,
            A_First  => A_First,
            M        => M,
            M_First  => M_First,
            M_Inv    => M_Inv);
         pragma Warnings (On, "unused assignment to ""Y""");

         Extract
           (X, X'First, X'First + L, Z, Z'First, V, V'First,
            M, M_First, M_Inv, RM, RM_First,
            N, N_First, N_Inv, RN, RN_First);

         Result := Bignum.Equal
           (Sign1, Sign1_First, Sign1_Last, V, V'First);
      else
         Result := False;
      end if;

      return Result;
   end Verify;

end LSC.EC_Signature;
