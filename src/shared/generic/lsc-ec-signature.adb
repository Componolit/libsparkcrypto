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

with LSC.Bignum;

package body LSC.EC.Signature
is

   procedure Extract
     (X     : in     EC.Coord;
      Z     : in     EC.Coord;
      V     :    out EC.Coord;
      M     : in     EC.Coord;
      M_Inv : in     Types.Word32;
      RM    : in     EC.Coord;
      N     : in     EC.Coord;
      N_Inv : in     Types.Word32;
      RN    : in     EC.Coord)
   --# derives
   --#   V from X, Z, M, M_Inv, RM, N, N_Inv, RN;
   --# pre
   --#   Bignum.Num_Of_Big_Int (X, X'First, X'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Z, Z'First, Z'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 < Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 + M_Inv * M (M'First) = 0 and
   --#   1 < Bignum.Num_Of_Big_Int (N, N'First, M'Length) and
   --#   1 + N_Inv * N (N'First) = 0 and
   --#   Bignum.Num_Of_Big_Int (RM, RM'First, RM'Length) =
   --#   Bignum.Base ** (2 * RM'Length) mod
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (RN, RN'First, RN'Length) =
   --#   Bignum.Base ** (2 * RN'Length) mod
   --#   Bignum.Num_Of_Big_Int (N, N'First, N'Length);
   --# post
   --#   Bignum.Num_Of_Big_Int (V, V'First, V'Length) <
   --#   Bignum.Num_Of_Big_Int (N, N'First, N'Length);
   is
      H : EC.Coord;
   begin
      EC.Invert (Z, H, RM, M, M_Inv);

      Bignum.Mont_Mult
        (V, V'First, V'Last, X, X'First, H, H'First,
         M, M'First, M_Inv);

      Bignum.Mont_Mult
        (H, H'First, H'Last, V, V'First, EC.One, EC.One'First,
         N, N'First, N_Inv);

      Bignum.Mont_Mult
        (V, V'First, V'Last, H, H'First, RN, RN'First,
         N, N'First, N_Inv);
   end Extract;

   ----------------------------------------------------------------------------

   procedure Sign
     (Sign1   :    out EC.Coord;
      Sign2   :    out EC.Coord;
      Hash    : in     EC.Coord;
      Rand    : in     EC.Coord;
      T       : in     Signature_Type;
      Priv    : in     EC.Coord;
      BX      : in     EC.Coord;
      BY      : in     EC.Coord;
      A       : in     EC.Coord;
      M       : in     EC.Coord;
      M_Inv   : in     Types.Word32;
      RM      : in     EC.Coord;
      N       : in     EC.Coord;
      N_Inv   : in     Types.Word32;
      RN      : in     EC.Coord;
      Success :    out Boolean)
   is
      X, Y, Z, PrivR, H1, H2 : EC.Coord;
   begin
      --# accept Flow, 10, Y, "Y not needed here";
      EC.Point_Mult
        (X1      => BX,
         Y1      => BY,
         Z1      => EC.One,
         E       => Rand,
         E_First => Rand'First,
         E_Last  => Rand'Last,
         X2      => X,
         Y2      => Y,
         Z2      => Z,
         A       => A,
         M       => M,
         M_Inv   => M_Inv);
      --# end accept;

      Extract (X, Z, Sign1, M, M_Inv, RM, N, N_Inv, RN);

      Bignum.Mont_Mult
        (PrivR, PrivR'First, PrivR'Last, Priv, Priv'First, RN, RN'First,
         N, N'First, N_Inv);

      case T is
         when ECDSA =>
            Bignum.Mont_Mult
              (H1, H1'First, H1'Last, PrivR, PrivR'First, Sign1, Sign1'First,
               N, N'First, N_Inv);

            Bignum.Mod_Add_Inplace
              (H1, H1'First, H1'Last, Hash, Hash'First, N, N'First);

            EC.Invert (Rand, H2, RN, N, N_Inv);

            Bignum.Mont_Mult
              (Sign2, Sign2'First, Sign2'Last, H1, H1'First, H2, H2'First,
               N, N'First, N_Inv);

         when ECGDSA =>
            Bignum.Mont_Mult
              (H1, H1'First, H1'Last, Rand, Rand'First, RN, RN'First,
               N, N'First, N_Inv);

            Bignum.Mont_Mult
              (H2, H2'First, H2'Last, H1, H1'First, Sign1, Sign1'First,
               N, N'First, N_Inv);

            Bignum.Mod_Sub_Inplace
              (H2, H2'First, H2'Last, Hash, Hash'First, N, N'First);

            Bignum.Mont_Mult
              (Sign2, Sign2'First, Sign2'Last, H2, H2'First, PrivR, PrivR'First,
               N, N'First, N_Inv);
      end case;

      Success :=
        not Bignum.Is_Zero (Sign1, Sign1'First, Sign1'Last) and then
        not Bignum.Is_Zero (Sign2, Sign2'First, Sign2'Last);
      --# accept Flow, 33, Y, "Y not needed here";
   end Sign;

   ----------------------------------------------------------------------------

   function Verify
     (Sign1 : EC.Coord;
      Sign2 : EC.Coord;
      Hash  : EC.Coord;
      T     : Signature_Type;
      PubX  : EC.Coord;
      PubY  : EC.Coord;
      BX    : EC.Coord;
      BY    : EC.Coord;
      A     : EC.Coord;
      M     : EC.Coord;
      M_Inv : Types.Word32;
      RM    : EC.Coord;
      N     : EC.Coord;
      N_Inv : Types.Word32;
      RN    : EC.Coord)
     return Boolean
   is
      Result : Boolean;
      H1, H2, H, X, Y, Z, V : EC.Coord;
   begin
      if
        not Bignum.Is_Zero (Sign1, Sign1'First, Sign1'Last) and then
        Bignum.Less (Sign1, Sign1'First, Sign1'Last, N, N'First) and then
        not Bignum.Is_Zero (Sign2, Sign2'First, Sign2'Last) and then
        Bignum.Less (Sign2, Sign2'First, Sign2'Last, N, N'First)
      then
         case T is
            when ECDSA =>
               EC.Invert (Sign2, H, RN, N, N_Inv);

               Bignum.Mont_Mult
                 (H2, H2'First, H2'Last, Sign1, Sign1'First, H, H'First,
                  N, N'First, N_Inv);

            when ECGDSA =>
               EC.Invert (Sign1, H, RN, N, N_Inv);

               Bignum.Mont_Mult
                 (H2, H2'First, H2'Last, Sign2, Sign2'First, H, H'First,
                  N, N'First, N_Inv);
         end case;

         Bignum.Mont_Mult
           (H1, H1'First, H1'Last, Hash, Hash'First, H, H'First,
            N, N'First, N_Inv);

         --# accept Flow, 10, Y, "Y not needed here";
         EC.Two_Point_Mult
           (X1       => BX,
            Y1       => BY,
            Z1       => EC.One,
            E1       => H1,
            E1_First => H1'First,
            E1_Last  => H1'Last,
            X2       => PubX,
            Y2       => PubY,
            Z2       => EC.One,
            E2       => H2,
            E2_First => H2'First,
            X3       => X,
            Y3       => Y,
            Z3       => Z,
            A        => A,
            M        => M,
            M_Inv    => M_Inv);
         --# end accept;

         Extract (X, Z, V, M, M_Inv, RM, N, N_Inv, RN);

         Result := Bignum.Equal
           (Sign1, Sign1'First, Sign1'Last, V, V'First);
      else
         Result := False;
      end if;

      --# accept Flow, 33, Y, "Y not needed here";
      return Result;
   end Verify;

end LSC.EC.Signature;
