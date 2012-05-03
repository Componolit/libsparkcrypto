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

with LSC.Types;
with LSC.Bignum;

use type LSC.Types.Word32;

--# inherit
--#   LSC.Types,
--#   LSC.Bignum;

package LSC.EC
is

   Coord_Length : constant := 10;
   subtype Coord_Index is Natural range 0 .. Coord_Length - 1;
   subtype Coord is Bignum.Big_Int (Coord_Index);

   One : constant Coord := Coord'(1, others => 0);
   --# for One declare Rule;

   procedure Point_Double
     (X1       : in     Coord;
      Y1       : in     Coord;
      Z1       : in     Coord;
      X2       :    out Coord;
      Y2       :    out Coord;
      Z2       :    out Coord;
      A        : in     Coord;
      M        : in     Coord;
      M_Inv    : in     Types.Word32);
   --# derives
   --#   X2, Y2 from X1, Y1, Z1, A, M, M_Inv &
   --#   Z2 from Y1, Z1, M, M_Inv;
   --# pre
   --#   Bignum.Num_Of_Big_Int (X1, X1'First, X1'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Y1, Y1'First, Y1'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Z1, Z1'First, Z1'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (A, A'First, A'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 < Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 + M_Inv * M (M'First) = 0;
   --# post
   --#   Bignum.Num_Of_Big_Int (X2, X2'First, X2'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Y2, Y2'First, Y2'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Z2, Z2'First, Z2'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length);

   procedure Point_Add
     (X1       : in     Coord;
      Y1       : in     Coord;
      Z1       : in     Coord;
      X2       : in     Coord;
      Y2       : in     Coord;
      Z2       : in     Coord;
      X3       :    out Coord;
      Y3       :    out Coord;
      Z3       :    out Coord;
      A        : in     Coord;
      M        : in     Coord;
      M_Inv    : in     Types.Word32);
   --# derives
   --#   X3, Y3 from X1, Y1, Z1, X2, Y2, Z2, A, M, M_Inv &
   --#   Z3 from X1, Y1, Z1, X2, Y2, Z2, M, M_Inv;
   --# pre
   --#   Bignum.Num_Of_Big_Int (X1, X1'First, X1'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Y1, Y1'First, Y1'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Z1, Z1'First, Z1'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (X2, X2'First, X2'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Y2, Y2'First, Y2'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Z2, Z2'First, Z2'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (A, A'First, A'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 < Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 + M_Inv * M (M'First) = 0;
   --# post
   --#   Bignum.Num_Of_Big_Int (X3, X3'First, X3'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Y3, Y3'First, Y3'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Z3, Z3'First, Z3'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length);

   procedure Point_Mult
     (X1       : in     Coord;
      Y1       : in     Coord;
      Z1       : in     Coord;
      E        : in     Bignum.Big_Int;
      E_First  : in     Natural;
      E_Last   : in     Natural;
      X2       :    out Coord;
      Y2       :    out Coord;
      Z2       :    out Coord;
      A        : in     Coord;
      M        : in     Coord;
      M_Inv    : in     Types.Word32);
   --# derives
   --#   X2, Y2, Z2 from X1, Y1, Z1, E, E_First, E_Last, A, M, M_Inv;
   --# pre
   --#   E_First in E'Range and
   --#   E_Last in E'Range and
   --#   E_First <= E_Last and
   --#   Bignum.Num_Of_Big_Int (X1, X1'First, X1'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Y1, Y1'First, Y1'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Z1, Z1'First, Z1'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (A, A'First, A'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 < Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 + M_Inv * M (M'First) = 0;
   --# post
   --#   Bignum.Num_Of_Big_Int (X2, X2'First, X2'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Y2, Y2'First, Y2'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Z2, Z2'First, Z2'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length);

   procedure Two_Point_Mult
     (X1       : in     Coord;
      Y1       : in     Coord;
      Z1       : in     Coord;
      E1       : in     Bignum.Big_Int;
      E1_First : in     Natural;
      E1_Last  : in     Natural;
      X2       : in     Coord;
      Y2       : in     Coord;
      Z2       : in     Coord;
      E2       : in     Bignum.Big_Int;
      E2_First : in     Natural;
      X3       :    out Coord;
      Y3       :    out Coord;
      Z3       :    out Coord;
      A        : in     Coord;
      M        : in     Coord;
      M_Inv    : in     Types.Word32);
   --# derives
   --#   X3, Y3, Z3 from
   --#   X1, Y1, Z1, X2, Y2, Z2,
   --#   E1, E1_First, E1_Last, E2, E2_First, A, M, M_Inv;
   --# pre
   --#   E1_First in E1'Range and
   --#   E1_Last in E1'Range and
   --#   E1_First <= E1_Last and
   --#   E2_First in E2'Range and
   --#   E2_First + (E1_Last - E1_First) in E2'Range and
   --#   Bignum.Num_Of_Big_Int (X1, X1'First, X1'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Y1, Y1'First, Y1'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Z1, Z1'First, Z1'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (X2, X2'First, X2'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Y2, Y2'First, Y2'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Z2, Z2'First, Z2'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (A, A'First, A'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 < Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 + M_Inv * M (M'First) = 0;
   --# post
   --#   Bignum.Num_Of_Big_Int (X3, X3'First, X3'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Y3, Y3'First, Y3'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Z3, Z3'First, Z3'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length);

   procedure Make_Affine
     (X1      : in     Coord;
      Y1      : in     Coord;
      Z1      : in     Coord;
      X2      :    out Coord;
      Y2      :    out Coord;
      R       : in     Coord;
      M       : in     Coord;
      M_Inv   : in     Types.Word32);
   --# derives
   --#   X2 from X1, Z1, R, M, M_Inv &
   --#   Y2 from Y1, Z1, R, M, M_Inv;
   --# pre
   --#   Bignum.Num_Of_Big_Int (X1, X1'First, X1'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Y1, Y1'First, Y1'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (Z1, Z1'First, Z1'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (R, R'First, R'Length) =
   --#   Bignum.Base ** (2 * R'Length) mod
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 < Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 + M_Inv * M (M'First) = 0;

   procedure Invert
     (A     : in     Coord;
      B     :    out Coord;
      R     : in     Coord;
      M     : in     Coord;
      M_Inv : in     Types.Word32);
   --# derives
   --#   B from A, R, M, M_Inv;
   --# pre
   --#   Bignum.Num_Of_Big_Int (R, R'First, R'Length) =
   --#   Bignum.Base ** (2 * R'Length) mod
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 < Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 + M_Inv * M (M'First) = 0;
   --# post
   --#   Bignum.Num_Of_Big_Int (B, B'First, B'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length);

   function On_Curve
     (X     : Coord;
      Y     : Coord;
      A     : Coord;
      B     : Coord;
      R     : Coord;
      M     : Coord;
      M_Inv : Types.Word32)
     return Boolean;
   --# pre
   --#   Bignum.Num_Of_Big_Int (A, A'First, A'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (B, B'First, B'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (R, R'First, R'Length) =
   --#   Bignum.Base ** (2 * R'Length) mod
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 < Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 + M_Inv * M (M'First) = 0;

end LSC.EC;
