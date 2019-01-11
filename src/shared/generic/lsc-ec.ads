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
with LSC.Math_Int;

use type LSC.Math_Int.Math_Int;
use type LSC.Types.Word32;

package LSC.EC
is
   pragma Pure;

   Max_Coord_Length : constant := 20;
   subtype Coord_Index is Natural range 0 .. Max_Coord_Length - 1;
   subtype Coord is Bignum.Big_Int (Coord_Index);

   One : constant Coord := Coord'(1, others => 0);

   function Point_Double_Spec
     (M, A, X1, Y1, Z1, X2, Y2, Z2 : Math_Int.Math_Int)
     return Boolean
     with Ghost, Import, Global => null;

   procedure Point_Double
     (X1       : in     Bignum.Big_Int;
      X1_First : in     Natural;
      X1_Last  : in     Natural;
      Y1       : in     Bignum.Big_Int;
      Y1_First : in     Natural;
      Z1       : in     Bignum.Big_Int;
      Z1_First : in     Natural;
      X2       :    out Bignum.Big_Int;
      X2_First : in     Natural;
      Y2       :    out Bignum.Big_Int;
      Y2_First : in     Natural;
      Z2       :    out Bignum.Big_Int;
      Z2_First : in     Natural;
      A        : in     Bignum.Big_Int;
      A_First  : in     Natural;
      M        : in     Bignum.Big_Int;
      M_First  : in     Natural;
      M_Inv    : in     Types.Word32)
     with
       Depends =>
         (X2 =>+
            (X1, X1_First, X1_Last, Y1, Y1_First, Z1, Z1_First,
             X2_First, A, A_First, M, M_First, M_Inv),
          Y2 =>+
            (X1, X1_First, X1_Last, Y1, Y1_First, Z1, Z1_First,
             Y2_First, A, A_First, M, M_First, M_Inv),
          Z2 =>+
            (X1_First, X1_Last, Y1, Y1_First, Z1, Z1_First,
             Z2_First, M, M_First, M_Inv)),
       Pre =>
         X1_First in X1'Range and then
         X1_Last in X1'Range and then
         X1_First < X1_Last and then
         X1_Last - X1_First < Max_Coord_Length and then
         Y1_First in Y1'Range and then
         Y1_First + (X1_Last - X1_First) in Y1'Range and then
         Z1_First in Z1'Range and then
         Z1_First + (X1_Last - X1_First) in Z1'Range and then
         X2_First in X2'Range and then
         X2_First + (X1_Last - X1_First) in X2'Range and then
         Y2_First in Y2'Range and then
         Y2_First + (X1_Last - X1_First) in Y2'Range and then
         Z2_First in Z2'Range and then
         Z2_First + (X1_Last - X1_First) in Z2'Range and then
         A_First in A'Range and then
         A_First + (X1_Last - X1_First) in A'Range and then
         M_First in M'Range and then
         M_First + (X1_Last - X1_First) in M'Range and then
         Bignum.Num_Of_Big_Int (X1, X1_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (Y1, Y1_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (Z1, Z1_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (A, A_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Math_Int.From_Word32 (1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         1 + M_Inv * M (M_First) = 0,
       Post =>
         Bignum.Num_Of_Big_Int (X2, X2_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and
         Bignum.Num_Of_Big_Int (Y2, Y2_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and
         Bignum.Num_Of_Big_Int (Z2, Z2_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and
         Point_Double_Spec
           (Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (A, A_First, X1_Last - X1_First + 1) *
            Bignum.Inverse
              (Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1),
               Bignum.Base) ** (X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (X1, X1_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Y1, Y1_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Z1, Z1_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (X2, X2_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Y2, Y2_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Z2, Z2_First, X1_Last - X1_First + 1));

   function Point_Add_Spec
     (M, A, X1, Y1, Z1, X2, Y2, Z2, X3, Y3, Z3 : Math_Int.Math_Int)
     return Boolean
     with Ghost, Import, Global => null;

   procedure Point_Add
     (X1       : in     Bignum.Big_Int;
      X1_First : in     Natural;
      X1_Last  : in     Natural;
      Y1       : in     Bignum.Big_Int;
      Y1_First : in     Natural;
      Z1       : in     Bignum.Big_Int;
      Z1_First : in     Natural;
      X2       : in     Bignum.Big_Int;
      X2_First : in     Natural;
      Y2       : in     Bignum.Big_Int;
      Y2_First : in     Natural;
      Z2       : in     Bignum.Big_Int;
      Z2_First : in     Natural;
      X3       :    out Bignum.Big_Int;
      X3_First : in     Natural;
      Y3       :    out Bignum.Big_Int;
      Y3_First : in     Natural;
      Z3       :    out Bignum.Big_Int;
      Z3_First : in     Natural;
      A        : in     Bignum.Big_Int;
      A_First  : in     Natural;
      M        : in     Bignum.Big_Int;
      M_First  : in     Natural;
      M_Inv    : in     Types.Word32)
     with
       Depends =>
         (X3 =>+
            (X1, X1_First, X1_Last, Y1, Y1_First, Z1, Z1_First,
             X2, X2_First, Y2, Y2_First, Z2, Z2_First,
             X3_First, A, A_First, M, M_First, M_Inv),
          Y3 =>+
            (X1, X1_First, X1_Last, Y1, Y1_First, Z1, Z1_First,
             X2, X2_First, Y2, Y2_First, Z2, Z2_First,
             Y3_First, A, A_First, M, M_First, M_Inv),
          Z3 =>+
            (X1, X1_First, X1_Last, Y1, Y1_First, Z1, Z1_First,
             X2, X2_First, Y2, Y2_First, Z2, Z2_First, Z3_First,
             M, M_First, M_Inv)),
       Pre =>
         X1_First in X1'Range and then
         X1_Last in X1'Range and then
         X1_First < X1_Last and then
         X1_Last - X1_First < Max_Coord_Length and then
         Y1_First in Y1'Range and then
         Y1_First + (X1_Last - X1_First) in Y1'Range and then
         Z1_First in Z1'Range and then
         Z1_First + (X1_Last - X1_First) in Z1'Range and then
         X2_First in X2'Range and then
         X2_First + (X1_Last - X1_First) in X2'Range and then
         Y2_First in Y2'Range and then
         Y2_First + (X1_Last - X1_First) in Y2'Range and then
         Z2_First in Z2'Range and then
         Z2_First + (X1_Last - X1_First) in Z2'Range and then
         X3_First in X3'Range and then
         X3_First + (X1_Last - X1_First) in X3'Range and then
         Y3_First in Y3'Range and then
         Y3_First + (X1_Last - X1_First) in Y3'Range and then
         Z3_First in Z3'Range and then
         Z3_First + (X1_Last - X1_First) in Z3'Range and then
         A_First in A'Range and then
         A_First + (X1_Last - X1_First) in A'Range and then
         M_First in M'Range and then
         M_First + (X1_Last - X1_First) in M'Range and then
         Bignum.Num_Of_Big_Int (X1, X1_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (Y1, Y1_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (Z1, Z1_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (X2, X2_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (Y2, Y2_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (Z2, Z2_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (A, A_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Math_Int.From_Word32 (1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         1 + M_Inv * M (M_First) = 0,
       Post =>
         Bignum.Num_Of_Big_Int (X3, X3_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and
         Bignum.Num_Of_Big_Int (Y3, Y3_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and
         Bignum.Num_Of_Big_Int (Z3, Z3_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and
         Point_Add_Spec
           (Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (A, A_First, X1_Last - X1_First + 1) *
            Bignum.Inverse
              (Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1),
               Bignum.Base) ** (X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (X1, X1_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Y1, Y1_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Z1, Z1_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (X2, X2_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Y2, Y2_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Z2, Z2_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (X3, X3_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Y3, Y3_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Z3, Z3_First, X1_Last - X1_First + 1));

   function Point_Mult_Spec
     (M, A, X1, Y1, Z1, E, X2, Y2, Z2 : Math_Int.Math_Int)
     return Boolean
     with Ghost, Import, Global => null;

   procedure Point_Mult
     (X1       : in     Bignum.Big_Int;
      X1_First : in     Natural;
      X1_Last  : in     Natural;
      Y1       : in     Bignum.Big_Int;
      Y1_First : in     Natural;
      Z1       : in     Bignum.Big_Int;
      Z1_First : in     Natural;
      E        : in     Bignum.Big_Int;
      E_First  : in     Natural;
      E_Last   : in     Natural;
      X2       :    out Bignum.Big_Int;
      X2_First : in     Natural;
      Y2       :    out Bignum.Big_Int;
      Y2_First : in     Natural;
      Z2       :    out Bignum.Big_Int;
      Z2_First : in     Natural;
      A        : in     Bignum.Big_Int;
      A_First  : in     Natural;
      M        : in     Bignum.Big_Int;
      M_First  : in     Natural;
      M_Inv    : in     Types.Word32)
     with
       Depends =>
         ((X2, Y2, Z2) =>
            (X1, X1_First, X1_Last, Y1, Y1_First, Z1, Z1_First,
             X2, X2_First, Y2, Y2_First, Z2, Z2_First,
             E, E_First, E_Last, A, A_First, M, M_First, M_Inv)),
       Pre =>
         X1_First in X1'Range and then
         X1_Last in X1'Range and then
         X1_First < X1_Last and then
         X1_Last - X1_First < Max_Coord_Length and then
         Y1_First in Y1'Range and then
         Y1_First + (X1_Last - X1_First) in Y1'Range and then
         Z1_First in Z1'Range and then
         Z1_First + (X1_Last - X1_First) in Z1'Range and then
         X2_First in X2'Range and then
         X2_First + (X1_Last - X1_First) in X2'Range and then
         Y2_First in Y2'Range and then
         Y2_First + (X1_Last - X1_First) in Y2'Range and then
         Z2_First in Z2'Range and then
         Z2_First + (X1_Last - X1_First) in Z2'Range and then
         A_First in A'Range and then
         A_First + (X1_Last - X1_First) in A'Range and then
         M_First in M'Range and then
         M_First + (X1_Last - X1_First) in M'Range and then
         E_First in E'Range and then
         E_Last in E'Range and then
         E_First <= E_Last and then
         Bignum.Num_Of_Big_Int (X1, X1_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (Y1, Y1_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (Z1, Z1_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (A, A_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Math_Int.From_Word32 (1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         1 + M_Inv * M (M_First) = 0,
       Post =>
         Bignum.Num_Of_Big_Int (X2, X2_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and
         Bignum.Num_Of_Big_Int (Y2, Y2_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and
         Bignum.Num_Of_Big_Int (Z2, Z2_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and
         Point_Mult_Spec
           (Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (A, A_First, X1_Last - X1_First + 1) *
            Bignum.Inverse
              (Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1),
               Bignum.Base) ** (X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (X1, X1_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Y1, Y1_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Z1, Z1_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (E, E_First, E_Last - E_First + 1),
            Bignum.Num_Of_Big_Int (X2, X2_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Y2, Y2_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Z2, Z2_First, X1_Last - X1_First + 1));

   function Two_Point_Mult_Spec
     (M, A, X1, Y1, Z1, E1, X2, Y2, Z2, E2, X3, Y3, Z3 : Math_Int.Math_Int)
     return Boolean
     with Ghost, Import, Global => null;

   procedure Two_Point_Mult
     (X1       : in     Bignum.Big_Int;
      X1_First : in     Natural;
      X1_Last  : in     Natural;
      Y1       : in     Bignum.Big_Int;
      Y1_First : in     Natural;
      Z1       : in     Bignum.Big_Int;
      Z1_First : in     Natural;
      E1       : in     Bignum.Big_Int;
      E1_First : in     Natural;
      E1_Last  : in     Natural;
      X2       : in     Bignum.Big_Int;
      X2_First : in     Natural;
      Y2       : in     Bignum.Big_Int;
      Y2_First : in     Natural;
      Z2       : in     Bignum.Big_Int;
      Z2_First : in     Natural;
      E2       : in     Bignum.Big_Int;
      E2_First : in     Natural;
      X3       :    out Bignum.Big_Int;
      X3_First : in     Natural;
      Y3       :    out Bignum.Big_Int;
      Y3_First : in     Natural;
      Z3       :    out Bignum.Big_Int;
      Z3_First : in     Natural;
      A        : in     Bignum.Big_Int;
      A_First  : in     Natural;
      M        : in     Bignum.Big_Int;
      M_First  : in     Natural;
      M_Inv    : in     Types.Word32)
     with
       Depends =>
         ((X3, Y3, Z3) =>
            (X1, X1_First, X1_Last, Y1, Y1_First, Z1, Z1_First,
             X2, X2_First, Y2, Y2_First, Z2, Z2_First,
             X3, X3_First, Y3, Y3_First, Z3, Z3_First,
             E1, E1_First, E1_Last, E2, E2_First,
             A, A_First, M, M_First, M_Inv)),
       Pre =>
         X1_First in X1'Range and then
         X1_Last in X1'Range and then
         X1_First < X1_Last and then
         X1_Last - X1_First < Max_Coord_Length and then
         Y1_First in Y1'Range and then
         Y1_First + (X1_Last - X1_First) in Y1'Range and then
         Z1_First in Z1'Range and then
         Z1_First + (X1_Last - X1_First) in Z1'Range and then
         X2_First in X2'Range and then
         X2_First + (X1_Last - X1_First) in X2'Range and then
         Y2_First in Y2'Range and then
         Y2_First + (X1_Last - X1_First) in Y2'Range and then
         Z2_First in Z2'Range and then
         Z2_First + (X1_Last - X1_First) in Z2'Range and then
         X3_First in X3'Range and then
         X3_First + (X1_Last - X1_First) in X3'Range and then
         Y3_First in Y3'Range and then
         Y3_First + (X1_Last - X1_First) in Y3'Range and then
         Z3_First in Z3'Range and then
         Z3_First + (X1_Last - X1_First) in Z3'Range and then
         A_First in A'Range and then
         A_First + (X1_Last - X1_First) in A'Range and then
         M_First in M'Range and then
         M_First + (X1_Last - X1_First) in M'Range and then
         E1_First in E1'Range and then
         E1_Last in E1'Range and then
         E1_First <= E1_Last and then
         E2_First in E2'Range and then
         E2_First + (E1_Last - E1_First) in E2'Range and then
         Bignum.Num_Of_Big_Int (X1, X1_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (Y1, Y1_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (Z1, Z1_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (X2, X2_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (Y2, Y2_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (Z2, Z2_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (A, A_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Math_Int.From_Word32 (1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         1 + M_Inv * M (M_First) = 0,
       Post =>
         Bignum.Num_Of_Big_Int (X3, X3_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and
         Bignum.Num_Of_Big_Int (Y3, Y3_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and
         Bignum.Num_Of_Big_Int (Z3, Z3_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and
         Two_Point_Mult_Spec
           (Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (A, A_First, X1_Last - X1_First + 1) *
            Bignum.Inverse
              (Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1),
               Bignum.Base) ** (X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (X1, X1_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Y1, Y1_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Z1, Z1_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (E1, E1_First, E1_Last - E1_First + 1),
            Bignum.Num_Of_Big_Int (X2, X2_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Y2, Y2_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Z2, Z2_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (E2, E2_First, E1_Last - E1_First + 1),
            Bignum.Num_Of_Big_Int (X3, X3_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Y3, Y3_First, X1_Last - X1_First + 1),
            Bignum.Num_Of_Big_Int (Z3, Z3_First, X1_Last - X1_First + 1));

   procedure Make_Affine
     (X1       : in     Bignum.Big_Int;
      X1_First : in     Natural;
      X1_Last  : in     Natural;
      Y1       : in     Bignum.Big_Int;
      Y1_First : in     Natural;
      Z1       : in     Bignum.Big_Int;
      Z1_First : in     Natural;
      X2       :    out Bignum.Big_Int;
      X2_First : in     Natural;
      Y2       :    out Bignum.Big_Int;
      Y2_First : in     Natural;
      R        : in     Bignum.Big_Int;
      R_First  : in     Natural;
      M        : in     Bignum.Big_Int;
      M_First  : in     Natural;
      M_Inv    : in     Types.Word32)
     with
       Depends =>
         (X2 =>+
            (X1, X1_First, X1_Last, X2_First, Z1, Z1_First,
             R, R_First, M, M_First, M_Inv),
          Y2 =>+
            (X1_First, X1_Last, Y1, Y1_First, Z1, Z1_First, Y2_First,
             R, R_First, M, M_First, M_Inv)),
       Pre =>
         X1_First in X1'Range and then
         X1_Last in X1'Range and then
         X1_First < X1_Last and then
         X1_Last - X1_First < Max_Coord_Length and then
         Y1_First in Y1'Range and then
         Y1_First + (X1_Last - X1_First) in Y1'Range and then
         Z1_First in Z1'Range and then
         Z1_First + (X1_Last - X1_First) in Z1'Range and then
         X2_First in X2'Range and then
         X2_First + (X1_Last - X1_First) in X2'Range and then
         Y2_First in Y2'Range and then
         Y2_First + (X1_Last - X1_First) in Y2'Range and then
         R_First in R'Range and then
         R_First + (X1_Last - X1_First) in R'Range and then
         M_First in M'Range and then
         M_First + (X1_Last - X1_First) in M'Range and then
         Bignum.Num_Of_Big_Int (X1, X1_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (Y1, Y1_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (Z1, Z1_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Bignum.Num_Of_Big_Int (R, R_First, X1_Last - X1_First + 1) =
         Bignum.Base ** (Math_Int.From_Integer (2) *
           Math_Int.From_Integer (X1_Last - X1_First + 1)) mod
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         Math_Int.From_Word32 (1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and then
         1 + M_Inv * M (M_First) = 0,
       Post =>
         Bignum.Num_Of_Big_Int (X2, X2_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1) and
         Bignum.Num_Of_Big_Int (Y2, Y2_First, X1_Last - X1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X1_Last - X1_First + 1);

   procedure Invert
     (A       : in     Bignum.Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural;
      B       :    out Bignum.Big_Int;
      B_First : in     Natural;
      R       : in     Bignum.Big_Int;
      R_First : in     Natural;
      M       : in     Bignum.Big_Int;
      M_First : in     Natural;
      M_Inv   : in     Types.Word32)
     with
       Depends =>
         (B =>+ (A, A_First, A_Last, B_First, R, R_First, M, M_First, M_Inv)),
       Pre =>
         A_First in A'Range and then
         A_Last in A'Range and then
         A_First < A_Last and then
         A_Last - A_First < Max_Coord_Length and then
         B_First in B'Range and then
         B_First + (A_Last - A_First) in B'Range and then
         R_First in R'Range and then
         R_First + (A_Last - A_First) in R'Range and then
         M_First in M'Range and then
         M_First + (A_Last - A_First) in M'Range and then
         Bignum.Num_Of_Big_Int (R, R_First, A_Last - A_First + 1) =
         Bignum.Base ** (Math_Int.From_Integer (2) *
           Math_Int.From_Integer (A_Last - A_First + 1)) mod
         Bignum.Num_Of_Big_Int (M, M_First, A_Last - A_First + 1) and then
         Math_Int.From_Word32 (1) <
         Bignum.Num_Of_Big_Int (M, M_First, A_Last - A_First + 1) and then
         1 + M_Inv * M (M_First) = 0,
       Post =>
         Bignum.Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, A_Last - A_First + 1);

   function On_Curve
     (X       : Bignum.Big_Int;
      X_First : Natural;
      X_Last  : Natural;
      Y       : Bignum.Big_Int;
      Y_First : Natural;
      A       : Bignum.Big_Int;
      A_First : Natural;
      B       : Bignum.Big_Int;
      B_First : Natural;
      R       : Bignum.Big_Int;
      R_First : Natural;
      M       : Bignum.Big_Int;
      M_First : Natural;
      M_Inv : Types.Word32)
     return Boolean
     with
       Pre =>
         X_First in X'Range and then
         X_Last in X'Range and then
         X_First < X_Last and then
         X_Last - X_First < Max_Coord_Length and then
         Y_First in Y'Range and then
         Y_First + (X_Last - X_First) in Y'Range and then
         A_First in A'Range and then
         A_First + (X_Last - X_First) in A'Range and then
         B_First in B'Range and then
         B_First + (X_Last - X_First) in B'Range and then
         R_First in R'Range and then
         R_First + (X_Last - X_First) in R'Range and then
         M_First in M'Range and then
         M_First + (X_Last - X_First) in M'Range and then
         Bignum.Num_Of_Big_Int (A, A_First, X_Last - X_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X_Last - X_First + 1) and then
         Bignum.Num_Of_Big_Int (B, B_First, X_Last - X_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X_Last - X_First + 1) and then
         Bignum.Num_Of_Big_Int (R, R_First, X_Last - X_First + 1) =
         Bignum.Base ** (Math_Int.From_Integer (2) *
           Math_Int.From_Integer (X_Last - X_First + 1)) mod
         Bignum.Num_Of_Big_Int (M, M_First, X_Last - X_First + 1) and then
         Math_Int.From_Word32 (1) <
         Bignum.Num_Of_Big_Int (M, M_First, X_Last - X_First + 1) and then
         1 + M_Inv * M (M_First) = 0;

   procedure Uncompress_Point
     (X       : in     Bignum.Big_Int;
      X_First : in     Natural;
      X_Last  : in     Natural;
      Even    : in     Boolean;
      A       : in     Bignum.Big_Int;
      A_First : in     Natural;
      B       : in     Bignum.Big_Int;
      B_First : in     Natural;
      R       : in     Bignum.Big_Int;
      R_First : in     Natural;
      M       : in     Bignum.Big_Int;
      M_First : in     Natural;
      M_Inv   : in     Types.Word32;
      Y       :    out Bignum.Big_Int;
      Y_First : in     Natural;
      Success :    out Boolean)
     with
       Depends =>
         ((Y, Success) =>
            (X, X_First, X_Last, Even, A, A_First, B, B_First,
             R, R_First, M, M_First, M_Inv, Y, Y_First)),
       Pre =>
         X_First in X'Range and then
         X_Last in X'Range and then
         X_First < X_Last and then
         X_Last - X_First < Max_Coord_Length and then
         Y_First in Y'Range and then
         Y_First + (X_Last - X_First) in Y'Range and then
         A_First in A'Range and then
         A_First + (X_Last - X_First) in A'Range and then
         B_First in B'Range and then
         B_First + (X_Last - X_First) in B'Range and then
         R_First in R'Range and then
         R_First + (X_Last - X_First) in R'Range and then
         M_First in M'Range and then
         M_First + (X_Last - X_First) in M'Range and then
         Bignum.Num_Of_Big_Int (A, A_First, X_Last - X_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X_Last - X_First + 1) and then
         Bignum.Num_Of_Big_Int (B, B_First, X_Last - X_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X_Last - X_First + 1) and then
         Bignum.Num_Of_Big_Int (R, R_First, X_Last - X_First + 1) =
         Bignum.Base ** (Math_Int.From_Integer (2) *
           Math_Int.From_Integer (X_Last - X_First + 1)) mod
         Bignum.Num_Of_Big_Int (M, M_First, X_Last - X_First + 1) and then
         Math_Int.From_Word32 (1) <
         Bignum.Num_Of_Big_Int (M, M_First, X_Last - X_First + 1) and then
         1 + M_Inv * M (M_First) = 0,
       Post =>
         Bignum.Num_Of_Big_Int (Y, Y_First, X_Last - X_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, X_Last - X_First + 1);

end LSC.EC;
