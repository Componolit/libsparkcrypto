with Types;

use type Types.Word32;
use type Types.Word64;

--# inherit Types;

package Bignum
is

   type Big_Int is array (Natural range <>) of Types.Word32;

   --# function Num_Of_Big_Int (A: Big_Int; F, L: Natural) return Integer;
   --# function Num_Of_Boolean (B: Boolean) return Integer;

   procedure Double_Inplace
     (A       : in out Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural;
      Carry   :    out Boolean);
   --# derives A, Carry from A, A_First, A_Last;
   --# pre
   --#   A_First in A'Range and
   --#   A_Last in A'Range and
   --#   A_First <= A_Last;
   --# post
   --#   Num_Of_Big_Int (A~, A_First, A_Last - A_First + 1) * 2 =
   --#   Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) +
   --#   2 ** (32 * (A_Last - A_First + 1)) * Num_Of_Boolean (Carry);

   procedure Sub_Inplace
     (A       : in out Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural;
      B       : in     Big_Int;
      B_First : in     Natural;
      Carry   :    out Boolean);
   --# derives A, Carry from A, A_First, A_Last, B, B_First;
   --# pre
   --#   A_First in A'Range and
   --#   A_Last in A'Range and
   --#   B_First in B'Range and
   --#   B_First + (A_Last - A_First) in B'Range and
   --#   A_First <= A_Last;
   --# post
   --#   Num_Of_Big_Int (A~, A_First, A_Last - A_First + 1) -
   --#   Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) =
   --#   Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) -
   --#   2 ** (32 * (A_Last - A_First + 1)) * Num_Of_Boolean (Carry);

   function Less
     (A       : Big_Int;
      A_First : Natural;
      A_Last  : Natural;
      B       : Big_Int;
      B_First : Natural)
     return Boolean;
   --# pre
   --#   A_First in A'Range and
   --#   A_Last in A'Range and
   --#   B_First in B'Range and
   --#   B_First + (A_Last - A_First) in B'Range and
   --#   A_First <= A_Last;
   --# return
   --#   Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) <
   --#   Num_Of_Big_Int (B, B_First, A_Last - A_First + 1);

   procedure Size_Square_Mod
     (M       : in     Big_Int;
      M_First : in     Natural;
      M_Last  : in     Natural;
      R       :    out Big_Int;
      R_First : in     Natural);
   --# derives
   --#   R from M, M_First, M_Last, R_First;
   --# pre
   --#   M_First in M'Range and
   --#   M_Last in M'Range and
   --#   M_First <= M_Last and
   --#   R_First in R'Range and
   --#   R_First + (M_Last - M_First) in R'Range;
   --# post
   --#   Num_Of_Big_Int (R, R_First, M_Last - M_First + 1) =
   --#   2 ** (32 * 2 * (M_Last - M_First + 1)) mod
   --#   Num_Of_Big_Int (M, M_First, M_Last - M_First + 1);

end Bignum;
