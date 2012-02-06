with LSC.Types;

use type LSC.Types.Word32;
use type LSC.Types.Word64;

--# inherit LSC.Types;

package LSC.Bignum
is

   Base : constant := 2 ** 32;

   type Big_Int is array (Natural range <>) of Types.Word32;

   --# function Num_Of_Big_Int (A: Big_Int; F, L: Natural)
   --#   return Universal_Integer;
   --# function Num_Of_Boolean (B: Boolean) return Universal_Integer;
   --# function Inverse (M, A: Universal_Integer) return Universal_Integer;

   procedure Initialize
     (A       :    out Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural);
   --# derives
   --#   A from A_First, A_Last;
   --# pre
   --#   A_First in A'Range and
   --#   A_Last in A'Range and
   --#   A_First <= A_Last;
   --# post
   --#   (for all K in Natural range A_First .. A_Last => (A (K) = 0));

   procedure Copy
     (A       : in     Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural;
      B       :    out Big_Int;
      B_First : in     Natural);
   --# derives
   --#   B from A, A_First, A_Last, B_First;
   --# pre
   --#   A_First in A'Range and
   --#   A_Last in A'Range and
   --#   A_First <= A_Last and
   --#   B_First in B'Range and
   --#   B_First + (A_Last - A_First) in B'Range;
   --# post
   --#   (for all K in Natural range A_First .. A_Last =>
   --#      (A (K) = B (B_First + (K - A_First))));

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
   --#   Base ** (A_Last - A_First + 1) * Num_Of_Boolean (Carry);

   procedure Add_Inplace
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
   --#   Num_Of_Big_Int (A~, A_First, A_Last - A_First + 1) +
   --#   Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) =
   --#   Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) +
   --#   Base ** (A_Last - A_First + 1) * Num_Of_Boolean (Carry);

   procedure Add
     (A       :    out Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural;
      B       : in     Big_Int;
      B_First : in     Natural;
      C       : in     Big_Int;
      C_First : in     Natural;
      Carry   :    out Boolean);
   --# derives
   --#   A, Carry from A_First, A_Last, B, B_First, C, C_First;
   --# pre
   --#   A_First in A'Range and
   --#   A_Last in A'Range and
   --#   B_First in B'Range and
   --#   B_First + (A_Last - A_First) in B'Range and
   --#   C_First in C'Range and
   --#   C_First + (A_Last - A_First) in C'Range and
   --#   A_First <= A_Last;
   --# post
   --#   Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) +
   --#   Num_Of_Big_Int (C, C_First, A_Last - A_First + 1) =
   --#   Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) +
   --#   Base ** (A_Last - A_First + 1) * Num_Of_Boolean (Carry);

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
   --#   Base ** (A_Last - A_First + 1) * Num_Of_Boolean (Carry);

   procedure Sub
     (A       :    out Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural;
      B       : in     Big_Int;
      B_First : in     Natural;
      C       : in     Big_Int;
      C_First : in     Natural;
      Carry   :    out Boolean);
   --# derives
   --#   A, Carry from A_First, A_Last, B, B_First, C, C_First;
   --# pre
   --#   A_First in A'Range and
   --#   A_Last in A'Range and
   --#   B_First in B'Range and
   --#   B_First + (A_Last - A_First) in B'Range and
   --#   C_First in C'Range and
   --#   C_First + (A_Last - A_First) in C'Range and
   --#   A_First <= A_Last;
   --# post
   --#   Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) -
   --#   Num_Of_Big_Int (C, C_First, A_Last - A_First + 1) =
   --#   Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) -
   --#   Base ** (A_Last - A_First + 1) * Num_Of_Boolean (Carry);

   procedure Mod_Add_Inplace
     (A       : in out Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural;
      B       : in     Big_Int;
      B_First : in     Natural;
      M       : in     Big_Int;
      M_First : in     Natural);
   --# derives A from A, A_First, A_Last, B, B_First, M, M_First;
   --# pre
   --#   A_First in A'Range and
   --#   A_Last in A'Range and
   --#   B_First in B'Range and
   --#   B_First + (A_Last - A_First) in B'Range and
   --#   M_First in M'Range and
   --#   M_First + (A_Last - A_First) in M'Range and
   --#   A_First <= A_Last and
   --#   (Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) <=
   --#    Num_Of_Big_Int (M, M_First, A_Last - A_First + 1) or
   --#    Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) <=
   --#    Num_Of_Big_Int (M, M_First, A_Last - A_First + 1));
   --# post
   --#   Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) =
   --#   Num_Of_Big_Int (A~, A_First, A_Last - A_First + 1) +
   --#   Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) -
   --#   Num_Of_Big_Int (M, M_First, A_Last - A_First + 1) *
   --#   Num_Of_Boolean
   --#     (Num_Of_Big_Int (A~, A_First, A_Last - A_First + 1) +
   --#      Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) >=
   --#      Base ** (A_Last - A_First + 1));

   procedure Mod_Add
     (A       :    out Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural;
      B       : in     Big_Int;
      B_First : in     Natural;
      C       : in     Big_Int;
      C_First : in     Natural;
      M       : in     Big_Int;
      M_First : in     Natural);
   --# derives
   --#   A from A_First, A_Last, B, B_First, C, C_First, M, M_First;
   --# pre
   --#   A_First in A'Range and
   --#   A_Last in A'Range and
   --#   B_First in B'Range and
   --#   B_First + (A_Last - A_First) in B'Range and
   --#   C_First in C'Range and
   --#   C_First + (A_Last - A_First) in C'Range and
   --#   M_First in M'Range and
   --#   M_First + (A_Last - A_First) in M'Range and
   --#   A_First <= A_Last and
   --#   (Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) <=
   --#    Num_Of_Big_Int (M, M_First, A_Last - A_First + 1) or
   --#    Num_Of_Big_Int (C, C_First, A_Last - A_First + 1) <=
   --#    Num_Of_Big_Int (M, M_First, A_Last - A_First + 1));
   --# post
   --#   Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) =
   --#   Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) +
   --#   Num_Of_Big_Int (C, C_First, A_Last - A_First + 1) -
   --#   Num_Of_Big_Int (M, M_First, A_Last - A_First + 1) *
   --#   Num_Of_Boolean
   --#     (Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) +
   --#      Num_Of_Big_Int (C, C_First, A_Last - A_First + 1) >=
   --#      Base ** (A_Last - A_First + 1));

   procedure Mod_Sub_Inplace
     (A       : in out Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural;
      B       : in     Big_Int;
      B_First : in     Natural;
      M       : in     Big_Int;
      M_First : in     Natural);
   --# derives A from A, A_First, A_Last, B, B_First, M, M_First;
   --# pre
   --#   A_First in A'Range and
   --#   A_Last in A'Range and
   --#   B_First in B'Range and
   --#   B_First + (A_Last - A_First) in B'Range and
   --#   M_First in M'Range and
   --#   M_First + (A_Last - A_First) in M'Range and
   --#   A_First <= A_Last and
   --#   Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) <=
   --#   Num_Of_Big_Int (M, M_First, A_Last - A_First + 1);
   --# post
   --#   Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) =
   --#   Num_Of_Big_Int (A~, A_First, A_Last - A_First + 1) -
   --#   Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) +
   --#   Num_Of_Big_Int (M, M_First, A_Last - A_First + 1) *
   --#   Num_Of_Boolean
   --#     (Num_Of_Big_Int (A~, A_First, A_Last - A_First + 1) <
   --#      Num_Of_Big_Int (B, B_First, A_Last - A_First + 1));

   procedure Mod_Sub
     (A       :    out Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural;
      B       : in     Big_Int;
      B_First : in     Natural;
      C       : in     Big_Int;
      C_First : in     Natural;
      M       : in     Big_Int;
      M_First : in     Natural);
   --# derives
   --#   A from A_First, A_Last, B, B_First, C, C_First, M, M_First;
   --# pre
   --#   A_First in A'Range and
   --#   A_Last in A'Range and
   --#   B_First in B'Range and
   --#   B_First + (A_Last - A_First) in B'Range and
   --#   C_First in C'Range and
   --#   C_First + (A_Last - A_First) in C'Range and
   --#   M_First in M'Range and
   --#   M_First + (A_Last - A_First) in M'Range and
   --#   A_First <= A_Last and
   --#   Num_Of_Big_Int (C, C_First, A_Last - A_First + 1) <=
   --#   Num_Of_Big_Int (M, M_First, A_Last - A_First + 1);
   --# post
   --#   Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) =
   --#   Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) -
   --#   Num_Of_Big_Int (C, C_First, A_Last - A_First + 1) +
   --#   Num_Of_Big_Int (M, M_First, A_Last - A_First + 1) *
   --#   Num_Of_Boolean
   --#     (Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) <
   --#      Num_Of_Big_Int (C, C_First, A_Last - A_First + 1));

   function Is_Zero
     (A       : Big_Int;
      A_First : Natural;
      A_Last  : Natural)
     return Boolean;
   --# pre
   --#   A_First in A'Range and
   --#   A_Last in A'Range and
   --#   A_First <= A_Last;
   --# return
   --#   Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) = 0;

   function Equal
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
   --#   Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) =
   --#   Num_Of_Big_Int (B, B_First, A_Last - A_First + 1);

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
   --#   R_First + (M_Last - M_First) in R'Range and
   --#   1 < Num_Of_Big_Int (M, M_First, M_Last - M_First + 1);
   --# post
   --#   Num_Of_Big_Int (R, R_First, M_Last - M_First + 1) =
   --#   Base ** (2 * (M_Last - M_First + 1)) mod
   --#   Num_Of_Big_Int (M, M_First, M_Last - M_First + 1);

   function Word_Inverse (M : Types.Word32) return Types.Word32;
   --# pre M mod 2 = 1;
   --# return Inv => 1 + Inv * M = 0;

   procedure Mont_Mult
     (A       :    out Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural;
      B       : in     Big_Int;
      B_First : in     Natural;
      C       : in     Big_Int;
      C_First : in     Natural;
      M       : in     Big_Int;
      M_First : in     Natural;
      M_Inv   : in     Types.Word32);
   --# derives
   --#   A from
   --#   A_First, A_Last, B, B_First, C, C_First, M, M_First, M_Inv;
   --# pre
   --#   A_First in A'Range and
   --#   A_Last in A'Range and
   --#   A_First < A_Last and
   --#   B_First in B'Range and
   --#   B_First + (A_Last - A_First) in B'Range and
   --#   C_First in C'Range and
   --#   C_First + (A_Last - A_First) in C'Range and
   --#   M_First in M'Range and
   --#   M_First + (A_Last - A_First) in M'Range and
   --#   Num_Of_Big_Int (C, C_First, A_Last - A_First + 1) <
   --#   Num_Of_Big_Int (M, M_First, A_Last - A_First + 1) and
   --#   1 < Num_Of_Big_Int (M, M_First, A_Last - A_First + 1) and
   --#   1 + M_Inv * M (M_First) = 0;
   --# post
   --#   Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) =
   --#   (Num_Of_Big_Int (B, B_First, A_Last - A_First + 1) *
   --#    Num_Of_Big_Int (C, C_First, A_Last - A_First + 1) *
   --#    Inverse (Num_Of_Big_Int (M, M_First, A_Last - A_First + 1),
   --#      Base) ** (A_Last - A_First + 1)) mod
   --#   Num_Of_Big_Int (M, M_First, A_Last - A_First + 1);

   procedure Mont_Exp
     (A          :    out Big_Int;
      A_First    : in     Natural;
      A_Last     : in     Natural;
      X          : in     Big_Int;
      X_First    : in     Natural;
      E          : in     Big_Int;
      E_First    : in     Natural;
      E_Last     : in     Natural;
      M          : in     Big_Int;
      M_First    : in     Natural;
      Aux1       :    out Big_Int;
      Aux1_First : in     Natural;
      Aux2       :    out Big_Int;
      Aux2_First : in     Natural;
      Aux3       :    out Big_Int;
      Aux3_First : in     Natural;
      R          : in     Big_Int;
      R_First    : in     Natural;
      M_Inv      : in     Types.Word32);
   --# derives
   --#   A from
   --#   A_First, A_Last, X, X_First, E, E_First, E_Last,
   --#   M, M_First, Aux1_First, Aux2_First, Aux3_First,
   --#   R, R_First, M_Inv &
   --#   Aux1 from
   --#   A_First, A_Last, Aux1_First &
   --#   Aux2 from
   --#   A_First, A_Last, Aux2_First,
   --#   X, X_First, R, R_First, M, M_First, M_Inv &
   --#   Aux3 from
   --#   A_First, A_Last, X, X_First, E, E_First, E_Last,
   --#   M, M_First, Aux1_First, Aux2_First, Aux3_First,
   --#   R, R_First, M_Inv;
   --# pre
   --#   A_First in A'Range and
   --#   A_Last in A'Range and
   --#   A_First < A_Last and
   --#   X_First in X'Range and
   --#   X_First + (A_Last - A_First) in X'Range and
   --#   E_First in E'Range and
   --#   E_Last in E'Range and
   --#   E_First <= E_Last and
   --#   M_First in M'Range and
   --#   M_First + (A_Last - A_First) in M'Range and
   --#   Aux1_First in Aux1'Range and
   --#   Aux1_First + (A_Last - A_First) in Aux1'Range and
   --#   Aux2_First in Aux2'Range and
   --#   Aux2_First + (A_Last - A_First) in Aux2'Range and
   --#   Aux3_First in Aux3'Range and
   --#   Aux3_First + (A_Last - A_First) in Aux3'Range and
   --#   R_First in R'Range and
   --#   R_First + (A_Last - A_First) in R'Range and
   --#   Num_Of_Big_Int (R, R_First, A_Last - A_First + 1) =
   --#   Base ** (2 * (A_Last - A_First + 1)) mod
   --#   Num_Of_Big_Int (M, M_First, A_Last - A_First + 1) and
   --#   1 < Num_Of_Big_Int (M, M_First, A_Last - A_First + 1) and
   --#   1 + M_Inv * M (M_First) = 0;
   --# post
   --#   Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) =
   --#   Num_Of_Big_Int (X, X_First, A_Last - A_First + 1) **
   --#   Num_Of_Big_Int (E, E_First, E_Last - E_First + 1) mod
   --#   Num_Of_Big_Int (M, M_First, A_Last - A_First + 1);

end LSC.Bignum;
