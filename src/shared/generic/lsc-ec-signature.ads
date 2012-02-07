with LSC.Types;

--# inherit
--#   LSC.Types,
--#   LSC.Bignum,
--#   LSC.EC;

package LSC.EC.Signature
is

   type Signature_Type is (ECDSA, ECGDSA);

   function Verify
     (Sign1 : EC.Coord;
      Sign2 : EC.Coord;
      Hash  : EC.Coord;
      T     : Signature_Type;
      BX    : EC.Coord;
      BY    : EC.Coord;
      PX    : EC.Coord;
      PY    : EC.Coord;
      A     : EC.Coord;
      M     : EC.Coord;
      M_Inv : Types.Word32;
      RM    : EC.Coord;
      N     : EC.Coord;
      N_Inv : Types.Word32;
      RN    : EC.Coord)
     return Boolean;
   --# pre
   --#   Bignum.Num_Of_Big_Int (BX, BX'First, BX'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (BY, BY'First, BY'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (PX, PX'First, PX'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (PY, PY'First, PY'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (A, A'First, A'Length) <
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

end LSC.EC.Signature;
