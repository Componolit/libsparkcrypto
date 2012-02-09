with LSC.Types;

--# inherit
--#   LSC.Types,
--#   LSC.Bignum,
--#   LSC.EC;

package LSC.EC.Signature
is

   type Signature_Type is (ECDSA, ECGDSA);

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
      Success :    out Boolean);
   --# derives
   --#   Sign1 from
   --#     Rand, BX, BY, A, M, M_Inv, RM, N, N_Inv, RN &
   --#   Sign2, Success from
   --#     Hash, Rand, T, Priv, BX, BY, A, M, M_Inv, RM, N, N_Inv, RN;
   --# pre
   --#   Bignum.Num_Of_Big_Int (Hash, Hash'First, Hash'Length) <
   --#   Bignum.Num_Of_Big_Int (N, N'First, N'Length) and
   --#   Bignum.Num_Of_Big_Int (BX, BX'First, BX'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (BY, BY'First, BY'Length) <
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
   --# post
   --#   Success ->
   --#     (0 < Bignum.Num_Of_Big_Int (Sign1, Sign1'First, Sign1'Length) and
   --#      Bignum.Num_Of_Big_Int (Sign1, Sign1'First, Sign1'Length) <
   --#      Bignum.Num_Of_Big_Int (N, N'First, N'Length) and
   --#      0 < Bignum.Num_Of_Big_Int (Sign2, Sign2'First, Sign2'Length) and
   --#      Bignum.Num_Of_Big_Int (Sign2, Sign2'First, Sign2'Length) <
   --#      Bignum.Num_Of_Big_Int (N, N'First, N'Length));

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
     return Boolean;
   --# pre
   --#   Bignum.Num_Of_Big_Int (PubX, PubX'First, PubX'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (PubY, PubY'First, PubY'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (BX, BX'First, BX'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (BY, BY'First, BY'Length) <
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
