with LSC.Bignum;

package body LSC.EC.Signature
is

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
     return Boolean
   is
      Result : Boolean;
      H1, H2, H, X, Y, Z, X_Aff, Y_Aff : EC.Coord;
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
            X2       => PX,
            Y2       => PY,
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

         --# accept Flow, 10, Y_Aff, "Y_Aff not needed here";
         EC.Make_Affine (X, Y, Z, X_Aff, Y_Aff, RM, M, M_Inv);
         --# end accept;

         Result := Bignum.Equal
           (Sign1, Sign1'First, Sign1'Last, X_Aff, X_Aff'First);
      else
         Result := False;
      end if;

      --# accept Flow, 33, Y_Aff, "Y_Aff not needed here";
      return Result;
   end Verify;

end LSC.EC.Signature;
