package body LSC.EC
is

   procedure Point_Double
     (X1       : in     Coord;
      Y1       : in     Coord;
      Z1       : in     Coord;
      X2       :    out Coord;
      Y2       :    out Coord;
      Z2       :    out Coord;
      A        : in     Coord;
      M        : in     Coord;
      M_Inv    : in     Types.Word32)
   is
      H1, H2, H3, H4, H5, H6 : Coord;
   begin
      if Bignum.Is_Zero (Z1, Z1'First, Z1'Last) then
         Bignum.Initialize (X2, X2'First, X2'Last);
         Bignum.Initialize (Y2, Y2'First, Y2'Last);
         Bignum.Initialize (Z2, Z2'First, Z2'Last);

      else
         Bignum.Mod_Add
           (H1, H1'First, H1'Last, Y1, Y1'First, Y1, Y1'First,
            M, M'First);

         Bignum.Mont_Mult
           (H2, H2'First, H2'Last, H1, H1'First, Z1, Z1'First,
            M, M'First, M_Inv);

         Bignum.Mod_Add
           (H3, H3'First, H3'Last, X1, X1'First, X1, X1'First,
            M, M'First);

         Bignum.Mod_Add_Inplace
           (H3, H3'First, H3'Last, X1, X1'First, M, M'First);

         Bignum.Mont_Mult
           (H1, H1'First, H1'Last, H3, H3'First, X1, X1'First,
            M, M'First, M_Inv);

         Bignum.Mont_Mult
           (H4, H4'First, H4'Last, A, A'First, Z1, Z1'First,
            M, M'First, M_Inv);

         Bignum.Mont_Mult
           (H3, H3'First, H3'Last, H4, H4'First, Z1, Z1'First,
            M, M'First, M_Inv);

         Bignum.Mod_Add_Inplace
           (H1, H1'First, H1'Last, H3, H3'First, M, M'First);

         Bignum.Mod_Sub_Inplace
           (H1, H1'First, H1'Last, M, M'First, M, M'First);

         Bignum.Mont_Mult
           (H4, H4'First, H4'Last, Y1, Y1'First, H2, H2'First,
            M, M'First, M_Inv);

         Bignum.Mod_Add
           (H6, H6'First, H6'Last, X1, X1'First, X1, X1'First,
            M, M'First);

         Bignum.Mont_Mult
           (H5, H5'First, H5'Last, H6, H6'First, H4, H4'First,
            M, M'First, M_Inv);

         Bignum.Mont_Mult
           (H6, H6'First, H6'Last, H1, H1'First, H1, H1'First,
            M, M'First, M_Inv);

         Bignum.Mod_Sub_Inplace
           (H6, H6'First, H6'Last, H5, H5'First, M, M'First);

         Bignum.Mod_Sub_Inplace
           (H6, H6'First, H6'Last, H5, H5'First, M, M'First);

         Bignum.Mont_Mult
           (X2, X2'First, H3'Last, H6, H6'First, H2, H2'First,
            M, M'First, M_Inv);

         Bignum.Mod_Sub
           (H3, H3'First, H3'Last, H5, H5'First, H6, H6'First,
            M, M'First);

         Bignum.Mont_Mult
           (Y2, Y2'First, Y2'Last, H3, H3'First, H1, H1'First,
            M, M'First, M_Inv);

         Bignum.Mod_Add
           (H3, H3'First, H3'Last, H4, H4'First, H4, H4'First,
            M, M'First);

         Bignum.Mont_Mult
           (H1, H1'First, H1'Last, H3, H3'First, H4, H4'First,
            M, M'First, M_Inv);

         Bignum.Mod_Sub_Inplace
           (Y2, Y2'First, Y2'Last, H1, H1'First, M, M'First);

         Bignum.Mont_Mult
           (H3, H3'First, H3'Last, H2, H2'First, H2, H2'First,
            M, M'First, M_Inv);

         Bignum.Mont_Mult
           (Z2, Z2'First, Z2'Last, H3, H3'First, H2, H2'First,
            M, M'First, M_Inv);
      end if;

   end Point_Double;

   ----------------------------------------------------------------------------

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
      M_Inv    : in     Types.Word32)
   is
      H1, H2, H3, H4, H5, H6, H7, H8 : Coord;
   begin
      if Bignum.Is_Zero (Z1, Z1'First, Z1'Last) then
         Bignum.Copy (X2, X2'First, X2'Last, X3, X3'First);
         Bignum.Copy (Y2, Y2'First, Y2'Last, Y3, Y3'First);
         Bignum.Copy (Z2, Z2'First, Z2'Last, Z3, Z3'First);

      elsif Bignum.Is_Zero (Z2, Z2'First, Z2'Last) then
         Bignum.Copy (X1, X1'First, X1'Last, X3, X3'First);
         Bignum.Copy (Y1, Y1'First, Y1'Last, Y3, Y3'First);
         Bignum.Copy (Z1, Z1'First, Z1'Last, Z3, Z3'First);

      else
         Bignum.Mont_Mult
           (H1, H1'First, H1'Last, X2, X2'First, Z1, Z1'First,
            M, M'First, M_Inv);

         Bignum.Mont_Mult
           (H2, H2'First, H2'Last, X1, X1'First, Z2, Z2'First,
            M, M'First, M_Inv);

         Bignum.Mont_Mult
           (H3, H3'First, H3'Last, Y2, Y2'First, Z1, Z1'First,
            M, M'First, M_Inv);

         Bignum.Mont_Mult
           (H4, H4'First, H4'Last, Y1, Y1'First, Z2, Z2'First,
            M, M'First, M_Inv);

         Bignum.Mod_Sub
           (H5, H5'First, H5'Last, H1, H1'First, H2, H2'First,
            M, M'First);

         Bignum.Mod_Sub
           (H6, H6'First, H6'Last, H3, H3'First, H4, H4'First,
            M, M'First);

         if Bignum.Is_Zero (H5, H5'First, H5'Last) then
            if Bignum.Is_Zero (H6, H6'First, H6'Last) then
               Point_Double (X1, Y1, Z1, X3, Y3, Z3, A, M, M_Inv);

            else
               Bignum.Initialize (X3, X3'First, X3'Last);
               Bignum.Initialize (Y3, Y3'First, Y3'Last);
               Bignum.Initialize (Z3, Z3'First, Z3'Last);
            end if;

         else
            Bignum.Mont_Mult
              (H7, H7'First, H7'Last, Z1, Z1'First, Z2, Z2'First,
               M, M'First, M_Inv);

            Bignum.Mod_Add
              (H8, H8'First, H8'Last, H1, H1'First, H2, H2'First,
               M, M'First);

            Bignum.Mont_Mult
              (H3, H3'First, H3'Last, H5, H5'First, H5, H5'First,
               M, M'First, M_Inv);

            Bignum.Mont_Mult
              (H1, H1'First, H1'Last, H2, H2'First, H3, H3'First,
               M, M'First, M_Inv);

            Bignum.Mont_Mult
              (H2, H2'First, H2'Last, H8, H8'First, H3, H3'First,
               M, M'First, M_Inv);

            Bignum.Mont_Mult
              (H8, H8'First, H8'Last, H3, H3'First, H5, H5'First,
               M, M'First, M_Inv);

            Bignum.Mont_Mult
              (X3, X3'First, X3'Last, H6, H6'First, H6, H6'First,
               M, M'First, M_Inv);

            Bignum.Mont_Mult
              (H3, H3'First, H3'Last, X3, X3'First, H7, H7'First,
               M, M'First, M_Inv);

            Bignum.Mod_Sub_Inplace
              (H3, H3'First, H3'Last, H2, H2'First, M, M'First);

            Bignum.Mont_Mult
              (X3, X3'First, X3'Last, H5, H5'First, H3, H3'First,
               M, M'First, M_Inv);

            Bignum.Mod_Sub_Inplace
              (H1, H1'First, H1'Last, H3, H3'First, M, M'First);

            Bignum.Mont_Mult
              (H2, H2'First, H2'Last, H1, H1'First, H6, H6'First,
               M, M'First, M_Inv);

            Bignum.Mont_Mult
              (H1, H1'First, H1'Last, H8, H8'First, H4, H4'First,
               M, M'First, M_Inv);

            Bignum.Mod_Sub
              (Y3, Y3'First, Y3'Last, H2, H2'First, H1, H1'First,
               M, M'First);

            Bignum.Mont_Mult
              (Z3, Z3'First, Z3'Last, H8, H8'First, H7, H7'First,
               M, M'First, M_Inv);
         end if;
      end if;
   end Point_Add;

   ----------------------------------------------------------------------------

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
      M_Inv    : in     Types.Word32)
   is
      X3, Y3, Z3 : Coord;
   begin
      Bignum.Initialize (X2, X2'First, X2'Last);
      Bignum.Initialize (Y2, Y2'First, Y2'Last);
      Bignum.Initialize (Z2, Z2'First, Z2'Last);

      for I in reverse Natural range E_First .. E_Last
      --# assert
      --#   Bignum.Num_Of_Big_Int (X2, X2'First, X2'Length) <
      --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
      --#   Bignum.Num_Of_Big_Int (Y2, Y2'First, Y2'Length) <
      --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
      --#   Bignum.Num_Of_Big_Int (Z2, Z2'First, Z2'Length) <
      --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length);
      loop
         for J in reverse Natural range 0 .. 31
         --# assert
         --#   Bignum.Num_Of_Big_Int (X2, X2'First, X2'Length) <
         --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
         --#   Bignum.Num_Of_Big_Int (Y2, Y2'First, Y2'Length) <
         --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
         --#   Bignum.Num_Of_Big_Int (Z2, Z2'First, Z2'Length) <
         --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length);
         loop
            Point_Double (X2, Y2, Z2, X3, Y3, Z3, A, M, M_Inv);

            if (E (I) and 2 ** J) /= 0 then
               Point_Add
                 (X1 => X3, Y1 => Y3, Z1 => Z3,
                  X2 => X1, Y2 => Y1, Z2 => Z1,
                  X3 => X2, Y3 => Y2, Z3 => Z2,
                  A => A, M => M, M_Inv => M_Inv);
            else
               Bignum.Copy (X3, X3'First, X3'Last, X2, X2'First);
               Bignum.Copy (Y3, Y3'First, Y3'Last, Y2, Y2'First);
               Bignum.Copy (Z3, Z3'First, Z3'Last, Z2, Z2'First);
            end if;

            --# assert
            --#   Bignum.Num_Of_Big_Int (X2, X2'First, X2'Length) <
            --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
            --#   Bignum.Num_Of_Big_Int (Y2, Y2'First, Y2'Length) <
            --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
            --#   Bignum.Num_Of_Big_Int (Z2, Z2'First, Z2'Length) <
            --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length);
         end loop;
      end loop;
   end Point_Mult;

   ----------------------------------------------------------------------------

   procedure Make_Affine
     (X1      : in     Coord;
      Y1      : in     Coord;
      Z1      : in     Coord;
      X2      :    out Coord;
      Y2      :    out Coord;
      R       : in     Coord;
      M       : in     Coord;
      M_Inv   : in     Types.Word32)
   is
      Carry : Boolean;
      H1, H2, H3, H4, H5 : Coord;
   begin
      Bignum.Initialize (H4, H4'First, H4'Last);
      H4 (H4'First) := 2;
      --# accept Flow, 10, Carry, "Carry not needed here";
      Bignum.Sub (H5, H5'First, H5'Last, M, M'First, H4, H4'First, Carry);
      --# end accept;

      --# accept Flow, 10, H1, "auxiliary variable" &
      --#        Flow, 10, H2, "auxiliary variable" &
      --#        Flow, 10, H3, "auxiliary variable";
      Bignum.Mont_Exp
        (A          => H4,
         A_First    => H4'First,
         A_Last     => H4'Last,
         X          => Z1,
         X_First    => Z1'First,
         E          => H5,
         E_First    => H5'First,
         E_Last     => H5'Last,
         M          => M,
         M_First    => M'First,
         Aux1       => H1,
         Aux1_First => H1'First,
         Aux2       => H2,
         Aux2_First => H2'First,
         Aux3       => H3,
         Aux3_First => H3'First,
         R          => R,
         R_First    => R'First,
         M_Inv      => M_Inv);
      --# end accept;

      Bignum.Mont_Mult
        (H1, H1'First, H1'Last, H4, H4'First, R, R'First,
         M, M'First, M_Inv);

      Bignum.Mont_Mult
        (X2, X2'First, X2'Last, X1, X1'First, H1, H1'First,
         M, M'First, M_Inv);

      Bignum.Mont_Mult
        (Y2, Y2'First, Y2'Last, Y1, Y1'First, H1, H1'First,
         M, M'First, M_Inv);

      --# accept Flow, 33, Carry, "Carry not needed here" &
      --#        Flow, 33, H2, "auxiliary variable" &
      --#        Flow, 33, H3, "auxiliary variable";
   end Make_Affine;

end LSC.EC;
