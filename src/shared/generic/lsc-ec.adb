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
      M_Inv    : in     Types.Word32)
   is
      X4, Y4, Z4, X5, Y5, Z5 : Coord;
   begin
      Point_Add
        (X1 => X1, Y1 => Y1, Z1 => Z1,
         X2 => X2, Y2 => Y2, Z2 => Z2,
         X3 => X5, Y3 => Y5, Z3 => Z5,
         A => A, M => M, M_Inv => M_Inv);

      Bignum.Initialize (X3, X3'First, X3'Last);
      Bignum.Initialize (Y3, Y3'First, Y3'Last);
      Bignum.Initialize (Z3, Z3'First, Z3'Last);

      for I in reverse Natural range E1_First .. E1_Last
      --# assert
      --#   Bignum.Num_Of_Big_Int (X3, X3'First, X3'Length) <
      --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
      --#   Bignum.Num_Of_Big_Int (Y3, Y3'First, Y3'Length) <
      --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
      --#   Bignum.Num_Of_Big_Int (Z3, Z3'First, Z3'Length) <
      --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
      --#   Bignum.Num_Of_Big_Int (X5, X5'First, X5'Length) <
      --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
      --#   Bignum.Num_Of_Big_Int (Y5, Y5'First, Y5'Length) <
      --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
      --#   Bignum.Num_Of_Big_Int (Z5, Z5'First, Z5'Length) <
      --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length);
      loop
         for J in reverse Natural range 0 .. 31
         --# assert
         --#   Bignum.Num_Of_Big_Int (X3, X3'First, X3'Length) <
         --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
         --#   Bignum.Num_Of_Big_Int (Y3, Y3'First, Y3'Length) <
         --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
         --#   Bignum.Num_Of_Big_Int (Z3, Z3'First, Z3'Length) <
         --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
         --#   Bignum.Num_Of_Big_Int (X5, X5'First, X5'Length) <
         --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
         --#   Bignum.Num_Of_Big_Int (Y5, Y5'First, Y5'Length) <
         --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
         --#   Bignum.Num_Of_Big_Int (Z5, Z5'First, Z5'Length) <
         --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length);
         loop
            Point_Double (X3, Y3, Z3, X4, Y4, Z4, A, M, M_Inv);

            if (E1 (I) and 2 ** J) /= 0 then
               if (E2 (E2_First + (I - E1_First)) and 2 ** J) /= 0 then
                  Point_Add
                    (X1 => X4, Y1 => Y4, Z1 => Z4,
                     X2 => X5, Y2 => Y5, Z2 => Z5,
                     X3 => X3, Y3 => Y3, Z3 => Z3,
                     A => A, M => M, M_Inv => M_Inv);
               else
                  Point_Add
                    (X1 => X4, Y1 => Y4, Z1 => Z4,
                     X2 => X1, Y2 => Y1, Z2 => Z1,
                     X3 => X3, Y3 => Y3, Z3 => Z3,
                     A => A, M => M, M_Inv => M_Inv);
               end if;
            elsif (E2 (E2_First + (I - E1_First)) and 2 ** J) /= 0 then
               Point_Add
                 (X1 => X4, Y1 => Y4, Z1 => Z4,
                  X2 => X2, Y2 => Y2, Z2 => Z2,
                  X3 => X3, Y3 => Y3, Z3 => Z3,
                  A => A, M => M, M_Inv => M_Inv);
            else
               Bignum.Copy (X4, X4'First, X4'Last, X3, X3'First);
               Bignum.Copy (Y4, Y4'First, Y4'Last, Y3, Y3'First);
               Bignum.Copy (Z4, Z4'First, Z4'Last, Z3, Z3'First);
            end if;

            --# assert
            --#   Bignum.Num_Of_Big_Int (X3, X3'First, X3'Length) <
            --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
            --#   Bignum.Num_Of_Big_Int (Y3, Y3'First, Y3'Length) <
            --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
            --#   Bignum.Num_Of_Big_Int (Z3, Z3'First, Z3'Length) <
            --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
            --#   Bignum.Num_Of_Big_Int (X5, X5'First, X5'Length) <
            --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
            --#   Bignum.Num_Of_Big_Int (Y5, Y5'First, Y5'Length) <
            --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
            --#   Bignum.Num_Of_Big_Int (Z5, Z5'First, Z5'Length) <
            --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length);
         end loop;
      end loop;
   end Two_Point_Mult;

   ----------------------------------------------------------------------------

   procedure Invert
     (A     : in     Coord;
      B     :    out Coord;
      R     : in     Coord;
      M     : in     Coord;
      M_Inv : in     Types.Word32)
   is
      Two : constant Coord := Coord'(2, others => 0);
      E, H1, H2, H3, H4 : Coord;
      Carry : Boolean;
   begin
      --# accept Flow, 10, Carry, "Carry not needed here";
      Bignum.Sub (E, E'First, E'Last, M, M'First, Two, Two'First, Carry);
      --# end accept;

      --# accept Flow, 10, H1, "auxiliary variable" &
      --#        Flow, 10, H2, "auxiliary variable" &
      --#        Flow, 10, H3, "auxiliary variable";
      Bignum.Mont_Exp
        (A          => H4,
         A_First    => H4'First,
         A_Last     => H4'Last,
         X          => A,
         X_First    => A'First,
         E          => E,
         E_First    => E'First,
         E_Last     => E'Last,
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
        (B, B'First, B'Last, H4, H4'First, R, R'First,
         M, M'First, M_Inv);

      --# accept Flow, 33, Carry, "Carry not needed here" &
      --#        Flow, 33, H1, "auxiliary variable" &
      --#        Flow, 33, H2, "auxiliary variable" &
      --#        Flow, 33, H3, "auxiliary variable";
   end Invert;

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
      H : Coord;
   begin
      Invert (Z1, H, R, M, M_Inv);

      Bignum.Mont_Mult
        (X2, X2'First, X2'Last, X1, X1'First, H, H'First,
         M, M'First, M_Inv);

      Bignum.Mont_Mult
        (Y2, Y2'First, Y2'Last, Y1, Y1'First, H, H'First,
         M, M'First, M_Inv);
   end Make_Affine;

   ----------------------------------------------------------------------------

   function On_Curve
     (X     : Coord;
      Y     : Coord;
      A     : Coord;
      B     : Coord;
      R     : Coord;
      M     : Coord;
      M_Inv : Types.Word32)
     return Boolean
   is
      H1, H2, H3, H4 : Coord;
   begin
      Bignum.Mont_Mult
        (H3, H3'First, H3'Last, Y, Y'First, R, R'First,
         M, M'First, M_Inv);

      Bignum.Mont_Mult
        (H1, H1'First, H1'Last, H3, H3'First, H3, H3'First,
         M, M'First, M_Inv);

      Bignum.Mont_Mult
        (H2, H2'First, H2'Last, X, X'First, R, R'First,
         M, M'First, M_Inv);

      Bignum.Mont_Mult
        (H3, H3'First, H3'Last, H2, H2'First, H2, H2'First,
         M, M'First, M_Inv);

      Bignum.Mod_Add_Inplace
        (H3, H3'First, H3'Last, A, A'First, M, M'First);

      Bignum.Mont_Mult
        (H4, H4'First, H4'Last, H3, H3'First, H2, H2'First,
         M, M'First, M_Inv);

      Bignum.Mod_Sub_Inplace
        (H1, H1'First, H1'Last, H4, H4'First, M, M'First);

      Bignum.Mod_Sub_Inplace
        (H1, H1'First, H1'Last, B, B'First, M, M'First);

      return Bignum.Is_Zero (H1, H1'First, H1'Last);
   end On_Curve;

end LSC.EC;
