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
   is
      L : Natural;
      H1, H2, H3, H4, H5, H6 : Coord;
   begin
      L := X1_Last - X1_First;

      if Bignum.Is_Zero (Z1, Z1_First, Z1_First + L) then
         Bignum.Initialize (X2, X2_First, X2_First + L);
         Bignum.Initialize (Y2, Y2_First, Y2_First + L);
         Bignum.Initialize (Z2, Z2_First, Z2_First + L);

      else
         Bignum.Mod_Add
           (H1, H1'First, H1'First + L, Y1, Y1_First, Y1, Y1_First,
            M, M_First);

         Bignum.Mont_Mult
           (H2, H2'First, H2'First + L, H1, H1'First, Z1, Z1_First,
            M, M_First, M_Inv);

         Bignum.Mod_Add
           (H3, H3'First, H3'First + L, X1, X1_First, X1, X1_First,
            M, M_First);

         Bignum.Mod_Add_Inplace
           (H3, H3'First, H3'First + L, X1, X1_First, M, M_First);

         Bignum.Mont_Mult
           (H1, H1'First, H1'First + L, H3, H3'First, X1, X1_First,
            M, M_First, M_Inv);

         Bignum.Mont_Mult
           (H4, H4'First, H4'First + L, A, A_First, Z1, Z1_First,
            M, M_First, M_Inv);

         Bignum.Mont_Mult
           (H3, H3'First, H3'First + L, H4, H4'First, Z1, Z1_First,
            M, M_First, M_Inv);

         Bignum.Mod_Add_Inplace
           (H1, H1'First, H1'First + L, H3, H3'First, M, M_First);

         Bignum.Mod_Sub_Inplace
           (H1, H1'First, H1'First + L, M, M_First, M, M_First);

         Bignum.Mont_Mult
           (H4, H4'First, H4'First + L, Y1, Y1_First, H2, H2'First,
            M, M_First, M_Inv);

         Bignum.Mod_Add
           (H6, H6'First, H6'First + L, X1, X1_First, X1, X1_First,
            M, M_First);

         Bignum.Mont_Mult
           (H5, H5'First, H5'First + L, H6, H6'First, H4, H4'First,
            M, M_First, M_Inv);

         Bignum.Mont_Mult
           (H6, H6'First, H6'First + L, H1, H1'First, H1, H1'First,
            M, M_First, M_Inv);

         Bignum.Mod_Sub_Inplace
           (H6, H6'First, H6'First + L, H5, H5'First, M, M_First);

         Bignum.Mod_Sub_Inplace
           (H6, H6'First, H6'First + L, H5, H5'First, M, M_First);

         Bignum.Mont_Mult
           (X2, X2_First, X2_First + L, H6, H6'First, H2, H2'First,
            M, M_First, M_Inv);

         Bignum.Mod_Sub
           (H3, H3'First, H3'First + L, H5, H5'First, H6, H6'First,
            M, M_First);

         Bignum.Mont_Mult
           (Y2, Y2_First, Y2_First + L, H3, H3'First, H1, H1'First,
            M, M_First, M_Inv);

         Bignum.Mod_Add
           (H3, H3'First, H3'First + L, H4, H4'First, H4, H4'First,
            M, M_First);

         Bignum.Mont_Mult
           (H1, H1'First, H1'First + L, H3, H3'First, H4, H4'First,
            M, M_First, M_Inv);

         Bignum.Mod_Sub_Inplace
           (Y2, Y2_First, Y2_First + L, H1, H1'First, M, M_First);

         Bignum.Mont_Mult
           (H3, H3'First, H3'First + L, H2, H2'First, H2, H2'First,
            M, M_First, M_Inv);

         Bignum.Mont_Mult
           (Z2, Z2_First, Z2_First + L, H3, H3'First, H2, H2'First,
            M, M_First, M_Inv);
      end if;
   end Point_Double;

   ----------------------------------------------------------------------------

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
   is
      L : Natural;
      H1, H2, H3, H4, H5, H6, H7, H8, H9 : Coord;
   begin
      L := X1_Last - X1_First;

      if Bignum.Is_Zero (Z1, Z1_First, Z1_First + L) then
         Bignum.Copy (X2, X2_First, X2_First + L, X3, X3_First);
         Bignum.Copy (Y2, Y2_First, Y2_First + L, Y3, Y3_First);
         Bignum.Copy (Z2, Z2_First, Z2_First + L, Z3, Z3_First);

      elsif Bignum.Is_Zero (Z2, Z2_First, Z2_First + L) then
         Bignum.Copy (X1, X1_First, X1_Last, X3, X3_First);
         Bignum.Copy (Y1, Y1_First, Y1_First + L, Y3, Y3_First);
         Bignum.Copy (Z1, Z1_First, Z1_First + L, Z3, Z3_First);

      else
         Bignum.Mont_Mult
           (H1, H1'First, H1'First + L, X2, X2_First, Z1, Z1_First,
            M, M_First, M_Inv);

         Bignum.Mont_Mult
           (H2, H2'First, H2'First + L, X1, X1_First, Z2, Z2_First,
            M, M_First, M_Inv);

         Bignum.Mont_Mult
           (H3, H3'First, H3'First + L, Y2, Y2_First, Z1, Z1_First,
            M, M_First, M_Inv);

         Bignum.Mont_Mult
           (H4, H4'First, H4'First + L, Y1, Y1_First, Z2, Z2_First,
            M, M_First, M_Inv);

         Bignum.Mod_Sub
           (H5, H5'First, H5'First + L, H1, H1'First, H2, H2'First,
            M, M_First);

         Bignum.Mod_Sub
           (H6, H6'First, H6'First + L, H3, H3'First, H4, H4'First,
            M, M_First);

         if Bignum.Is_Zero (H5, H5'First, H5'First + L) then
            if Bignum.Is_Zero (H6, H6'First, H6'First + L) then
               Point_Double
                 (X1, X1_First, X1_Last, Y1, Y1_First, Z1, Z1_First,
                  X3, X3_First, Y3, Y3_First, Z3, Z3_First,
                  A, A_First, M, M_First, M_Inv);

            else
               Bignum.Initialize (X3, X3_First, X3_First + L);
               Bignum.Initialize (Y3, Y3_First, Y3_First + L);
               Bignum.Initialize (Z3, Z3_First, Z3_First + L);
            end if;

         else
            Bignum.Mont_Mult
              (H7, H7'First, H7'First + L, Z1, Z1_First, Z2, Z2_First,
               M, M_First, M_Inv);

            Bignum.Mod_Add
              (H8, H8'First, H8'First + L, H1, H1'First, H2, H2'First,
               M, M_First);

            Bignum.Mont_Mult
              (H3, H3'First, H3'First + L, H5, H5'First, H5, H5'First,
               M, M_First, M_Inv);

            Bignum.Mont_Mult
              (H1, H1'First, H1'First + L, H2, H2'First, H3, H3'First,
               M, M_First, M_Inv);

            Bignum.Mont_Mult
              (H2, H2'First, H2'First + L, H8, H8'First, H3, H3'First,
               M, M_First, M_Inv);

            Bignum.Mont_Mult
              (H8, H8'First, H8'First + L, H3, H3'First, H5, H5'First,
               M, M_First, M_Inv);

            Bignum.Mont_Mult
              (H9, H9'First, H9'First + L, H6, H6'First, H6, H6'First,
               M, M_First, M_Inv);

            Bignum.Mont_Mult
              (H3, H3'First, H3'First + L, H9, H9'First, H7, H7'First,
               M, M_First, M_Inv);

            Bignum.Mod_Sub_Inplace
              (H3, H3'First, H3'First + L, H2, H2'First, M, M_First);

            Bignum.Mont_Mult
              (X3, X3_First, X3_First + L, H5, H5'First, H3, H3'First,
               M, M_First, M_Inv);

            Bignum.Mod_Sub_Inplace
              (H1, H1'First, H1'First + L, H3, H3'First, M, M_First);

            Bignum.Mont_Mult
              (H2, H2'First, H2'First + L, H1, H1'First, H6, H6'First,
               M, M_First, M_Inv);

            Bignum.Mont_Mult
              (H1, H1'First, H1'First + L, H8, H8'First, H4, H4'First,
               M, M_First, M_Inv);

            Bignum.Mod_Sub
              (Y3, Y3_First, Y3_First + L, H2, H2'First, H1, H1'First,
               M, M_First);

            Bignum.Mont_Mult
              (Z3, Z3_First, Z3_First + L, H8, H8'First, H7, H7'First,
               M, M_First, M_Inv);
         end if;
      end if;
   end Point_Add;

   ----------------------------------------------------------------------------

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
   is
      L : Natural;
      X3, Y3, Z3 : Coord;
   begin
      L := X1_Last - X1_First;

      Bignum.Initialize (X2, X2_First, X2_First + L);
      Bignum.Initialize (Y2, Y2_First, Y2_First + L);
      Bignum.Initialize (Z2, Z2_First, Z2_First + L);

      for I in reverse Natural range E_First .. E_Last
      --# assert
      --#   L = X1_Last - X1_First and
      --#   Bignum.Num_Of_Big_Int (X2, X2_First, L + 1) <
      --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
      --#   Bignum.Num_Of_Big_Int (Y2, Y2_First, L + 1) <
      --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
      --#   Bignum.Num_Of_Big_Int (Z2, Z2_First, L + 1) <
      --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1);
      loop
         for J in reverse Natural range 0 .. 31
         --# assert
         --#   L = X1_Last - X1_First and
         --#   Bignum.Num_Of_Big_Int (X2, X2_First, L + 1) <
         --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
         --#   Bignum.Num_Of_Big_Int (Y2, Y2_First, L + 1) <
         --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
         --#   Bignum.Num_Of_Big_Int (Z2, Z2_First, L + 1) <
         --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1);
         loop
            Point_Double
              (X2, X2_First, X2_First + L, Y2, Y2_First, Z2, Z2_First,
               X3, X3'First, Y3, Y3'First, Z3, Z3'First,
               A, A_First, M, M_First, M_Inv);

            if (E (I) and 2 ** J) /= 0 then
               Point_Add
                 (X3, X3'First, X3'First + L, Y3, Y3'First, Z3, Z3'First,
                  X1, X1_First, Y1, Y1_First, Z1, Z1_First,
                  X2, X2_First, Y2, Y2_First, Z2, Z2_First,
                  A, A_First, M, M_First, M_Inv);
            else
               Bignum.Copy (X3, X3'First, X3'First + L, X2, X2_First);
               Bignum.Copy (Y3, Y3'First, Y3'First + L, Y2, Y2_First);
               Bignum.Copy (Z3, Z3'First, Z3'First + L, Z2, Z2_First);
            end if;

            --# assert
            --#   L = X1_Last - X1_First and
            --#   Bignum.Num_Of_Big_Int (X2, X2_First, L + 1) <
            --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
            --#   Bignum.Num_Of_Big_Int (Y2, Y2_First, L + 1) <
            --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
            --#   Bignum.Num_Of_Big_Int (Z2, Z2_First, L + 1) <
            --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1);
         end loop;
      end loop;
   end Point_Mult;

   ----------------------------------------------------------------------------

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
   is
      L : Natural;
      X4, Y4, Z4, X5, Y5, Z5 : Coord;
   begin
      L := X1_Last - X1_First;

      Point_Add
        (X1, X1_First, X1_Last, Y1, Y1_First, Z1, Z1_First,
         X2, X2_First, Y2, Y2_First, Z2, Z2_First,
         X5, X5'First, Y5, Y5'First, Z5, Z5'First,
         A, A_First, M, M_First, M_Inv);

      Bignum.Initialize (X3, X3_First, X3_First + L);
      Bignum.Initialize (Y3, Y3_First, Y3_First + L);
      Bignum.Initialize (Z3, Z3_First, Z3_First + L);

      for I in reverse Natural range E1_First .. E1_Last
      --# assert
      --#   L = X1_Last - X1_First and
      --#   Bignum.Num_Of_Big_Int (X3, X3_First, L + 1) <
      --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
      --#   Bignum.Num_Of_Big_Int (Y3, Y3_First, L + 1) <
      --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
      --#   Bignum.Num_Of_Big_Int (Z3, Z3_First, L + 1) <
      --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
      --#   Bignum.Num_Of_Big_Int (X5, X5'First, L + 1) <
      --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
      --#   Bignum.Num_Of_Big_Int (Y5, Y5'First, L + 1) <
      --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
      --#   Bignum.Num_Of_Big_Int (Z5, Z5'First, L + 1) <
      --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1);
      loop
         for J in reverse Natural range 0 .. 31
         --# assert
         --#   L = X1_Last - X1_First and
         --#   Bignum.Num_Of_Big_Int (X3, X3_First, L + 1) <
         --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
         --#   Bignum.Num_Of_Big_Int (Y3, Y3_First, L + 1) <
         --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
         --#   Bignum.Num_Of_Big_Int (Z3, Z3_First, L + 1) <
         --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
         --#   Bignum.Num_Of_Big_Int (X5, X5'First, L + 1) <
         --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
         --#   Bignum.Num_Of_Big_Int (Y5, Y5'First, L + 1) <
         --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
         --#   Bignum.Num_Of_Big_Int (Z5, Z5'First, L + 1) <
         --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1);
         loop
            Point_Double
              (X3, X3_First, X3_First + L, Y3, Y3_First, Z3, Z3_First,
               X4, X4'First, Y4, Y4'First, Z4, Z4'First,
               A, A_First, M, M_First, M_Inv);

            if (E1 (I) and 2 ** J) /= 0 then
               if (E2 (E2_First + (I - E1_First)) and 2 ** J) /= 0 then
                  Point_Add
                    (X4, X4'First, X4'First + L, Y4, Y4'First, Z4, Z4'First,
                     X5, X5'First, Y5, Y5'First, Z5, Z5'First,
                     X3, X3_First, Y3, Y3_First, Z3, Z3_First,
                     A, A_First, M, M_First, M_Inv);
               else
                  Point_Add
                    (X4, X4'First, X4'First + L, Y4, Y4'First, Z4, Z4'First,
                     X1, X1_First, Y1, Y1_First, Z1, Z1_First,
                     X3, X3_First, Y3, Y3_First, Z3, Z3_First,
                     A, A_First, M, M_First, M_Inv);
               end if;
            elsif (E2 (E2_First + (I - E1_First)) and 2 ** J) /= 0 then
               Point_Add
                 (X4, X4'First, X4'First + L, Y4, Y4'First, Z4, Z4'First,
                  X2, X2_First, Y2, Y2_First, Z2, Z2_First,
                  X3, X3_First, Y3, Y3_First, Z3, Z3_First,
                  A, A_First, M, M_First, M_Inv);
            else
               Bignum.Copy (X4, X4'First, X4'First + L, X3, X3_First);
               Bignum.Copy (Y4, Y4'First, Y4'First + L, Y3, Y3_First);
               Bignum.Copy (Z4, Z4'First, Z4'First + L, Z3, Z3_First);
            end if;

            --# assert
            --#   L = X1_Last - X1_First and
            --#   Bignum.Num_Of_Big_Int (X3, X3_First, L + 1) <
            --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
            --#   Bignum.Num_Of_Big_Int (Y3, Y3_First, L + 1) <
            --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
            --#   Bignum.Num_Of_Big_Int (Z3, Z3_First, L + 1) <
            --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
            --#   Bignum.Num_Of_Big_Int (X5, X5'First, L + 1) <
            --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
            --#   Bignum.Num_Of_Big_Int (Y5, Y5'First, L + 1) <
            --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1) and
            --#   Bignum.Num_Of_Big_Int (Z5, Z5'First, L + 1) <
            --#   Bignum.Num_Of_Big_Int (M, M_First, L + 1);
         end loop;
      end loop;
   end Two_Point_Mult;

   ----------------------------------------------------------------------------

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
   is
      L : Natural;
      Two : constant Coord := Coord'(2, others => 0);
      E, H1, H2, H3, H4 : Coord;
      Carry : Boolean;
   begin
      L := A_Last - A_First;

      --# accept Flow, 10, Carry, "Carry not needed here";
      Bignum.Sub (E, E'First, E'First + L, M, M_First, Two, Two'First, Carry);
      --# end accept;

      --# accept Flow, 10, H1, "auxiliary variable" &
      --#        Flow, 10, H2, "auxiliary variable" &
      --#        Flow, 10, H3, "auxiliary variable";
      Bignum.Mont_Exp
        (A          => H4,
         A_First    => H4'First,
         A_Last     => H4'First + L,
         X          => A,
         X_First    => A_First,
         E          => E,
         E_First    => E'First,
         E_Last     => E'First + L,
         M          => M,
         M_First    => M_First,
         Aux1       => H1,
         Aux1_First => H1'First,
         Aux2       => H2,
         Aux2_First => H2'First,
         Aux3       => H3,
         Aux3_First => H3'First,
         R          => R,
         R_First    => R_First,
         M_Inv      => M_Inv);
      --# end accept;

      Bignum.Mont_Mult
        (B, B_First, B_First + L, H4, H4'First, R, R_First,
         M, M_First, M_Inv);

      --# accept Flow, 33, Carry, "Carry not needed here" &
      --#        Flow, 33, H1, "auxiliary variable" &
      --#        Flow, 33, H2, "auxiliary variable" &
      --#        Flow, 33, H3, "auxiliary variable";
   end Invert;

   ----------------------------------------------------------------------------

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
   is
      L : Natural;
      H : Coord;
   begin
      L := X1_Last - X1_First;

      Invert
        (Z1, Z1_First, Z1_First + L, H, H'First,
         R, R_First, M, M_First, M_Inv);

      Bignum.Mont_Mult
        (X2, X2_First, X2_First + L, X1, X1_First, H, H'First,
         M, M_First, M_Inv);

      Bignum.Mont_Mult
        (Y2, Y2_First, Y2_First + L, Y1, Y1_First, H, H'First,
         M, M_First, M_Inv);
   end Make_Affine;

   ----------------------------------------------------------------------------

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
   is
      L : Natural;
      H1, H2, H3, H4 : Coord;
   begin
      L := X_Last - X_First;

      Bignum.Mont_Mult
        (H3, H3'First, H3'First + L, Y, Y_First, R, R_First,
         M, M_First, M_Inv);

      Bignum.Mont_Mult
        (H1, H1'First, H1'First + L, H3, H3'First, H3, H3'First,
         M, M_First, M_Inv);

      Bignum.Mont_Mult
        (H2, H2'First, H2'First + L, X, X_First, R, R_First,
         M, M_First, M_Inv);

      Bignum.Mont_Mult
        (H3, H3'First, H3'First + L, H2, H2'First, H2, H2'First,
         M, M_First, M_Inv);

      Bignum.Mod_Add_Inplace
        (H3, H3'First, H3'First + L, A, A_First, M, M_First);

      Bignum.Mont_Mult
        (H4, H4'First, H4'First + L, H3, H3'First, H2, H2'First,
         M, M_First, M_Inv);

      Bignum.Mod_Sub_Inplace
        (H1, H1'First, H1'First + L, H4, H4'First, M, M_First);

      Bignum.Mod_Sub_Inplace
        (H1, H1'First, H1'First + L, B, B_First, M, M_First);

      return Bignum.Is_Zero (H1, H1'First, H1'First + L);
   end On_Curve;

   ----------------------------------------------------------------------------

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
   is
      L : Natural;
      H1, H2, H3, H4, H5, H6 : Coord;
      Carry : Boolean;
   begin
      L := X_Last - X_First;

      Bignum.Mont_Mult
        (H1, H1'First, H1'First + L, X, X_First, R, R_First,
         M, M_First, M_Inv);

      Bignum.Mont_Mult
        (H2, H2'First, H2'First + L, H1, H1'First, H1, H1'First,
         M, M_First, M_Inv);

      Bignum.Mod_Add_Inplace
        (H2, H2'First, H2'First + L, A, A_First, M, M_First);

      Bignum.Mont_Mult
        (H3, H3'First, H3'First + L, H2, H2'First, H1, H1'First,
         M, M_First, M_Inv);

      Bignum.Mod_Add_Inplace
        (H3, H3'First, H3'First + L, B, B_First, M, M_First);

      Bignum.Mont_Mult
        (H1, H1'First, H1'First + L, H3, H3'First, One, One'First,
         M, M_First, M_Inv);

      --# accept Flow, 10, Carry, "not needed here";
      Bignum.Add
        (H2, H2'First, H2'First + L, M, M_First, One, One'First, Carry);
      --# end accept;

      Bignum.SHR_Inplace (H2, H2'First, H2'First + L, 2);

      --# accept Flow, 10, H4, "auxiliary variable" &
      --#        Flow, 10, H5, "auxiliary variable" &
      --#        Flow, 10, H6, "auxiliary variable";
      Bignum.Mont_Exp
        (H3, H3'First, H3'First + L,
         H1, H1'First, H2, H2'First, H2'First + L,
         M, M_First,
         H4, H4'First, H5, H5'First, H6, H6'First,
         R, R_First, M_Inv);
      --# end accept;

      if
        Bignum.Is_Zero (H3, H3'First, H3'First + L) or else
        (H3 (H3'First) mod 2 = 0) = Even
      then
         Bignum.Copy (H3, H3'First, H3'First + L, Y, Y_First);
      else
         --# accept Flow, 10, Carry, "not needed here";
         Bignum.Sub (Y, Y_First, Y_First + L, M, M_First, H3, H3'First, Carry);
         --# end accept;
      end if;

      Bignum.Mont_Mult
        (H2, H2'First, H2'First + L, Y, Y_First, R, R_First,
         M, M_First, M_Inv);

      Bignum.Mont_Mult
        (H3, H3'First, H3'First + L, Y, Y_First, H2, H2'First,
         M, M_First, M_Inv);

      Success := Bignum.Equal (H1, H1'First, H1'First + L, H3, H3'First);

      --# accept Flow, 33, Carry, "not needed here" &
      --#        Flow, 33, H4, "auxiliary variable" &
      --#        Flow, 33, H5, "auxiliary variable" &
      --#        Flow, 33, H6, "auxiliary variable";
   end Uncompress_Point;

end LSC.EC;
