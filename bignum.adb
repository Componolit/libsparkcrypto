with Types;

package body Bignum
is

   --# function GCD (A, B: Universal_Integer) return Universal_Integer;

   procedure Initialize
      (A       :    out Big_Int;
       A_First : in     Natural;
       A_Last  : in     Natural)
   --# derives
   --#   A from A_First, A_Last;
   --# pre
   --#   A_First in A'Range and
   --#   A_Last in A'Range and
   --#   A_First <= A_Last;
   --# post
   --#   (for all K in Natural range A_First .. A_Last => (A (K) = 0));
   is
   begin

      for I in Natural range A_First .. A_Last
        --# assert (for all K in Natural range A_First .. I - 1 => (A (K) = 0));
      loop
         --# accept Flow, 23, A, "Initialized between A_First and A_Last";
         A (I) := 0;
      end loop;
      --# accept Flow, 602, A, A, "OK";
   end Initialize;

   ----------------------------------------------------------------------------

   function Word_Of_Boolean (B : Boolean) return Types.Word32
     --# return Result => Universal_Integer (Result) = Num_Of_Boolean (B);
   is
      Result : Types.Word32;
   begin
      if B then
         Result := 1;
      else
         Result := 0;
      end if;

      return Result;
   end Word_Of_Boolean;

   ----------------------------------------------------------------------------

   procedure Double_Inplace
     (A       : in out Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural;
      Carry   :    out Boolean)
   is
      New_Carry : Boolean;
   begin
      Carry := False;

      for I in Natural range A_First .. A_Last
        --# assert
        --#   Num_Of_Big_Int (A~, A_First, I - A_First) * 2 =
        --#   Num_Of_Big_Int (A, A_First, I - A_First) +
        --#   2 ** (32 * (I - A_First)) * Num_Of_Boolean (Carry) and
        --#   (for all K in Natural range I .. A_Last =>
        --#      (A (K) = A~ (K)));
      loop
         New_Carry := (A (I) and 2 ** 31) /= 0;
         A (I) := Types.SHL32 (A (I), 1) + Word_Of_Boolean (Carry);
         Carry := New_Carry;
      end loop;
   end Double_Inplace;

   ----------------------------------------------------------------------------

   procedure Sub_Inplace
     (A       : in out Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural;
      B       : in     Big_Int;
      B_First : in     Natural;
      Carry   :    out Boolean)
   is
      J         : Natural;
      New_Carry : Boolean;
   begin
      Carry := False;

      for I in Natural range A_First .. A_Last
        --# assert
        --#   Num_Of_Big_Int (A~, A_First, I - A_First) -
        --#   Num_Of_Big_Int (B, B_First, I - A_First) =
        --#   Num_Of_Big_Int (A, A_First, I - A_First) -
        --#   2 ** (32 * (I - A_First)) * Num_Of_Boolean (Carry) and
        --#   (for all K in Natural range I .. A_Last =>
        --#      (A (K) = A~ (K)));
      loop
         J := B_First + (I - A_First);
         New_Carry := A (I) < B (J) or else (A (I) = B (J) and then Carry);
         A (I) := (A (I) - B (J)) - Word_Of_Boolean (Carry);
         Carry := New_Carry;
      end loop;
   end Sub_Inplace;

   ----------------------------------------------------------------------------

   function Less
     (A       : Big_Int;
      A_First : Natural;
      A_Last  : Natural;
      B       : Big_Int;
      B_First : Natural)
     return Boolean
   is
      J      : Natural;
      Result : Boolean;
   begin
      Result := False;

      for I in reverse Natural range A_First .. A_Last
        --# assert
        --#   Num_Of_Big_Int (A, I + 1, A_Last - I) =
        --#   Num_Of_Big_Int (B, B_First + (I - A_First) + 1, A_Last - I) and
        --#   not Result and A_First% = A_First;
      loop
         J := B_First + (I - A_First);

         if A (I) < B (J) then
           Result := True;
           exit;
         end if;

         exit when A (I) > B (J);
      end loop;

      return Result;
   end Less;

   ----------------------------------------------------------------------------

   procedure Size_Square_Mod
     (M       : in     Big_Int;
      M_First : in     Natural;
      M_Last  : in     Natural;
      R       :    out Big_Int;
      R_First : in     Natural)
   is
      R_Last : Natural;
      Carry  : Boolean;
   begin
      R_Last := R_First + (M_Last - M_First);
      Initialize (R, R_First, R_Last);

      R (R_First) := 1;

      for I in Natural range M_First .. M_Last
        --# assert
        --#   Num_Of_Big_Int (R, R_First, M_Last - M_First + 1) =
        --#   2 ** (32 * 2 * (I - M_First)) mod
        --#   Num_Of_Big_Int (M, M_First, M_Last - M_First + 1) and
        --#   R_Last = R_First + (M_Last - M_First);
      loop
         for J in Natural range 0 .. 63
           --# assert
           --#   Num_Of_Big_Int (R, R_First, M_Last - M_First + 1) =
           --#   2 ** (32 * 2 * (I - M_First) + J) mod
           --#   Num_Of_Big_Int (M, M_First, M_Last - M_First + 1) and
           --#   R_Last = R_First + (M_Last - M_First);
         loop
            Double_Inplace (R, R_First, R_Last, Carry);
            if Carry or else not Less (R, R_First, R_Last, M, M_First) then
               --# accept Flow, 10, Carry, "Carry not needed here";
               Sub_Inplace (R, R_First, R_Last, M, M_First, Carry);
            end if;
         end loop;
      end loop;
   end Size_Square_Mod;

   ----------------------------------------------------------------------------

   function Word_Inverse (M : Types.Word32) return Types.Word32
   is
      A, B, Quot, New_B, P, Q, New_Q : Types.Word32;
   begin
      A := M;
      B := (0 - M) mod M;
      P := 1;
      Q := (0 - ((0 - M) / M)) - 1;

      while B /= 0
        --# assert
        --#   A = P * M and B = Q * M and
        --#   GCD (Universal_Integer (A), Universal_Integer (B)) = 1;
      loop
         Quot := A / B;
         New_B := A mod B;
         A := B;
         B := New_B;
         New_Q := P - Quot * Q;
         P := Q;
         Q := New_Q;
      end loop;

      return 0 - P;
   end Word_Inverse;

   ----------------------------------------------------------------------------

   procedure Add_Mult_Inplace
     (A       : in out Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural;
      B       : in     Big_Int;
      B_First : in     Natural;
      C       : in     Types.Word32;
      Carry   :    out Boolean)
   is
      Temp   : Types.Word64;
      Carry2 : Types.Word32;
   begin
      Carry2 := 0;

      for I in Natural range A_First .. A_Last - 1
        --# assert
        --#   Num_Of_Big_Int (A~, A_First, I - A_First) +
        --#   Num_Of_Big_Int (B, B_First, I - A_First) *
        --#   Universal_Integer (C) =
        --#   Num_Of_Big_Int (A, A_First, I - A_First) +
        --#   2 ** (32 * (I - A_First)) * Universal_Integer (Carry2) and
        --#   (for all K in Natural range I .. A_Last =>
        --#      (A (K) = A~ (K)));
      loop
         Temp := Types.Word64 (A (I)) +
           Types.Word64 (B (B_First + (I - A_First))) * Types.Word64 (C) +
           Types.Word64 (Carry2);

         A (I) := Types.Word32 (Temp and Types.Word64 (Types.Word32'Last));
         Carry2 := Types.Word32 (Types.SHR (Temp, 32));
      end loop;

      A (A_Last) := A (A_Last) + Carry2;
      Carry := A (A_Last) < Carry2;
   end Add_Mult_Inplace;

   ----------------------------------------------------------------------------

   procedure Single_Add_Mult_Mult
     (A       : in out Types.Word32;
      V       : in     Types.Word32;
      W       : in     Types.Word32;
      X       : in     Types.Word32;
      Y       : in     Types.Word32;
      Carry1  : in out Types.Word32;
      Carry2  : in out Types.Word32)
     --# derives
     --#   A from A, V, W, X, Y, Carry1 &
     --#   Carry1, Carry2 from A, V, W, X, Y, Carry1, Carry2;
     --# post
     --#   Universal_Integer (A~) +
     --#   Universal_Integer (V) * Universal_Integer (W) +
     --#   Universal_Integer (X) * Universal_Integer (Y) +
     --#   Universal_Integer (Carry1~) +
     --#   Base * Universal_Integer (Carry2~) =
     --#   Universal_Integer (A) +
     --#   Base * (Universal_Integer (Carry1) +
     --#     Base * Universal_Integer (Carry2));
   is
      Mult1, Mult2, Temp : Types.Word64;
   begin
      Mult1 := Types.Word64 (V) * Types.Word64 (W);
      Mult2 := Types.Word64 (X) * Types.Word64 (Y);
      Temp :=
        Types.Word64 (A) +
        Types.Word64 (Carry1) +
        (Mult1 and Types.Word64 (Types.Word32'Last)) +
        (Mult2 and Types.Word64 (Types.Word32'Last));
      A := Types.Word32 (Temp and Types.Word64 (Types.Word32'Last));
      Temp :=
        Types.Word64 (Carry2) +
        Types.SHR (Mult1, 32) +
        Types.SHR (Mult2, 32) +
        Types.SHR (Temp, 32);
      Carry1 := Types.Word32 (Temp and Types.Word64 (Types.Word32'Last));
      Carry2 := Types.Word32 (Types.SHR (Temp, 32));
   end Single_Add_Mult_Mult;

   ----------------------------------------------------------------------------

   procedure Add_Mult_Mult
     (A       : in out Big_Int;
      A_First : in     Natural;
      A_Last  : in     Natural;
      B       : in     Big_Int;
      B_First : in     Natural;
      C       : in     Big_Int;
      C_First : in     Natural;
      X       : in     Types.Word32;
      Y       : in     Types.Word32;
      Carry1  : in out Types.Word32;
      Carry2  : in out Types.Word32)
     --# derives
     --#   A, Carry1, Carry2 from
     --#   A, A_First, A_Last, B, B_First, C, C_First, X, Y, Carry1, Carry2;
     --# pre
     --#   A_First in A'Range and
     --#   A_Last + 1 in A'Range and
     --#   A_First <= A_Last and
     --#   B_First in B'Range and
     --#   B_First + (A_Last - A_First) in B'Range and
     --#   C_First in C'Range and
     --#   C_First + (A_Last - A_First) in C'Range;
     --# post
     --#   Num_Of_Big_Int (A~, A_First + 1, A_Last - A_First + 1) +
     --#   Num_Of_Big_int (B, B_First, A_Last - A_First + 1) *
     --#   Universal_Integer (X) +
     --#   Num_Of_Big_int (C, C_First, A_Last - A_First + 1) *
     --#   Universal_Integer (Y) +
     --#   Universal_Integer (Carry1~) +
     --#   Base * Universal_Integer (Carry2~) =
     --#   Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) +
     --#   Base ** (A_Last - A_First + 1) * (Universal_Integer (Carry1) +
     --#     Base * Universal_Integer (Carry2));
   is
      Temp : Types.Word32;
   begin
      for I in Natural range A_First .. A_Last
        --# assert
        --#   Num_Of_Big_Int (A~, A_First + 1, I - A_First) +
        --#   Num_Of_Big_int (B, B_First, I - A_First) *
        --#   Universal_Integer (X) +
        --#   Num_Of_Big_int (C, C_First, I - A_First) *
        --#   Universal_Integer (Y) +
        --#   Universal_Integer (Carry1~) +
        --#   Base * Universal_Integer (Carry2~) =
        --#   Num_Of_Big_Int (A, A_First, I - A_First) +
        --#   Base ** (I - A_First) * (Universal_Integer (Carry1) +
        --#     Base * Universal_Integer (Carry2)) and
        --#   (for all K in Natural range I .. A_Last + 1 =>
        --#      (A (K) = A~ (K)));
      loop
         Temp := A (I + 1);
         Single_Add_Mult_Mult
           (Temp,
            B (B_First + (I - A_First)), X,
            C (C_First + (I - A_First)), Y,
            Carry1, Carry2);
         A (I) := Temp;
      end loop;
   end Add_Mult_Mult;

   ----------------------------------------------------------------------------

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
      M_Inv   : in     Types.Word32)
   is
      Carry : Boolean;
      Carry1, Carry2, A_MSW, BI, U : Types.Word32;
   begin
      Initialize (A, A_First, A_Last);
      A_MSW := 0;

      for I in Natural range A_First .. A_Last
        --# assert
        --#   (Num_Of_Big_Int (A, A_First, A_Last - A_First + 1) +
        --#    Base ** (A_Last - A_First + 1) * Universal_Integer (A_MSW)) mod
        --#   Num_Of_Big_Int (M, M_First, A_Last - A_First + 1) =
        --#   (Num_Of_Big_Int (B, B_First, I - A_First) *
        --#    Num_Of_Big_Int (C, C_First, A_Last - A_First + 1) *
        --#    Inverse (Num_Of_Big_Int (M, M_First, A_Last - A_First + 1),
        --#      Base) ** (I - A_First)) mod
        --#   Num_Of_Big_Int (M, M_First, A_Last - A_First + 1);
      loop
         Carry1 := 0;
         Carry2 := 0;
         BI := B (B_First + (I - A_First));
         U := (A (A_First) + BI * C (C_First)) * M_Inv;
         Single_Add_Mult_Mult
           (A (A_First), BI, C (C_First), M (M_First), U, Carry1, Carry2);
         Add_Mult_Mult
           (A, A_First, A_Last - 1,
            C, C_First + 1, M, M_First + 1,
            BI, U, Carry1, Carry2);
         A (A_Last) := A_MSW + Carry1;
         A_MSW := Carry2 + Word_Of_Boolean (A (A_Last) < Carry1);
      end loop;

      if A_MSW /= 0 or else
        not Less (A, A_First, A_Last, M, M_First) then
         --# accept Flow, 10, Carry, "Carry not needed here" &
         --#        Flow, 33, Carry, "Carry not needed here";
         Sub_Inplace (A, A_First, A_Last, M, M_First, Carry);
      end if;
   end Mont_Mult;

end Bignum;
