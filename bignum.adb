with Types;

package body Bignum
is

   --# function GCD (A, B: Integer) return Integer;

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
     --# return Result => Integer (Result) = Num_Of_Boolean (B);
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
        --#   GCD (Integer (A), Integer (B)) = 1;
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
        --#   Num_Of_Big_Int (B, B_First, I - A_First) * Integer (C) =
        --#   Num_Of_Big_Int (A, A_First, I - A_First) +
        --#   2 ** (32 * (I - A_First)) * Integer (Carry2) and
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

end Bignum;
