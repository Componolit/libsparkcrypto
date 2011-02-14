package Interfaces
is
   type Unsigned_32 is mod 2**32;
   type Unsigned_64 is mod 2**64;

   function Shift_Right (Value : Unsigned_64; Amount : Natural) return Unsigned_64;
   --# return Result => Result = Value / 2 ** Amount;

end Interfaces;
