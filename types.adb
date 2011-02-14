package body Types is

   function SHR (Value : Word64; Amount : Natural) return Word64
   is
   begin
      return Interfaces.Shift_Right (Value, Amount);
   end SHR;

   ----------------------------------------------------------------------------

   function SHL (Value : Word64; Amount : Natural) return Word64
   is
   begin
      return Interfaces.Shift_Left (Value, Amount);
   end SHL;

   ----------------------------------------------------------------------------

   function SHR32 (Value : Word32; Amount : Natural) return Word32
   is
   begin
      return Interfaces.Shift_Right (Value, Amount);
   end SHR32;

   ----------------------------------------------------------------------------

   function SHL32 (Value : Word32; Amount : Natural) return Word32
   is
   begin
      return Interfaces.Shift_Left (Value, Amount);
   end SHL32;

end Types;
