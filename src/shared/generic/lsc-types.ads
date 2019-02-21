package LSC.Types
is
   type Byte is mod 2**8 with Size => 8;

   --  Natural index type
   subtype Natural_Index is Natural range Natural'First .. Natural'Last - 1;

   --  Byte array type
   type Bytes is array (Natural_Index range <>) of Byte;

   -- Perform XOR on two arrays of bytes
   --
   -- @Left@   - First input array
   -- @Right@  - Second input array
   -- @Result@ - Result array
   procedure Bytes_XOR
     (Left   : in     Bytes;
      Right  : in     Bytes;
      Result :    out Bytes)
     with
       Pre =>
         Left'Length < Natural_Index'Last and
         Left'Length = Right'Length and
         Result'Length >= Left'Length,
       Post =>
         (for all I in Natural_Index range 0 .. Left'Length - 1 =>
            (Result (Result'First + I) = (Left (Left'First + I) xor Right (Right'First + I)))),
       Inline;

end LSC.Types;
