package LSC.Types
is
   type Byte is mod 2**8;

   --  Natural index type
   subtype Natural_Index is Natural range Natural'First .. Natural'Last - 1;

   --  Byte array type
   type Bytes is array (Natural_Index range <>) of Byte;

end LSC.Types;
