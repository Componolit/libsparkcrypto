--  This file is part of the sparkcrypto library.
--
--  Copyright (C) 2010  secunet Security Networks AG
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>

--  This library  is free software:  you can  redistribute it and/or  modify it
--  under the  terms of the GNU  Lesser General Public License  as published by
--  the Free Software Foundation, either version  3 of the License, or (at your
--  option) any later version.

--  This library is distributed in the hope that it will be useful, but WITHOUT
--  ANY  WARRANTY; without  even  the implied  warranty  of MERCHANTABILITY  or
--  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
--  for more details.

--  You should  have received a copy  of the GNU Lesser  General Public License
--  along with this library. If not, see <http://www.gnu.org/licenses/>.

with Unchecked_Conversion;

package body Types is

   function ROTR (Value : Word64; Amount : Natural) return Word64 is
   begin
      return Interfaces.Rotate_Right (Value, Amount);
   end ROTR;
   pragma Inline (ROTR);

   function SHR (Value : Word64; Amount : Natural) return Word64 is
   begin
      return Interfaces.Shift_Right (Value, Amount);
   end SHR;
   pragma Inline (SHR);

   function SHL (Value : Word64; Amount : Natural) return Word64 is
   begin
      return Interfaces.Shift_Left (Value, Amount);
   end SHL;
   pragma Inline (SHL);

   function ROTL32 (Value : Word32; Amount : Natural) return Word32 is
   begin
      return Interfaces.Rotate_Left (Value, Amount);
   end ROTL32;
   pragma Inline (ROTL32);

   function SHL32 (Value : Word32; Amount : Natural) return Word32 is
   begin
      return Interfaces.Shift_Left (Value, Amount);
   end SHL32;
   pragma Inline (SHL32);

   function Word32_To_Byte_Array (Value : Word32) return Byte_Array_Type is
      function W322W8A is new Unchecked_Conversion (Word32, Byte_Array_Type);
   begin
      return W322W8A (Value);
   end Word32_To_Byte_Array;

   function Byte_Array_To_Word32 (Value : Byte_Array_Type) return Word32 is
      function W8A2W32 is new Unchecked_Conversion (Byte_Array_Type, Word32);
   begin
      return W8A2W32 (Value);
   end Byte_Array_To_Word32;

   function Bytes_To_Word32
      (Byte0 : Byte;
       Byte1 : Byte;
       Byte2 : Byte;
       Byte3 : Byte) return Word32
   is
   begin
      return Byte_Array_To_Word32 (Byte_Array_Type'(Byte0, Byte1, Byte2, Byte3));
   end Bytes_To_Word32;

   function ByteX (Value    : Word32;
                   Position : Byte_Array_Index) return Byte
   is
      Temp : Byte_Array_Type;
   begin
      Temp := Word32_To_Byte_Array (Value);
      return Temp (Position);
   end ByteX;

   function Byte0 (Value : Word32) return Byte
   is
   begin
      return ByteX (Value, 0);
   end Byte0;

   function Byte1 (Value : Word32) return Byte
   is
   begin
      return ByteX (Value, 1);
   end Byte1;

   function Byte2 (Value : Word32) return Byte
   is
   begin
      return ByteX (Value, 2);
   end Byte2;

   function Byte3 (Value : Word32) return Byte
   is
   begin
      return ByteX (Value, 3);
   end Byte3;

end Types;
