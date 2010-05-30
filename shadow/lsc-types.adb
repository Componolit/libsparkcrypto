--  This file is part of the sparkcrypto library.

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

package body LSC.Types is

   function ROTR (Value : Word64; Amount : Natural) return Word64
   is
   begin
      return Interfaces.Rotate_Right (Value, Amount);
   end ROTR;
   pragma Inline (ROTR);

   ----------------------------------------------------------------------------

   function SHR (Value : Word64; Amount : Natural) return Word64
   is
   begin
      return Interfaces.Shift_Right (Value, Amount);
   end SHR;
   pragma Inline (SHR);

   ----------------------------------------------------------------------------

   function SHL (Value : Word64; Amount : Natural) return Word64
   is
   begin
      return Interfaces.Shift_Left (Value, Amount);
   end SHL;
   pragma Inline (SHL);

   ----------------------------------------------------------------------------

   function ROTL32 (Value : Word32; Amount : Natural) return Word32
   is
   begin
      return Interfaces.Rotate_Left (Value, Amount);
   end ROTL32;
   pragma Inline (ROTL32);

   ----------------------------------------------------------------------------

   function SHL32 (Value : Word32; Amount : Natural) return Word32
   is
   begin
      return Interfaces.Shift_Left (Value, Amount);
   end SHL32;
   pragma Inline (SHL32);

   ----------------------------------------------------------------------------

   function Word32_To_Byte_Array (Value : Word32) return Byte_Array_Type
   is
      function W322W8A is new Unchecked_Conversion (Word32, Byte_Array_Type);
   begin
      return W322W8A (Value);
   end Word32_To_Byte_Array;
   pragma Inline (Word32_To_Byte_Array);

   ----------------------------------------------------------------------------

   function Byte_Array_To_Word32 (Value : Byte_Array_Type) return Word32
   is
      function W8A2W32 is new Unchecked_Conversion (Byte_Array_Type, Word32);
   begin
      return W8A2W32 (Value);
   end Byte_Array_To_Word32;
   pragma Inline (Byte_Array_To_Word32);

end LSC.Types;
