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

   ----------------------------------------------------------------------------

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

   function ROTL32 (Value : Word32; Amount : Natural) return Word32
   is
   begin
      return Interfaces.Rotate_Left (Value, Amount);
   end ROTL32;

   ----------------------------------------------------------------------------

   function ROTR32 (Value : Word32; Amount : Natural) return Word32
   is
   begin
      return Interfaces.Rotate_Right (Value, Amount);
   end ROTR32;

   ----------------------------------------------------------------------------

   function SHL32 (Value : Word32; Amount : Natural) return Word32
   is
   begin
      return Interfaces.Shift_Left (Value, Amount);
   end SHL32;

   ----------------------------------------------------------------------------

   function SHR32 (Value : Word32; Amount : Natural) return Word32
   is
   begin
      return Interfaces.Shift_Right (Value, Amount);
   end SHR32;

   ----------------------------------------------------------------------------

   function Word32_To_Byte_Array32 (Value : Word32) return Byte_Array32_Type
   is
      function W322W8A is new Unchecked_Conversion (Word32, Byte_Array32_Type);
   begin
      return W322W8A (Value);
   end Word32_To_Byte_Array32;

   ----------------------------------------------------------------------------

   function Byte_Array32_To_Word32 (Value : Byte_Array32_Type) return Word32
   is
      function W8A2W32 is new Unchecked_Conversion (Byte_Array32_Type, Word32);
   begin
      return W8A2W32 (Value);
   end Byte_Array32_To_Word32;

   ----------------------------------------------------------------------------

   function Word64_To_Byte_Array64 (Value : Word64) return Byte_Array64_Type
   is
      function W642W8A is new Unchecked_Conversion (Word64, Byte_Array64_Type);
   begin
      return W642W8A (Value);
   end Word64_To_Byte_Array64;

   ----------------------------------------------------------------------------

   function Byte_Array64_To_Word64 (Value : Byte_Array64_Type) return Word64
   is
      function W8A2W64 is new Unchecked_Conversion (Byte_Array64_Type, Word64);
   begin
      return W8A2W64 (Value);
   end Byte_Array64_To_Word64;

end LSC.Types;
