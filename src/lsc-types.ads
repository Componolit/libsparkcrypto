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

with Interfaces;
--# inherit Interfaces;

package LSC.Types is

   type Index is range 0 .. 60;

   subtype Byte is Interfaces.Unsigned_8;
   subtype Word32 is Interfaces.Unsigned_32;
   subtype Word64 is Interfaces.Unsigned_64;

   function ROTR (Value : Word64; Amount : Natural) return Word64;
   function SHR (Value : Word64; Amount : Natural) return Word64;
   function SHL (Value : Word64; Amount : Natural) return Word64;
   function ROTL32 (Value : Word32; Amount : Natural) return Word32;
   function SHL32 (Value : Word32; Amount : Natural) return Word32;

   type Byte_Array_Index is (B3, B2, B1, B0);
   for Byte_Array_Index use (B3 => 0, B2 => 1, B1 => 2, B0 => 3);

   type Byte_Array_Type is array (Byte_Array_Index) of Byte;

   function Word32_To_Byte_Array (Value : Word32) return Byte_Array_Type;
   function Byte_Array_To_Word32 (Value : Byte_Array_Type) return Word32;

   type Word64_Array_Type is array (Index range <>) of Word64;

end LSC.Types;
