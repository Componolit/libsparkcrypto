-------------------------------------------------------------------------------
--  This file is part of the sparkcrypto library.
--
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>
--  Copyright (C) 2010  secunet Security Networks AG
--
--  This program is free software: you can redistribute it and/or modify it
--  under the terms of the GNU General Public License as published by the Free
--  Software Foundation, either version 3 of the License, or (at your option)
--  any later version.
--
--  This program is distributed in the hope that it will be useful, but WITHOUT
--  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
--  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
--  more details.
--  
--  You should have received a copy of the GNU General Public License along
--  with this program.  If not, see <http://www.gnu.org/licenses/>.
--  
--  As a special exception, if other files instantiate generics from this unit,
--  or you link this unit with other files to produce an executable, this unit
--  does not by itself cause the resulting executable to be covered by the GNU
--  General Public License. This exception does not however invalidate any
--  other reasons why the executable file might be covered by the GNU Public
--  License.
-------------------------------------------------------------------------------

with Interfaces;
--# inherit Interfaces;

package LSC.Types is

   pragma Pure;

   type Index is range 0 .. 79;

   subtype Byte is Interfaces.Unsigned_8;
   subtype Word32 is Interfaces.Unsigned_32;
   subtype Word64 is Interfaces.Unsigned_64;

   function ROTR (Value : Word64; Amount : Natural) return Word64;
   pragma Inline (ROTR);

   function SHR (Value : Word64; Amount : Natural) return Word64;
   pragma Inline (SHR);

   function SHL (Value : Word64; Amount : Natural) return Word64;
   pragma Inline (SHL);

   function ROTR32 (Value : Word32; Amount : Natural) return Word32;
   pragma Inline (ROTR32);

   function ROTL32 (Value : Word32; Amount : Natural) return Word32;
   pragma Inline (ROTL32);

   function SHL32 (Value : Word32; Amount : Natural) return Word32;
   pragma Inline (SHL32);

   function SHR32 (Value : Word32; Amount : Natural) return Word32;
   pragma Inline (SHR32);

   subtype Byte_Array32_Index is Index range 0 .. 3;
   type Byte_Array32_Type is array (Byte_Array32_Index) of Byte;

   subtype Byte_Array64_Index is Index range 0 .. 7;
   type Byte_Array64_Type is array (Byte_Array64_Index) of Byte;

   function Word32_To_Byte_Array32 (Value : Word32) return Byte_Array32_Type;
   pragma Inline (Word32_To_Byte_Array32);

   function Byte_Array32_To_Word32 (Value : Byte_Array32_Type) return Word32;
   pragma Inline (Byte_Array32_To_Word32);

   function Word64_To_Byte_Array64 (Value : Word64) return Byte_Array64_Type;
   pragma Inline (Word64_To_Byte_Array64);

   function Byte_Array64_To_Word64 (Value : Byte_Array64_Type) return Word64;
   pragma Inline (Byte_Array64_To_Word64);

   type Word32_Array_Type is array (Index range <>) of Word32;
   type Word64_Array_Type is array (Index range <>) of Word64;

end LSC.Types;
