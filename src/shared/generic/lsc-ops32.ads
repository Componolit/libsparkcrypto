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

with LSC.Types;
use type LSC.Types.Word32;
--# inherit LSC.Types;

package LSC.Ops32 is

   function Bytes_To_Word
      (Byte0 : Types.Byte;
       Byte1 : Types.Byte;
       Byte2 : Types.Byte;
       Byte3 : Types.Byte) return Types.Word32;
   pragma Inline (Bytes_To_Word);

   function ByteX (Value    : Types.Word32;
                   Position : Types.Byte_Array32_Index) return Types.Byte;
   pragma Inline (ByteX);

   function Byte0 (Value : Types.Word32) return Types.Byte;
   pragma Inline (Byte0);

   function Byte1 (Value : Types.Word32) return Types.Byte;
   pragma Inline (Byte1);

   function Byte2 (Value : Types.Word32) return Types.Byte;
   pragma Inline (Byte2);

   function Byte3 (Value : Types.Word32) return Types.Byte;
   pragma Inline (Byte3);

   function XOR2 (V0, V1 : Types.Word32) return Types.Word32;
   --# return V0 xor V1;
   pragma Inline (XOR2);

   function XOR3 (V0, V1, V2 : Types.Word32) return Types.Word32;
   --# return V0 xor V1 xor V2;
   pragma Inline (XOR3);

   function XOR4 (V0, V1, V2, V3 : Types.Word32) return Types.Word32;
   --# return V0 xor V1 xor V2 xor V3;
   pragma Inline (XOR4);

   function XOR5 (V0, V1, V2, V3, V4 : Types.Word32) return Types.Word32;
   --# return V0 xor V1 xor V2 xor V3 xor V4;
   pragma Inline (XOR5);

   procedure Block_XOR
     (Left   : in     Types.Word32_Array_Type;
      Right  : in     Types.Word32_Array_Type;
      Result :    out Types.Word32_Array_Type);
   --# derives
   --#   Result from Left, Right;
   --# pre
   --#   Left'First  = Right'First and
   --#   Left'Last   = Right'Last  and
   --#   Right'First = Result'First and
   --#   Right'Last  = Result'Last;
   --# post
   --#   (for all I in Types.Index range Left'First .. Left'Last =>
   --#        (Result (I) = XOR2 (Left (I), Right (I))));
   pragma Inline (Block_XOR);

end LSC.Ops32;
