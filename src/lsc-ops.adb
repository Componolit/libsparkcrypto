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

package body LSC.Ops is

   function Bytes_To_Word32
      (Byte0 : Types.Byte;
       Byte1 : Types.Byte;
       Byte2 : Types.Byte;
       Byte3 : Types.Byte) return Types.Word32
   is
   begin
      return Types.Byte_Array_To_Word32 (Types.Byte_Array_Type'(Byte3, Byte2, Byte1, Byte0));
   end Bytes_To_Word32;

   ----------------------------------------------------------------------------

   function ByteX (Value    : Types.Word32;
                   Position : Types.Byte_Array_Index) return Types.Byte
   is
      Temp : Types.Byte_Array_Type;
   begin
      Temp := Types.Word32_To_Byte_Array (Value);
      return Temp (Position);
   end ByteX;

   ----------------------------------------------------------------------------

   function Byte0 (Value : Types.Word32) return Types.Byte
   is
   begin
      return ByteX (Value, 3);
   end Byte0;

   ----------------------------------------------------------------------------

   function Byte1 (Value : Types.Word32) return Types.Byte
   is
   begin
      return ByteX (Value, 2);
   end Byte1;

   ----------------------------------------------------------------------------

   function Byte2 (Value : Types.Word32) return Types.Byte
   is
   begin
      return ByteX (Value, 1);
   end Byte2;

   ----------------------------------------------------------------------------

   function Byte3 (Value : Types.Word32) return Types.Byte
   is
   begin
      return ByteX (Value, 0);
   end Byte3;

   ----------------------------------------------------------------------------

   function Byte_Swap32 (Value : Types.Word32) return Types.Word32
   is
      Temp : Types.Byte_Array_Type;
   begin
      Temp := Types.Word32_To_Byte_Array (Value);
      return Bytes_To_Word32 (Temp (0), Temp (1), Temp (2), Temp (3));
   end Byte_Swap32;

   ----------------------------------------------------------------------------

   function XOR2 (V0, V1 : Types.Word32) return Types.Word32
   is
   begin
      return V0 xor V1;
   end XOR2;
   pragma Inline (XOR2);

   ----------------------------------------------------------------------------

   function XOR3 (V0, V1, V2 : Types.Word32) return Types.Word32
   is
   begin
      return V0 xor V1 xor V2;
   end XOR3;
   pragma Inline (XOR3);

   ----------------------------------------------------------------------------

   function XOR4 (V0, V1, V2, V3 : Types.Word32) return Types.Word32
   is
   begin
      return V0 xor V1 xor V2 xor V3;
   end XOR4;
   pragma Inline (XOR4);

   ----------------------------------------------------------------------------

   function XOR5 (V0, V1, V2, V3, V4 : Types.Word32) return Types.Word32
   is
   begin
      return V0 xor V1 xor V2 xor V3 xor V4;
   end XOR5;
   pragma Inline (XOR5);

end LSC.Ops;
