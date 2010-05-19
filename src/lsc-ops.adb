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

package body LSC.Ops is

   function Bytes_To_Word32
      (Byte0 : LSC.Types.Byte;
       Byte1 : LSC.Types.Byte;
       Byte2 : LSC.Types.Byte;
       Byte3 : LSC.Types.Byte) return LSC.Types.Word32
   is
   begin
      return LSC.Types.Byte_Array_To_Word32 (LSC.Types.Byte_Array_Type'(Byte3, Byte2, Byte1, Byte0));
   end Bytes_To_Word32;

   function ByteX (Value    : LSC.Types.Word32;
                   Position : LSC.Types.Byte_Array_Index) return LSC.Types.Byte
   is
      Temp : LSC.Types.Byte_Array_Type;
   begin
      Temp := LSC.Types.Word32_To_Byte_Array (Value);
      return Temp (Position);
   end ByteX;

   function Byte0 (Value : LSC.Types.Word32) return LSC.Types.Byte
   is
   begin
      return ByteX (Value, LSC.Types.B0);
   end Byte0;

   function Byte1 (Value : LSC.Types.Word32) return LSC.Types.Byte
   is
   begin
      return ByteX (Value, LSC.Types.B1);
   end Byte1;

   function Byte2 (Value : LSC.Types.Word32) return LSC.Types.Byte
   is
   begin
      return ByteX (Value, LSC.Types.B2);
   end Byte2;

   function Byte3 (Value : LSC.Types.Word32) return LSC.Types.Byte
   is
   begin
      return ByteX (Value, LSC.Types.B3);
   end Byte3;

end LSC.Ops;
