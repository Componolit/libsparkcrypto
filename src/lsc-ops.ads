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

with LSC.Types;
use type LSC.Types.Word32;
--# inherit LSC.Types;

package LSC.Ops is

   function Bytes32_To_Word32
      (Byte0 : Types.Byte;
       Byte1 : Types.Byte;
       Byte2 : Types.Byte;
       Byte3 : Types.Byte) return Types.Word32;

   function Byte0 (Value : Types.Word32) return Types.Byte;
   function Byte1 (Value : Types.Word32) return Types.Byte;
   function Byte2 (Value : Types.Word32) return Types.Byte;
   function Byte3 (Value : Types.Word32) return Types.Byte;
   function Byte_Swap32 (Value : Types.Word32) return Types.Word32;

   function XOR2 (V0, V1 : Types.Word32) return Types.Word32;
   --# return V0 xor V1;

   function XOR3 (V0, V1, V2 : Types.Word32) return Types.Word32;
   --# return V0 xor V1 xor V2;

   function XOR4 (V0, V1, V2, V3 : Types.Word32) return Types.Word32;
   --# return V0 xor V1 xor V2 xor V3;

   function XOR5 (V0, V1, V2, V3, V4 : Types.Word32) return Types.Word32;
   --# return V0 xor V1 xor V2 xor V3 xor V4;

   procedure Block_XOR
     (Left   : in     Types.Word32_Array_Type;
      Right  : in     Types.Word32_Array_Type;
      Result : in out Types.Word32_Array_Type);
   --# derives
   --#   Result from *, Left, Right;
   --# pre
   --#   Left'First  = Right'First and
   --#   Left'Last   = Right'Last  and
   --#   Right'First = Result'First and
   --#   Right'Last  = Result'Last;
   --# post
   --#   (for all I in Types.Index range Left'First .. Left'Last =>
   --#        (Result (I) = XOR2 (Left (I), Right (I))));

end LSC.Ops;
