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

package body LSC.Byteswap is

   function Swap32 (Value : Types.Word32) return Types.Word32
   is
      Temp : Types.Byte_Array32_Type;
   begin
      Temp := Types.Word32_To_Byte_Array32 (Value);
      return Ops.Bytes32_To_Word32 (Temp (0), Temp (1), Temp (2), Temp (3));
   end Swap32;

   ----------------------------------------------------------------------------

   function Swap64 (Value : Types.Word64) return Types.Word64
   is
      Temp : Types.Byte_Array64_Type;
   begin
      Temp := Types.Word64_To_Byte_Array64 (Value);
      return Ops64.Bytes64_To_Word64 (Temp (0), Temp (1), Temp (2), Temp (3),
                                      Temp (4), Temp (5), Temp (6), Temp (7));
   end Swap64;

end LSC.Byteswap;
