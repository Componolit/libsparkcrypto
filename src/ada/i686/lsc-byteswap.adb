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

with System.Machine_Code;
with Unchecked_Conversion;

package body LSC.Byteswap is

   function Swap32 (Value : Types.Word32) return Types.Word32
   is
      Result : Types.Word32;
   begin
      System.Machine_Code.Asm
         ("bswap %0",
          Inputs   => (Types.Word32'Asm_Input ("0", Value)),
          Outputs  => (Types.Word32'Asm_Output ("=r", Result)),
          Volatile => True);
      return Result;
   end Swap32;

   ---------------------------------------------------------------------------

   function Swap64 (Value : Types.Word64) return Types.Word64
   is
      type W32A is
      record
         MSB : Types.Word32;
         LSB : Types.Word32;
      end record;

      function To_Word64 is new Unchecked_Conversion (W32A, Types.Word64);
      function To_W32A   is new Unchecked_Conversion (Types.Word64, W32A);

      Temp : W32A := To_W32A (Value);
   begin
      return To_Word64 (W32A'(MSB => Swap32 (Temp.LSB),
                              LSB => Swap32 (Temp.MSB)));
   end Swap64;

end LSC.Byteswap;
