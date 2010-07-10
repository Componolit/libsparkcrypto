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

package body LSC.Byteswap64 is

   function Swap (Value : Types.Word64) return Types.Word64
   is
      Result : Types.Word64;
   begin
      System.Machine_Code.Asm
         ("bswap %0",
          Inputs   => (Types.Word64'Asm_Input ("0", Value)),
          Outputs  => (Types.Word64'Asm_Output ("=r", Result)),
          Volatile => True);
      return Result;
   end Swap;

end LSC.Byteswap64;
