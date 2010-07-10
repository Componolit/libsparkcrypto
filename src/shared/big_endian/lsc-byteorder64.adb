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

package body LSC.Byteorder64 is

   function Native_To_BE (Item : Types.Word64) return Types.Word64
   is
   begin
      return Item;
   end Native_To_BE;

   ---------------------------------------------------------------------------

   function Native_To_LE (Item : Types.Word64) return Types.Word64
   is
   begin
      return Byteswap.Swap64 (Item);
   end Native_To_LE;

   ---------------------------------------------------------------------------

   function BE_To_Native (Item : Types.Word64) return Types.Word64
   is
   begin
      return Item;
   end BE_To_Native;

   ---------------------------------------------------------------------------

   function LE_To_Native (Item : Types.Word64) return Types.Word64
   is
   begin
      return Byteswap.Swap64 (Item);
   end LE_To_Native;

end LSC.Byteorder64;
