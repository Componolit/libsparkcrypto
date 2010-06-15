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

with LSC.Ops, LSC.Ops64, LSC.Types, LSC.Byteswap;
--# inherit LSC.Ops,
--#         LSC.Ops64,
--#         LSC.Types,
--#         LSC.Byteswap;

package LSC.Byteorder is

   type Order_Type is (Big_Endian, Little_Endian);
   Native_Order : constant Order_Type := Little_Endian;

   function Native_To_BE32 (Item : Types.Word32) return Types.Word32;
   pragma Inline (Native_To_BE32);

   function Native_To_LE32 (Item : Types.Word32) return Types.Word32;
   pragma Inline (Native_To_LE32);

   function BE_To_Native32 (Item : Types.Word32) return Types.Word32;
   pragma Inline (BE_To_Native32);

   function LE_To_Native32 (Item : Types.Word32) return Types.Word32;
   pragma Inline (LE_To_Native32);

   function Native_To_BE64 (Item : Types.Word64) return Types.Word64;
   pragma Inline (Native_To_BE64);

   function Native_To_LE64 (Item : Types.Word64) return Types.Word64;
   pragma Inline (Native_To_LE64);

   function BE_To_Native64 (Item : Types.Word64) return Types.Word64;
   pragma Inline (BE_To_Native64);

   function LE_To_Native64 (Item : Types.Word64) return Types.Word64;
   pragma Inline (LE_To_Native64);

end LSC.Byteorder;
