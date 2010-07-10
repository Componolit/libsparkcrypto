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

with LSC.SHA256, LSC.SHA512, LSC.IO, LSC.Test, LSC.Types, LSC.Byteorder;
use type LSC.SHA512.SHA512_Hash_Type;
use type LSC.SHA256.SHA256_Hash_Type;

--# inherit LSC.IO,
--#         LSC.SHA256,
--#         LSC.SHA512,
--#         LSC.Byteorder,
--#         LSC.Types,
--#         LSC.Test;

--# main_program;
procedure Main
   --# derives ;
is
   function N (Item : LSC.Types.Word64) return LSC.Types.Word64
   is
   begin
      return LSC.Byteorder.BE_To_Native64 (Item);
   end N;

   function M (Item : LSC.Types.Word32) return LSC.Types.Word32
   is
   begin
      return LSC.Byteorder.BE_To_Native32 (Item);
   end M;

   procedure SHA256_Tests
   --# derives ;
   is separate;

   procedure SHA384_Tests
   --# derives ;
   is separate;

   procedure SHA512_Tests
   --# derives ;
   is separate;

begin

   SHA256_Tests;
   SHA384_Tests;
   SHA512_Tests;

end Main;
