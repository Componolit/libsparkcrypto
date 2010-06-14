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

with LSC.AES, LSC.IO, LSC.Test, LSC.Byteorder, LSC.Types, LSC.AES.CBC;
use type LSC.AES.Block_Type;
use type LSC.AES.Message_Type;

--# inherit LSC.IO,
--#         LSC.AES,
--#         LSC.Test,
--#         LSC.Byteorder,
--#         LSC.Types,
--#         LSC.AES.CBC;

--# main_program;
procedure Main
   --# derives ;
is
   function N (Item : LSC.Types.Word32) return LSC.Types.Word32
   is
   begin
      return LSC.Byteorder.BE_To_Native32 (Item);
   end N;

   procedure AES_Tests
   --# derives ;
   is separate;

   procedure AES_CBC_Tests
   --# derives ;
   is separate;

begin

   AES_Tests;
   AES_CBC_Tests;

end Main;
