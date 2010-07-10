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

with LSC.RIPEMD160, LSC.IO, LSC.Byteorder32, LSC.Types, LSC.Test;
use type LSC.RIPEMD160.Hash_Type;

--# inherit LSC.IO,
--#         LSC.Byteorder32,
--#         LSC.RIPEMD160,
--#         LSC.Types,
--#         LSC.Test;

--# main_program;
procedure Main
   --# derives ;
is
   function N (Item : LSC.Types.Word32) return LSC.Types.Word32
   is
   begin
      return LSC.Byteorder32.BE_To_Native (Item);
   end N;


   procedure RIPEMD160_Tests
   --# derives ;
   is separate;

begin

   RIPEMD160_Tests;

end Main;
