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

with LSC.SHA2, LSC.Types, LSC.IO;
use type LSC.SHA2.SHA512_Hash_Type;
use type LSC.Types.Word64;

--# inherit LSC.IO,
--#         LSC.SHA2,
--#         LSC.Types;

--# main_program;
procedure Main
   --# derives ;
is
   --# hide Main;

   Ctx   : LSC.SHA2.Context_Type;
   Hash  : LSC.SHA2.SHA512_Hash_Type;
   Block : LSC.SHA2.Block_Type :=
               LSC.SHA2.Block_Type'(others => 16#eaea_eaea_eaea_eaea#);

begin

   Ctx := LSC.SHA2.SHA512_Context_Init;
   for I in Natural range 1 .. 1_000_000
   loop
      LSC.SHA2.Context_Update (Ctx, Block);
   end loop;
   LSC.SHA2.Context_Finalize (Ctx, Block, 0);
   Hash := LSC.SHA2.SHA512_Get_Hash (Ctx);

   LSC.IO.Print_Hash (Hash);

end Main;
