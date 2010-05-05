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

with SHA2, Types, IO;
use type SHA2.Hash_Type;
use type SHA2.Block_Index;
use type Types.Word8;
use type Types.Word64;

--# inherit IO,
--#         SHA2,
--#         Types;

--# main_program;
procedure Main
   --# derives ;
is
   --# hide Main;

   Ctx   : SHA2.Context_Type;
   Hash  : SHA2.Hash_Type;
   Block : SHA2.Block_Type :=
      SHA2.Block_Type'(others => 16#eaea_eaea_eaea_eaea#);

begin

   Ctx := SHA2.Context_Init;
   for I in Natural range 1 .. 1_000_000
   loop
      SHA2.Context_Update (Ctx, Block);
   end loop;
   SHA2.Context_Finalize (Ctx, Block, 0);
   Hash := SHA2.Get_Hash (Ctx);

   IO.Print_Hash (Hash);

end Main;
