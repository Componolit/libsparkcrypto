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

with LSC.SHA2, LSC.Types, LSC.IO, OpenSSL;
use type LSC.SHA2.SHA512_Hash_Type;
use type LSC.Types.Word64;

--# inherit LSC.IO,
--#         LSC.SHA2,
--#         LSC.Types;
--#         LSC.Debug;
--#         OpenSSL;

--# main_program;
procedure Main
   --# derives ;
is
   Context : aliased OpenSSL.SHA512_Context;
   Block   : aliased LSC.SHA2.Block_Type;
   Hash    : aliased LSC.SHA2.SHA512_Hash_Type;
begin

   Block := LSC.SHA2.Block_Type'(0 => 16#0000000000636261#, others => 0);
   OpenSSL.C_SHA512_Init (Context'Unchecked_Access);
   OpenSSL.C_SHA512_Update (Context'Unchecked_Access, Block'Unchecked_Access, 3);
   OpenSSL.C_SHA512_Final (Hash'Unchecked_Access, Context'Unchecked_Access);
   LSC.IO.Print_Word64_Array (Hash, Space => 2, Break => 4, Newln => True);
end Main;
