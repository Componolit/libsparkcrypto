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

with LSC.SHA2, LSC.Types, LSC.IO, LSC.Test, OpenSSL;
use type LSC.SHA2.SHA512_Hash_Type;
use type LSC.Types.Word64;

--# inherit LSC.IO,
--#         LSC.SHA2,
--#         LSC.Types;
--#         LSC.Debug;
--#         LSC.Test;
--#         OpenSSL;

--# main_program;
procedure Main
   --# derives ;
is
   Block           : LSC.SHA2.Block_Type;

   SHA512_Context1 : OpenSSL.SHA512_Context_Type;
   Hash1           : LSC.SHA2.SHA512_Hash_Type;

   SHA512_Context2 : LSC.SHA2.Context_Type;
   Hash2           : LSC.SHA2.SHA512_Hash_Type;

   Length          : LSC.SHA2.Block_Length_Type;
begin

   Block  := LSC.SHA2.Block_Type'(others => 16#0000000000636261#);
   Length := 56;

   OpenSSL.Context_Init (SHA512_Context1);
   OpenSSL.Context_Finalize (SHA512_Context1, Block, Length);
   Hash1 := OpenSSL.SHA512_Get_Hash (SHA512_Context1);

   SHA512_Context2 := LSC.SHA2.SHA512_Context_Init;
   LSC.SHA2.Context_Finalize (SHA512_Context2, Block, Length);
   Hash2 := LSC.SHA2.SHA512_Get_Hash (SHA512_Context2);

   LSC.Test.Run ("Equal result", Hash1 = Hash2);
   LSC.IO.Print_Word64_Array (Hash1, 1, LSC.Types.Index'Last, True);
   LSC.IO.Print_Word64_Array (Hash2, 1, LSC.Types.Index'Last, True);
end Main;
