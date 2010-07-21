-------------------------------------------------------------------------------
--  This file is part of the sparkcrypto library.
--
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>
--  Copyright (C) 2010  secunet Security Networks AG
--
--  This program is free software: you can redistribute it and/or modify it
--  under the terms of the GNU General Public License as published by the Free
--  Software Foundation, either version 3 of the License, or (at your option)
--  any later version.
--
--  This program is distributed in the hope that it will be useful, but WITHOUT
--  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
--  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
--  more details.
--  
--  You should have received a copy of the GNU General Public License along
--  with this program.  If not, see <http://www.gnu.org/licenses/>.
--  
--  As a special exception, if other files instantiate generics from this unit,
--  or you link this unit with other files to produce an executable, this unit
--  does not by itself cause the resulting executable to be covered by the GNU
--  General Public License. This exception does not however invalidate any
--  other reasons why the executable file might be covered by the GNU Public
--  License.
-------------------------------------------------------------------------------

with LSC.SHA256,
     LSC.SHA512,
     LSC.IO,
     LSC.Test,
     LSC.Types,
     LSC.Byteorder32,
     LSC.Byteorder64;

use type LSC.SHA512.SHA512_Hash_Type;
use type LSC.SHA256.SHA256_Hash_Type;

--# inherit LSC.IO,
--#         LSC.SHA256,
--#         LSC.SHA512,
--#         LSC.Byteorder32,
--#         LSC.Byteorder64,
--#         LSC.Types,
--#         LSC.Test;

--# main_program;
procedure Main
   --# derives ;
is
   function N (Item : LSC.Types.Word64) return LSC.Types.Word64
   is
   begin
      return LSC.Byteorder64.BE_To_Native (Item);
   end N;

   function M (Item : LSC.Types.Word32) return LSC.Types.Word32
   is
   begin
      return LSC.Byteorder32.BE_To_Native (Item);
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
