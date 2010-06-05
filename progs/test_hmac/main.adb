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

with LSC.SHA2,
     LSC.RIPEMD160,
     LSC.HMAC.SHA512,
     LSC.HMAC.SHA384,
     LSC.HMAC.RIPEMD,
     LSC.IO,
     LSC.Types,
     LSC.Test;

use type LSC.Types.Word32_Array_Type;
use type LSC.Types.Word64_Array_Type;

--# inherit LSC.IO,
--#         LSC.SHA2,
--#         LSC.RIPEMD160,
--#         LSC.HMAC.SHA512,
--#         LSC.HMAC.SHA384,
--#         LSC.HMAC.RIPEMD,
--#         LSC.Types,
--#         LSC.Test;

--# main_program;
procedure Main
   --# derives ;
is

   procedure HMAC_SHA384_Tests
   --# derives ;
   is separate;

   procedure HMAC_SHA512_Tests
   --# derives ;
   is separate;

   procedure HMAC_RIPEMD160_Tests
   --# derives ;
   is separate;

begin

   HMAC_SHA384_Tests;
   HMAC_SHA512_Tests;
   HMAC_RIPEMD160_Tests;

end Main;
