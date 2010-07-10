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

with LSC.IO, LSC.Test, LSC.Types, LSC.Byteswap32, LSC.Byteswap64;
use type LSC.Types.Word32;
use type LSC.Types.Word64;

--# inherit LSC.IO,
--#         LSC.Byteswap,
--#         LSC.Types,
--#         LSC.Test;

--# main_program;
procedure Main
   --# derives ;
is
begin

   LSC.Test.Suite ("Shadow tests");

   LSC.Test.Run
     ("Byte swap (32-bit)", LSC.Byteswap32.Swap (16#aabbccdd#) = 16#ddccbbaa#);

   LSC.Test.Run
     ("Byte swap (64-bit)", LSC.Byteswap64.Swap (16#aabbccddeeff0011#) = 16#1100ffeeddccbbaa#);
end Main;
