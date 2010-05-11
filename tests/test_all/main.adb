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

with SHA2, HMAC.SHA512, AES256, IO, Test;
use type SHA2.Hash_Type;
use type AES256.Block_Type;

--# inherit IO,
--#         SHA2,
--#         HMAC.SHA512,
--#         AES256,
--#         Test;

--# main_program;
procedure Main
   --# derives ;
is

   procedure SHA2_Tests
   --# derives ;
   is separate;

   procedure HMAC_Tests
   --# derives ;
   is separate;

   procedure AES_Tests
   --# derives ;
   is separate;

begin

   SHA2_Tests;
   HMAC_Tests;
   AES_Tests;

end Main;
