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

separate (Main)
procedure AES_Tests
is
   Plaintext, Cyphertext, Expected_Cyphertext : AES256.Block_Type;
   Key                                        : AES256.Key_Type;

begin

   Test.Suite ("AES tests");

   Key := AES256.Key_Type'
      (16#00010203#,
       16#04050607#,
       16#08090a0b#,
       16#0c0d0e0f#,
       16#10111213#,
       16#14151617#,
       16#18191a1b#,
       16#1c1d1e1f#);

   Plaintext := AES256.Block_Type'
      (16#00112233#,
       16#44556677#,
       16#8899aabb#,
       16#ccddeeff#);

   Expected_Cyphertext := AES256.Block_Type'
      (16#8ea2b7ca#,
       16#516745bf#,
       16#eafc4990#,
       16#4b496089#);

   Cyphertext := AES256.Encrypt (Key => Key, Plaintext => Plaintext);

   Test.Run ("C.3 AES-256 (Nk=8, Nr=14)", Cyphertext = Expected_Cyphertext);

end AES_Tests;
