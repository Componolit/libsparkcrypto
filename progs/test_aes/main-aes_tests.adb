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
   Plaintext, Ciphertext                     : LSC.AES.Block_Type;
   Key128                                    : LSC.AES.AES128_Key_Type;
   Key192                                    : LSC.AES.AES192_Key_Type;
   Key256                                    : LSC.AES.AES256_Key_Type;
   Enc_Context                               : LSC.AES.AES_Enc_Context;
   Dec_Context                               : LSC.AES.AES_Dec_Context;

begin

   LSC.Test.Suite ("AES tests");

   --------------
   -- AES128 test
   --------------

   --  Key expansion

   --# accept Flow, 10, Key128, "Only debug output needed";
   Key128 := LSC.AES.AES128_Key_Type'(16#16157e2b#,
                                      16#a6d2ae28#,
                                      16#8815f7ab#,
                                      16#3c4fcf09#);

   --# accept Flow, 10, "Only debug output needed";
   Enc_Context := LSC.AES.Create_AES128_Enc_Context (Key128);

   Key128 := LSC.AES.AES128_Key_Type'(16#03020100#,
                                      16#07060504#,
                                      16#0b0a0908#,
                                      16#0f0e0d0c#);

   Plaintext := LSC.AES.Block_Type'(16#33221100#,
                                    16#77665544#,
                                    16#bbaa9988#,
                                    16#ffeeddcc#);

   Ciphertext := LSC.AES.Block_Type'(16#d8e0c469#,
                                     16#30047b6a#,
                                     16#80b7cdd8#,
                                     16#5ac5b470#);

   --  Encryption
   Enc_Context := LSC.AES.Create_AES128_Enc_Context (Key128);
   LSC.Test.Run ("C.1 AES-128 (Nk=4, Nr=10), Encryption",
                 Ciphertext = LSC.AES.Encrypt (Enc_Context, Plaintext));

   -- Decryption
   Dec_Context := LSC.AES.Create_AES128_Dec_Context (Key128);
   LSC.Test.Run ("C.1 AES-128 (Nk=4, Nr=10), Decryption",
                 Plaintext = LSC.AES.Decrypt (Dec_Context, Ciphertext));

   --------------
   -- AES192 test
   --------------

   --# accept Flow, 10, Key192, "Only debug output needed";
   Key192 := LSC.AES.AES192_Key_Type'(16#f7b0738e#,
                                      16#52640eda#,
                                      16#2bf310c8#,
                                      16#e5799080#,
                                      16#d2eaf862#,
                                      16#7b6b2c52#);

   --# accept Flow, 10, "Only debug output needed";
   Enc_Context := LSC.AES.Create_AES192_Enc_Context (Key192);

   Key192 := LSC.AES.AES192_Key_Type'(16#03020100#,
                                      16#07060504#,
                                      16#0b0a0908#,
                                      16#0f0e0d0c#,
                                      16#13121110#,
                                      16#17161514#);

   Plaintext := LSC.AES.Block_Type'(16#33221100#,
                                    16#77665544#,
                                    16#bbaa9988#,
                                    16#ffeeddcc#);

   Ciphertext := LSC.AES.Block_Type'(16#a47ca9dd#,
                                     16#e0df4c86#,
                                     16#a070af6e#,
                                     16#91710dec#);

   --  Encryption
   Enc_Context := LSC.AES.Create_AES192_Enc_Context (Key192);
   LSC.Test.Run ("C.2 AES-192 (Nk=6, Nr=12), Encryption",
                 Ciphertext = LSC.AES.Encrypt (Enc_Context, Plaintext));

   --  Decryption
   Dec_Context := LSC.AES.Create_AES192_Dec_Context (Key192);
   LSC.Test.Run ("C.2 AES-192 (Nk=6, Nr=12), Decryption",
                 Plaintext = LSC.AES.Decrypt (Dec_Context, Ciphertext));

   --------------
   -- AES256 test
   --------------

   --# accept Flow, 10, Key256, "Only debug output needed";
   Key256 := LSC.AES.AES256_Key_Type'(16#10eb3d60#,
                                      16#be71ca15#,
                                      16#f0ae732b#,
                                      16#81777d85#,
                                      16#072c351f#,
                                      16#d708613b#,
                                      16#a310982d#,
                                      16#f4df1409#);

   --# accept Flow, 10, "Only debug output needed";
   Enc_Context := LSC.AES.Create_AES256_Enc_Context (Key256);

   Key256 := LSC.AES.AES256_Key_Type'(16#03020100#,
                                      16#07060504#,
                                      16#0b0a0908#,
                                      16#0f0e0d0c#,
                                      16#13121110#,
                                      16#17161514#,
                                      16#1b1a1918#,
                                      16#1f1e1d1c#);

   Plaintext := LSC.AES.Block_Type'(16#33221100#,
                                    16#77665544#,
                                    16#bbaa9988#,
                                    16#ffeeddcc#);

   Ciphertext := LSC.AES.Block_Type'(16#cab7a28e#,
                                     16#bf456751#,
                                     16#9049fcea#,
                                     16#8960494b#);

   --  Encryption
   Enc_Context := LSC.AES.Create_AES256_Enc_Context (Key256);
   LSC.Test.Run ("C.3 AES-256 (Nk=8, Nr=14), Encryption",
                 Ciphertext = LSC.AES.Encrypt (Enc_Context, Plaintext));

   --  Decryption
   Dec_Context := LSC.AES.Create_AES256_Dec_Context (Key256);
   LSC.Test.Run ("C.3 AES-256 (Nk=8, Nr=14), Decryption",
                 Plaintext = LSC.AES.Decrypt (Dec_Context, Ciphertext));

end AES_Tests;
