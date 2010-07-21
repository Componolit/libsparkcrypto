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
   Key128 := LSC.AES.AES128_Key_Type'
      (N (16#2b7e1516#), N (16#28aed2a6#), N (16#abf71588#), N (16#09cf4f3c#));

   --# accept Flow, 10, "Only debug output needed";
   Enc_Context := LSC.AES.Create_AES128_Enc_Context (Key128);

   Key128 := LSC.AES.AES128_Key_Type'
      (N (16#00010203#), N (16#04050607#), N (16#08090a0b#), N (16#0c0d0e0f#));

   Plaintext := LSC.AES.Block_Type'
      (N (16#00112233#), N (16#44556677#), N (16#8899aabb#), N (16#ccddeeff#));

   Ciphertext := LSC.AES.Block_Type'
      (N (16#69c4e0d8#), N (16#6a7b0430#), N (16#d8cdb780#), N (16#70b4c55a#));

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
   Key192 := LSC.AES.AES192_Key_Type'
      (N (16#8e73b0f7#), N (16#da0e6452#), N (16#c810f32b#),
       N (16#809079e5#), N (16#62f8ead2#), N (16#522c6b7b#));

   --# accept Flow, 10, "Only debug output needed";
   Enc_Context := LSC.AES.Create_AES192_Enc_Context (Key192);

   Key192 := LSC.AES.AES192_Key_Type'
      (N (16#00010203#), N (16#04050607#), N (16#08090a0b#),
       N (16#0c0d0e0f#), N (16#10111213#), N (16#14151617#));

   Plaintext := LSC.AES.Block_Type'
      (N (16#00112233#), N (16#44556677#), N (16#8899aabb#), N (16#ccddeeff#));

   Ciphertext := LSC.AES.Block_Type'
      (N (16#dda97ca4#), N (16#864cdfe0#), N (16#6eaf70a0#), N (16#ec0d7191#));

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
   Key256 := LSC.AES.AES256_Key_Type'
      (N (16#603deb10#), N (16#15ca71be#), N (16#2b73aef0#), N (16#857d7781#),
       N (16#1f352c07#), N (16#3b6108d7#), N (16#2d9810a3#), N (16#0914dff4#));

   --# accept Flow, 10, "Only debug output needed";
   Enc_Context := LSC.AES.Create_AES256_Enc_Context (Key256);

   Key256 := LSC.AES.AES256_Key_Type'
      (N (16#00010203#), N (16#04050607#), N (16#08090a0b#), N (16#0c0d0e0f#),
       N (16#10111213#), N (16#14151617#), N (16#18191a1b#), N (16#1c1d1e1f#));

   Plaintext := LSC.AES.Block_Type'
      (N (16#00112233#), N (16#44556677#), N (16#8899aabb#), N (16#ccddeeff#));

   Ciphertext := LSC.AES.Block_Type'
      (N (16#8ea2b7ca#), N (16#516745bf#), N (16#eafc4990#), N (16#4b496089#));

   --  Encryption
   Enc_Context := LSC.AES.Create_AES256_Enc_Context (Key256);
   LSC.Test.Run ("C.3 AES-256 (Nk=8, Nr=14), Encryption",
                 Ciphertext = LSC.AES.Encrypt (Enc_Context, Plaintext));

   --  Decryption
   Dec_Context := LSC.AES.Create_AES256_Dec_Context (Key256);
   LSC.Test.Run ("C.3 AES-256 (Nk=8, Nr=14), Decryption",
                 Plaintext = LSC.AES.Decrypt (Dec_Context, Ciphertext));

end AES_Tests;
