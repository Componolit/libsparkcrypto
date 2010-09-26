-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2010, Alexander Senier
-- Copyright (C) 2010, secunet Security Networks AG
-- All rights reserved.
--
-- Redistribution  and  use  in  source  and  binary  forms,  with  or  without
-- modification, are permitted provided that the following conditions are met:
--
--    * Redistributions of source code must retain the above copyright notice,
--      this list of conditions and the following disclaimer.
--
--    * Redistributions in binary form must reproduce the above copyright
--      notice, this list of conditions and the following disclaimer in the
--      documentation and/or other materials provided with the distribution.
--
--    * Neither the name of the  nor the names of its contributors may be used
--      to endorse or promote products derived from this software without
--      specific prior written permission.
--
-- THIS SOFTWARE IS PROVIDED BY THE  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-- AND ANY  EXPRESS OR IMPLIED WARRANTIES,  INCLUDING, BUT NOT LIMITED  TO, THE
-- IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
-- ARE  DISCLAIMED. IN  NO EVENT  SHALL  THE COPYRIGHT  HOLDER OR  CONTRIBUTORS
-- BE  LIABLE FOR  ANY  DIRECT, INDIRECT,  INCIDENTAL,  SPECIAL, EXEMPLARY,  OR
-- CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT  LIMITED  TO,  PROCUREMENT  OF
-- SUBSTITUTE GOODS  OR SERVICES; LOSS  OF USE,  DATA, OR PROFITS;  OR BUSINESS
-- INTERRUPTION)  HOWEVER CAUSED  AND ON  ANY THEORY  OF LIABILITY,  WHETHER IN
-- CONTRACT,  STRICT LIABILITY,  OR  TORT (INCLUDING  NEGLIGENCE OR  OTHERWISE)
-- ARISING IN ANY WAY  OUT OF THE USE OF THIS SOFTWARE, EVEN  IF ADVISED OF THE
-- POSSIBILITY OF SUCH DAMAGE.
-------------------------------------------------------------------------------

separate (Main)
procedure AES_Tests
is
   AES_Suite                                 : SPARKUnit.Index_Type;
   Plaintext, Ciphertext                     : LSC.AES.Block_Type;
   Key128                                    : LSC.AES.AES128_Key_Type;
   Key192                                    : LSC.AES.AES192_Key_Type;
   Key256                                    : LSC.AES.AES256_Key_Type;
   Enc_Context                               : LSC.AES.AES_Enc_Context;
   Dec_Context                               : LSC.AES.AES_Dec_Context;

begin

   SPARKUnit.Create_Suite (Harness, "AES tests", AES_Suite);

   --------------
   -- AES128 test
   --------------

   --  Key expansion

   --# accept Flow, 10, Key128, "Only debug output needed";
   Key128 := LSC.AES.AES128_Key_Type'
      (M (16#2b7e1516#), M (16#28aed2a6#), M (16#abf71588#), M (16#09cf4f3c#));

   --# accept Flow, 10, "Only debug output needed";
   Enc_Context := LSC.AES.Create_AES128_Enc_Context (Key128);

   Key128 := LSC.AES.AES128_Key_Type'
      (M (16#00010203#), M (16#04050607#), M (16#08090a0b#), M (16#0c0d0e0f#));

   Plaintext := LSC.AES.Block_Type'
      (M (16#00112233#), M (16#44556677#), M (16#8899aabb#), M (16#ccddeeff#));

   Ciphertext := LSC.AES.Block_Type'
      (M (16#69c4e0d8#), M (16#6a7b0430#), M (16#d8cdb780#), M (16#70b4c55a#));

   --  Encryption
   Enc_Context := LSC.AES.Create_AES128_Enc_Context (Key128);
   SPARKUnit.Create_Test
      (Harness,
       AES_Suite,
       "C.1 AES-128 (Nk=4, Nr=10), Encryption",
       Ciphertext = LSC.AES.Encrypt (Enc_Context, Plaintext));

   -- Decryption
   Dec_Context := LSC.AES.Create_AES128_Dec_Context (Key128);
   SPARKUnit.Create_Test
      (Harness,
       AES_Suite,
       "C.1 AES-128 (Nk=4, Nr=10), Decryption",
       Plaintext = LSC.AES.Decrypt (Dec_Context, Ciphertext));

   --------------
   -- AES192 test
   --------------

   --# accept Flow, 10, Key192, "Only debug output needed";
   Key192 := LSC.AES.AES192_Key_Type'
      (M (16#8e73b0f7#), M (16#da0e6452#), M (16#c810f32b#),
       M (16#809079e5#), M (16#62f8ead2#), M (16#522c6b7b#));

   --# accept Flow, 10, "Only debug output needed";
   Enc_Context := LSC.AES.Create_AES192_Enc_Context (Key192);

   Key192 := LSC.AES.AES192_Key_Type'
      (M (16#00010203#), M (16#04050607#), M (16#08090a0b#),
       M (16#0c0d0e0f#), M (16#10111213#), M (16#14151617#));

   Plaintext := LSC.AES.Block_Type'
      (M (16#00112233#), M (16#44556677#), M (16#8899aabb#), M (16#ccddeeff#));

   Ciphertext := LSC.AES.Block_Type'
      (M (16#dda97ca4#), M (16#864cdfe0#), M (16#6eaf70a0#), M (16#ec0d7191#));

   --  Encryption
   Enc_Context := LSC.AES.Create_AES192_Enc_Context (Key192);
   SPARKUnit.Create_Test
      (Harness,
       AES_Suite,
       "C.2 AES-192 (Nk=6, Nr=12), Encryption",
       Ciphertext = LSC.AES.Encrypt (Enc_Context, Plaintext));

   --  Decryption
   Dec_Context := LSC.AES.Create_AES192_Dec_Context (Key192);
   SPARKUnit.Create_Test
      (Harness,
       AES_Suite,
       "C.2 AES-192 (Nk=6, Nr=12), Decryption",
       Plaintext = LSC.AES.Decrypt (Dec_Context, Ciphertext));

   --------------
   -- AES256 test
   --------------

   --# accept Flow, 10, Key256, "Only debug output needed";
   Key256 := LSC.AES.AES256_Key_Type'
      (M (16#603deb10#), M (16#15ca71be#), M (16#2b73aef0#), M (16#857d7781#),
       M (16#1f352c07#), M (16#3b6108d7#), M (16#2d9810a3#), M (16#0914dff4#));

   --# accept Flow, 10, "Only debug output needed";
   Enc_Context := LSC.AES.Create_AES256_Enc_Context (Key256);

   Key256 := LSC.AES.AES256_Key_Type'
      (M (16#00010203#), M (16#04050607#), M (16#08090a0b#), M (16#0c0d0e0f#),
       M (16#10111213#), M (16#14151617#), M (16#18191a1b#), M (16#1c1d1e1f#));

   Plaintext := LSC.AES.Block_Type'
      (M (16#00112233#), M (16#44556677#), M (16#8899aabb#), M (16#ccddeeff#));

   Ciphertext := LSC.AES.Block_Type'
      (M (16#8ea2b7ca#), M (16#516745bf#), M (16#eafc4990#), M (16#4b496089#));

   --  Encryption
   Enc_Context := LSC.AES.Create_AES256_Enc_Context (Key256);
   SPARKUnit.Create_Test
      (Harness,
       AES_Suite,
       "C.3 AES-256 (Nk=8, Nr=14), Encryption",
       Ciphertext = LSC.AES.Encrypt (Enc_Context, Plaintext));

   --  Decryption
   Dec_Context := LSC.AES.Create_AES256_Dec_Context (Key256);
   SPARKUnit.Create_Test
      (Harness,
       AES_Suite,
       "C.3 AES-256 (Nk=8, Nr=14), Decryption",
       Plaintext = LSC.AES.Decrypt (Dec_Context, Ciphertext));

end AES_Tests;
