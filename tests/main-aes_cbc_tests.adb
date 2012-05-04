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
procedure AES_CBC_Tests
is
   subtype Msg_Index is Natural range 1 .. 10;
   subtype Msg_Type is LSC.AES.Message_Type (Msg_Index);

   AES_CBC_Suite         : SPARKUnit.Index_Type;
   Plaintext, Ciphertext : Msg_Type;
   Result                : Msg_Type;
   Key128                : LSC.AES.AES128_Key_Type;
   Key192                : LSC.AES.AES192_Key_Type;
   Key256                : LSC.AES.AES256_Key_Type;
   IV                    : LSC.AES.Block_Type;
   Enc_Context           : LSC.AES.AES_Enc_Context;
   Dec_Context           : LSC.AES.AES_Dec_Context;

   function Equal
      (Left   : Msg_Type;
       Right  : Msg_Type;
       Length : Msg_Index) return Boolean
   --# pre
   --#    Left'First + Length in Msg_Index and
   --#    Right'First + Length in Msg_Index;
   is
      Result : Boolean := True;
   begin
      for I in Msg_Index range Left'First .. Length
        --# assert True;
      loop
         if Left (I) /= Right (I)
         then
            Result := False;
            exit;
         end if;
      end loop;
      return Result;
   end Equal;

begin

   SPARKUnit.Create_Suite (Harness, "AES-CBC tests", AES_CBC_Suite);

   Plaintext := Msg_Type'
      (LSC.AES.Block_Type'(M (16#6bc1bee2#), M (16#2e409f96#), M (16#e93d7e11#), M (16#7393172a#)),
       LSC.AES.Block_Type'(M (16#ae2d8a57#), M (16#1e03ac9c#), M (16#9eb76fac#), M (16#45af8e51#)),
       LSC.AES.Block_Type'(M (16#30c81c46#), M (16#a35ce411#), M (16#e5fbc119#), M (16#1a0a52ef#)),
       LSC.AES.Block_Type'(M (16#f69f2445#), M (16#df4f9b17#), M (16#ad2b417b#), M (16#e66c3710#)),
       others => LSC.AES.Null_Block);

   IV := LSC.AES.Block_Type'(M (16#00010203#), M (16#04050607#), M (16#08090a0b#), M (16#0c0d0e0f#));

   --------------
   -- AES128 test
   --------------

   Key128 := LSC.AES.AES128_Key_Type'
      (M (16#2b7e1516#), M (16#28aed2a6#), M (16#abf71588#), M (16#09cf4f3c#));

   Ciphertext := Msg_Type'
      (LSC.AES.Block_Type'(M (16#7649abac#), M (16#8119b246#), M (16#cee98e9b#), M (16#12e9197d#)),
      (LSC.AES.Block_Type'(M (16#5086cb9b#), M (16#507219ee#), M (16#95db113a#), M (16#917678b2#))),
      (LSC.AES.Block_Type'(M (16#73bed6b8#), M (16#e3c1743b#), M (16#7116e69e#), M (16#22229516#))),
      (LSC.AES.Block_Type'(M (16#3ff1caa1#), M (16#681fac09#), M (16#120eca30#), M (16#7586e1a7#))),
       others => LSC.AES.Null_Block);

   --  Encryption
   Enc_Context := LSC.AES.Create_AES128_Enc_Context (Key128);
   LSC.AES.CBC.Encrypt (Enc_Context, IV, Plaintext, 4, Result);
   SPARKUnit.Create_Test
      (Harness,
       AES_CBC_Suite,
       "F.2.1 CBC-AES128.Encrypt", Equal (Result, Ciphertext, 4));

   --  Decryption
   Dec_Context := LSC.AES.Create_AES128_Dec_Context (Key128);
   LSC.AES.CBC.Decrypt (Dec_Context, IV, Ciphertext, 4, Result);
   SPARKUnit.Create_Test
      (Harness,
       AES_CBC_Suite,
       "F.2.2 CBC-AES128.Decrypt", Equal (Result, Plaintext, 4));

   --------------
   -- AES192 test
   --------------

   Key192 := LSC.AES.AES192_Key_Type'
      (M (16#8e73b0f7#), M (16#da0e6452#), M (16#c810f32b#),
       M (16#809079e5#), M (16#62f8ead2#), M (16#522c6b7b#));

   Ciphertext := Msg_Type'
      (LSC.AES.Block_Type'(M (16#4f021db2#), M (16#43bc633d#), M (16#7178183a#), M (16#9fa071e8#)),
       LSC.AES.Block_Type'(M (16#b4d9ada9#), M (16#ad7dedf4#), M (16#e5e73876#), M (16#3f69145a#)),
       LSC.AES.Block_Type'(M (16#571b2420#), M (16#12fb7ae0#), M (16#7fa9baac#), M (16#3df102e0#)),
       LSC.AES.Block_Type'(M (16#08b0e279#), M (16#88598881#), M (16#d920a9e6#), M (16#4f5615cd#)),
       others => LSC.AES.Null_Block);

   --  Encryption
   Enc_Context := LSC.AES.Create_AES192_Enc_Context (Key192);
   LSC.AES.CBC.Encrypt (Enc_Context, IV, Plaintext, 4, Result);
   SPARKUnit.Create_Test
      (Harness,
       AES_CBC_Suite,
       "F.2.3 CBC-AES192.Encrypt", Equal (Result, Ciphertext, 4));

   --  Decryption
   Dec_Context := LSC.AES.Create_AES192_Dec_Context (Key192);
   LSC.AES.CBC.Decrypt (Dec_Context, IV, Ciphertext, 4, Result);
   SPARKUnit.Create_Test
      (Harness,
       AES_CBC_Suite,
       "F.2.4 CBC-AES192.Decrypt", Equal (Result, Plaintext, 4));

   --------------
   -- AES256 test
   --------------

   Key256 := LSC.AES.AES256_Key_Type'
      (M (16#603deb10#), M (16#15ca71be#), M (16#2b73aef0#), M (16#857d7781#),
       M (16#1f352c07#), M (16#3b6108d7#), M (16#2d9810a3#), M (16#0914dff4#));

   Ciphertext := Msg_Type'
      (LSC.AES.Block_Type'(M (16#f58c4c04#), M (16#d6e5f1ba#), M (16#779eabfb#), M (16#5f7bfbd6#)),
       LSC.AES.Block_Type'(M (16#9cfc4e96#), M (16#7edb808d#), M (16#679f777b#), M (16#c6702c7d#)),
       LSC.AES.Block_Type'(M (16#39f23369#), M (16#a9d9bacf#), M (16#a530e263#), M (16#04231461#)),
       LSC.AES.Block_Type'(M (16#b2eb05e2#), M (16#c39be9fc#), M (16#da6c1907#), M (16#8c6a9d1b#)),
       others => LSC.AES.Null_Block);

   --  Encryption
   Enc_Context := LSC.AES.Create_AES256_Enc_Context (Key256);
   LSC.AES.CBC.Encrypt (Enc_Context, IV, Plaintext, 4, Result);
   SPARKUnit.Create_Test
      (Harness,
       AES_CBC_Suite,
       "F.2.5 CBC-AES256.Encrypt", Equal (Result, Ciphertext, 4));

   --  Decryption
   Dec_Context := LSC.AES.Create_AES256_Dec_Context (Key256);
   LSC.AES.CBC.Decrypt (Dec_Context, IV, Ciphertext, 4, Result);
   SPARKUnit.Create_Test
      (Harness,
       AES_CBC_Suite,
       "F.2.6 CBC-AES256.Decrypt", Equal (Result, Plaintext, 4));

end AES_CBC_Tests;
