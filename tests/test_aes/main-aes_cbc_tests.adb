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
procedure AES_CBC_Tests
is
   subtype Msg_Index is Natural range 1 .. 4;
   subtype Msg_Type is LSC.AES.Message_Type (Msg_Index);

   Plaintext, Ciphertext : Msg_Type;
   Result                : Msg_Type := Msg_Type'(others => LSC.AES.Block_Type'(others => 0));
   Key128                : LSC.AES.AES128_Key_Type;
   Key192                : LSC.AES.AES192_Key_Type;
   Key256                : LSC.AES.AES256_Key_Type;
   IV                    : LSC.AES.Block_Type;
   Enc_Context           : LSC.AES.AES_Enc_Context;
   Dec_Context           : LSC.AES.AES_Dec_Context;

begin

   Plaintext := Msg_Type'
      (LSC.AES.Block_Type'(N (16#6bc1bee2#), N (16#2e409f96#), N (16#e93d7e11#), N (16#7393172a#)),
       LSC.AES.Block_Type'(N (16#ae2d8a57#), N (16#1e03ac9c#), N (16#9eb76fac#), N (16#45af8e51#)),
       LSC.AES.Block_Type'(N (16#30c81c46#), N (16#a35ce411#), N (16#e5fbc119#), N (16#1a0a52ef#)),
       LSC.AES.Block_Type'(N (16#f69f2445#), N (16#df4f9b17#), N (16#ad2b417b#), N (16#e66c3710#)));

   IV := LSC.AES.Block_Type'(N (16#00010203#), N (16#04050607#), N (16#08090a0b#), N (16#0c0d0e0f#));

   --------------
   -- AES128 test
   --------------

   Key128 := LSC.AES.AES128_Key_Type'
      (N (16#2b7e1516#), N (16#28aed2a6#), N (16#abf71588#), N (16#09cf4f3c#));

   Ciphertext := Msg_Type'
      (LSC.AES.Block_Type'(N (16#7649abac#), N (16#8119b246#), N (16#cee98e9b#), N (16#12e9197d#)),
      (LSC.AES.Block_Type'(N (16#5086cb9b#), N (16#507219ee#), N (16#95db113a#), N (16#917678b2#))),
      (LSC.AES.Block_Type'(N (16#73bed6b8#), N (16#e3c1743b#), N (16#7116e69e#), N (16#22229516#))),
      (LSC.AES.Block_Type'(N (16#3ff1caa1#), N (16#681fac09#), N (16#120eca30#), N (16#7586e1a7#))));

   --  Encryption
   Enc_Context := LSC.AES.Create_AES128_Enc_Context (Key128);
   LSC.AES.CBC.Encrypt (Enc_Context, IV, Plaintext, Result);
   LSC.Test.Run ("F.2.1 CBC-AES128.Encrypt", Result = Ciphertext);

   --  Decryption
   Dec_Context := LSC.AES.Create_AES128_Dec_Context (Key128);
   LSC.AES.CBC.Decrypt (Dec_Context, IV, Ciphertext, Result);
   LSC.Test.Run ("F.2.2 CBC-AES128.Decrypt", Result = Plaintext);

   --------------
   -- AES192 test
   --------------

   Key192 := LSC.AES.AES192_Key_Type'
      (N (16#8e73b0f7#), N (16#da0e6452#), N (16#c810f32b#),
       N (16#809079e5#), N (16#62f8ead2#), N (16#522c6b7b#));

   Ciphertext := Msg_Type'
      (LSC.AES.Block_Type'(N (16#4f021db2#), N (16#43bc633d#), N (16#7178183a#), N (16#9fa071e8#)),
       LSC.AES.Block_Type'(N (16#b4d9ada9#), N (16#ad7dedf4#), N (16#e5e73876#), N (16#3f69145a#)),
       LSC.AES.Block_Type'(N (16#571b2420#), N (16#12fb7ae0#), N (16#7fa9baac#), N (16#3df102e0#)),
       LSC.AES.Block_Type'(N (16#08b0e279#), N (16#88598881#), N (16#d920a9e6#), N (16#4f5615cd#)));

   --  Encryption
   Enc_Context := LSC.AES.Create_AES192_Enc_Context (Key192);
   LSC.AES.CBC.Encrypt (Enc_Context, IV, Plaintext, Result);
   LSC.Test.Run ("F.2.3 CBC-AES192.Encrypt", Result = Ciphertext);

   --  Decryption
   Dec_Context := LSC.AES.Create_AES192_Dec_Context (Key192);
   LSC.AES.CBC.Decrypt (Dec_Context, IV, Ciphertext, Result);
   LSC.Test.Run ("F.2.4 CBC-AES192.Decrypt", Result = Plaintext);

   --------------
   -- AES256 test
   --------------

   Key256 := LSC.AES.AES256_Key_Type'
      (N (16#603deb10#), N (16#15ca71be#), N (16#2b73aef0#), N (16#857d7781#),
       N (16#1f352c07#), N (16#3b6108d7#), N (16#2d9810a3#), N (16#0914dff4#));

   Ciphertext := Msg_Type'
      (LSC.AES.Block_Type'(N (16#f58c4c04#), N (16#d6e5f1ba#), N (16#779eabfb#), N (16#5f7bfbd6#)),
       LSC.AES.Block_Type'(N (16#9cfc4e96#), N (16#7edb808d#), N (16#679f777b#), N (16#c6702c7d#)),
       LSC.AES.Block_Type'(N (16#39f23369#), N (16#a9d9bacf#), N (16#a530e263#), N (16#04231461#)),
       LSC.AES.Block_Type'(N (16#b2eb05e2#), N (16#c39be9fc#), N (16#da6c1907#), N (16#8c6a9d1b#)));

   --  Encryption
   Enc_Context := LSC.AES.Create_AES256_Enc_Context (Key256);
   LSC.AES.CBC.Encrypt (Enc_Context, IV, Plaintext, Result);
   LSC.Test.Run ("F.2.5 CBC-AES256.Encrypt", Result = Ciphertext);

   --  Decryption
   Dec_Context := LSC.AES.Create_AES256_Dec_Context (Key256);
   LSC.AES.CBC.Decrypt (Dec_Context, IV, Ciphertext, Result);
   LSC.Test.Run ("F.2.6 CBC-AES256.Decrypt", Result = Plaintext);

end AES_CBC_Tests;
