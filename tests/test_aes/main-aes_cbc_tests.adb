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
procedure AES_CBC_Tests
is
   subtype Msg_Index is Natural range 1 .. 4;
   subtype Msg_Type is LSC.AES.Message_Type (Msg_Index);

   Plaintext, Ciphertext, Expected_Ciphertext : Msg_Type;
   Key256                                     : LSC.AES.AES256_Key_Type;
   IV                                         : LSC.AES.Block_Type;
   Enc_Context                                : LSC.AES.AES_Enc_Context;

   function N (Item : LSC.Types.Word32) return LSC.Types.Word32
   is
   begin
      return LSC.Byteorder.BE_To_Native32 (Item);
   end N;

begin

   Plaintext := Msg_Type'
      (LSC.AES.Block_Type'(N (16#6bc1bee2#), N (16#2e409f96#), N (16#e93d7e11#), N (16#7393172a#)),
       LSC.AES.Block_Type'(N (16#ae2d8a57#), N (16#1e03ac9c#), N (16#9eb76fac#), N (16#45af8e51#)),
       LSC.AES.Block_Type'(N (16#30c81c46#), N (16#a35ce411#), N (16#e5fbc119#), N (16#1a0a52ef#)),
       LSC.AES.Block_Type'(N (16#f69f2445#), N (16#df4f9b17#), N (16#ad2b417b#), N (16#e66c3710#)));

   IV := LSC.AES.Block_Type'(N (16#00010203#), N (16#04050607#), N (16#08090a0b#), N (16#0c0d0e0f#));

   --------------
   -- AES256 test
   --------------

   Key256 := LSC.AES.AES256_Key_Type'
      (N (16#603deb10#), N (16#15ca71be#), N (16#2b73aef0#), N (16#857d7781#),
       N (16#1f352c07#), N (16#3b6108d7#), N (16#2d9810a3#), N (16#0914dff4#));

   Expected_Ciphertext := Msg_Type'
      (LSC.AES.Block_Type'(N (16#f58c4c04#), N (16#d6e5f1ba#), N (16#779eabfb#), N (16#5f7bfbd6#)),
       LSC.AES.Block_Type'(N (16#9cfc4e96#), N (16#7edb808d#), N (16#679f777b#), N (16#c6702c7d#)),
       LSC.AES.Block_Type'(N (16#39f23369#), N (16#a9d9bacf#), N (16#a530e263#), N (16#04231461#)),
       LSC.AES.Block_Type'(N (16#b2eb05e2#), N (16#c39be9fc#), N (16#da6c1907#), N (16#8c6a9d1b#)));

   --  Encryption
   Enc_Context := LSC.AES.Create_AES256_Enc_Context (Key256);
   LSC.AES.CBC.Encrypt (Enc_Context, IV, Plaintext, Ciphertext);
   LSC.Test.Run ("F.2.5 CBC-AES256.Encrypt", Ciphertext = Expected_Ciphertext);

end AES_CBC_Tests;
