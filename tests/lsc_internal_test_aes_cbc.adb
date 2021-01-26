-------------------------------------------------------------------------------
--  This file is part of libsparkcrypto.
--
--  Copyright (C) 2010, Alexander Senier
--  Copyright (C) 2010, secunet Security Networks AG
--  All rights reserved.
--
--  Redistribution  and  use  in  source  and  binary  forms,  with  or  without
--  modification, are permitted provided that the following conditions are met:
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
--  THIS SOFTWARE IS PROVIDED BY THE  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
--  AND ANY  EXPRESS OR IMPLIED WARRANTIES,  INCLUDING, BUT NOT LIMITED  TO, THE
--  IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
--  ARE  DISCLAIMED. IN  NO EVENT  SHALL  THE COPYRIGHT  HOLDER OR  CONTRIBUTORS
--  BE  LIABLE FOR  ANY  DIRECT, INDIRECT,  INCIDENTAL,  SPECIAL, EXEMPLARY,  OR
--  CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT  LIMITED  TO,  PROCUREMENT  OF
--  SUBSTITUTE GOODS  OR SERVICES; LOSS  OF USE,  DATA, OR PROFITS;  OR BUSINESS
--  INTERRUPTION)  HOWEVER CAUSED  AND ON  ANY THEORY  OF LIABILITY,  WHETHER IN
--  CONTRACT,  STRICT LIABILITY,  OR  TORT (INCLUDING  NEGLIGENCE OR  OTHERWISE)
--  ARISING IN ANY WAY  OUT OF THE USE OF THIS SOFTWARE, EVEN  IF ADVISED OF THE
--  POSSIBILITY OF SUCH DAMAGE.
-------------------------------------------------------------------------------

with LSC.Internal.Types;
with LSC.Internal.AES;
with LSC.Internal.AES.CBC;
with AUnit.Assertions; use AUnit.Assertions;
with Util; use Util;

pragma Elaborate_All (Util);
pragma Style_Checks ("-s");
pragma Warnings (Off, "formal parameter ""T"" is not referenced");

use type LSC.Internal.Types.Word32_Array_Type;

package body LSC_Internal_Test_AES_CBC
is

   subtype Msg_Index is Natural range 1 .. 10;
   subtype Msg_Type is LSC.Internal.AES.Message_Type (Msg_Index);

   Plaintext : constant Msg_Type := Msg_Type'
      (LSC.Internal.AES.Block_Type'(M (16#6bc1bee2#), M (16#2e409f96#), M (16#e93d7e11#), M (16#7393172a#)),
       LSC.Internal.AES.Block_Type'(M (16#ae2d8a57#), M (16#1e03ac9c#), M (16#9eb76fac#), M (16#45af8e51#)),
       LSC.Internal.AES.Block_Type'(M (16#30c81c46#), M (16#a35ce411#), M (16#e5fbc119#), M (16#1a0a52ef#)),
       LSC.Internal.AES.Block_Type'(M (16#f69f2445#), M (16#df4f9b17#), M (16#ad2b417b#), M (16#e66c3710#)),
       others => LSC.Internal.AES.Null_Block);

   IV : constant LSC.Internal.AES.Block_Type := LSC.Internal.AES.Block_Type'
      (M (16#00010203#), M (16#04050607#), M (16#08090a0b#), M (16#0c0d0e0f#));

   ---------------------------------------------------------------------------

   function Equal
      (Left   : Msg_Type;
       Right  : Msg_Type;
       Length : Msg_Index) return Boolean
   is
      Result : Boolean := True;
   begin
      for I in Msg_Index range Left'First .. Length
      loop
         if Left (I) /= Right (I)
         then
            Result := False;
            exit;
         end if;
      end loop;
      return Result;
   end Equal;

   ---------------------------------------------------------------------------

   procedure Test_AES128_CBC (T : in out Test_Cases.Test_Case'Class)
   is
      Key         : LSC.Internal.AES.AES128_Key_Type;
      Ciphertext  : Msg_Type;
      Enc_Context : LSC.Internal.AES.AES_Enc_Context;
      Dec_Context : LSC.Internal.AES.AES_Dec_Context;
      Result      : Msg_Type;
   begin
      Key := LSC.Internal.AES.AES128_Key_Type'
         (M (16#2b7e1516#), M (16#28aed2a6#), M (16#abf71588#), M (16#09cf4f3c#));

      Ciphertext := Msg_Type'
         (LSC.Internal.AES.Block_Type'(M (16#7649abac#), M (16#8119b246#), M (16#cee98e9b#), M (16#12e9197d#)),
         (LSC.Internal.AES.Block_Type'(M (16#5086cb9b#), M (16#507219ee#), M (16#95db113a#), M (16#917678b2#))),
         (LSC.Internal.AES.Block_Type'(M (16#73bed6b8#), M (16#e3c1743b#), M (16#7116e69e#), M (16#22229516#))),
         (LSC.Internal.AES.Block_Type'(M (16#3ff1caa1#), M (16#681fac09#), M (16#120eca30#), M (16#7586e1a7#))),
          others => LSC.Internal.AES.Null_Block);

      --  Encryption
      Enc_Context := LSC.Internal.AES.Create_AES128_Enc_Context (Key);
      LSC.Internal.AES.CBC.Encrypt (Enc_Context, IV, Plaintext, 4, Result);
      Assert (Equal (Result, Ciphertext, 4), "Invalid ciphertext");

      --  Decryption
      Dec_Context := LSC.Internal.AES.Create_AES128_Dec_Context (Key);
      LSC.Internal.AES.CBC.Decrypt (Dec_Context, IV, Ciphertext, 4, Result);
      Assert (Equal (Result, Plaintext, 4), "Invalid plaintext");

   end Test_AES128_CBC;

   ---------------------------------------------------------------------------

   procedure Test_AES192_CBC (T : in out Test_Cases.Test_Case'Class)
   is
      Key         : LSC.Internal.AES.AES192_Key_Type;
      Ciphertext  : Msg_Type;
      Enc_Context : LSC.Internal.AES.AES_Enc_Context;
      Dec_Context : LSC.Internal.AES.AES_Dec_Context;
      Result      : Msg_Type;
   begin
      Key := LSC.Internal.AES.AES192_Key_Type'
         (M (16#8e73b0f7#), M (16#da0e6452#), M (16#c810f32b#),
          M (16#809079e5#), M (16#62f8ead2#), M (16#522c6b7b#));

      Ciphertext := Msg_Type'
         (LSC.Internal.AES.Block_Type'(M (16#4f021db2#), M (16#43bc633d#), M (16#7178183a#), M (16#9fa071e8#)),
          LSC.Internal.AES.Block_Type'(M (16#b4d9ada9#), M (16#ad7dedf4#), M (16#e5e73876#), M (16#3f69145a#)),
          LSC.Internal.AES.Block_Type'(M (16#571b2420#), M (16#12fb7ae0#), M (16#7fa9baac#), M (16#3df102e0#)),
          LSC.Internal.AES.Block_Type'(M (16#08b0e279#), M (16#88598881#), M (16#d920a9e6#), M (16#4f5615cd#)),
          others => LSC.Internal.AES.Null_Block);

      --  Encryption
      Enc_Context := LSC.Internal.AES.Create_AES192_Enc_Context (Key);
      LSC.Internal.AES.CBC.Encrypt (Enc_Context, IV, Plaintext, 4, Result);
      Assert (Equal (Result, Ciphertext, 4), "Invalid ciphertext");

      --  Decryption
      Dec_Context := LSC.Internal.AES.Create_AES192_Dec_Context (Key);
      LSC.Internal.AES.CBC.Decrypt (Dec_Context, IV, Ciphertext, 4, Result);
      Assert (Equal (Result, Plaintext, 4), "Invalid plaintext");

   end Test_AES192_CBC;

   ---------------------------------------------------------------------------

   procedure Test_AES256_CBC (T : in out Test_Cases.Test_Case'Class)
   is
      Key         : LSC.Internal.AES.AES256_Key_Type;
      Ciphertext  : Msg_Type;
      Enc_Context : LSC.Internal.AES.AES_Enc_Context;
      Dec_Context : LSC.Internal.AES.AES_Dec_Context;
      Result      : Msg_Type;
   begin
      Key := LSC.Internal.AES.AES256_Key_Type'
         (M (16#603deb10#), M (16#15ca71be#), M (16#2b73aef0#), M (16#857d7781#),
          M (16#1f352c07#), M (16#3b6108d7#), M (16#2d9810a3#), M (16#0914dff4#));

      Ciphertext := Msg_Type'
         (LSC.Internal.AES.Block_Type'(M (16#f58c4c04#), M (16#d6e5f1ba#), M (16#779eabfb#), M (16#5f7bfbd6#)),
          LSC.Internal.AES.Block_Type'(M (16#9cfc4e96#), M (16#7edb808d#), M (16#679f777b#), M (16#c6702c7d#)),
          LSC.Internal.AES.Block_Type'(M (16#39f23369#), M (16#a9d9bacf#), M (16#a530e263#), M (16#04231461#)),
          LSC.Internal.AES.Block_Type'(M (16#b2eb05e2#), M (16#c39be9fc#), M (16#da6c1907#), M (16#8c6a9d1b#)),
          others => LSC.Internal.AES.Null_Block);

      --  Encryption
      Enc_Context := LSC.Internal.AES.Create_AES256_Enc_Context (Key);
      LSC.Internal.AES.CBC.Encrypt (Enc_Context, IV, Plaintext, 4, Result);
      Assert (Equal (Result, Ciphertext, 4), "Invalid ciphertext");

      --  Decryption
      Dec_Context := LSC.Internal.AES.Create_AES256_Dec_Context (Key);
      LSC.Internal.AES.CBC.Decrypt (Dec_Context, IV, Ciphertext, 4, Result);
      Assert (Equal (Result, Plaintext, 4), "Invalid plaintext");

   end Test_AES256_CBC;

   ---------------------------------------------------------------------------

   procedure Register_Tests (T : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (T, Test_AES128_CBC'Access, "128 (F.2.1/F.2.2)");
      Register_Routine (T, Test_AES192_CBC'Access, "192 (F.2.3/F.2.4)");
      Register_Routine (T, Test_AES256_CBC'Access, "256 (F.2.5/F.2.6)");
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("AES-CBC");
   end Name;

end LSC_Internal_Test_AES_CBC;
