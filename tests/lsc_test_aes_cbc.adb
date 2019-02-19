-------------------------------------------------------------------------------
--  This file is part of libsparkcrypto.
--
--  Copyright (C) 2018 Componolit GmbH
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

with AUnit.Assertions; use AUnit.Assertions;
with Util; use Util;
with LSC.AES.CBC;
with LSC.Types;

use LSC;

pragma Style_Checks ("-s");
pragma Warnings (Off, "formal parameter ""T"" is not referenced");

package body LSC_Test_AES_CBC is

   --  All test vectors are from
   --     Morris Dworkin: NIST Special Publication 800-38A, Recommendation for
   --     Block Cipher Modes of Operation, Methods and Techniques, F.2 CBC
   --     Example vectors

   ---------------------------------------------------------------------------

   --  NIST SP 800-38A, F.2.2 - CBC-AES128.Decrypt
   procedure Test_AES128_CBC_Decrypt (T : in out Test_Cases.Test_Case'Class)
   is
      use type LSC.Types.Bytes;
      Plaintext : LSC.Types.Bytes (1 .. 64);
   begin
      AES.CBC.Decrypt (Ciphertext => S2B ("7649abac8119b246cee98e9b12e9197d" &
                                          "5086cb9b507219ee95db113a917678b2" &
                                          "73bed6b8e3c1743b7116e69e22229516" &
                                          "3ff1caa1681fac09120eca307586e1a7"),
                       Key        => S2B ("2b7e151628aed2a6abf7158809cf4f3c"),
                       IV         => S2B ("000102030405060708090a0b0c0d0e0f"),
                       Keylen     => AES.L128,
                       Plaintext  => Plaintext);

      Assert (Plaintext = S2B ("6bc1bee22e409f96e93d7e117393172a" &
                               "ae2d8a571e03ac9c9eb76fac45af8e51" &
                               "30c81c46a35ce411e5fbc1191a0a52ef" &
                               "f69f2445df4f9b17ad2b417be66c3710"),
              "Invalid plaintext: " & B2S (Plaintext));
   end Test_AES128_CBC_Decrypt;

   ---------------------------------------------------------------------------

   --  NIST SP 800-38A, F.2.1 - CBC-AES128.Encrypt
   procedure Test_AES128_CBC_Encrypt (T : in out Test_Cases.Test_Case'Class)
   is
      use type LSC.Types.Bytes;
      Ciphertext : LSC.Types.Bytes (1 .. 64);
   begin
      AES.CBC.Encrypt (Plaintext  => S2B ("6bc1bee22e409f96e93d7e117393172a" &
                                          "ae2d8a571e03ac9c9eb76fac45af8e51" &
                                          "30c81c46a35ce411e5fbc1191a0a52ef" &
                                          "f69f2445df4f9b17ad2b417be66c3710"),

                       Key        => S2B ("2b7e151628aed2a6abf7158809cf4f3c"),
                       IV         => S2B ("000102030405060708090a0b0c0d0e0f"),
                       Keylen     => AES.L128,
                       Ciphertext => Ciphertext);

      Assert (Ciphertext =  S2B ("7649abac8119b246cee98e9b12e9197d" &
                                 "5086cb9b507219ee95db113a917678b2" &
                                 "73bed6b8e3c1743b7116e69e22229516" &
                                 "3ff1caa1681fac09120eca307586e1a7"),
              "Invalid ciphertext: " & B2S (Ciphertext));
   end Test_AES128_CBC_Encrypt;

   ---------------------------------------------------------------------------

   --  NIST SP 800-38A, F.2.4 - CBC-AES192.Decrypt
   procedure Test_AES192_CBC_Decrypt (T : in out Test_Cases.Test_Case'Class)
   is
      use type LSC.Types.Bytes;
      Plaintext : LSC.Types.Bytes (1 .. 64);
   begin
      AES.CBC.Decrypt (Ciphertext => S2B ("4f021db243bc633d7178183a9fa071e8" &
                                          "b4d9ada9ad7dedf4e5e738763f69145a" &
                                          "571b242012fb7ae07fa9baac3df102e0" &
                                          "08b0e27988598881d920a9e64f5615cd"),
                       Key        => S2B ("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
                       IV         => S2B ("000102030405060708090a0b0c0d0e0f"),
                       Keylen     => AES.L192,
                       Plaintext  => Plaintext);

      Assert (Plaintext = S2B ("6bc1bee22e409f96e93d7e117393172a" &
                               "ae2d8a571e03ac9c9eb76fac45af8e51" &
                               "30c81c46a35ce411e5fbc1191a0a52ef" &
                               "f69f2445df4f9b17ad2b417be66c3710"),
              "Invalid plaintext: " & B2S (Plaintext));
   end Test_AES192_CBC_Decrypt;

   ---------------------------------------------------------------------------

   --  NIST SP 800-38A, F.2.3 - CBC-AES192.Encrypt
   procedure Test_AES192_CBC_Encrypt (T : in out Test_Cases.Test_Case'Class)
   is
      use type LSC.Types.Bytes;
      Ciphertext : LSC.Types.Bytes (1 .. 64);
   begin
      AES.CBC.Encrypt (Plaintext  => S2B ("6bc1bee22e409f96e93d7e117393172a" &
                                          "ae2d8a571e03ac9c9eb76fac45af8e51" &
                                          "30c81c46a35ce411e5fbc1191a0a52ef" &
                                          "f69f2445df4f9b17ad2b417be66c3710"),

                       Key        => S2B ("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
                       IV         => S2B ("000102030405060708090a0b0c0d0e0f"),
                       Keylen     => AES.L192,
                       Ciphertext => Ciphertext);

      Assert (Ciphertext =  S2B ("4f021db243bc633d7178183a9fa071e8" &
                                 "b4d9ada9ad7dedf4e5e738763f69145a" &
                                 "571b242012fb7ae07fa9baac3df102e0" &
                                 "08b0e27988598881d920a9e64f5615cd"),
              "Invalid ciphertext: " & B2S (Ciphertext));
   end Test_AES192_CBC_Encrypt;

   ---------------------------------------------------------------------------

   --  NIST SP 800-38A, F.2.6 - CBC-AES256.Decrypt
   procedure Test_AES256_CBC_Decrypt (T : in out Test_Cases.Test_Case'Class)
   is
      use type LSC.Types.Bytes;
      Plaintext : LSC.Types.Bytes (1 .. 64);
   begin
      AES.CBC.Decrypt (Ciphertext => S2B ("f58c4c04d6e5f1ba779eabfb5f7bfbd6" &
                                          "9cfc4e967edb808d679f777bc6702c7d" &
                                          "39f23369a9d9bacfa530e26304231461" &
                                          "b2eb05e2c39be9fcda6c19078c6a9d1b"),
                       Key        => S2B ("603deb1015ca71be2b73aef0857d7781" &
                                          "1f352c073b6108d72d9810a30914dff4"),
                       IV         => S2B ("000102030405060708090a0b0c0d0e0f"),
                       Keylen     => AES.L256,
                       Plaintext  => Plaintext);

      Assert (Plaintext = S2B ("6bc1bee22e409f96e93d7e117393172a" &
                               "ae2d8a571e03ac9c9eb76fac45af8e51" &
                               "30c81c46a35ce411e5fbc1191a0a52ef" &
                               "f69f2445df4f9b17ad2b417be66c3710"),
              "Invalid plaintext: " & B2S (Plaintext));
   end Test_AES256_CBC_Decrypt;

   ---------------------------------------------------------------------------

   --  NIST SP 800-38A, F.2.5 - CBC-AES256.Encrypt
   procedure Test_AES256_CBC_Encrypt (T : in out Test_Cases.Test_Case'Class)
   is
      use type LSC.Types.Bytes;
      Ciphertext : LSC.Types.Bytes (1 .. 64);
   begin
      AES.CBC.Encrypt (Plaintext  => S2B ("6bc1bee22e409f96e93d7e117393172a" &
                                          "ae2d8a571e03ac9c9eb76fac45af8e51" &
                                          "30c81c46a35ce411e5fbc1191a0a52ef" &
                                          "f69f2445df4f9b17ad2b417be66c3710"),

                       Key        => S2B ("603deb1015ca71be2b73aef0857d7781" &
                                          "1f352c073b6108d72d9810a30914dff4"),
                       IV         => S2B ("000102030405060708090a0b0c0d0e0f"),
                       Keylen     => AES.L256,
                       Ciphertext => Ciphertext);

      Assert (Ciphertext =  S2B ("f58c4c04d6e5f1ba779eabfb5f7bfbd6" &
                                 "9cfc4e967edb808d679f777bc6702c7d" &
                                 "39f23369a9d9bacfa530e26304231461" &
                                 "b2eb05e2c39be9fcda6c19078c6a9d1b"),
              "Invalid ciphertext: " & B2S (Ciphertext));
   end Test_AES256_CBC_Encrypt;

   ---------------------------------------------------------------------------

   procedure Register_Tests (T : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (T, Test_AES128_CBC_Decrypt'Access, "AES-128-CBC decryption");
      Register_Routine (T, Test_AES128_CBC_Encrypt'Access, "AES-128-CBC encryption");
      Register_Routine (T, Test_AES192_CBC_Decrypt'Access, "AES-192-CBC decryption");
      Register_Routine (T, Test_AES192_CBC_Encrypt'Access, "AES-192-CBC encryption");
      Register_Routine (T, Test_AES256_CBC_Decrypt'Access, "AES-256-CBC decryption");
      Register_Routine (T, Test_AES256_CBC_Encrypt'Access, "AES-256-CBC encryption");
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("AES-CBC");
   end Name;

end LSC_Test_AES_CBC;
