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
with LSC.AES;
with LSC.Types;

use LSC;

pragma Style_Checks ("-s");
pragma Warnings (Off, "formal parameter ""T"" is not referenced");

package body LSC_Test_AES is

   ---------------------------------------------------------------------------

   procedure Test_AES128_Decrypt (T : in out Test_Cases.Test_Case'Class)
   is
      use type LSC.Types.Bytes;

      --  FIPS 197, C.1
      Plaintext : constant LSC.Types.Bytes :=
         AES.Decrypt (Ciphertext => S2B ("69c4e0d86a7b0430d8cdb78070b4c55a"),
                      Key        => AES.Dec_Key (K      => S2B ("000102030405060708090a0b0c0d0e0f"),
                                                 Keylen => AES.L128));
   begin
      Assert (Plaintext = S2B ("00112233445566778899aabbccddeeff"),
              "Invalid plaintext: " & B2S (Plaintext));
   end Test_AES128_Decrypt;

   ---------------------------------------------------------------------------

   procedure Test_AES128_Encrypt (T : in out Test_Cases.Test_Case'Class)
   is
      use type LSC.Types.Bytes;

      --  FIPS 197, C.1
      Ciphertext : constant LSC.Types.Bytes :=
         AES.Encrypt (Plaintext => S2B ("00112233445566778899aabbccddeeff"),
                      Key       => AES.Enc_Key (K      => S2B ("000102030405060708090a0b0c0d0e0f"),
                                                Keylen => AES.L128));
   begin
      Assert (Ciphertext = S2B ("69c4e0d86a7b0430d8cdb78070b4c55a"),
              "Invalid ciphertext: " & B2S (Ciphertext));
   end Test_AES128_Encrypt;

   ---------------------------------------------------------------------------

   procedure Test_AES192_Decrypt (T : in out Test_Cases.Test_Case'Class)
   is
      use type LSC.Types.Bytes;

      --  FIPS 197, C.2
      Plaintext : constant LSC.Types.Bytes :=
         AES.Decrypt (Ciphertext => S2B ("dda97ca4864cdfe06eaf70a0ec0d7191"),
                      Key        => AES.Dec_Key (K      => S2B ("000102030405060708090a0b0c0d0e0f1011121314151617"),
                                                 Keylen => AES.L192));
   begin
      Assert (Plaintext = S2B ("00112233445566778899aabbccddeeff"),
              "Invalid plaintext: " & B2S (Plaintext));
   end Test_AES192_Decrypt;

   ---------------------------------------------------------------------------

   procedure Test_AES192_Encrypt (T : in out Test_Cases.Test_Case'Class)
   is
      use type LSC.Types.Bytes;

      --  FIPS 197, C.2
      Ciphertext : constant LSC.Types.Bytes :=
         AES.Encrypt (Plaintext => S2B ("00112233445566778899aabbccddeeff"),
                      Key       => AES.Enc_Key (K      => S2B ("000102030405060708090a0b0c0d0e0f1011121314151617"),
                                                Keylen => AES.L192));
   begin
      Assert (Ciphertext = S2B ("dda97ca4864cdfe06eaf70a0ec0d7191"),
              "Invalid ciphertext: " & B2S (Ciphertext));
   end Test_AES192_Encrypt;

   ---------------------------------------------------------------------------

   procedure Test_AES256_Decrypt (T : in out Test_Cases.Test_Case'Class)
   is
      use type LSC.Types.Bytes;

      Key : constant AES.Dec_Key_Type :=
         AES.Dec_Key (K      => S2B ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                      Keylen => AES.L256);

      --  FIPS 197, C.3
      Plaintext : constant LSC.Types.Bytes :=
         AES.Decrypt (Ciphertext => S2B ("8ea2b7ca516745bfeafc49904b496089"),
                      Key        => Key);
   begin
      Assert (Plaintext = S2B ("00112233445566778899aabbccddeeff"),
              "Invalid plaintext: " & B2S (Plaintext));
   end Test_AES256_Decrypt;

   ---------------------------------------------------------------------------

   procedure Test_AES256_Encrypt (T : in out Test_Cases.Test_Case'Class)
   is
      use type LSC.Types.Bytes;

      Key : constant AES.Enc_Key_Type :=
         AES.Enc_Key (K      => S2B ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                      Keylen => AES.L256);

      --  FIPS 197, C.3
      Ciphertext : constant LSC.Types.Bytes :=
         AES.Encrypt (Plaintext => S2B ("00112233445566778899aabbccddeeff"),
                      Key       => Key);
   begin
      Assert (Ciphertext = S2B ("8ea2b7ca516745bfeafc49904b496089"),
              "Invalid ciphertext: " & B2S (Ciphertext));
   end Test_AES256_Encrypt;

   ---------------------------------------------------------------------------

   procedure Register_Tests (T : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (T, Test_AES128_Decrypt'Access, "AES-128 decryption");
      Register_Routine (T, Test_AES128_Encrypt'Access, "AES-128 encryption");
      Register_Routine (T, Test_AES192_Decrypt'Access, "AES-192 decryption");
      Register_Routine (T, Test_AES192_Encrypt'Access, "AES-192 encryption");
      Register_Routine (T, Test_AES256_Decrypt'Access, "AES-256 decryption");
      Register_Routine (T, Test_AES256_Encrypt'Access, "AES-256 encryption");
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("AES");
   end Name;

end LSC_Test_AES;
