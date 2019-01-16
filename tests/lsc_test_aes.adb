-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2018 Componolit GmbH
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

with AUnit.Assertions; use AUnit.Assertions;
with LSC.Internal.AES;
with OpenSSL;

package body LSC_Test_AES is

   ---------------------------------------------------------------------------

   procedure Test_AES128_Decrypt (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      type Message_Type is array (Message_Index) of LSC.Internal.AES.Block_Type;

      Plain1, Plain2, Cipher  : Message_Type;
      Key128                  : LSC.Internal.AES.AES128_Key_Type;
      Context1                : OpenSSL.AES_Dec_Context_Type;
      Context2                : LSC.Internal.AES.AES_Dec_Context;
   begin

      Cipher := Message_Type'
         (others => LSC.Internal.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key128 := LSC.Internal.AES.AES128_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#0b0a0908#,
                                          16#1f1e1d1c#);

      Context1 := OpenSSL.Create_AES128_Dec_Context (Key128);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Plain1 (I) := OpenSSL.Decrypt (Context1, Cipher (I));
         end loop;
      end loop;

      Context2 := LSC.Internal.AES.Create_AES128_Dec_Context (Key128);

      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Plain2 (I) := LSC.Internal.AES.Decrypt (Context2, Cipher (I));
         end loop;
      end loop;

      Assert (Plain1 = Plain2, "Plaintext differs");

	end Test_AES128_Decrypt;

   ---------------------------------------------------------------------------

   procedure Test_AES128_Encrypt (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      type Message_Type is array (Message_Index) of LSC.Internal.AES.Block_Type;

      Plain, Cipher1, Cipher2 : Message_Type;
      Key128                  : LSC.Internal.AES.AES128_Key_Type;
      Context1                : OpenSSL.AES_Enc_Context_Type;
      Context2                : LSC.Internal.AES.AES_Enc_Context;
   begin

      Plain := Message_Type'
         (others => LSC.Internal.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key128 := LSC.Internal.AES.AES128_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#0b0a0908#,
                                          16#0f0e0d0c#);

      Context1 := OpenSSL.Create_AES128_Enc_Context (Key128);

      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Cipher1 (I) := OpenSSL.Encrypt (Context1, Plain (I));
         end loop;
      end loop;

      Context2 := LSC.Internal.AES.Create_AES128_Enc_Context (Key128);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Cipher2 (I) := LSC.Internal.AES.Encrypt (Context2, Plain (I));
         end loop;
      end loop;

      Assert (Cipher1 = Cipher2, "Ciphertext differs");

   end Test_AES128_Encrypt;

   ---------------------------------------------------------------------------

   procedure Test_AES192_Decrypt (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      type Message_Type is array (Message_Index) of LSC.Internal.AES.Block_Type;

      Plain1, Plain2, Cipher  : Message_Type;
      Key192                  : LSC.Internal.AES.AES192_Key_Type;
      Context1                : OpenSSL.AES_Dec_Context_Type;
      Context2                : LSC.Internal.AES.AES_Dec_Context;
   begin

      Cipher := Message_Type'
         (others => LSC.Internal.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key192 := LSC.Internal.AES.AES192_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#13121110#,
                                          16#17161514#,
                                          16#1b1a1918#,
                                          16#1f1e1d1c#);

      Context1 := OpenSSL.Create_AES192_Dec_Context (Key192);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Plain1 (I) := OpenSSL.Decrypt (Context1, Cipher (I));
         end loop;
      end loop;

      Context2 := LSC.Internal.AES.Create_AES192_Dec_Context (Key192);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Plain2 (I) := LSC.Internal.AES.Decrypt (Context2, Cipher (I));
         end loop;
      end loop;

      Assert (Plain1 = Plain2, "Plaintext differs");

   end Test_AES192_Decrypt;

   ---------------------------------------------------------------------------

   procedure Test_AES192_Encrypt (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      type Message_Type is array (Message_Index) of LSC.Internal.AES.Block_Type;

      Plain, Cipher1, Cipher2 : Message_Type;
      Key192                  : LSC.Internal.AES.AES192_Key_Type;
      Context1                : OpenSSL.AES_Enc_Context_Type;
      Context2                : LSC.Internal.AES.AES_Enc_Context;
   begin

      Plain := Message_Type'
         (others => LSC.Internal.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key192 := LSC.Internal.AES.AES192_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#07060504#,
                                          16#0b0a0908#,
                                          16#0b0a0908#,
                                          16#0f0e0d0c#);

      Context1 := OpenSSL.Create_AES192_Enc_Context (Key192);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Cipher1 (I) := OpenSSL.Encrypt (Context1, Plain (I));
         end loop;
      end loop;

      Context2 := LSC.Internal.AES.Create_AES192_Enc_Context (Key192);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Cipher2 (I) := LSC.Internal.AES.Encrypt (Context2, Plain (I));
         end loop;
      end loop;

      Assert (Cipher1 = Cipher2, "Ciphertext differs");

   end Test_AES192_Encrypt;

   ---------------------------------------------------------------------------

   procedure Test_AES256_Decrypt (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      type Message_Type is array (Message_Index) of LSC.Internal.AES.Block_Type;

      Plain1, Plain2, Cipher  : Message_Type;
      Key256                  : LSC.Internal.AES.AES256_Key_Type;
      Context1                : OpenSSL.AES_Dec_Context_Type;
      Context2                : LSC.Internal.AES.AES_Dec_Context;
   begin

      Cipher := Message_Type'
         (others => LSC.Internal.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key256 := LSC.Internal.AES.AES256_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#0b0a0908#,
                                          16#0f0e0d0c#,
                                          16#13121110#,
                                          16#17161514#,
                                          16#1b1a1918#,
                                          16#1f1e1d1c#);

      Context1 := OpenSSL.Create_AES256_Dec_Context (Key256);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Plain1 (I) := OpenSSL.Decrypt (Context1, Cipher (I));
         end loop;
      end loop;

      Context2 := LSC.Internal.AES.Create_AES256_Dec_Context (Key256);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Plain2 (I) := LSC.Internal.AES.Decrypt (Context2, Cipher (I));
         end loop;
      end loop;

      Assert (Plain1 = Plain2, "Plaintext differs");

   end Test_AES256_Decrypt;

   ---------------------------------------------------------------------------

   procedure Test_AES256_Encrypt (T : in out Test_Cases.Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      type Message_Type is array (Message_Index) of LSC.Internal.AES.Block_Type;

      Plain, Cipher1, Cipher2 : Message_Type;
      Key256                  : LSC.Internal.AES.AES256_Key_Type;
      Context1                : OpenSSL.AES_Enc_Context_Type;
      Context2                : LSC.Internal.AES.AES_Enc_Context;
   begin

      Plain := Message_Type'
         (others => LSC.Internal.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key256 := LSC.Internal.AES.AES256_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#0b0a0908#,
                                          16#0f0e0d0c#,
                                          16#13121110#,
                                          16#17161514#,
                                          16#1b1a1918#,
                                          16#1f1e1d1c#);

      Context1 := OpenSSL.Create_AES256_Enc_Context (Key256);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Cipher1 (I) := OpenSSL.Encrypt (Context1, Plain (I));
         end loop;
      end loop;

      Context2 := LSC.Internal.AES.Create_AES256_Enc_Context (Key256);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Cipher2 (I) := LSC.Internal.AES.Encrypt (Context2, Plain (I));
         end loop;
      end loop;

      Assert (Cipher1 = Cipher2, "Plaintext differs");

   end Test_AES256_Encrypt;

   ---------------------------------------------------------------------------

   procedure Register_Tests (T: in out Test_Case) is
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
