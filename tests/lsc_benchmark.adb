-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2018, Componolit GmbH
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

with LSC.Types;
with LSC.RIPEMD160;
with LSC.SHA1;
with LSC.SHA256;
with LSC.SHA512;
with LSC.AES.CBC;
with OpenSSL;
with AUnit.Assertions; use AUnit.Assertions;
with AUnit.Test_Results; use AUnit.Test_Results;
with Interfaces;

use type LSC.Types.Word32_Array_Type;
use type LSC.Types.Word64_Array_Type;
use type LSC.AES.Message_Type;
use type Interfaces.Unsigned_32;

package body LSC_Benchmark
is
   use Ada.Calendar;

   function Routine_Name (T : Test_Case) return Message_String
   is
      use Ada.Calendar;
      Ref_Time  : constant Duration := T.Reference_Stop - T.Reference_Start;
      Test_Time : constant Duration := T.Test_Stop - T.Test_Start;
      Percent   : constant Natural := Natural (Duration'(Test_Time / Ref_Time) * 100.0);
   begin
      return Format (AUnit.Test_Cases.Test_Case (T).Routine_Name.all & " ... [" & Percent'Img & "% ]");
   end Routine_Name;

   ---------------------------------------------------------------------------

   procedure Benchmark_RIPEMD160 (T : in out Test_Case'Class)
   is
      Block1, Block2       : LSC.RIPEMD160.Block_Type;
      RIPEMD160_Context1   : OpenSSL.RIPEMD160_Context_Type;
      RIPEMD160_Context2   : LSC.RIPEMD160.Context_Type;
      H1, H2               : LSC.RIPEMD160.Hash_Type;
   begin

      Block1  := LSC.RIPEMD160.Block_Type'(others => 16#cafebabe#);
      Block2  := LSC.RIPEMD160.Block_Type'(others => 16#00636261#);

      T.Reference_Start := Clock;
      for I in Natural range 1 .. 200000
      loop
         OpenSSL.RIPEMD160_Context_Init (RIPEMD160_Context1);
         OpenSSL.RIPEMD160_Context_Update (RIPEMD160_Context1, Block1);
         OpenSSL.RIPEMD160_Context_Finalize (RIPEMD160_Context1, Block2, 56);
      end loop;
      H1 := OpenSSL.RIPEMD160_Get_Hash (RIPEMD160_Context1);
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      for I in Natural range 1 .. 200000
      loop
         RIPEMD160_Context2 := LSC.RIPEMD160.Context_Init;
         LSC.RIPEMD160.Context_Update (RIPEMD160_Context2, Block1);
         LSC.RIPEMD160.Context_Finalize (RIPEMD160_Context2, Block2, 56);
      end loop;
      H2 := LSC.RIPEMD160.Get_Hash (RIPEMD160_Context2);
      T.Test_Stop := Clock;

      Assert (H1 = H2, "Invalid hash");

   end Benchmark_RIPEMD160;

   ---------------------------------------------------------------------------

   procedure Benchmark_SHA1 (T : in out Test_Case'Class)
   is
      Block1, Block2 : LSC.SHA1.Block_Type;
      SHA1_Context1  : OpenSSL.SHA1_Context_Type;
      SHA1_Context2  : LSC.SHA1.Context_Type;
      H1, H2         : LSC.SHA1.Hash_Type;
   begin
      Block1 := LSC.SHA1.Block_Type'(others => 16#cafebabe#);
      Block2 := LSC.SHA1.Block_Type'(others => 16#00636261#);

      T.Reference_Start := Clock;
      for I in Natural range 1 .. 500000
      loop
         OpenSSL.SHA1_Context_Init (SHA1_Context1);
         OpenSSL.SHA1_Context_Update (SHA1_Context1, Block1);
         OpenSSL.SHA1_Context_Finalize (SHA1_Context1, Block2, 56);
      end loop;
      H1 := OpenSSL.SHA1_Get_Hash (SHA1_Context1);
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      for I in Natural range 1 .. 500000
      loop
         SHA1_Context2 := LSC.SHA1.Context_Init;
         LSC.SHA1.Context_Update (SHA1_Context2, Block1);
         LSC.SHA1.Context_Finalize (SHA1_Context2, Block2, 56);
      end loop;
      H2 := LSC.SHA1.Get_Hash (SHA1_Context2);
      T.Test_Stop := Clock;

      Assert (H1 = H2, "Invalid hash");

   end Benchmark_SHA1;

   ---------------------------------------------------------------------------

   procedure Benchmark_SHA256 (T : in out Test_Case'Class)
   is
      Block1, Block2  : LSC.SHA256.Block_Type;
      SHA256_Context1 : OpenSSL.SHA256_Context_Type;
      SHA256_Context2 : LSC.SHA256.Context_Type;
      H1, H2          : LSC.SHA256.SHA256_Hash_Type;
   begin
      Block1  := LSC.SHA256.Block_Type'(others => 16#cafebabe#);
      Block2  := LSC.SHA256.Block_Type'(others => 16#00636261#);

      T.Reference_Start := Clock;
      for I in Natural range 1 .. 500000
      loop
         OpenSSL.SHA256_Context_Init (SHA256_Context1);
         OpenSSL.SHA256_Context_Update (SHA256_Context1, Block1);
         OpenSSL.SHA256_Context_Finalize (SHA256_Context1, Block2, 56);
      end loop;
      H1 := OpenSSL.SHA256_Get_Hash (SHA256_Context1);
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      for I in Natural range 1 .. 500000
      loop
         SHA256_Context2 := LSC.SHA256.SHA256_Context_Init;
         LSC.SHA256.Context_Update (SHA256_Context2, Block1);
         LSC.SHA256.Context_Finalize (SHA256_Context2, Block2, 56);
      end loop;
      H2 := LSC.SHA256.SHA256_Get_Hash (SHA256_Context2);
      T.Test_Stop := Clock;

      Assert (H1 = H2, "Invalid hash");

   end Benchmark_SHA256;

   ---------------------------------------------------------------------------

   procedure Benchmark_SHA384 (T : in out Test_Case'Class)
   is
      Block1, Block2  : LSC.SHA512.Block_Type;
      SHA384_Context1 : OpenSSL.SHA384_Context_Type;
      SHA384_Context2 : LSC.SHA512.Context_Type;
      H1, H2          : LSC.SHA512.SHA384_Hash_Type;
   begin
      Block1  := LSC.SHA512.Block_Type'(others => 16#deadbeefcafebabe#);
      Block2  := LSC.SHA512.Block_Type'(others => 16#0000000000636261#);

      T.Reference_Start := Clock;
      for I in Natural range 1 .. 500000
      loop
         OpenSSL.SHA384_Context_Init (SHA384_Context1);
         OpenSSL.SHA384_Context_Update (SHA384_Context1, Block1);
         OpenSSL.SHA384_Context_Finalize (SHA384_Context1, Block2, 56);
      end loop;
      H1 := OpenSSL.SHA384_Get_Hash (SHA384_Context1);
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      for I in Natural range 1 .. 500000
      loop
         SHA384_Context2 := LSC.SHA512.SHA384_Context_Init;
         LSC.SHA512.Context_Update (SHA384_Context2, Block1);
         LSC.SHA512.Context_Finalize (SHA384_Context2, Block2, 56);
      end loop;
      H2 := LSC.SHA512.SHA384_Get_Hash (SHA384_Context2);
      T.Test_Stop := Clock;

      Assert (H1 = H2, "Invalid hash");

   end Benchmark_SHA384;

   ---------------------------------------------------------------------------

   procedure Benchmark_SHA512 (T : in out Test_Case'Class)
   is
      Block1, Block2  : LSC.SHA512.Block_Type;
      SHA512_Context1 : OpenSSL.SHA512_Context_Type;
      SHA512_Context2 : LSC.SHA512.Context_Type;
      H1, H2          : LSC.SHA512.SHA512_Hash_Type;
   begin
      Block1  := LSC.SHA512.Block_Type'(others => 16#deadbeefcafebabe#);
      Block2  := LSC.SHA512.Block_Type'(others => 16#0000000000636261#);

      T.Reference_Start := Clock;
      for I in Natural range 1 .. 500000
      loop
         OpenSSL.SHA512_Context_Init (SHA512_Context1);
         OpenSSL.SHA512_Context_Update (SHA512_Context1, Block1);
         OpenSSL.SHA512_Context_Finalize (SHA512_Context1, Block2, 56);
      end loop;
      H1 := OpenSSL.SHA512_Get_Hash (SHA512_Context1);
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      for I in Natural range 1 .. 500000
      loop
         SHA512_Context2 := LSC.SHA512.SHA512_Context_Init;
         LSC.SHA512.Context_Update (SHA512_Context2, Block1);
         LSC.SHA512.Context_Finalize (SHA512_Context2, Block2, 56);
      end loop;
      H2 := LSC.SHA512.SHA512_Get_Hash (SHA512_Context2);
      T.Test_Stop := Clock;

      Assert (H1 = H2, "Invalid hash");
   end Benchmark_SHA512;

   ---------------------------------------------------------------------------

   procedure Benchmark_AES128_Decrypt (T : in out Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      subtype Message_Type is LSC.AES.Message_Type (Message_Index);

      Plain1, Plain2, Cipher  : Message_Type;
      Key128                  : LSC.AES.AES128_Key_Type;
      Context1                : OpenSSL.AES_Dec_Context_Type;
      Context2                : LSC.AES.AES_Dec_Context;
   begin

      Cipher := Message_Type'
         (others => LSC.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key128 := LSC.AES.AES128_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#0b0a0908#,
                                          16#1f1e1d1c#);

      T.Reference_Start := Clock;
      Context1 := OpenSSL.Create_AES128_Dec_Context (Key128);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Plain1 (I) := OpenSSL.Decrypt (Context1, Cipher (I));
         end loop;
      end loop;
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      Context2 := LSC.AES.Create_AES128_Dec_Context (Key128);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Plain2 (I) := LSC.AES.Decrypt (Context2, Cipher (I));
         end loop;
      end loop;
      T.Test_Stop := Clock;

      Assert (Plain1 = Plain2, "Invalid decryption");

   end Benchmark_AES128_Decrypt;

   ---------------------------------------------------------------------------

   procedure Benchmark_AES128_CBC_Decrypt (T : in out Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      subtype Message_Type is LSC.AES.Message_Type (Message_Index);

      Plain1, Plain2, Cipher  : Message_Type;
      Key128                  : LSC.AES.AES128_Key_Type;
      Context1                : OpenSSL.AES_Dec_Context_Type;
      Context2                : LSC.AES.AES_Dec_Context;
      IV                      : LSC.AES.Block_Type;
   begin

      IV := LSC.AES.Block_Type'
        (16#cafebabe#,
         16#deadbeef#,
         16#d00faffe#,
         16#12345678#);

      Cipher := Message_Type'
         (others => LSC.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key128 := LSC.AES.AES128_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#0b0a0908#,
                                          16#1f1e1d1c#);

      T.Reference_Start := Clock;
      Context1 := OpenSSL.Create_AES128_Dec_Context (Key128);
      for k in Natural range 1 .. 20
      loop
         OpenSSL.CBC_Decrypt (Cipher, Plain1, Context1, IV);
      end loop;
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      Context2 := LSC.AES.Create_AES128_Dec_Context (Key128);
      for k in Natural range 1 .. 20
      loop
         LSC.AES.CBC.Decrypt (Context2, IV, Cipher, Cipher'Length, Plain2);
      end loop;
      T.Test_Stop := Clock;

      Assert (Plain1 = Plain2, "Invalid decryption");

   end Benchmark_AES128_CBC_Decrypt;

   ---------------------------------------------------------------------------

   procedure Benchmark_AES128_Encrypt (T : in out Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      subtype Message_Type is LSC.AES.Message_Type (Message_Index);

      Plain, Cipher1, Cipher2 : Message_Type;
      Key128                  : LSC.AES.AES128_Key_Type;
      Context1                : OpenSSL.AES_Enc_Context_Type;
      Context2                : LSC.AES.AES_Enc_Context;
   begin

      Plain := Message_Type'
         (others => LSC.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key128 := LSC.AES.AES128_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#0b0a0908#,
                                          16#0f0e0d0c#);

      T.Reference_Start := Clock;
      Context1 := OpenSSL.Create_AES128_Enc_Context (Key128);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Cipher1 (I) := OpenSSL.Encrypt (Context1, Plain (I));
         end loop;
      end loop;
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      Context2 := LSC.AES.Create_AES128_Enc_Context (Key128);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Cipher2 (I) := LSC.AES.Encrypt (Context2, Plain (I));
         end loop;
      end loop;
      T.Test_Stop := Clock;

      Assert (Cipher1 = Cipher2, "Invalid encryption");

   end Benchmark_AES128_Encrypt;

   ---------------------------------------------------------------------------

   procedure Benchmark_AES128_CBC_Encrypt (T : in out Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      subtype Message_Type is LSC.AES.Message_Type (Message_Index);

      Plain, Cipher1, Cipher2 : Message_Type;
      Key128                  : LSC.AES.AES128_Key_Type;
      Context1                : OpenSSL.AES_Enc_Context_Type;
      Context2                : LSC.AES.AES_Enc_Context;
      IV                      : LSC.AES.Block_Type;
   begin

      IV := LSC.AES.Block_Type'
        (16#cafebabe#,
         16#deadbeef#,
         16#d00faffe#,
         16#12345678#);

      Plain := Message_Type'
         (others => LSC.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key128 := LSC.AES.AES128_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#0b0a0908#,
                                          16#0f0e0d0c#);

      T.Reference_Start := Clock;
      Context1 := OpenSSL.Create_AES128_Enc_Context (Key128);
      for k in Natural range 1 .. 20
      loop
         OpenSSL.CBC_Encrypt (Plain, Cipher1, Context1, IV);
      end loop;
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      Context2 := LSC.AES.Create_AES128_Enc_Context (Key128);
      for k in Natural range 1 .. 20
      loop
         LSC.AES.CBC.Encrypt (Context2, IV, Plain, Plain'Length, Cipher2);
      end loop;
      T.Test_Stop := Clock;

      Assert (Cipher1 = Cipher2, "Invalid decryption");

   end Benchmark_AES128_CBC_Encrypt;

   ---------------------------------------------------------------------------

   procedure Benchmark_AES192_Decrypt (T : in out Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      subtype Message_Type is LSC.AES.Message_Type (Message_Index);

      Plain1, Plain2, Cipher  : Message_Type;
      Key192                  : LSC.AES.AES192_Key_Type;
      Context1                : OpenSSL.AES_Dec_Context_Type;
      Context2                : LSC.AES.AES_Dec_Context;
   begin

      Cipher := Message_Type'
         (others => LSC.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key192 := LSC.AES.AES192_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#13121110#,
                                          16#17161514#,
                                          16#1b1a1918#,
                                          16#1f1e1d1c#);

      T.Reference_Start := Clock;
      Context1 := OpenSSL.Create_AES192_Dec_Context (Key192);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Plain1 (I) := OpenSSL.Decrypt (Context1, Cipher (I));
         end loop;
      end loop;
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      Context2 := LSC.AES.Create_AES192_Dec_Context (Key192);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Plain2 (I) := LSC.AES.Decrypt (Context2, Cipher (I));
         end loop;
      end loop;
      T.Test_Stop := Clock;

      Assert (Plain1 = Plain2, "Invalid decryption");

   end Benchmark_AES192_Decrypt;

   ---------------------------------------------------------------------------

   procedure Benchmark_AES192_CBC_Decrypt (T : in out Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      subtype Message_Type is LSC.AES.Message_Type (Message_Index);

      Plain1, Plain2, Cipher  : Message_Type;
      Key192                  : LSC.AES.AES192_Key_Type;
      Context1                : OpenSSL.AES_Dec_Context_Type;
      Context2                : LSC.AES.AES_Dec_Context;
      IV                      : LSC.AES.Block_Type;
   begin

      IV := LSC.AES.Block_Type'
        (16#cafebabe#,
         16#deadbeef#,
         16#d00faffe#,
         16#12345678#);

      Cipher := Message_Type'
         (others => LSC.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key192 := LSC.AES.AES192_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#13121110#,
                                          16#17161514#,
                                          16#1b1a1918#,
                                          16#1f1e1d1c#);

      T.Reference_Start := Clock;
      Context1 := OpenSSL.Create_AES192_Dec_Context (Key192);
      for k in Natural range 1 .. 20
      loop
         OpenSSL.CBC_Decrypt (Cipher, Plain1, Context1, IV);
      end loop;
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      Context2 := LSC.AES.Create_AES192_Dec_Context (Key192);
      for k in Natural range 1 .. 20
      loop
         LSC.AES.CBC.Decrypt (Context2, IV, Cipher, Cipher'Length, Plain2);
      end loop;
      T.Test_Stop := Clock;

      Assert (Plain1 = Plain2, "Invalid decryption");

   end Benchmark_AES192_CBC_Decrypt;

   ---------------------------------------------------------------------------

   procedure Benchmark_AES192_Encrypt (T : in out Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      subtype Message_Type is LSC.AES.Message_Type (Message_Index);

      Plain, Cipher1, Cipher2 : Message_Type;
      Key192                  : LSC.AES.AES192_Key_Type;
      Context1                : OpenSSL.AES_Enc_Context_Type;
      Context2                : LSC.AES.AES_Enc_Context;
   begin

      Plain := Message_Type'
         (others => LSC.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key192 := LSC.AES.AES192_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#07060504#,
                                          16#0b0a0908#,
                                          16#0b0a0908#,
                                          16#0f0e0d0c#);

      T.Reference_Start := Clock;
      Context1 := OpenSSL.Create_AES192_Enc_Context (Key192);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Cipher1 (I) := OpenSSL.Encrypt (Context1, Plain (I));
         end loop;
      end loop;
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      Context2 := LSC.AES.Create_AES192_Enc_Context (Key192);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Cipher2 (I) := LSC.AES.Encrypt (Context2, Plain (I));
         end loop;
      end loop;
      T.Test_Stop := Clock;

      Assert (Cipher1 = Cipher2, "Invalid encryption");

   end Benchmark_AES192_Encrypt;

   ---------------------------------------------------------------------------

   procedure Benchmark_AES192_CBC_Encrypt (T : in out Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      subtype Message_Type is LSC.AES.Message_Type (Message_Index);

      Plain, Cipher1, Cipher2 : Message_Type;
      Key192                  : LSC.AES.AES192_Key_Type;
      Context1                : OpenSSL.AES_Enc_Context_Type;
      Context2                : LSC.AES.AES_Enc_Context;
      IV                      : LSC.AES.Block_Type;
   begin

      IV := LSC.AES.Block_Type'
        (16#cafebabe#,
         16#deadbeef#,
         16#d00faffe#,
         16#12345678#);

      Plain := Message_Type'
         (others => LSC.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key192 := LSC.AES.AES192_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#07060504#,
                                          16#0b0a0908#,
                                          16#0b0a0908#,
                                          16#0f0e0d0c#);

      T.Reference_Start := Clock;
      Context1 := OpenSSL.Create_AES192_Enc_Context (Key192);
      for k in Natural range 1 .. 20
      loop
         OpenSSL.CBC_Encrypt (Plain, Cipher1, Context1, IV);
      end loop;
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      Context2 := LSC.AES.Create_AES192_Enc_Context (Key192);
      for k in Natural range 1 .. 20
      loop
         LSC.AES.CBC.Encrypt (Context2, IV, Plain, Plain'Length, Cipher2);
      end loop;
      T.Test_Stop := Clock;

      Assert (Cipher1 = Cipher2, "Invalid encryption");

   end Benchmark_AES192_CBC_Encrypt;

   ---------------------------------------------------------------------------

   procedure Benchmark_AES256_Decrypt (T : in out Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      subtype Message_Type is LSC.AES.Message_Type (Message_Index);

      Plain1, Plain2, Cipher  : Message_Type;
      Key256                  : LSC.AES.AES256_Key_Type;
      Context1                : OpenSSL.AES_Dec_Context_Type;
      Context2                : LSC.AES.AES_Dec_Context;
   begin

      Cipher := Message_Type'
         (others => LSC.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key256 := LSC.AES.AES256_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#0b0a0908#,
                                          16#0f0e0d0c#,
                                          16#13121110#,
                                          16#17161514#,
                                          16#1b1a1918#,
                                          16#1f1e1d1c#);

      T.Reference_Start := Clock;
      Context1 := OpenSSL.Create_AES256_Dec_Context (Key256);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Plain1 (I) := OpenSSL.Decrypt (Context1, Cipher (I));
         end loop;
      end loop;
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      Context2 := LSC.AES.Create_AES256_Dec_Context (Key256);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Plain2 (I) := LSC.AES.Decrypt (Context2, Cipher (I));
         end loop;
      end loop;
      T.Test_Stop := Clock;

      Assert (Plain1 = Plain2, "Invalid decryption");

   end Benchmark_AES256_Decrypt;

   ---------------------------------------------------------------------------

   procedure Benchmark_AES256_CBC_Decrypt (T : in out Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      subtype Message_Type is LSC.AES.Message_Type (Message_Index);

      Plain1, Plain2, Cipher  : Message_Type;
      Key256                  : LSC.AES.AES256_Key_Type;
      Context1                : OpenSSL.AES_Dec_Context_Type;
      Context2                : LSC.AES.AES_Dec_Context;
      IV                      : LSC.AES.Block_Type;
   begin

      IV := LSC.AES.Block_Type'
        (16#cafebabe#,
         16#deadbeef#,
         16#d00faffe#,
         16#12345678#);

      Cipher := Message_Type'
         (others => LSC.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key256 := LSC.AES.AES256_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#0b0a0908#,
                                          16#0f0e0d0c#,
                                          16#13121110#,
                                          16#17161514#,
                                          16#1b1a1918#,
                                          16#1f1e1d1c#);

      T.Reference_Start := Clock;
      Context1 := OpenSSL.Create_AES256_Dec_Context (Key256);
      for k in Natural range 1 .. 20
      loop
         OpenSSL.CBC_Decrypt (Cipher, Plain1, Context1, IV);
      end loop;
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      Context2 := LSC.AES.Create_AES256_Dec_Context (Key256);
      for k in Natural range 1 .. 20
      loop
         LSC.AES.CBC.Decrypt (Context2, IV, Cipher, Cipher'Length, Plain2);
      end loop;
      T.Test_Stop := Clock;

      Assert (Plain1 = Plain2, "Invalid decryption");

   end Benchmark_AES256_CBC_Decrypt;

   ---------------------------------------------------------------------------

   procedure Benchmark_AES256_Encrypt (T : in out Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      subtype Message_Type is LSC.AES.Message_Type (Message_Index);

      Plain, Cipher1, Cipher2 : Message_Type;
      Key256                  : LSC.AES.AES256_Key_Type;
      Context1                : OpenSSL.AES_Enc_Context_Type;
      Context2                : LSC.AES.AES_Enc_Context;
   begin

      Plain := Message_Type'
         (others => LSC.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key256 := LSC.AES.AES256_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#0b0a0908#,
                                          16#0f0e0d0c#,
                                          16#13121110#,
                                          16#17161514#,
                                          16#1b1a1918#,
                                          16#1f1e1d1c#);

      T.Reference_Start := Clock;
      Context1 := OpenSSL.Create_AES256_Enc_Context (Key256);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Cipher1 (I) := OpenSSL.Encrypt (Context1, Plain (I));
         end loop;
      end loop;
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      Context2 := LSC.AES.Create_AES256_Enc_Context (Key256);
      for k in Natural range 1 .. 20
      loop
         for I in Message_Index
         loop
            Cipher2 (I) := LSC.AES.Encrypt (Context2, Plain (I));
         end loop;
      end loop;
      T.Test_Stop := Clock;

      Assert (Cipher1 = Cipher2, "Invalid encryption");

   end Benchmark_AES256_Encrypt;

   ---------------------------------------------------------------------------

   procedure Benchmark_AES256_CBC_Encrypt (T : in out Test_Case'Class)
   is
      subtype Message_Index is Natural range 1 .. 100000;
      subtype Message_Type is LSC.AES.Message_Type (Message_Index);

      Plain, Cipher1, Cipher2 : Message_Type;
      Key256                  : LSC.AES.AES256_Key_Type;
      Context1                : OpenSSL.AES_Enc_Context_Type;
      Context2                : LSC.AES.AES_Enc_Context;
      IV                      : LSC.AES.Block_Type;
   begin

      IV := LSC.AES.Block_Type'
        (16#cafebabe#,
         16#deadbeef#,
         16#d00faffe#,
         16#12345678#);

      Plain := Message_Type'
         (others => LSC.AES.Block_Type'(16#33221100#,
                                        16#77665544#,
                                        16#bbaa9988#,
                                        16#ffeeddcc#));

      Key256 := LSC.AES.AES256_Key_Type' (16#03020100#,
                                          16#07060504#,
                                          16#0b0a0908#,
                                          16#0f0e0d0c#,
                                          16#13121110#,
                                          16#17161514#,
                                          16#1b1a1918#,
                                          16#1f1e1d1c#);

      T.Reference_Start := Clock;
      Context1 := OpenSSL.Create_AES256_Enc_Context (Key256);
      for k in Natural range 1 .. 20
      loop
         OpenSSL.CBC_Encrypt (Plain, Cipher1, Context1, IV);
      end loop;
      T.Reference_Stop := Clock;

      T.Test_Start := Clock;
      Context2 := LSC.AES.Create_AES256_Enc_Context (Key256);
      for k in Natural range 1 .. 20
      loop
         LSC.AES.CBC.Encrypt (Context2, IV, Plain, Plain'Length, Cipher2);
      end loop;
      T.Test_Stop := Clock;

      Assert (Cipher1 = Cipher2, "Invalid encryption");

   end Benchmark_AES256_CBC_Encrypt;

   ---------------------------------------------------------------------------

   procedure Register_Tests (T: in out Test_Case) is
      package Registration is new
         AUnit.Test_Cases.Specific_Test_Case_Registration (Test_Case);
      use Registration;
   begin
      Register_Wrapper (T, Benchmark_RIPEMD160'Access, "RIPEMD160");
      Register_Wrapper (T, Benchmark_SHA1'Access, "SHA1");
      Register_Wrapper (T, Benchmark_SHA256'Access, "SHA256");
      Register_Wrapper (T, Benchmark_SHA384'Access, "SHA384");
      Register_Wrapper (T, Benchmark_SHA512'Access, "SHA512");
      Register_Wrapper (T, Benchmark_AES128_Decrypt'Access, "AES128 (decrypt)");
      Register_Wrapper (T, Benchmark_AES128_CBC_Decrypt'Access, "AES128 CBC (decrypt)");
      Register_Wrapper (T, Benchmark_AES128_Encrypt'Access, "AES128 (encrypt)");
      Register_Wrapper (T, Benchmark_AES128_CBC_Encrypt'Access, "AES128 CBC (encrypt)");
      Register_Wrapper (T, Benchmark_AES192_Decrypt'Access, "AES192 (decrypt)");
      Register_Wrapper (T, Benchmark_AES192_CBC_Decrypt'Access, "AES192 CBC (decrypt)");
      Register_Wrapper (T, Benchmark_AES192_Encrypt'Access, "AES192 (encrypt)");
      Register_Wrapper (T, Benchmark_AES192_CBC_Encrypt'Access, "AES192 CBC (encrypt)");
      Register_Wrapper (T, Benchmark_AES256_Decrypt'Access, "AES256 (decrypt)");
      Register_Wrapper (T, Benchmark_AES256_CBC_Decrypt'Access, "AES256 CBC (decrypt)");
      Register_Wrapper (T, Benchmark_AES256_Encrypt'Access, "AES256 (encrypt)");
      Register_Wrapper (T, Benchmark_AES256_CBC_Encrypt'Access, "AES256 CBC (encrypt)");
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("Benchmark");
   end Name;

end LSC_Benchmark;
