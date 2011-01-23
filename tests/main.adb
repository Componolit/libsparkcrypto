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

with LSC.AES;
with LSC.IO;
with LSC.Byteorder32;
with LSC.Byteorder64;
with LSC.Byteswap32;
with LSC.Byteswap64;
with LSC.Types;
with LSC.AES.CBC;
with LSC.SHA1;
with LSC.SHA256;
with LSC.SHA512;
with LSC.RIPEMD160;
with LSC.HMAC_SHA256;
with LSC.HMAC_SHA512;
with LSC.HMAC_SHA384;
with LSC.HMAC_RIPEMD160;
with SPARKUnit;
with OpenSSL;

use type LSC.AES.Block_Type;
use type LSC.AES.Message_Type;
use type LSC.SHA512.SHA512_Hash_Type;
use type LSC.Types.Word32;
use type LSC.Types.Word64;

--# inherit
--#    LSC.IO,
--#    LSC.AES,
--#    LSC.SHA1,
--#    LSC.SHA256,
--#    LSC.SHA512,
--#    LSC.Byteorder32,
--#    LSC.Byteorder64,
--#    LSC.Types,
--#    LSC.AES.CBC,
--#    LSC.RIPEMD160,
--#    LSC.HMAC_SHA256,
--#    LSC.HMAC_SHA512,
--#    LSC.HMAC_SHA384,
--#    LSC.HMAC_RIPEMD160,
--#    SPARKUnit,
--#    SPARK_IO;

--# main_program;
procedure Main
--# global in out SPARK_IO.Outputs;
--# derives SPARK_IO.Outputs from *;
is
   subtype Harness_Index is Natural range 1 .. 1000;
   subtype Harness_Type is SPARKUnit.Harness_Type (Harness_Index);

   Harness     : Harness_Type;
   Benchmarks  : SPARKUnit.Index_Type;

   function N (Item : LSC.Types.Word64) return LSC.Types.Word64
   is
   begin
      return LSC.Byteorder64.BE_To_Native (Item);
   end N;

   function M (Item : LSC.Types.Word32) return LSC.Types.Word32
   is
   begin
      return LSC.Byteorder32.BE_To_Native (Item);
   end M;

   procedure AES_Tests
   --# global Harness;
   --# derives Harness from Harness;
   is separate;

   procedure AES_CBC_Tests
   --# global Harness;
   --# derives Harness from Harness;
   is separate;

   procedure SHA1_Tests
   --# global Harness;
   --# derives Harness from Harness;
   is separate;

   procedure SHA256_Tests
   --# global Harness;
   --# derives Harness from Harness;
   is separate;

   procedure SHA384_Tests
   --# global Harness;
   --# derives Harness from Harness;
   is separate;

   procedure SHA512_Tests
   --# global Harness;
   --# derives Harness from Harness;
   is separate;

   procedure HMAC_SHA256_Tests
   --# global Harness;
   --# derives Harness from Harness;
   is separate;

   procedure HMAC_SHA384_Tests
   --# global Harness;
   --# derives Harness from Harness;
   is separate;

   procedure HMAC_SHA512_Tests
   --# global Harness;
   --# derives Harness from Harness;
   is separate;

   procedure HMAC_RIPEMD160_Tests
   --# global Harness;
   --# derives Harness from Harness;
   is separate;

   procedure RIPEMD160_Tests
   --# global Harness;
   --# derives Harness from Harness;
   is separate;

   procedure Shadow_Tests
   --# global Harness;
   --# derives Harness from Harness;
   is separate;

   procedure Test_AES128_Decrypt
   --# global Harness, Benchmarks;
   --# derives Harness from Harness, Benchmarks;
   is separate;

   procedure Test_AES128_Encrypt
   --# global Harness, Benchmarks;
   --# derives Harness from Harness, Benchmarks;
   is separate;

   procedure Test_AES192_Encrypt
   --# global Harness, Benchmarks;
   --# derives Harness from Harness, Benchmarks;
   is separate;

   procedure Test_AES256_Encrypt
   --# global Harness, Benchmarks;
   --# derives Harness from Harness, Benchmarks;
   is separate;

   procedure Test_AES192_Decrypt
   --# global Harness, Benchmarks;
   --# derives Harness from Harness, Benchmarks;
   is separate;

   procedure Test_AES256_Decrypt
   --# global Harness, Benchmarks;
   --# derives Harness from Harness, Benchmarks;
   is separate;

   procedure Test_SHA256
   --# global Harness, Benchmarks;
   --# derives Harness from Harness, Benchmarks;
   is separate;

   procedure Test_SHA384
   --# global Harness, Benchmarks;
   --# derives Harness from Harness, Benchmarks;
   is separate;

   procedure Test_SHA512
   --# global Harness, Benchmarks;
   --# derives Harness from Harness, Benchmarks;
   is separate;

   procedure Test_RIPEMD160
   --# global Harness, Benchmarks;
   --# derives Harness from Harness, Benchmarks;
   is separate;

   procedure Test_HMAC_SHA256
   --# global Harness, Benchmarks;
   --# derives Harness from Harness, Benchmarks;
   is separate;

   procedure Test_HMAC_SHA384
   --# global Harness, Benchmarks;
   --# derives Harness from Harness, Benchmarks;
   is separate;

   procedure Test_HMAC_SHA512
   --# global Harness, Benchmarks;
   --# derives Harness from Harness, Benchmarks;
   is separate;

   procedure Test_HMAC_RMD160
   --# global Harness, Benchmarks;
   --# derives Harness from Harness, Benchmarks;
   is separate;

begin

   SPARKUnit.Create_Harness (Harness, "libsparkcrypto tests");
   SPARKUnit.Create_Suite (Harness, "Benchmarks", Benchmarks);

   AES_Tests;
   AES_CBC_Tests;
   SHA1_Tests;
   SHA256_Tests;
   SHA384_Tests;
   SHA512_Tests;
   HMAC_SHA256_Tests;
   HMAC_SHA384_Tests;
   HMAC_SHA512_Tests;
   HMAC_RIPEMD160_Tests;
   RIPEMD160_Tests;
   Shadow_Tests;
   Test_AES128_Decrypt;
   Test_AES128_Encrypt;
   Test_AES192_Encrypt;
   Test_AES256_Encrypt;
   Test_AES192_Decrypt;
   Test_AES256_Decrypt;
   Test_SHA256;
   Test_SHA384;
   Test_SHA512;
   Test_RIPEMD160;
   Test_HMAC_SHA256;
   Test_HMAC_SHA384;
   Test_HMAC_SHA512;
   Test_HMAC_RMD160;

   SPARKUnit.Text_Report (Harness);

end Main;
