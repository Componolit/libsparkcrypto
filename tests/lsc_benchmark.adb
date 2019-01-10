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
with OpenSSL;
with AUnit.Assertions; use AUnit.Assertions;
with AUnit.Test_Results; use AUnit.Test_Results;

use type LSC.Types.Word32_Array_Type;
use type LSC.Types.Word64_Array_Type;

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
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("Benchmark");
   end Name;

end LSC_Benchmark;
