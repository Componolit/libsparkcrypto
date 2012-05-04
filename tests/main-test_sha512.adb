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
procedure Test_SHA512
is
   Block1, Block2  : LSC.SHA512.Block_Type;
   SHA512_Context1 : OpenSSL.SHA512_Context_Type;
   SHA512_Context2 : LSC.SHA512.Context_Type;
   H1, H2          : LSC.SHA512.SHA512_Hash_Type;
   Measurement     : SPARKUnit.Measurement_Type;
begin
   Block1  := LSC.SHA512.Block_Type'(others => 16#deadbeefcafebabe#);
   Block2  := LSC.SHA512.Block_Type'(others => 16#0000000000636261#);

   SPARKUnit.Reference_Start (Measurement);
   for I in Natural range 1 .. 500000
     --# assert True;
   loop
      OpenSSL.SHA512_Context_Init (SHA512_Context1);
      OpenSSL.SHA512_Context_Update (SHA512_Context1, Block1);
      OpenSSL.SHA512_Context_Finalize (SHA512_Context1, Block2, 56);
   end loop;
   H1 := OpenSSL.SHA512_Get_Hash (SHA512_Context1);
   SPARKUnit.Reference_Stop (Measurement);

   SPARKUnit.Measurement_Start (Measurement);
   for I in Natural range 1 .. 500000
     --# assert True;
   loop
      SHA512_Context2 := LSC.SHA512.SHA512_Context_Init;
      LSC.SHA512.Context_Update (SHA512_Context2, Block1);
      LSC.SHA512.Context_Finalize (SHA512_Context2, Block2, 56);
   end loop;
   H2 := LSC.SHA512.SHA512_Get_Hash (SHA512_Context2);
   SPARKUnit.Measurement_Stop (Measurement);

   SPARKUnit.Create_Benchmark (Harness, Benchmarks, "SHA512", Measurement, H1 = H2);
end Test_SHA512;
