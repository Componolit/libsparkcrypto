-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2011, Adrian-Ken Rueegsegger
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
procedure Test_HMAC_SHA1
is
   Message : constant OpenSSL.SHA1_Message_Type := OpenSSL.SHA1_Message_Type'
     (others => LSC.SHA1.Block_Type'(others => 16#dead_beef#));

   Key     : constant LSC.SHA1.Block_Type := LSC.SHA1.Block_Type'(others => 16#c0deaffe#);

   H1      : LSC.SHA1.Hash_Type;
   H2      : LSC.SHA1.Hash_Type;
   Measurement : SPARKUnit.Measurement_Type;
begin

   SPARKUnit.Reference_Start (Measurement);
   for I in Natural range 1 .. 50000
     --# assert True;
   loop
      H1 := OpenSSL.Authenticate_SHA1 (Key, Message, 10000);
   end loop;
   SPARKUnit.Reference_Stop (Measurement);

   SPARKUnit.Measurement_Start (Measurement);
   for I in Natural range 1 .. 50000
     --# assert True;
   loop
      H2 := LSC.HMAC_SHA1.Authenticate (Key, Message, 10000);
   end loop;
   SPARKUnit.Measurement_Stop (Measurement);

   SPARKUnit.Create_Benchmark (Harness, Benchmarks, "HMAC_SHA1", Measurement, H1 = H2);
end Test_HMAC_SHA1;
