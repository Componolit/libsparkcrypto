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
procedure Test_AES256_Decrypt
is
   type Message_Type is array (1 .. 100000) of LSC.AES.Block_Type;

   Plain1, Plain2, Cipher  : Message_Type;
   Key256                  : LSC.AES.AES256_Key_Type;
   Context1                : OpenSSL.AES_Dec_Context_Type;
   Context2                : LSC.AES.AES_Dec_Context;
   M                       : SPARKUnit.Measurement_Type;
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

   Context1 := OpenSSL.Create_AES256_Dec_Context (Key256);
   SPARKUnit.Reference_Start (M);
   for k in 1 .. 20
   loop
      for I in Message_Type'Range
      loop
         Plain1 (I) := OpenSSL.Decrypt (Context1, Cipher (I));
      end loop;
   end loop;
   SPARKUnit.Reference_Stop (M);

   Context2 := LSC.AES.Create_AES256_Dec_Context (Key256);
   SPARKUnit.Measurement_Start (M);
   for k in 1 .. 20
   loop
      for I in Message_Type'Range
      loop
         Plain2 (I) := LSC.AES.Decrypt (Context2, Cipher (I));
      end loop;
   end loop;
   SPARKUnit.Measurement_Stop (M);

   SPARKUnit.Create_Benchmark (Harness, Benchmarks, "AES-256_DEC", M, Plain1 = Plain2);
end;
