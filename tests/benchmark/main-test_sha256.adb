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
procedure Test_SHA256
is
   Block1, Block2  : LSC.SHA256.Block_Type;
   SHA256_Context1 : OpenSSL.SHA256_Context_Type;
   SHA256_Context2 : LSC.SHA256.Context_Type;
   H1, H2          : LSC.SHA256.SHA256_Hash_Type;
begin
   Block1  := LSC.SHA256.Block_Type'(others => 16#cafebabe#);
   Block2  := LSC.SHA256.Block_Type'(others => 16#00636261#);

   S1 := Clock;
   for I in 1 .. 500000
   loop
      OpenSSL.SHA256_Context_Init (SHA256_Context1);
      OpenSSL.SHA256_Context_Update (SHA256_Context1, Block1);
      OpenSSL.SHA256_Context_Finalize (SHA256_Context1, Block2, 56);
   end loop;
   H1 := OpenSSL.SHA256_Get_Hash (SHA256_Context1);
   D1 := Clock - S1;

   S2 := Clock;
   for I in 1 .. 500000
   loop
      SHA256_Context2 := LSC.SHA256.SHA256_Context_Init;
      LSC.SHA256.Context_Update (SHA256_Context2, Block1);
      LSC.SHA256.Context_Finalize (SHA256_Context2, Block2, 56);
   end loop;
   H2 := LSC.SHA256.SHA256_Get_Hash (SHA256_Context2);
   D2 := Clock - S2;

   Result ("     SHA256", H1 = H2, D1, D2);
end Test_SHA256;
