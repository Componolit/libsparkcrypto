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
procedure Test_AES192_Encrypt
is
   type Message_Type is array (1 .. 100000) of LSC.AES.Block_Type;

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

   Context1 := OpenSSL.Create_AES192_Enc_Context (Key192);
   S1 := Clock;
   for k in 1 .. 20
   loop
      for I in Message_Type'Range
      loop
         Cipher1 (I) := OpenSSL.Encrypt (Context1, Plain (I));
      end loop;
   end loop;
   D1 := Clock - S1;

   Context2 := LSC.AES.Create_AES192_Enc_Context (Key192);
   S2 := Clock;
   for k in 1 .. 20
   loop
      for I in Message_Type'Range
      loop
         Cipher2 (I) := LSC.AES.Encrypt (Context2, Plain (I));
      end loop;
   end loop;
   D2 := Clock - S2;

   Result ("AES-192_ENC", Cipher1 = Cipher2, D1, D2);
end;
