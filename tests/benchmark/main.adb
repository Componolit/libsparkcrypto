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

with LSC.SHA256;
with LSC.SHA512;
with LSC.RIPEMD160;
with LSC.Types;
with LSC.AES;
with LSC.Test;
with LSC.IO;
with LSC.HMAC_SHA256;
with LSC.HMAC_SHA384;
with LSC.HMAC_SHA512;
with LSC.HMAC_RIPEMD160;
with OpenSSL;

with Ada.Text_IO; use Ada.Text_IO;
with Ada.Real_Time; use Ada.Real_Time;

use type LSC.Types.Word32_Array_Type;
use type LSC.Types.Word64_Array_Type;

procedure Main
is
   S1, S2  : Time;
   D1, D2  : Time_Span;

   procedure Result
      (Message   : String;
       Result    : Boolean;
       Duration1 : Time_Span;
       Duration2 : Time_Span)
   is
      Percent : Integer;
   begin
      Put (Message & ": ");
      if Result
      then
         Percent := (Time_Span (100 * Duration1) / Duration2);
         Put_Line (Percent'Img & " %");
      else
         Put_Line ("FAILED");
      end if;
   end Result;

   procedure Test_AES128_Encrypt is separate;
   procedure Test_AES192_Encrypt is separate;
   procedure Test_AES256_Encrypt is separate;
   procedure Test_AES128_Decrypt is separate;
   procedure Test_AES192_Decrypt is separate;
   procedure Test_AES256_Decrypt is separate;
   procedure Test_SHA256 is separate;
   procedure Test_SHA384 is separate;
   procedure Test_SHA512 is separate;
   procedure Test_RIPEMD160 is separate;
   procedure Test_HMAC_SHA256 is separate;
   procedure Test_HMAC_SHA384 is separate;
   procedure Test_HMAC_SHA512 is separate;
   procedure Test_HMAC_RMD160 is separate;

begin

   New_Line;
   Put_Line ("libsparkcrypto benchmarks:");

   Test_AES128_Encrypt;
   Test_AES192_Encrypt;
   Test_AES256_Encrypt;
   Test_AES128_Decrypt;
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

end Main;
