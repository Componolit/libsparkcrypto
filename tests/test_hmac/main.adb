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

with LSC.SHA256,
     LSC.SHA512,
     LSC.RIPEMD160,
     LSC.HMAC_SHA256,
     LSC.HMAC_SHA512,
     LSC.HMAC_SHA384,
     LSC.HMAC_RIPEMD160,
     LSC.IO,
     LSC.Types,
     LSC.Byteorder32,
     LSC.Byteorder64,
     LSC.Debug,
     LSC.Test;

use type LSC.Types.Word32_Array_Type;
use type LSC.Types.Word64_Array_Type;
use type LSC.Types.Word64;

--# inherit LSC.IO,
--#         LSC.SHA256,
--#         LSC.SHA512,
--#         LSC.RIPEMD160,
--#         LSC.HMAC_SHA256,
--#         LSC.HMAC_SHA512,
--#         LSC.HMAC_SHA384,
--#         LSC.HMAC_RIPEMD160,
--#         LSC.Types,
--#         LSC.Byteorder32,
--#         LSC.Byteorder64,
--#         LSC.Debug,
--#         LSC.Test;

--# main_program;
procedure Main
   --# derives ;
is
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

   procedure HMAC_SHA256_Tests
   --# derives ;
   is separate;

   procedure HMAC_SHA384_Tests
   --# derives ;
   is separate;

   procedure HMAC_SHA512_Tests
   --# derives ;
   is separate;

   procedure HMAC_RIPEMD160_Tests
   --# derives ;
   is separate;

begin

   HMAC_SHA256_Tests;
   HMAC_SHA384_Tests;
   HMAC_SHA512_Tests;
   HMAC_RIPEMD160_Tests;

end Main;
