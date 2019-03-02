-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- @author Alexander Senier
-- @date   2019-01-21
--
-- Copyright (C) 2018 Componolit GmbH
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

with LSC.SHA2;
with LSC.SHA2.HMAC_Generic;
with LSC.Types;

package LSC.SHA2.HMAC
is
   function HMAC_SHA256 is new SHA2.HMAC_Generic.HMAC_SHA256
      (Types.Natural_Index, Types.Byte, Types.Bytes,
       Types.Natural_Index, Types.Byte, Types.Bytes,
       SHA2.SHA256_Hash_Index, Types.Byte, SHA2.SHA256_Hash_Type);

   function HMAC_SHA384 is new SHA2.HMAC_Generic.HMAC_SHA384
      (Types.Natural_Index, Types.Byte, Types.Bytes,
       Types.Natural_Index, Types.Byte, Types.Bytes,
       SHA2.SHA384_Hash_Index, Types.Byte, SHA2.SHA384_Hash_Type);

   function HMAC_SHA512 is new SHA2.HMAC_Generic.HMAC_SHA512
      (Types.Natural_Index, Types.Byte, Types.Bytes,
       Types.Natural_Index, Types.Byte, Types.Bytes,
       SHA2.SHA512_Hash_Index, Types.Byte, SHA2.SHA512_Hash_Type);

end LSC.SHA2.HMAC;
