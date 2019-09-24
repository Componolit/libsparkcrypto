-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- @author Alexander Senier
-- @date   2019-01-16
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

with LSC.AES_Generic;
with LSC.Types;

pragma Elaborate_All (LSC.AES_Generic);

package LSC.AES
is
   pragma Pure;

   subtype Dec_Key_Type is LSC.AES_Generic.Dec_Key_Type;
   subtype Enc_Key_Type is LSC.AES_Generic.Enc_Key_Type;

   L128 : constant LSC.AES_Generic.Keylen_Type := LSC.AES_Generic.L128;
   L192 : constant LSC.AES_Generic.Keylen_Type := LSC.AES_Generic.L192;
   L256 : constant LSC.AES_Generic.Keylen_Type := LSC.AES_Generic.L256;

   function Dec_Key is
      new AES_Generic.Dec_Key (Types.Natural_Index, Types.Byte, Types.Bytes);

   function Enc_Key is
      new AES_Generic.Enc_Key (Types.Natural_Index, Types.Byte, Types.Bytes);

   function Encrypt is
      new AES_Generic.Encrypt (Types.Natural_Index, Types.Byte, Types.Bytes,
                               Types.Natural_Index, Types.Byte, Types.Bytes);

   function Decrypt is
      new AES_Generic.Decrypt (Types.Natural_Index, Types.Byte, Types.Bytes,
                               Types.Natural_Index, Types.Byte, Types.Bytes);

end LSC.AES;
