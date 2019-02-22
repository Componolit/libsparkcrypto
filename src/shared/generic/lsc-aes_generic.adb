-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- @author Alexander Senier
-- @date   2019-02-21
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

with LSC.Internal.Convert;

package body LSC.AES_Generic
is
   function Dec_Key (K      : Key_Type;
                     Keylen : Keylen_Type) return Dec_Key_Type
   is
      package Convert is new LSC.Internal.Convert (Index_Type, Elem_Type, Key_Type);
      use Convert;
      use Internal.AES;
   begin
      return (Context => (case Keylen is
        when L128 => Create_AES128_Dec_Context (K128 (K (K'First .. Index_Type'Val (Index_Type'Pos (K'First) + 15)))),
        when L192 => Create_AES192_Dec_Context (K192 (K (K'First .. Index_Type'Val (Index_Type'Pos (K'First) + 23)))),
        when L256 => Create_AES256_Dec_Context (K256 (K (K'First .. Index_Type'Val (Index_Type'Pos (K'First) + 31))))));
   end Dec_Key;

   ----------------------------------------------------------------------------

   function Enc_Key (K      : Key_Type;
                     Keylen : Keylen_Type) return Enc_Key_Type
   is
      package Convert is new LSC.Internal.Convert (Index_Type, Elem_Type, Key_Type);
      use Convert;
      use Internal.AES;
   begin
      return (Context => (case Keylen is
        when L128 => Create_AES128_Enc_Context (K128 (K (K'First .. Index_Type'Val (Index_Type'Pos (K'First) + 15)))),
        when L192 => Create_AES192_Enc_Context (K192 (K (K'First .. Index_Type'Val (Index_Type'Pos (K'First) + 23)))),
        when L256 => Create_AES256_Enc_Context (K256 (K (K'First .. Index_Type'Val (Index_Type'Pos (K'First) + 31))))));
   end Enc_Key;

   ----------------------------------------------------------------------------

   function Decrypt (Ciphertext : Ciphertext_Type;
                     Key        : Dec_Key_Type) return Plaintext_Type
   is
      package CP is new LSC.Internal.Convert (Plaintext_Index_Type, Plaintext_Elem_Type, Plaintext_Type);
      package CI is new LSC.Internal.Convert (Ciphertext_Index_Type, Ciphertext_Elem_Type, Ciphertext_Type);
   begin
      return CP.To_Public (Internal.AES.Decrypt (Key.Context, CI.To_Internal (Ciphertext)));
   end Decrypt;

   ----------------------------------------------------------------------------

   function Encrypt (Plaintext : Plaintext_Type;
                     Key       : Enc_Key_Type) return Ciphertext_Type
   is
      package CP is new LSC.Internal.Convert (Ciphertext_Index_Type, Ciphertext_Elem_Type, Ciphertext_Type);
      package CI is new LSC.Internal.Convert (Plaintext_Index_Type, Plaintext_Elem_Type, Plaintext_Type);
   begin
      return CP.To_Public (Internal.AES.Encrypt (Key.Context, CI.To_Internal (Plaintext)));
   end Encrypt;

end LSC.AES_Generic;
