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

with LSC.Internal.Convert;
with LSC.Internal.AES.CBC;
with Ada.Unchecked_Conversion;

package body LSC.AES.CBC
is
   use LSC.Internal.Convert;

   -------------
   -- Decrypt --
   -------------

   procedure Decrypt
     (Ciphertext :     LSC.Types.Bytes;
      Key        :     LSC.Types.Bytes;
      IV         :     LSC.Types.Bytes;
      Keylen     :     Keylen_Type;
      Plaintext  : out LSC.Types.Bytes)
   is
      Context : constant Internal.AES.AES_Dec_Context :=
         (case Keylen is
          when L128 => Internal.AES.Create_AES128_Dec_Context (K128 (Key (Key'First .. Key'First + 15))),
          when L192 => Internal.AES.Create_AES192_Dec_Context (K192 (Key (Key'First .. Key'First + 23))),
          when L256 => Internal.AES.Create_AES256_Dec_Context (K256 (Key (Key'First .. Key'First + 31))));

      subtype CT_Type is LSC.Types.Bytes (Ciphertext'First .. Ciphertext'First + Ciphertext'Length - 1);
      subtype CT_Internal_Type is Internal.AES.Message_Type (1 .. Ciphertext'Length / 16);
      function To_Internal is new Ada.Unchecked_Conversion (CT_Type, CT_Internal_Type);

      PT_Internal : Internal.AES.Message_Type (1 .. Plaintext'Length / 16)
      with Address => Plaintext'Address;
   begin
      LSC.Internal.AES.CBC.Decrypt (Context    => Context,
                                    IV         => To_Internal (IV),
                                    Ciphertext => To_Internal (Ciphertext),
                                    Length     => Ciphertext'Length / 16,
                                    Plaintext  => PT_Internal);
   end Decrypt;

   -------------
   -- Encrypt --
   -------------

   procedure Encrypt
     (Plaintext  :     LSC.Types.Bytes;
      Key        :     LSC.Types.Bytes;
      IV         :     LSC.Types.Bytes;
      Keylen     :     Keylen_Type;
      Ciphertext : out LSC.Types.Bytes)
   is
      Context : constant Internal.AES.AES_Enc_Context :=
         (case Keylen is
          when L128 => Internal.AES.Create_AES128_Enc_Context (K128 (Key (Key'First .. Key'First + 15))),
          when L192 => Internal.AES.Create_AES192_Enc_Context (K192 (Key (Key'First .. Key'First + 23))),
          when L256 => Internal.AES.Create_AES256_Enc_Context (K256 (Key (Key'First .. Key'First + 31))));

      subtype PT_Type is LSC.Types.Bytes (1 .. Plaintext'Length);
      subtype PT_Internal_Type is Internal.AES.Message_Type (1 .. Plaintext'Length / 16);
      function To_Internal is new Ada.Unchecked_Conversion (PT_Type, PT_Internal_Type);

      CT_Internal : Internal.AES.Message_Type (1 .. Ciphertext'Length / 16)
      with Address => Ciphertext'Address;
   begin
      LSC.Internal.AES.CBC.Encrypt (Context    => Context,
                                    IV         => To_Internal (IV),
                                    Plaintext  => To_Internal (Plaintext),
                                    Length     => Plaintext'Length / 16,
                                    Ciphertext => CT_Internal);
   end Encrypt;

end LSC.AES.CBC;
