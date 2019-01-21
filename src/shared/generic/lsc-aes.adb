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

with LSC.Internal.AES;
with Ada.Unchecked_Conversion;

package body LSC.AES
is
   subtype Key128_Type is Types.Bytes (1 .. 16);
   subtype Key192_Type is Types.Bytes (1 .. 24);
   subtype Key256_Type is Types.Bytes (1 .. 32);
   subtype Block_Type is Types.Bytes (1 .. 16);

   function K128 is new Ada.Unchecked_Conversion (Key128_Type, Internal.AES.AES128_Key_Type);
   function K192 is new Ada.Unchecked_Conversion (Key192_Type, Internal.AES.AES192_Key_Type);
   function K256 is new Ada.Unchecked_Conversion (Key256_Type, Internal.AES.AES256_Key_Type);
   function To_Internal is new Ada.Unchecked_Conversion (Block_Type, Internal.AES.Block_Type);
   function To_Public is new Ada.Unchecked_Conversion (Internal.AES.Block_Type, Block_Type);

   -------------
   -- Decrypt --
   -------------

   function Decrypt (Ciphertext : Types.Bytes;
                     Key        : Types.Bytes;
                     Keylen     : Keylen_Type) return Types.Bytes
   is
      Dec_Context : constant Internal.AES.AES_Dec_Context :=
         (case Keylen is
          when L128 => Internal.AES.Create_AES128_Dec_Context (K128 (Key (1 .. 16))),
          when L192 => Internal.AES.Create_AES192_Dec_Context (K192 (Key (1 .. 24))),
          when L256 => Internal.AES.Create_AES256_Dec_Context (K256 (Key (1 .. 32))));
   begin
      return To_Public (Internal.AES.Decrypt (Dec_Context, To_Internal (Ciphertext)));
   end Decrypt;

   -------------
   -- Encrypt --
   -------------

   function Encrypt (Plaintext : Types.Bytes;
                     Key       : Types.Bytes;
                     Keylen    : Keylen_Type) return Types.Bytes
   is
      Enc_Context : constant Internal.AES.AES_Enc_Context :=
         (case Keylen is
          when L128 => Internal.AES.Create_AES128_Enc_Context (K128 (Key (1 .. 16))),
          when L192 => Internal.AES.Create_AES192_Enc_Context (K192 (Key (1 .. 24))),
          when L256 => Internal.AES.Create_AES256_Enc_Context (K256 (Key (1 .. 32))));
   begin
      return To_Public (Internal.AES.Encrypt (Enc_Context, To_Internal (Plaintext)));
   end Encrypt;

end LSC.AES;
