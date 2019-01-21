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

with LSC.Types;
with LSC.AES;

package LSC.AES.CBC
is
   procedure Decrypt (Ciphertext :     LSC.Types.Bytes;
                      Key        :     LSC.Types.Bytes;
                      IV         :     LSC.Types.Bytes;
                      Keylen     :     Keylen_Type;
                      Plaintext  : out LSC.Types.Bytes)
   with
      Pre  => Ciphertext'Length > 0 and
              Ciphertext'Length mod 16 = 0 and
              Plaintext'Length >= Ciphertext'Length and
              Key'Length = Key_Bytes (Keylen) and
              IV'Length = 16;
   --  Decrypt @Ciphertext to @Plaintext using @Key in CBC mode
   --  @Keylen determines the AES key length (AES-128, AES-192, AES-256)

   procedure Encrypt (Plaintext  :     LSC.Types.Bytes;
                      Key        :     LSC.Types.Bytes;
                      IV         :     LSC.Types.Bytes;
                      Keylen     :     Keylen_Type;
                      Ciphertext : out LSC.Types.Bytes)
   with
      Pre  => Plaintext'Length > 0 and
              Plaintext'Length mod 16 = 0 and
              Ciphertext'Length >= Plaintext'Length and
              Key'Length = Key_Bytes (Keylen) and
              IV'Length = 16;
   --  Encrypt @Plaintext to @Ciphertext using @Key in CBC mode
   --  @Keylen determines the AES key length (AES-128, AES-192, AES-256)

end LSC.AES.CBC;
