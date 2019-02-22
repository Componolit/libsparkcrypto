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

private with LSC.Internal.AES;

package LSC.AES_Universal
is
   type Keylen_Type is (L128, L192, L256);
   --  Available AES modes

   function Key_Bytes (Keylen : Keylen_Type) return Natural;
   --  AES key lengths for @Keylen in bytes

   --  FIXME: This crashes GCC 6.3. Re-add as soon as it's not used anymore.
   --  with Ghost;

   type Dec_Key_Type is private;
   type Enc_Key_Type is private;

   generic
      type Index_Type is (<>);
      type Elem_Type is (<>);
      type Key_Type is array (Index_Type range <>) of Elem_Type;
   function Dec_Key (K      : Key_Type;
                     Keylen : Keylen_Type) return Dec_Key_Type
   with
      Pre => K'Length = Key_Bytes (Keylen);
   --  Return decryption key of length @Keylen from byte array

   generic
      type Index_Type is (<>);
      type Elem_Type is (<>);
      type Key_Type is array (Index_Type range <>) of Elem_Type;
   function Enc_Key (K      : Key_Type;
                     Keylen : Keylen_Type) return Enc_Key_Type
   with
      Pre => K'Length = Key_Bytes (Keylen);
   --  Return encryption key of length @Keylen from byte array

   generic
      type Plaintext_Index_Type is (<>);
      type Plaintext_Elem_Type is (<>);
      type Plaintext_Type is array (Plaintext_Index_Type range <>) of Plaintext_Elem_Type;
      type Ciphertext_Index_Type is (<>);
      type Ciphertext_Elem_Type is (<>);
      type Ciphertext_Type is array (Ciphertext_Index_Type range <>) of Ciphertext_Elem_Type;
   function Decrypt (Ciphertext : Ciphertext_Type;
                     Key        : Dec_Key_Type) return Plaintext_Type
   with
      Pre  => Ciphertext'Length = 16,
      Post => Decrypt'Result'Length = 16;
   --  Decrypt @Ciphertext using @Key, @Keylen determines the AES key
   --  length (AES-128, AES-192, AES-256)

   generic
      type Plaintext_Index_Type is (<>);
      type Plaintext_Elem_Type is (<>);
      type Plaintext_Type is array (Plaintext_Index_Type range <>) of Plaintext_Elem_Type;
      type Ciphertext_Index_Type is (<>);
      type Ciphertext_Elem_Type is (<>);
      type Ciphertext_Type is array (Ciphertext_Index_Type range <>) of Ciphertext_Elem_Type;
   function Encrypt (Plaintext : Plaintext_Type;
                     Key       : Enc_Key_Type) return Ciphertext_Type
   with
      Pre  => Plaintext'Length = 16,
      Post => Encrypt'Result'Length = 16;
   --  Decrypt @Plaintext using @Key, @Keylen determines the AES key
   --  length (AES-128, AES-192, AES-256)

private

   function Key_Bytes (Keylen : Keylen_Type) return Natural is
      (case Keylen is
       when L128 => 16,
       when L192 => 24,
       when L256 => 32);

   type Dec_Key_Type is
   record
      Context : Internal.AES.AES_Dec_Context;
   end record;

   type Enc_Key_Type is
   record
      Context : Internal.AES.AES_Enc_Context;
   end record;

end LSC.AES_Universal;
