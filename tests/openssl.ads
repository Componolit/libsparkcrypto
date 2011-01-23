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

with LSC.Types;
with LSC.SHA1;
with LSC.SHA256;
with LSC.SHA512;
with LSC.RIPEMD160;
with LSC.AES;
with LSC.HMAC_SHA256;
with LSC.HMAC_SHA384;
with LSC.HMAC_SHA512;
with LSC.HMAC_RIPEMD160;
with Interfaces.C;

use type LSC.Types.Word32;
use type LSC.Types.Word64;

-------------------------------------------------------------------------------
--  ATTENTION: This is *NOT* a proper OpenSSL binding. It is very hacky and
--  e.g. relies on facts like GNAT being used, that 'access all' is equivalent
--  to a C pointer, and much more. It is bad style and only intended for
--  benchmarking LSC - do not use it for anything but that. You've been warned!
-------------------------------------------------------------------------------
package OpenSSL is

   pragma Linker_Options ("-lglue");

   type SHA1_Context_Type is private;
   type SHA256_Context_Type is private;
   type SHA384_Context_Type is private;
   type SHA512_Context_Type is private;
   type RIPEMD160_Context_Type is private;
   type AES_Enc_Context_Type is private;
   type AES_Dec_Context_Type is private;

   ----------------------------------------------------------------------------

   -- AES
   function Create_AES128_Enc_Context (Key : LSC.AES.AES128_Key_Type) return AES_Enc_Context_Type;
   function Create_AES192_Enc_Context (Key : LSC.AES.AES192_Key_Type) return AES_Enc_Context_Type;
   function Create_AES256_Enc_Context (Key : LSC.AES.AES256_Key_Type) return AES_Enc_Context_Type;

   function Encrypt (Context   : AES_Enc_Context_Type;
                     Plaintext : LSC.AES.Block_Type) return LSC.AES.Block_Type;
   pragma Inline (Encrypt);

   function Create_AES128_Dec_Context (Key : LSC.AES.AES128_Key_Type) return AES_Dec_Context_Type;
   function Create_AES192_Dec_Context (Key : LSC.AES.AES192_Key_Type) return AES_Dec_Context_Type;
   function Create_AES256_Dec_Context (Key : LSC.AES.AES256_Key_Type) return AES_Dec_Context_Type;

   function Decrypt (Context    : AES_Dec_Context_Type;
                     Ciphertext : LSC.AES.Block_Type) return LSC.AES.Block_Type;
   pragma Inline (Decrypt);

   ----------------------------------------------------------------------------

   -- SHA-1
   procedure SHA1_Context_Init (Context : in out SHA1_Context_Type);

   procedure SHA1_Context_Update (Context : in out SHA1_Context_Type;
                                  Block   : in     LSC.SHA1.Block_Type);

   procedure SHA1_Context_Finalize (Context : in out SHA1_Context_Type;
                                    Block   : in     LSC.SHA1.Block_Type;
                                    Length  : in     LSC.SHA1.Block_Length_Type);
   pragma Inline (SHA1_Context_Update, SHA1_Context_Finalize);

   function SHA1_Get_Hash (Context : in SHA1_Context_Type) return LSC.SHA1.Hash_Type;

   ----------------------------------------------------------------------------

   -- SHA-256
   procedure SHA256_Context_Init (Context : in out SHA256_Context_Type);

   procedure SHA256_Context_Update (Context : in out SHA256_Context_Type;
                                    Block   : in     LSC.SHA256.Block_Type);

   procedure SHA256_Context_Finalize (Context : in out SHA256_Context_Type;
                                      Block   : in     LSC.SHA256.Block_Type;
                                      Length  : in     LSC.SHA256.Block_Length_Type);
   pragma Inline (SHA256_Context_Update, SHA256_Context_Finalize);

   function SHA256_Get_Hash (Context : in SHA256_Context_Type) return LSC.SHA256.SHA256_Hash_Type;

   ----------------------------------------------------------------------------

   -- SHA-384
   procedure SHA384_Context_Init (Context : in out SHA384_Context_Type);

   procedure SHA384_Context_Update (Context : in out SHA384_Context_Type;
                                    Block   : in     LSC.SHA512.Block_Type);

   procedure SHA384_Context_Finalize (Context : in out SHA384_Context_Type;
                                      Block   : in     LSC.SHA512.Block_Type;
                                      Length  : in     LSC.SHA512.Block_Length_Type);
   pragma Inline (SHA384_Context_Update, SHA384_Context_Finalize);

   function SHA384_Get_Hash (Context : in SHA384_Context_Type) return LSC.SHA512.SHA384_Hash_Type;

   ----------------------------------------------------------------------------

   -- SHA-512
   procedure SHA512_Context_Init (Context : in out SHA512_Context_Type);

   procedure SHA512_Context_Update (Context : in out SHA512_Context_Type;
                                    Block   : in     LSC.SHA512.Block_Type);

   procedure SHA512_Context_Finalize (Context : in out SHA512_Context_Type;
                                      Block   : in     LSC.SHA512.Block_Type;
                                      Length  : in     LSC.SHA512.Block_Length_Type);
   pragma Inline (SHA512_Context_Update, SHA512_Context_Finalize);

   function SHA512_Get_Hash (Context : in SHA512_Context_Type) return LSC.SHA512.SHA512_Hash_Type;

   ----------------------------------------------------------------------------

   -- RIPEMD-160
   procedure RIPEMD160_Context_Init (Context : in out RIPEMD160_Context_Type);

   procedure RIPEMD160_Context_Update (Context : in out RIPEMD160_Context_Type;
                                       Block   : in     LSC.RIPEMD160.Block_Type);

   procedure RIPEMD160_Context_Finalize (Context : in out RIPEMD160_Context_Type;
                                         Block   : in     LSC.RIPEMD160.Block_Type;
                                         Length  : in     LSC.RIPEMD160.Block_Length_Type);
   pragma Inline (RIPEMD160_Context_Update, RIPEMD160_Context_Finalize);

   function RIPEMD160_Get_Hash (Context : in RIPEMD160_Context_Type) return LSC.RIPEMD160.Hash_Type;

   ----------------------------------------------------------------------------

   -- HMAC_SHA1

   subtype SHA1_Message_Type is LSC.SHA1.Message_Type (LSC.Types.Word64 range 1 .. 100);

   function Authenticate_SHA1
     (Key     : LSC.SHA1.Block_Type;
      Message : SHA1_Message_Type;
      Length  : LSC.Types.Word64) return LSC.SHA1.Hash_Type;
   pragma Inline (Authenticate_SHA1);

   ----------------------------------------------------------------------------

   -- HMAC_SHA256

   subtype SHA256_Message_Type is LSC.SHA256.Message_Type (LSC.Types.Word64 range 1 .. 100);

   function Authenticate_SHA256
      (Key     : LSC.SHA256.Block_Type;
       Message : SHA256_Message_Type;
       Length  : LSC.Types.Word64) return LSC.HMAC_SHA256.Auth_Type;
   pragma Inline (Authenticate_SHA256);

   ----------------------------------------------------------------------------

   subtype SHA512_Message_Type is LSC.SHA512.Message_Type (LSC.Types.Word64 range 1 .. 100);

   -- HMAC_SHA384

   function Authenticate_SHA384
      (Key     : LSC.SHA512.Block_Type;
       Message : SHA512_Message_Type;
       Length  : LSC.Types.Word64) return LSC.HMAC_SHA384.Auth_Type;
   pragma Inline (Authenticate_SHA384);

   ----------------------------------------------------------------------------

   -- HMAC_SHA512

   function Authenticate_SHA512
      (Key     : LSC.SHA512.Block_Type;
       Message : SHA512_Message_Type;
       Length  : LSC.Types.Word64) return LSC.HMAC_SHA512.Auth_Type;
   pragma Inline (Authenticate_SHA512);

   ----------------------------------------------------------------------------

   -- HMAC_RMD160

   subtype RMD160_Message_Type is LSC.RIPEMD160.Message_Type (LSC.Types.Word64 range 1 .. 100);

   function Authenticate_RMD160
      (Key     : LSC.RIPEMD160.Block_Type;
       Message : RMD160_Message_Type;
       Length  : LSC.Types.Word64) return LSC.RIPEMD160.Hash_Type;
   pragma Inline (Authenticate_RMD160);

private

   pragma Linker_Options ("-lcrypto");

   type SHA512_Block_Type_Ptr is access all LSC.SHA512.Block_Type;
   pragma Convention (C, SHA512_Block_Type_Ptr);

   type SHA256_Block_Type_Ptr is access all LSC.SHA256.Block_Type;
   pragma Convention (C, SHA256_Block_Type_Ptr);

   type SHA1_Block_Type_Ptr is access all LSC.SHA1.Block_Type;
   pragma Convention (C, SHA1_Block_Type_Ptr);

   type SHA512_Hash_Type_Ptr is access all LSC.SHA512.SHA512_Hash_Type;
   pragma Convention (C, SHA512_Hash_Type_Ptr);

   type SHA256_Hash_Type_Ptr is access all LSC.SHA256.SHA256_Hash_Type;
   pragma Convention (C, SHA256_Hash_Type_Ptr);

   type SHA1_Hash_Type_Ptr is access all LSC.SHA1.Hash_Type;
   pragma Convention (C, SHA1_Hash_Type_Ptr);

   type C_Context_Type is array (1 .. 512) of Character;
   pragma Convention (C, C_Context_Type);
   type C_Context_Ptr is access all C_Context_Type;
   pragma Convention (C, C_Context_Ptr);

   ----------------------------------------------------------------------------

   --  SHA-1 C binding
   procedure C_SHA1_Init (Context : C_Context_Ptr);
   pragma Import (C, C_SHA1_Init, "SHA1_Init");

   procedure C_SHA1_Update (Context : C_Context_Ptr;
                            Data    : SHA1_Block_Type_Ptr;
                            Length  : Interfaces.C.Size_t);
   pragma Import (C, C_SHA1_Update, "SHA1_Update");

   procedure C_SHA1_Final (MD      : SHA1_Hash_Type_Ptr;
                           Context : C_Context_Ptr);
   pragma Import (C, C_SHA1_Final, "SHA1_Final");

   ----------------------------------------------------------------------------

   --  SHA-256 C binding
   procedure C_SHA256_Init (Context : C_Context_Ptr);
   pragma Import (C, C_SHA256_Init, "SHA256_Init");

   procedure C_SHA256_Update (Context : C_Context_Ptr;
                              Data    : SHA256_Block_Type_Ptr;
                              Length  : Interfaces.C.Size_t);
   pragma Import (C, C_SHA256_Update, "SHA256_Update");

   procedure C_SHA256_Final (MD      : SHA256_Hash_Type_Ptr;
                             Context : C_Context_Ptr);
   pragma Import (C, C_SHA256_Final, "SHA256_Final");

   ----------------------------------------------------------------------------

   --  SHA-384 C binding
   procedure C_SHA384_Init (Context : C_Context_Ptr);
   pragma Import (C, C_SHA384_Init, "SHA384_Init");

   procedure C_SHA384_Update (Context : C_Context_Ptr;
                              Data    : SHA512_Block_Type_Ptr;
                              Length  : Interfaces.C.Size_t);
   pragma Import (C, C_SHA384_Update, "SHA384_Update");

   procedure C_SHA384_Final (MD      : SHA512_Hash_Type_Ptr;
                             Context : C_Context_Ptr);
   pragma Import (C, C_SHA384_Final, "SHA384_Final");

   ----------------------------------------------------------------------------

   --  SHA-512 C binding
   procedure C_SHA512_Init (Context : C_Context_Ptr);
   pragma Import (C, C_SHA512_Init, "SHA512_Init");

   procedure C_SHA512_Update (Context : C_Context_Ptr;
                              Data    : SHA512_Block_Type_Ptr;
                              Length  : Interfaces.C.Size_t);
   pragma Import (C, C_SHA512_Update, "SHA512_Update");

   procedure C_SHA512_Final (MD      : SHA512_Hash_Type_Ptr;
                             Context : C_Context_Ptr);
   pragma Import (C, C_SHA512_Final, "SHA512_Final");

   ----------------------------------------------------------------------------

   --  RIPEMD C binding
   type RIPEMD160_Block_Type_Ptr is access all LSC.RIPEMD160.Block_Type;
   pragma Convention (C, RIPEMD160_Block_Type_Ptr);

   type RIPEMD160_Hash_Type_Ptr is access all LSC.RIPEMD160.Hash_Type;
   pragma Convention (C, RIPEMD160_Hash_Type_Ptr);

   procedure C_RIPEMD160_Init (Context : C_Context_Ptr);
   pragma Import (C, C_RIPEMD160_Init, "RIPEMD160_Init");

   procedure C_RIPEMD160_Update (Context : C_Context_Ptr;
                                 Data    : RIPEMD160_Block_Type_Ptr;
                                 Length  : Interfaces.C.Size_t);
   pragma Import (C, C_RIPEMD160_Update, "RIPEMD160_Update");

   procedure C_RIPEMD160_Final (MD      : RIPEMD160_Hash_Type_Ptr;
                                Context : C_Context_Ptr);
   pragma Import (C, C_RIPEMD160_Final, "RIPEMD160_Final");

   ----------------------------------------------------------------------------

   --  AES C binding
   type Key_Ptr is access all LSC.AES.AES256_Key_Type;
   pragma Convention (C, Key_Ptr);
   type Block_Ptr is access all LSC.AES.Block_Type;
   pragma Convention (C, Block_Ptr);

   procedure C_AES_set_encrypt_key (UserKey : Key_Ptr;
                                    Bits    : Interfaces.C.Int;
                                    AESKey  : C_Context_Ptr);
   pragma Import (C, C_AES_set_encrypt_key, "AES_set_encrypt_key");

   procedure C_AES_encrypt (In_Block  : Block_Ptr;
                            Out_Block : Block_Ptr;
                            AESKey    : C_Context_Ptr);
   pragma Import (C, C_AES_encrypt, "AES_encrypt");

   procedure C_AES_set_decrypt_key (UserKey : Key_Ptr;
                                    Bits    : Interfaces.C.Int;
                                    AESKey  : C_Context_Ptr);
   pragma Import (C, C_AES_set_decrypt_key, "AES_set_decrypt_key");

   procedure C_AES_decrypt (In_Block  : Block_Ptr;
                            Out_Block : Block_Ptr;
                            AESKey    : C_Context_Ptr);
   pragma Import (C, C_AES_decrypt, "AES_decrypt");

   ----------------------------------------------------------------------------

   --  libglue/HMAC_SHA1 C binding
   type HMAC_SHA1_Key_Ptr is access all LSC.SHA1.Block_Type;
   pragma Convention (C, HMAC_SHA1_Key_Ptr);

   type HMAC_SHA1_Msg_Ptr is access all SHA1_Message_Type;
   pragma Convention (C, HMAC_SHA1_Msg_Ptr);

   type HMAC_SHA1_Auth_Ptr is access all LSC.SHA1.Hash_Type;
   pragma Convention (C, HMAC_SHA1_Auth_Ptr);

   procedure C_Authenticate_SHA1
     (Key     : HMAC_SHA1_Key_Ptr;
      Message : HMAC_SHA1_Msg_Ptr;
      Length  : LSC.Types.Word64;
      Digest  : HMAC_SHA1_Auth_Ptr);
   pragma Import (C, C_Authenticate_SHA1, "Authenticate_SHA1");

   ----------------------------------------------------------------------------

   --  libglue/HMAC_SHA256 C binding
   type HMAC_SHA256_Key_Ptr is access all LSC.SHA256.Block_Type;
   pragma Convention (C, HMAC_SHA256_Key_Ptr);

   type HMAC_SHA256_Msg_Ptr is access all SHA256_Message_Type;
   pragma Convention (C, HMAC_SHA256_Msg_Ptr);

   type HMAC_SHA256_Auth_Ptr is access all LSC.HMAC_SHA256.Auth_Type;
   pragma Convention (C, HMAC_SHA256_Auth_Ptr);

   procedure C_Authenticate_SHA256
      (Key     : HMAC_SHA256_Key_Ptr;
       Message : HMAC_SHA256_Msg_Ptr;
       Length  : LSC.Types.Word64;
       Digest  : HMAC_SHA256_Auth_Ptr);
   pragma Import (C, C_Authenticate_SHA256, "Authenticate_SHA256");

   ----------------------------------------------------------------------------

   type HMAC_SHA512_Key_Ptr is access all LSC.SHA512.Block_Type;
   pragma Convention (C, HMAC_SHA512_Key_Ptr);

   type HMAC_SHA512_Msg_Ptr is access all SHA512_Message_Type;
   pragma Convention (C, HMAC_SHA512_Msg_Ptr);

   --  libglue/HMAC_SHA384 C binding

   type HMAC_SHA384_Auth_Ptr is access all LSC.HMAC_SHA384.Auth_Type;
   pragma Convention (C, HMAC_SHA384_Auth_Ptr);

   procedure C_Authenticate_SHA384
      (Key     : HMAC_SHA512_Key_Ptr;
       Message : HMAC_SHA512_Msg_Ptr;
       Length  : LSC.Types.Word64;
       Digest  : HMAC_SHA384_Auth_Ptr);
   pragma Import (C, C_Authenticate_SHA384, "Authenticate_SHA384");

   ----------------------------------------------------------------------------

   --  libglue/HMAC_SHA512 C binding
   type HMAC_SHA512_Auth_Ptr is access all LSC.HMAC_SHA512.Auth_Type;
   pragma Convention (C, HMAC_SHA512_Auth_Ptr);

   procedure C_Authenticate_SHA512
      (Key     : HMAC_SHA512_Key_Ptr;
       Message : HMAC_SHA512_Msg_Ptr;
       Length  : LSC.Types.Word64;
       Digest  : HMAC_SHA512_Auth_Ptr);
   pragma Import (C, C_Authenticate_SHA512, "Authenticate_SHA512");

   ----------------------------------------------------------------------------

   --  libglue/HMAC_RMD160 C binding
   type HMAC_RMD160_Key_Ptr is access all LSC.RIPEMD160.Block_Type;
   pragma Convention (C, HMAC_RMD160_Key_Ptr);

   type HMAC_RMD160_Msg_Ptr is access all RMD160_Message_Type;
   pragma Convention (C, HMAC_RMD160_Msg_Ptr);

   type HMAC_RMD160_Auth_Ptr is access all LSC.RIPEMD160.Hash_Type;
   pragma Convention (C, HMAC_RMD160_Auth_Ptr);

   procedure C_Authenticate_RMD160
      (Key     : HMAC_RMD160_Key_Ptr;
       Message : HMAC_RMD160_Msg_Ptr;
       Length  : LSC.Types.Word64;
       Digest  : HMAC_RMD160_Auth_Ptr);
   pragma Import (C, C_Authenticate_RMD160, "Authenticate_RMD160");

   ----------------------------------------------------------------------------

   type AES_Enc_Context_Type is
   record
      C_Context : C_Context_Type;
   end record;

   type AES_Dec_Context_Type is
   record
      C_Context : C_Context_Type;
   end record;

   type SHA1_Context_Type is
   record
      C_Context : C_Context_Type;
      Hash      : LSC.SHA1.Hash_Type;
   end record;

   type SHA256_Context_Type is
   record
      C_Context : C_Context_Type;
      Hash      : LSC.SHA256.SHA256_Hash_Type;
   end record;

   type SHA384_Context_Type is
   record
      C_Context : C_Context_Type;
      Hash      : LSC.SHA512.SHA384_Hash_Type;
   end record;

   type SHA512_Context_Type is
   record
      C_Context : C_Context_Type;
      Hash      : LSC.SHA512.SHA512_Hash_Type;
   end record;

   type RIPEMD160_Context_Type is
   record
      C_Context : C_Context_Type;
      Hash      : LSC.RIPEMD160.Hash_Type;
   end record;

end OpenSSL;
