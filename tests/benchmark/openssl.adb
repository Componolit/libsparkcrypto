-------------------------------------------------------------------------------
-- This file is part of the sparkcrypto library.
--
-- Copyright (C) 2010  Alexander Senier <mail@senier.net>
-- Copyright (C) 2010  secunet Security Networks AG
--
-- libsparkcrypto is  free software; you  can redistribute it and/or  modify it
-- under  terms of  the GNU  General Public  License as  published by  the Free
-- Software  Foundation;  either version  3,  or  (at  your option)  any  later
-- version.  libsparkcrypto  is  distributed  in  the  hope  that  it  will  be
-- useful,  but WITHOUT  ANY WARRANTY;  without  even the  implied warranty  of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
--
-- As a  special exception under  Section 7 of GPL  version 3, you  are granted
-- additional  permissions  described in  the  GCC  Runtime Library  Exception,
-- version 3.1, as published by the Free Software Foundation.
--
-- You should  have received  a copy of  the GNU General  Public License  and a
-- copy  of  the  GCC  Runtime  Library  Exception  along  with  this  program;
-- see  the  files  COPYING3  and COPYING.RUNTIME  respectively.  If  not,  see
-- <http://www.gnu.org/licenses/>.
-------------------------------------------------------------------------------

-------------------------------------------------------------------------------
--  ATTENTION: READ THE WARNING IN THE HEADER OF THE SPEC FILE!
-------------------------------------------------------------------------------
package body OpenSSL is

   ----------------------------------------------------------------------------
   -- AES
   ----------------------------------------------------------------------------

   function Create_AES128_Enc_Context (Key : LSC.AES.AES128_Key_Type)
      return AES_Enc_Context_Type
   is
      Result : C_Context_Type;
   begin
      C_AES_set_encrypt_key (UserKey => Key'Unrestricted_Access,
                             Bits    => 128,
                             AESKey  => Result'Unrestricted_Access);
      return AES_Enc_Context_Type'(C_Context => Result);
   end Create_AES128_Enc_Context;

   ----------------------------------------------------------------------------

   function Create_AES192_Enc_Context (Key : LSC.AES.AES192_Key_Type)
       return AES_Enc_Context_Type
   is
      Result : C_Context_Type;
   begin
      C_AES_set_encrypt_key (UserKey => Key'Unrestricted_Access,
                             Bits    => 192,
                             AESKey  => Result'Unrestricted_Access);
      return AES_Enc_Context_Type'(C_Context => Result);
   end Create_AES192_Enc_Context;

   ----------------------------------------------------------------------------

   function Create_AES256_Enc_Context (Key : LSC.AES.AES256_Key_Type)
      return AES_Enc_Context_Type
   is
      Result : C_Context_Type;
   begin
      C_AES_set_encrypt_key (UserKey => Key'Unrestricted_Access,
                             Bits    => 256,
                             AESKey  => Result'Unrestricted_Access);
      return AES_Enc_Context_Type'(C_Context => Result);
   end Create_AES256_Enc_Context;

   ----------------------------------------------------------------------------

   function Encrypt (Context   : AES_Enc_Context_Type;
                     Plaintext : LSC.AES.Block_Type) return LSC.AES.Block_Type
   is
      Result : LSC.AES.Block_Type;
   begin
      C_AES_encrypt (In_Block  => Plaintext'Unrestricted_Access,
                     Out_Block => Result'Unrestricted_Access,
                     AESKey    => Context.C_Context'Unrestricted_Access);
      return Result;
   end Encrypt;

   ----------------------------------------------------------------------------

   function Create_AES128_Dec_Context (Key : LSC.AES.AES128_Key_Type)
      return AES_Dec_Context_Type
   is
      Result : C_Context_Type;
   begin
      C_AES_set_decrypt_key (UserKey => Key'Unrestricted_Access,
                             Bits    => 128,
                             AESKey  => Result'Unrestricted_Access);
      return AES_Dec_Context_Type'(C_Context => Result);
   end Create_AES128_Dec_Context;

   ----------------------------------------------------------------------------

   function Create_AES192_Dec_Context (Key : LSC.AES.AES192_Key_Type)
       return AES_Dec_Context_Type
   is
      Result : C_Context_Type;
   begin
      C_AES_set_decrypt_key (UserKey => Key'Unrestricted_Access,
                             Bits    => 192,
                             AESKey  => Result'Unrestricted_Access);
      return AES_Dec_Context_Type'(C_Context => Result);
   end Create_AES192_Dec_Context;

   ----------------------------------------------------------------------------

   function Create_AES256_Dec_Context (Key : LSC.AES.AES256_Key_Type)
      return AES_Dec_Context_Type
   is
      Result : C_Context_Type;
   begin
      C_AES_set_decrypt_key (UserKey => Key'Unrestricted_Access,
                             Bits    => 256,
                             AESKey  => Result'Unrestricted_Access);
      return AES_Dec_Context_Type'(C_Context => Result);
   end Create_AES256_Dec_Context;

   ----------------------------------------------------------------------------

   function Decrypt (Context    : AES_Dec_Context_Type;
                     Ciphertext : LSC.AES.Block_Type) return LSC.AES.Block_Type
   is
      Result : LSC.AES.Block_Type;
   begin
      C_AES_decrypt (In_Block  => Ciphertext'Unrestricted_Access,
                     Out_Block => Result'Unrestricted_Access,
                     AESKey    => Context.C_Context'Unrestricted_Access);
      return Result;
   end Decrypt;

   ----------------------------------------------------------------------------
   -- SHA-256
   ----------------------------------------------------------------------------

   procedure SHA256_Context_Init (Context : in out SHA256_Context_Type)
   is
   begin
      OpenSSL.C_SHA256_Init (Context.C_Context'Unrestricted_Access);
   end SHA256_Context_Init;

   ----------------------------------------------------------------------------

   procedure SHA256_Context_Update
      (Context : in out SHA256_Context_Type;
       Block   : in     LSC.SHA256.Block_Type)
   is
   begin
      OpenSSL.C_SHA256_Update (Context.C_Context'Unrestricted_Access,
                               Block'Unrestricted_Access,
                               64);
   end SHA256_Context_Update;

   ----------------------------------------------------------------------------

   procedure SHA256_Context_Finalize
      (Context : in out SHA256_Context_Type;
       Block   : in     LSC.SHA256.Block_Type;
       Length  : in     LSC.SHA256.Block_Length_Type)
   is
   begin
      OpenSSL.C_SHA256_Update (Context.C_Context'Unrestricted_Access,
                               Block'Unrestricted_Access,
                               Interfaces.C.size_t (Length / 8));
      OpenSSL.C_SHA256_Final (Context.Hash'Unrestricted_Access,
                              Context.C_Context'Unrestricted_Access);
   end SHA256_Context_Finalize;

   ----------------------------------------------------------------------------

   function SHA256_Get_Hash (Context : in SHA256_Context_Type)
      return LSC.SHA256.SHA256_Hash_Type
   is
   begin
      return Context.Hash;
   end SHA256_Get_Hash;

   ----------------------------------------------------------------------------
   -- SHA-384
   ----------------------------------------------------------------------------

   procedure SHA384_Context_Init (Context : in out SHA384_Context_Type)
   is
   begin
      OpenSSL.C_SHA384_Init (Context.C_Context'Unrestricted_Access);
   end SHA384_Context_Init;

   ----------------------------------------------------------------------------

   procedure SHA384_Context_Update
      (Context : in out SHA384_Context_Type;
       Block   : in     LSC.SHA512.Block_Type)
   is
   begin
      OpenSSL.C_SHA384_Update (Context.C_Context'Unrestricted_Access,
                               Block'Unrestricted_Access,
                               128);
   end SHA384_Context_Update;

   ----------------------------------------------------------------------------

   procedure SHA384_Context_Finalize
      (Context : in out SHA384_Context_Type;
       Block   : in     LSC.SHA512.Block_Type;
       Length  : in     LSC.SHA512.Block_Length_Type)
   is
   begin
      OpenSSL.C_SHA384_Update (Context.C_Context'Unrestricted_Access,
                               Block'Unrestricted_Access,
                               Interfaces.C.size_t (Length / 8));
      OpenSSL.C_SHA384_Final (Context.Hash'Unrestricted_Access,
                              Context.C_Context'Unrestricted_Access);
   end SHA384_Context_Finalize;

   ----------------------------------------------------------------------------

   function SHA384_Get_Hash (Context : in SHA384_Context_Type)
      return LSC.SHA512.SHA384_Hash_Type
   is
   begin
      return Context.Hash;
   end SHA384_Get_Hash;

   ----------------------------------------------------------------------------
   -- SHA-512
   ----------------------------------------------------------------------------

   procedure SHA512_Context_Init (Context : in out SHA512_Context_Type)
   is
   begin
      OpenSSL.C_SHA512_Init (Context.C_Context'Unrestricted_Access);
   end SHA512_Context_Init;

   ----------------------------------------------------------------------------

   procedure SHA512_Context_Update
      (Context : in out SHA512_Context_Type;
       Block   : in     LSC.SHA512.Block_Type)
   is
   begin
      OpenSSL.C_SHA512_Update (Context.C_Context'Unrestricted_Access,
                               Block'Unrestricted_Access,
                               128);
   end SHA512_Context_Update;

   ----------------------------------------------------------------------------

   procedure SHA512_Context_Finalize
      (Context : in out SHA512_Context_Type;
       Block   : in     LSC.SHA512.Block_Type;
       Length  : in     LSC.SHA512.Block_Length_Type)
   is
   begin
      OpenSSL.C_SHA512_Update (Context.C_Context'Unrestricted_Access,
                               Block'Unrestricted_Access,
                               Interfaces.C.size_t (Length / 8));
      OpenSSL.C_SHA512_Final (Context.Hash'Unrestricted_Access,
                              Context.C_Context'Unrestricted_Access);
   end SHA512_Context_Finalize;

   ----------------------------------------------------------------------------

   function SHA512_Get_Hash (Context : in SHA512_Context_Type)
      return LSC.SHA512.SHA512_Hash_Type
   is
   begin
      return Context.Hash;
   end SHA512_Get_Hash;

   ----------------------------------------------------------------------------
   -- RIPEMD-160
   ----------------------------------------------------------------------------

   procedure RIPEMD160_Context_Init (Context : in out RIPEMD160_Context_Type)
   is
   begin
      OpenSSL.C_RIPEMD160_Init (Context.C_Context'Unrestricted_Access);
   end RIPEMD160_Context_Init;

   ----------------------------------------------------------------------------

   procedure RIPEMD160_Context_Update
      (Context : in out RIPEMD160_Context_Type;
       Block   : in     LSC.RIPEMD160.Block_Type)
   is
   begin
      OpenSSL.C_RIPEMD160_Update (Context.C_Context'Unrestricted_Access,
                                  Block'Unrestricted_Access,
                                  64);
   end RIPEMD160_Context_Update;

   ----------------------------------------------------------------------------

   procedure RIPEMD160_Context_Finalize
      (Context : in out RIPEMD160_Context_Type;
       Block   : in     LSC.RIPEMD160.Block_Type;
       Length  : in     LSC.RIPEMD160.Block_Length_Type)
   is
   begin
      OpenSSL.C_RIPEMD160_Update (Context.C_Context'Unrestricted_Access,
                                  Block'Unrestricted_Access,
                                  Interfaces.C.size_t (Length / 8));
      OpenSSL.C_RIPEMD160_Final (Context.Hash'Unrestricted_Access,
                                 Context.C_Context'Unrestricted_Access);
   end RIPEMD160_Context_Finalize;

   ----------------------------------------------------------------------------

   function RIPEMD160_Get_Hash (Context : in RIPEMD160_Context_Type)
      return LSC.RIPEMD160.Hash_Type
   is
   begin
      return Context.Hash;
   end RIPEMD160_Get_Hash;
end OpenSSL;
