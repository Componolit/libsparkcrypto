--  This file is part of the sparkcrypto library.

--  Copyright (C) 2010  secunet Security Networks AG
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>

--  This library  is free software:  you can  redistribute it and/or  modify it
--  under the  terms of the GNU  Lesser General Public License  as published by
--  the Free Software Foundation, either version  3 of the License, or (at your
--  option) any later version.

--  This library is distributed in the hope that it will be useful, but WITHOUT
--  ANY  WARRANTY; without  even  the implied  warranty  of MERCHANTABILITY  or
--  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
--  for more details.

--  You should  have received a copy  of the GNU Lesser  General Public License
--  along with this library. If not, see <http://www.gnu.org/licenses/>.

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
   -- SHA-512
   ----------------------------------------------------------------------------

   procedure SHA384_Context_Init (Context : in out SHA384_Context_Type)
   is
   begin
      OpenSSL.C_SHA384_Init (Context.C_Context'Unrestricted_Access);
   end SHA384_Context_Init;

   ----------------------------------------------------------------------------

   procedure SHA384_Context_Update
      (Context : in out SHA384_Context_Type;
       Block   : in     LSC.SHA2.Block_Type)
   is
   begin
      OpenSSL.C_SHA384_Update (Context.C_Context'Unrestricted_Access,
                               Block'Unrestricted_Access,
                               128);
   end SHA384_Context_Update;

   ----------------------------------------------------------------------------

   procedure SHA384_Context_Finalize
      (Context : in out SHA384_Context_Type;
       Block   : in     LSC.SHA2.Block_Type;
       Length  : in     LSC.SHA2.Block_Length_Type)
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
      return LSC.SHA2.SHA384_Hash_Type
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
       Block   : in     LSC.SHA2.Block_Type)
   is
   begin
      OpenSSL.C_SHA512_Update (Context.C_Context'Unrestricted_Access,
                               Block'Unrestricted_Access,
                               128);
   end SHA512_Context_Update;

   ----------------------------------------------------------------------------

   procedure SHA512_Context_Finalize
      (Context : in out SHA512_Context_Type;
       Block   : in     LSC.SHA2.Block_Type;
       Length  : in     LSC.SHA2.Block_Length_Type)
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
      return LSC.SHA2.SHA512_Hash_Type
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
