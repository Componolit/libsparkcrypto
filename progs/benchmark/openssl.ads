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

with LSC.Types;
with LSC.SHA2;
with LSC.RIPEMD160;
with LSC.AES;
with Interfaces.C;

use type LSC.Types.Word32;
use type LSC.Types.Word64;

package OpenSSL is

   type SHA512_Context_Type is private;
   type SHA384_Context_Type is private;
   type RIPEMD160_Context_Type is private;
   type AES_Enc_Context_Type is private;

   -- AES
   function Create_AES128_Enc_Context (Key : LSC.AES.AES128_Key_Type) return AES_Enc_Context_Type;
   function Create_AES192_Enc_Context (Key : LSC.AES.AES192_Key_Type) return AES_Enc_Context_Type;
   function Create_AES256_Enc_Context (Key : LSC.AES.AES256_Key_Type) return AES_Enc_Context_Type;

   function Encrypt (Context   : AES_Enc_Context_Type;
                     Plaintext : LSC.AES.Block_Type) return LSC.AES.Block_Type;

   -- SHA-384
   procedure SHA384_Context_Init (Context : in out SHA384_Context_Type);

   procedure SHA384_Context_Update (Context : in out SHA384_Context_Type;
                                    Block   : in     LSC.SHA2.Block_Type);

   procedure SHA384_Context_Finalize (Context : in out SHA384_Context_Type;
                                      Block   : in     LSC.SHA2.Block_Type;
                                      Length  : in     LSC.SHA2.Block_Length_Type);

   function SHA384_Get_Hash (Context : in SHA384_Context_Type) return LSC.SHA2.SHA384_Hash_Type;

   -- SHA-512
   procedure SHA512_Context_Init (Context : in out SHA512_Context_Type);

   procedure SHA512_Context_Update (Context : in out SHA512_Context_Type;
                                    Block   : in     LSC.SHA2.Block_Type);

   procedure SHA512_Context_Finalize (Context : in out SHA512_Context_Type;
                                      Block   : in     LSC.SHA2.Block_Type;
                                      Length  : in     LSC.SHA2.Block_Length_Type);

   function SHA512_Get_Hash (Context : in SHA512_Context_Type) return LSC.SHA2.SHA512_Hash_Type;

   -- RIPEMD-160
   procedure RIPEMD160_Context_Init (Context : in out RIPEMD160_Context_Type);

   procedure RIPEMD160_Context_Update (Context : in out RIPEMD160_Context_Type;
                                       Block   : in     LSC.RIPEMD160.Block_Type);

   procedure RIPEMD160_Context_Finalize (Context : in out RIPEMD160_Context_Type;
                                         Block   : in     LSC.RIPEMD160.Block_Type;
                                         Length  : in     LSC.RIPEMD160.Block_Length_Type);

   function RIPEMD160_Get_Hash (Context : in RIPEMD160_Context_Type) return LSC.RIPEMD160.Hash_Type;

private

   pragma Linker_Options ("-lcrypto");

   type Block_Type_Ptr is access all LSC.SHA2.Block_Type;
   pragma Convention (C, Block_Type_Ptr);

   type Hash_Type_Ptr is access all LSC.SHA2.SHA512_Hash_Type;
   pragma Convention (C, Hash_Type_Ptr);

   type C_Context_Type is array (1 .. 512) of Character;
   pragma Convention (C, C_Context_Type);
   type C_Context_Ptr is access all C_Context_Type;
   pragma Convention (C, C_Context_Ptr);

   --  SHA-384 C binding
   procedure C_SHA384_Init (Context : C_Context_Ptr);
   pragma Import (C, C_SHA384_Init, "SHA384_Init");

   procedure C_SHA384_Update (Context : C_Context_Ptr;
                              Data    : Block_Type_Ptr;
                              Length  : Interfaces.C.Size_t);
   pragma Import (C, C_SHA384_Update, "SHA384_Update");

   procedure C_SHA384_Final (MD      : Hash_Type_Ptr;
                             Context : C_Context_Ptr);
   pragma Import (C, C_SHA384_Final, "SHA384_Final");

   --  SHA-512 C binding
   procedure C_SHA512_Init (Context : C_Context_Ptr);
   pragma Import (C, C_SHA512_Init, "SHA512_Init");

   procedure C_SHA512_Update (Context : C_Context_Ptr;
                              Data    : Block_Type_Ptr;
                              Length  : Interfaces.C.Size_t);
   pragma Import (C, C_SHA512_Update, "SHA512_Update");

   procedure C_SHA512_Final (MD      : Hash_Type_Ptr;
                             Context : C_Context_Ptr);
   pragma Import (C, C_SHA512_Final, "SHA512_Final");

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

   type AES_Enc_Context_Type is
   record
      C_Context : C_Context_Type;
   end record;

   type SHA384_Context_Type is
   record
      C_Context : C_Context_Type;
      Hash      : LSC.SHA2.SHA384_Hash_Type;
   end record;

   type SHA512_Context_Type is
   record
      C_Context : C_Context_Type;
      Hash      : LSC.SHA2.SHA512_Hash_Type;
   end record;

   type RIPEMD160_Context_Type is
   record
      C_Context : C_Context_Type;
      Hash      : LSC.RIPEMD160.Hash_Type;
   end record;

end OpenSSL;
