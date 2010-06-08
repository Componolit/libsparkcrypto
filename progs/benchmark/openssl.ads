with LSC.Types, LSC.SHA2, Interfaces.C;
use type LSC.Types.Word64;
--# inherit LSC.Types,
--#         LSC.SHA2;

package OpenSSL is

   type SHA512_Context_Type is private;

   procedure Context_Init (Context : in out SHA512_Context_Type);

   procedure Context_Update (Context : in out SHA512_Context_Type;
                             Block   : in     LSC.SHA2.Block_Type);

   procedure Context_Finalize (Context : in out SHA512_Context_Type;
                               Block   : in     LSC.SHA2.Block_Type;
                               Length  : in     LSC.SHA2.Block_Length_Type);

   function SHA512_Get_Hash (Context : in SHA512_Context_Type) return LSC.SHA2.SHA512_Hash_Type;

private

   --# hide OpenSSL;

   pragma Linker_Options ("-lcrypto");

   type C_SHA512_Context_Type is array (1 .. 216) of Character;
   for C_SHA512_Context_Type'Size use 8*216;
   type C_SHA512_Context_Ptr is access all C_SHA512_Context_Type;

   type Block_Type_Ptr is access all LSC.SHA2.Block_Type;
   type Hash_Type_Ptr is access all LSC.SHA2.SHA512_Hash_Type;

   pragma Convention (C, C_SHA512_Context_Type);
   pragma Convention (C, C_SHA512_Context_Ptr);
   pragma Convention (C, Block_Type_Ptr);
   pragma Convention (C, Hash_Type_Ptr);

   type SHA512_Context_Type is
   record
      C_Context : C_SHA512_Context_Type;
      Hash      : LSC.SHA2.SHA512_Hash_Type;
   end record;

   procedure C_SHA512_Init (Context : C_SHA512_Context_Ptr);
   pragma Import (C, C_SHA512_Init, "SHA512_Init");

   procedure C_SHA512_Update (Context : C_SHA512_Context_Ptr;
                              Data    : Block_Type_Ptr;
                              Length  : Interfaces.C.Size_t);
   pragma Import (C, C_SHA512_Update, "SHA512_Update");

   procedure C_SHA512_Final (MD      : Hash_Type_Ptr;
                             Context : C_SHA512_Context_Ptr);
   pragma Import (C, C_SHA512_Final, "SHA512_Final");

end OpenSSL;
