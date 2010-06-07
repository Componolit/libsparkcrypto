with LSC.Types, LSC.SHA2, Interfaces.C;
--# inherit LSC.Types,
--#         LSC.SHA2;

package OpenSSL is

   --# hide OpenSSL;

   pragma Linker_Options ("-lcrypto");

   type SHA512_Context is array (1 .. 216) of Character;
   for SHA512_Context'Size use 8*216;
   type SHA512_Context_Ptr is access all SHA512_Context;
   type Block_Type_Ptr is access all LSC.SHA2.Block_Type;
   type Hash_Type_Ptr is access all LSC.SHA2.SHA512_Hash_Type;

   pragma Convention (C, SHA512_Context);
   pragma Convention (C, SHA512_Context_Ptr);
   pragma Convention (C, Block_Type_Ptr);
   pragma Convention (C, Hash_Type_Ptr);

   type SHA512_Context_Type is tagged
   record
      Context : SHA512_Context;
   end record;

   procedure C_SHA512_Init (Context : access SHA512_Context);
   pragma Import (C, C_SHA512_Init, "SHA512_Init");

   procedure C_SHA512_Update (Context : SHA512_Context_Ptr;
                              Data    : Block_Type_Ptr;
                              Length  : Interfaces.C.Size_t);
   pragma Import (C, C_SHA512_Update, "SHA512_Update");

   procedure C_SHA512_Final (MD      : Hash_Type_Ptr;
                             Context : SHA512_Context_Ptr);
   pragma Import (C, C_SHA512_Final, "SHA512_Final");

end OpenSSL;
