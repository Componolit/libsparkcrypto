package body OpenSSL is

   procedure Context_Init (Context : in out SHA512_Context_Type)
   is
   begin
      OpenSSL.C_SHA512_Init (Context.C_Context'Unrestricted_Access);
   end Context_Init;

   procedure Context_Update (Context : in out SHA512_Context_Type;
                             Block   : in     LSC.SHA2.Block_Type)
   is
   begin
      OpenSSL.C_SHA512_Update (Context.C_Context'Unrestricted_Access,
                               Block'Unrestricted_Access,
                               128);
   end Context_Update;

   procedure Context_Finalize (Context : in out SHA512_Context_Type;
                               Block   : in     LSC.SHA2.Block_Type;
                               Length  : in     LSC.SHA2.Block_Length_Type)
   is
   begin
      OpenSSL.C_SHA512_Update (Context.C_Context'Unrestricted_Access,
                               Block'Unrestricted_Access,
                               Interfaces.C.size_t (Length / 8));
      OpenSSL.C_SHA512_Final (Context.Hash'Unrestricted_Access,
                              Context.C_Context'Unrestricted_Access);
   end Context_Finalize;

   function SHA512_Get_Hash (Context : in SHA512_Context_Type) return LSC.SHA2.SHA512_Hash_Type
   is
   begin
      return Context.Hash;
   end SHA512_Get_Hash;

end OpenSSL;
