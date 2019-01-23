package body LSC.SHA2 is

   -----------------
   -- Hash_SHA256 --
   -----------------

   function Hash_SHA256 (Message : LSC.Types.Bytes) return LSC.Types.Bytes
   is
      use type Internal.SHA256.Block_Length_Type;
      Temp          : SHA256_Block_Type := (others => 0);
      Context       : Internal.SHA256.Context_Type := Internal.SHA256.SHA256_Context_Init;

      Full_Blocks   : constant Natural := Message'Length / SHA256_Block_Len;
      Partial_Bytes : constant Natural := Message'Length - Full_Blocks * SHA256_Block_Len;
   begin
      for I in 0 .. Full_Blocks - 1
      loop
         Internal.SHA256.Context_Update
            (Context => Context,
             Block   => To_Internal (Message (Message'First + I * SHA256_Block_Len ..
                                              Message'First + I * SHA256_Block_Len + SHA256_Block_Len - 1)));
      end loop;

      Temp (Temp'First .. Temp'First + Partial_Bytes - 1) :=
         Message (Message'First + SHA256_Block_Len * Full_Blocks ..
                  Message'First + SHA256_Block_Len * Full_Blocks + Partial_Bytes - 1);

      Internal.SHA256.Context_Finalize
         (Context => Context,
          Block   => To_Internal (Temp),
          Length  => 8 * Internal.SHA256.Block_Length_Type (Partial_Bytes));

      return To_Public (Internal.SHA256.SHA256_Get_Hash (Context));
   end Hash_SHA256;

   -----------------
   -- Hash_SHA384 --
   -----------------

   function Hash_SHA384 (Message : LSC.Types.Bytes) return LSC.Types.Bytes
   is
      use type Internal.SHA512.Block_Length_Type;

      Temp    : SHA512_Block_Type := (others => 0);
      Context : Internal.SHA512.Context_Type := Internal.SHA512.SHA384_Context_Init;

      Full_Blocks   : constant Natural := Message'Length / SHA512_Block_Len;
      Partial_Bytes : constant Natural := Message'Length - Full_Blocks * SHA512_Block_Len;
   begin
      for I in 0 .. Full_Blocks - 1
      loop
         Internal.SHA512.Context_Update
            (Context => Context,
             Block   => To_Internal (Message (Message'First + I * SHA512_Block_Len ..
                                              Message'First + I * SHA512_Block_Len + SHA512_Block_Len - 1)));
      end loop;

      Temp (Temp'First .. Temp'First + Partial_Bytes - 1) :=
         Message (Message'First + SHA512_Block_Len * Full_Blocks ..
                  Message'First + SHA512_Block_Len * Full_Blocks + Partial_Bytes - 1);

      Internal.SHA512.Context_Finalize
         (Context => Context,
          Block   => To_Internal (Temp),
          Length  => 8 * Internal.SHA512.Block_Length_Type (Partial_Bytes));

      return To_Public_384 (Internal.SHA512.SHA384_Get_Hash (Context));

   end Hash_SHA384;

   -----------------
   -- Hash_SHA512 --
   -----------------

   function Hash_SHA512 (Message : LSC.Types.Bytes) return LSC.Types.Bytes
   is
      use type Internal.SHA512.Block_Length_Type;

      Temp    : SHA512_Block_Type := (others => 0);
      Context : Internal.SHA512.Context_Type := Internal.SHA512.SHA512_Context_Init;

      Full_Blocks   : constant Natural := Message'Length / SHA512_Block_Len;
      Partial_Bytes : constant Natural := Message'Length - Full_Blocks * SHA512_Block_Len;
   begin
      for I in 0 .. Full_Blocks - 1
      loop
         Internal.SHA512.Context_Update
            (Context => Context,
             Block   => To_Internal (Message (Message'First + I * SHA512_Block_Len ..
                                              Message'First + I * SHA512_Block_Len + SHA512_Block_Len - 1)));
      end loop;

      Temp (Temp'First .. Temp'First + Partial_Bytes - 1) :=
         Message (Message'First + SHA512_Block_Len * Full_Blocks ..
                  Message'First + SHA512_Block_Len * Full_Blocks + Partial_Bytes - 1);

      Internal.SHA512.Context_Finalize
         (Context => Context,
          Block   => To_Internal (Temp),
          Length  => 8 * Internal.SHA512.Block_Length_Type (Partial_Bytes));

      return To_Public_512 (Internal.SHA512.SHA512_Get_Hash (Context));
   end Hash_SHA512;

   ----------
   -- Hash --
   ----------

   function Hash
     (Algorithm : Algorithm_Type;
      Message   : LSC.Types.Bytes) return LSC.Types.Bytes
   is
   begin
      case Algorithm is
         when SHA256 => return Hash_SHA256 (Message);
         when SHA384 => return Hash_SHA384 (Message);
         when SHA512 => return Hash_SHA512 (Message);
      end case;
   end Hash;

end LSC.SHA2;
