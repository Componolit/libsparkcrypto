with LSC.Internal.SHA256;
with Ada.Unchecked_Conversion;

package body LSC.SHA2 is

   -----------------
   -- Hash_SHA256 --
   -----------------

   function Hash_SHA256 (Message : LSC.Types.Bytes) return LSC.Types.Bytes
   is
      use type Internal.SHA256.Block_Length_Type;

      Context : Internal.SHA256.Context_Type := Internal.SHA256.SHA256_Context_Init;

      Block_Len     : constant := 64;
      Full_Blocks   : constant Natural := Message'Length / Block_Len;
      Partial_Bytes : constant Natural := Message'Length - Full_Blocks * Block_Len;

      subtype Block_Type is LSC.Types.Bytes (1 .. Block_Len);
      function To_Internal is new Ada.Unchecked_Conversion (Block_Type, Internal.SHA256.Block_Type);

      Temp : Block_Type := (others => 0);

      subtype Hash_Type is LSC.Types.Bytes (1 .. 32);
      function To_Public is new Ada.Unchecked_Conversion (Internal.SHA256.SHA256_Hash_Type, Hash_Type);
   begin
      for I in 0 .. Full_Blocks - 1
      loop
         Internal.SHA256.Context_Update
            (Context => Context,
             Block   => To_Internal (Message (Message'First + I * Block_Len .. Message'First + I * Block_Len + Block_Len - 1)));
      end loop;

      Temp (Temp'First .. Temp'First + Partial_Bytes - 1) :=
         Message (Message'First + Block_Len * Full_Blocks .. Message'First + Block_Len * Full_Blocks + Partial_Bytes - 1);

      Internal.SHA256.Context_Finalize
         (Context => Context,
          Block   => To_Internal (Temp),
          Length  => 8 * Internal.SHA256.Block_Length_Type (Partial_Bytes));

      return To_Public (Internal.SHA256.SHA256_Get_Hash (Context));
   end Hash_SHA256;

   ----------
   -- Hash --
   ----------

   function Hash
     (Algorithm : Algorithm_Type;
      Message   : LSC.Types.Bytes) return LSC.Types.Bytes
   is
      Invalid : constant LSC.Types.Bytes (1 .. 1) := (others => 0);
   begin
      case Algorithm is
         when SHA256 => return Hash_SHA256 (Message);
         when others => return Invalid;
      end case;
   end Hash;

end LSC.SHA2;
