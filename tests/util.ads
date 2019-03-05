with LSC.Types;

with LSC.Internal.Types;
with LSC.Internal.Byteorder32;
with LSC.Internal.Byteorder64;

package Util
is

   function N (Item : LSC.Internal.Types.Word64) return LSC.Internal.Types.Word64
      is (LSC.Internal.Byteorder64.BE_To_Native (Item));
   function M (Item : LSC.Internal.Types.Word32) return LSC.Internal.Types.Word32
      is (LSC.Internal.Byteorder32.BE_To_Native (Item));

   --  Convert byte array to hex string
   function B2S (Data : LSC.Types.Bytes) return String;

   --  Convert hex string to byte array
   function S2B (Data : String) return LSC.Types.Bytes;

   --  Convert text to equivalent byte array representation
   function T2B (Data : String) return LSC.Types.Bytes;

   procedure T2B (Input  :     String;
                  Output : out LSC.Types.Bytes;
                  Last   : out LSC.Types.Natural_Index);

   --  Convert byte array to equivalent string representation
   function B2T (Data : LSC.Types.Bytes) return String;

end Util;
