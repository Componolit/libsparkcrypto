with LSC.Types;
with LSC.Byteorder32;
with LSC.Byteorder64;

package Util
is

   function N (Item : LSC.Types.Word64) return LSC.Types.Word64 is (LSC.Byteorder64.BE_To_Native (Item));
   function M (Item : LSC.Types.Word32) return LSC.Types.Word32 is (LSC.Byteorder32.BE_To_Native (Item));

end Util;
