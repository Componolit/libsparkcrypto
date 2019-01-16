with LSC.Internal.Types;
with LSC.Internal.Byteorder32;
with LSC.Internal.Byteorder64;

package Util
is

   function N (Item : LSC.Internal.Types.Word64) return LSC.Internal.Types.Word64 is (LSC.Internal.Byteorder64.BE_To_Native (Item));
   function M (Item : LSC.Internal.Types.Word32) return LSC.Internal.Types.Word32 is (LSC.Internal.Byteorder32.BE_To_Native (Item));

end Util;
