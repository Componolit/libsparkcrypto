with LSC.Internal.Types;

package LSC.Internal.Math_Int
with
   SPARK_Mode => On
is
   pragma Pure;

   type Math_Int is private;

   function "+" (A : Math_Int; B : Math_Int) return Math_Int
     with Ghost, Import, Global => null;

   function "-" (A : Math_Int; B : Math_Int) return Math_Int
     with Ghost, Import, Global => null;

   function "*" (A : Math_Int; B : Math_Int) return Math_Int
     with Ghost, Import, Global => null;

   function "/" (A : Math_Int; B : Math_Int) return Math_Int
     with Ghost, Import, Global => null;

   function "mod" (A : Math_Int; B : Math_Int) return Math_Int
     with Ghost, Import, Global => null;

   function "**" (A : Math_Int; B : Natural) return Math_Int
     with Ghost, Import, Global => null;

   function "**" (A : Math_Int; B : Math_Int) return Math_Int
     with Ghost, Import, Global => null;

   function "=" (A : Math_Int; B : Math_Int) return Boolean
     with Ghost, Import, Global => null;

   function "<" (A : Math_Int; B : Math_Int) return Boolean
     with Ghost, Import, Global => null;

   function ">" (A : Math_Int; B : Math_Int) return Boolean
     with Ghost, Import, Global => null;

   function "<=" (A : Math_Int; B : Math_Int) return Boolean
     with Ghost, Import, Global => null;

   function ">=" (A : Math_Int; B : Math_Int) return Boolean
     with Ghost, Import, Global => null;

   function From_Integer (A : Integer) return Math_Int
     with Ghost, Import, Global => null;

   function From_Word32 (A : Types.Word32) return Math_Int
     with Ghost, Import, Global => null;

   function From_Word64 (A : Types.Word64) return Math_Int
     with Ghost, Import, Global => null;

private
   pragma SPARK_Mode (Off);

   type Math_Int is new Integer;
end LSC.Internal.Math_Int;
