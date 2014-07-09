with LSC.Types;

package LSC.Math_Int
is
   type Math_Int is private;

   function "+" (A : Math_Int; B : Math_Int) return Math_Int
     with Convention => Ghost, Import, Global => Null;

   function "-" (A : Math_Int; B : Math_Int) return Math_Int
     with Convention => Ghost, Import, Global => Null;

   function "*" (A : Math_Int; B : Math_Int) return Math_Int
     with Convention => Ghost, Import, Global => Null;

   function "/" (A : Math_Int; B : Math_Int) return Math_Int
     with Convention => Ghost, Import, Global => Null;

   function "mod" (A : Math_Int; B : Math_Int) return Math_Int
     with Convention => Ghost, Import, Global => Null;

   function "**" (A : Math_Int; B : Natural) return Math_Int
     with Convention => Ghost, Import, Global => Null;

   function "**" (A : Math_Int; B : Math_Int) return Math_Int
     with Convention => Ghost, Import, Global => Null;

   function "=" (A : Math_Int; B : Math_Int) return Boolean
     with Convention => Ghost, Import, Global => Null;

   function "<" (A : Math_Int; B : Math_Int) return Boolean
     with Convention => Ghost, Import, Global => Null;

   function ">" (A : Math_Int; B : Math_Int) return Boolean
     with Convention => Ghost, Import, Global => Null;

   function "<=" (A : Math_Int; B : Math_Int) return Boolean
     with Convention => Ghost, Import, Global => Null;

   function ">=" (A : Math_Int; B : Math_Int) return Boolean
     with Convention => Ghost, Import, Global => Null;

   function From_Integer (A : Integer) return Math_Int
     with Convention => Ghost, Import, Global => Null;

   function From_Word32 (A : Types.Word32) return Math_Int
     with Convention => Ghost, Import, Global => Null;

   function From_Word64 (A : Types.Word64) return Math_Int
     with Convention => Ghost, Import, Global => Null;

private
   pragma SPARK_Mode (Off);

   type Math_Int is new Integer;
end LSC.Math_Int;
