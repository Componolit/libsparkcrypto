with LSC.Internal.Debug;

package body LSC.Internal.Bignum.Print
  with SPARK_Mode => Off
is

   procedure Print_Big_Int
     (Item    : LSC.Internal.Bignum.Big_Int;
      Columns : Natural)
   is
   begin
      for I in reverse Item'Range
      loop
         LSC.Internal.Debug.Print_Word32 (Item (I));
         LSC.Internal.Debug.Put (" ");
         if (Item'Last - I + 1) mod Columns = 0 then
            LSC.Internal.Debug.New_Line;
         end if;
      end loop;
      if Item'Length mod Columns /= 0 then
         LSC.Internal.Debug.New_Line;
      end if;
      LSC.Internal.Debug.New_Line;
   end Print_Big_Int;

end LSC.Internal.Bignum.Print;
