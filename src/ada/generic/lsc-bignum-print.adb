with LSC.Debug;

package body LSC.Bignum.Print
is

   procedure Print_Big_Int
     (Item    : LSC.Bignum.Big_Int;
      Columns : Natural)
   is
   begin
      for I in reverse Item'Range
      loop
         LSC.Debug.Print_Word32 (Item (I));
         LSC.Debug.Put (" ");
         if (Item'Last - I + 1) mod Columns = 0 then
            LSC.Debug.New_Line;
         end if;
      end loop;
      if Item'Length mod Columns /= 0 then
         LSC.Debug.New_Line;
      end if;
      LSC.Debug.New_Line;
   end Print_Big_Int;

end LSC.Bignum.Print;
