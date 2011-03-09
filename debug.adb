with Bignum;
with Types;
with Ada.Text_IO;

package body Debug
is
   procedure Message (Msg : String)
   is
   begin
      Ada.Text_IO.Put_Line (Msg);
   end;

   procedure Put_Big_Int
     (Item : Bignum.Big_Int;
      Columns : Natural)
   is
      package Word_IO is new Ada.Text_IO.Modular_IO (Types.Word32);
   begin
      for I in reverse Item'Range
      loop
         Word_IO.Put (Item => Item (I), Base => 16, Width => 12);
         Ada.Text_IO.Put (" ");
         if (Item'Last - I + 1) mod Columns = 0 then
            Ada.Text_IO.New_Line;
         end if;
      end loop;
      if Item'Length mod Columns /= 0 then
         Ada.Text_IO.New_Line;
      end if;
      Ada.Text_IO.New_Line;
   end Put_Big_Int;
end Debug;
