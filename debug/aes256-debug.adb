with LSC.Debug, IO;

package body AES256.Debug is

   procedure Print_Schedule (S : AES256.Schedule_Type) is
   begin
      for Index in AES256.Schedule_Index
      loop
         IO.Put ("W" & Index'Img & "= ");
         LSC.Debug.Print_Word32 (S (Index));
         if Index mod 4 = 3
         then
            IO.New_Line;
         end if;
      end loop;
      IO.New_Line;
   end Print_Schedule;

end AES256.Debug;
