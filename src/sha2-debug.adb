with Ada.Text_IO; use Ada.Text_IO;

package body SHA2.Debug is

    package WIO is new Ada.Text_IO.Modular_IO (Types.Word64);
    package SIO is new Ada.Text_IO.Integer_IO (SHA2.Schedule_Index);

    procedure Put_T (T : SHA2.Schedule_Index)
    is
    begin
        Put ("t =");
        SIO.Put (T);
        New_Line;
    end Put_T;

    procedure Put_Line (T : String)
    is
    begin
        Ada.Text_IO.Put_Line (T);
    end Put_Line;

    procedure Put_State (S : SHA2.State_Type)
    is
    begin
        Put_Line ("          a/e                  b/f                  c/g                  d/h");
        for Index in SHA2.State_Index
        loop
            WIO.Put (Item => S (Index), Base => 16, Width => 21);
            if Index = d then
                New_Line;
            end if;
        end loop;
        New_Line;
        New_Line;
    end Put_State;

    procedure Put_Hash (H : SHA2.Hash_Type)
    is
    begin
        New_Line;
        for Index in SHA2.Hash_Index
        loop
            Put ("  H");
            Put (Index'Img);
            Put (": ");
            WIO.Put (Item => H (Index), Base => 16, Width => 21);
            New_Line;
        end loop;
        New_Line;
        New_Line;
    end Put_Hash;

    procedure Put_Schedule (S : SHA2.Schedule_Type)
    is
        Second_Index : Schedule_Index;
    begin
        New_Line;
        for Index in Schedule_Index range 0 .. 7
        loop
            Second_Index := Index + 8;
            Put ("  W");
            SIO.Put (Item => Index);
            Put (" =");
            WIO.Put (Item => S (Index), Base => 16, Width => 21);
            Put ("     W");
            SIO.Put (Second_Index);
            Put (" =");
            WIO.Put (Item => S (Second_Index), Base => 16, Width => 21);
            New_Line;
        end loop;
        New_Line;
        New_Line;
    end Put_Schedule;

end SHA2.Debug;
