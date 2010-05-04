--  This file is part of the sparkcrypto library.
--
--  Copyright (C) 2010  secunet Security Networks AG
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>

--  This library  is free software:  you can  redistribute it and/or  modify it
--  under the  terms of the GNU  Lesser General Public License  as published by
--  the Free Software Foundation, either version  3 of the License, or (at your
--  option) any later version.

--  This library is distributed in the hope that it will be useful, but WITHOUT
--  ANY  WARRANTY; without  even  the implied  warranty  of MERCHANTABILITY  or
--  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
--  for more details.

--  You should  have received a copy  of the GNU Lesser  General Public License
--  along with this library. If not, see <http://www.gnu.org/licenses/>.

with IO;
with Ada.Text_IO; use Ada.Text_IO;

package body SHA2.Debug is

    package SIO is new Ada.Text_IO.Integer_IO (SHA2.Schedule_Index);
    package IIO is new Ada.Text_IO.Integer_IO (Natural);

    procedure Put_Natural (I : Natural)
    is
    begin
       IIO.Put (I);
    end Put_Natural;

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
        Put_Line ("      a/e               b/f               c/g               d/h");
        for Index in SHA2.State_Index
        loop
            IO.Print_Word64 (S (Index));
            if Index = d then
                New_Line;
            else
                IO.Put ("  ");
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
            Put (" = ");
            IO.Print_Word64 (H (Index));
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
            Put (" = ");
            IO.Print_Word64 (S (Index));
            Put ("     W");
            SIO.Put (Second_Index);
            Put (" = ");
            IO.Print_Word64 (S (Second_Index));
            New_Line;
        end loop;
        New_Line;
        New_Line;
    end Put_Schedule;

end SHA2.Debug;
