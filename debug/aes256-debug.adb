--  This file is part of the sparkcrypto library.

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

with Ada.Text_IO, LSC.Debug, IO;

package body AES256.Debug is

   package SIIO is new Ada.Text_IO.Integer_IO (AES256.Schedule_Index);

   procedure Print_Schedule (S : AES256.Schedule_Type)
   is
   begin
      for Index in AES256.Schedule_Index
      loop
         IO.Put ("   W");
         SIIO.Put (Item => Index, Width => 3);
         IO.Put (" = ");
         LSC.Debug.Print_Word32 (S (Index));
         if Index mod  AES256.Nb = 0
         then
            IO.New_Line;
         end if;
      end loop;
      IO.New_Line;
   end Print_Schedule;

   procedure Print_Schedule_Index (I : Schedule_Index)
   is
   begin
       SIIO.Put (Item => I, Width => 3);
   end Print_Schedule_Index;

end AES256.Debug;
