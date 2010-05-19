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

with Ada.Text_IO, LSC.Debug, LSC.IO;

package body LSC.AES.Print is

   package SIIO is new Ada.Text_IO.Integer_IO (LSC.AES.Schedule_Index);

   procedure Print_Schedule (S : LSC.AES.Schedule_Type)
   is
   begin
      for Index in LSC.AES.Schedule_Index
      loop
         LSC.IO.Put ("   W");
         SIIO.Put (Item => Index, Width => 3);
         LSC.IO.Put (" = ");
         LSC.Debug.Print_Word32 (S (Index));
         if Index mod  LSC.AES.Nb = LSC.AES.Nb - 1
         then
            LSC.IO.New_Line;
         end if;
      end loop;
      LSC.IO.New_Line;
   end Print_Schedule;

   procedure Print_Schedule_Index (I : Schedule_Index)
   is
   begin
       SIIO.Put (Item => I, Width => 3);
   end Print_Schedule_Index;

   procedure Print_Block (B : LSC.AES.Block_Type)
   is
   begin
      for Index in LSC.AES.Block_Index
      loop
         LSC.Debug.Print_Word32 (B (Index));
      end loop;
   end Print_Block;

   procedure Print_Key (K : LSC.AES.Key_Type)
   is
   begin
      for Index in LSC.AES.Key_Index
      loop
         LSC.Debug.Print_Word32 (K (Index));
      end loop;
   end Print_Key;

   procedure Print_Round (T : String;
                          R : LSC.AES.Schedule_Index;
                          B : LSC.AES.Block_Type)
   is
   begin
      LSC.Debug.Put ("round[");
      Print_Schedule_Index (R);
      LSC.Debug.Put ("]." & T & "      ");
      Print_Block (B);
      LSC.Debug.New_Line;
   end Print_Round;

end LSC.AES.Print;
