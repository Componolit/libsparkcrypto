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

with LSC.IO;
with Ada.Text_IO; use Ada.Text_IO;

package body LSC.SHA2.Print is

   procedure Put_State (S : SHA2.State_Type) is
   begin
      Put_Line
        ("      a/e               b/f               c/g               d/h");
      for Index in SHA2.State_Index
      loop
         LSC.IO.Print_Word64 (S (Index));
         if Index = d
         then
            New_Line;
         else
            LSC.IO.Put ("  ");
         end if;
      end loop;
      New_Line;
      New_Line;
   end Put_State;

end LSC.SHA2.Print;
