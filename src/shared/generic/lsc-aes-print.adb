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

package body LSC.AES.Print is

   procedure Print_Round (T : String;
                          R : AES.Schedule_Index;
                          B : AES.Block_Type)
   is
   begin
      --# accept Flow, 30, T, "Null implementation" &
      --#        Flow, 30, R, "Null implementation" &
      --#        Flow, 30, B, "Null implementation";
      null;
   end Print_Round;

end LSC.AES.Print;