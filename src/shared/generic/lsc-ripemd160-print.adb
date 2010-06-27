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

package body LSC.RIPEMD160.Print is

   procedure Print_Schedule (M : String;
                             A : Types.Word32;
                             B : Types.Word32;
                             C : Types.Word32;
                             D : Types.Word32;
                             E : Types.Word32;
                             X : Types.Word32;
                             S : Natural)
   is
   begin
      --# accept Flow, 30, M, "Null implementation" &
      --#        Flow, 30, A, "Null implementation" &
      --#        Flow, 30, B, "Null implementation" &
      --#        Flow, 30, C, "Null implementation" &
      --#        Flow, 30, D, "Null implementation" &
      --#        Flow, 30, E, "Null implementation" &
      --#        Flow, 30, X, "Null implementation" &
      --#        Flow, 30, S, "Null implementation";
      null;
   end Print_Schedule;

end LSC.RIPEMD160.Print;