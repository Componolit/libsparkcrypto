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

package body LSC.SHA2.Print is

   procedure Put_Line (T : String) is
   begin
      --# accept Flow, 30, T, "Null implementation";
      null;
   end Put_Line;

   procedure Put_Natural (I : Natural) is
   begin
      --# accept Flow, 30, I, "Null implementation";
      null;
   end Put_Natural;

   procedure Put_T (T : SHA2.Schedule_Index) is
   begin
      --# accept Flow, 30, T, "Null implementation";
      null;
   end Put_T;

   procedure Put_State (S : SHA2.State_Type) is
   begin
      --# accept Flow, 30, S, "Null implementation";
      null;
   end Put_State;

   procedure Put_Hash (H : SHA2.SHA512_Hash_Type) is
   begin
      --# accept Flow, 30, H, "Null implementation";
      null;
   end Put_Hash;

   procedure Put_Schedule (S : SHA2.Schedule_Type) is
   begin
      --# accept Flow, 30, S, "Null implementation";
      null;
   end Put_Schedule;

end LSC.SHA2.Print;
