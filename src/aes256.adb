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

package body AES256 is

   function Key_Expansion (Key : Key_Type) return Schedule_Type is
      Temp   : Types.Word32;
      Index  : Key_Index := Key_Index'First;
      Result : Schedule_Type;
   begin

      for Index in Key_Index
      loop
         Result (Index) := Key (Index);
      end loop;

      for Index in Schedule_Index range Key_Index'Last + 1 .. Schedule_Index'Last
      loop
         Temp := Result (Index - 1);
         if Index mod Nk = 0
         then
            Temp := Sub_Word (Rot_Word (Temp)) xor Rcon (Index/Nk);
         else if Index mod Nk = 4
         then
            Temp := Sub_Word (Temp);
         end if;
         Result (Index) := Result (Index - 1) xor Temp;
      end loop;
   end Key_Expansion;

end AES256;
