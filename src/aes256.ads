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

with Types;
--# inherit Types;

package AES256 is

   Nk : constant Positive :=  8;
   Nb : constant Positive :=  4;
   Nr : constant Positive := 14;

   subtype Key_Index is Natural range 1 .. Nk;
   type Key_Type is array (Key_Index) of Types.Word32;

   subtype Schedule_Index is Natural range 1 .. Nb * (Nr + 1);
   type Schedule_Type is array (Schedule_Index) of Types.Word32;

   function Key_Expansion (Key : Key_Type) return Schedule_Type;

end AES256;
