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

with Ada.Text_IO.Text_Streams;

package body IO is

    procedure Put (T : String) renames Ada.Text_IO.Put;
    procedure Put_Line (T : String) renames Ada.Text_IO.Put_Line;

    function Read_Character return Character
    is
       Result : Character;
    begin
      Character'Read
               (Ada.Text_IO.Text_Streams.Stream (Ada.Text_IO.Standard_Input), Result);
      return Result;
    end Read_Character;

    function End_Of_Stream return Boolean
    is
    begin
       return Ada.Text_IO.End_Of_File (Ada.Text_IO.Standard_Input);
    end End_Of_Stream;

end IO;
