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
use type Types.Word64;

package body Debug is

    procedure Print_Word64 (Item : in Types.Word64)
    is
       subtype HD_Index is Positive range 1 .. 16;
       subtype HD_Type is String (HD_Index);
       subtype Nibble is Natural range 0 .. 15;

       Result : HD_Type;
       Digit  : Character;
       Number : Types.Word64;
    begin

       Number := Item;
       Result := HD_Type'(others => 'X');

       for Index in HD_Index
       --# assert Index in HD_Index;
       loop

          case Nibble(Number mod 16) is
             when 16#0# => Digit := '0';
             when 16#1# => Digit := '1';
             when 16#2# => Digit := '2';
             when 16#3# => Digit := '3';
             when 16#4# => Digit := '4';
             when 16#5# => Digit := '5';
             when 16#6# => Digit := '6';
             when 16#7# => Digit := '7';
             when 16#8# => Digit := '8';
             when 16#9# => Digit := '9';
             when 16#A# => Digit := 'a';
             when 16#B# => Digit := 'b';
             when 16#C# => Digit := 'c';
             when 16#D# => Digit := 'd';
             when 16#E# => Digit := 'e';
             when 16#F# => Digit := 'f';
         end case;

          Result ((HD_Index'Last - Index) + 1) := Digit;
          Number := Number / 16;

       end loop;

       IO.Put (Result);
    end Print_Word64;

    procedure Print_Hash (Hash : SHA2.Hash_Type)
    is
    begin
       for Index in SHA2.Hash_Index
       --# assert Index in SHA2.Hash_Index;
       loop
          Print_Word64 (Hash (Index));
       end loop;
    end Print_Hash;

end Debug;
