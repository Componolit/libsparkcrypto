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

with SHA2, Types, IO;
use type SHA2.Hash_Type;
use type SHA2.Block_Index;
use type Types.Word8;
use type Types.Word64;

--# inherit SHA2, Types, IO;

--# main_program;
procedure Main
--# global IO.Inputs;
--# derives null from IO.Inputs;
is
--# hide Main;

    type Byte_Index is range 0 .. 7;
    type Byte_Array is array (Byte_Index) of Types.Word8;

    Ctx        : SHA2.Context_Type;
    Data       : Types.Word64;
    Hash       : SHA2.Hash_Type;
    Next_Bytes : Byte_Array;
    Block      : SHA2.Block_Type          := SHA2.Block_Type'(others => 0);
    Block_Len  : Types.Word64 := 0;

    procedure Print_Word64 (Item : in Types.Word64)
    --# derives null from Item;
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
    --# derives null from Hash;
    is
    begin
       for Index in SHA2.Hash_Index
       --# assert Index in SHA2.Hash_Index;
       loop
          Print_Word64 (Hash (Index));
       end loop;
    end Print_Hash;

    function To_Word64 (Data : Byte_Array) return Types.Word64
    is
       Result : Types.Word64 := 0;
    begin

       for Index in Byte_Index
       --# assert Index in Byte_Index;
       loop
         Result := Result xor Types.SHL (Types.Word64 (Data (Index)), 8 * Natural ((Byte_Index'Last - Index)));
       end loop;

       return Result;

    end To_Word64;

begin

    Ctx := SHA2.Context_Init;

    while not IO.End_Of_Stream
    loop

        for Index in SHA2.Block_Index
        loop

            for Byte_Pos in Byte_Index
            loop
                if not IO.End_Of_Stream
                then
                    Next_Bytes (Byte_Pos) := IO.Read_Byte;
                    Block_Len             := Block_Len + 8;
                    IO.Put_Word8 (Next_Bytes (Byte_Pos));
                else
                    Next_Bytes (Byte_Pos) := 0;
                end if;
            end loop;

            Block (Index) := To_Word64 (Next_Bytes);

        end loop;

        if Block_Len = 1024
        then
            SHA2.Context_Update (Ctx, Block);
            Block_Len := 0;
        end if;

    end loop;

    Hash := SHA2.Context_Finalize (Ctx, Block, Block_Len);
    Print_Hash (Hash);

end Main;
