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

with SHA2, Types, IO, Debug;
use type SHA2.Hash_Type;
use type Types.Word8;
use type Types.Word64;

--# inherit SHA2, Types, IO, Debug;

--# main_program;
procedure Main
--# derives ;
is
--# hide Main;

    type Byte_Index is range 0 .. 7;
    type Byte_Array is array (Byte_Index) of Types.Word8;

    Ctx        : SHA2.Context_Type;
    Hash       : SHA2.Hash_Type;
    Next_Bytes : Byte_Array;
    Block      : SHA2.Block_Type          := SHA2.Block_Type'(others => 0);
    Block_Len  : Types.Word64 := 0;

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

    SHA2.Context_Finalize (Ctx, Block, Block_Len);
    Hash := SHA2.Get_Hash (Ctx);
    Debug.Print_Hash (Hash);

end Main;
