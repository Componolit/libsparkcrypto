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

with LSC.SHA2, LSC.Types, LSC.IO;
use type LSC.SHA2.SHA512_Hash_Type;
use type LSC.Types.Byte;
use type LSC.Types.Word64;

--# inherit LSC.IO,
--#         LSC.SHA2,
--#         LSC.Types;

--# main_program;
procedure Main
   --# derives ;
is
   --# hide Main;

   type Byte_Index is range 0 .. 7;
   type Byte_Array is array (Byte_Index) of LSC.Types.Byte;

   Ctx        : LSC.SHA2.Context_Type;
   Hash       : LSC.SHA2.SHA512_Hash_Type;
   Next_Bytes : Byte_Array;
   Block      : LSC.SHA2.Block_Type := LSC.SHA2.Block_Type'(others => 0);
   Block_Len  : LSC.Types.Word64    := 0;

   function To_Word64 (Data : Byte_Array) return LSC.Types.Word64 is
      Result : LSC.Types.Word64 := 0;
   begin

      for Index in Byte_Index
         --# assert Index in Byte_Index;
      loop
         Result := Result xor
                   LSC.Types.SHL
                      (LSC.Types.Word64 (Data (Index)),
                       8 * Natural ((Byte_Index'Last - Index)));
      end loop;

      return Result;

   end To_Word64;

begin

   Ctx := LSC.SHA2.SHA512_Context_Init;

   while not LSC.IO.End_Of_Stream
   loop

      for Index in LSC.SHA2.Block_Index
      loop

         for Byte_Pos in Byte_Index
         loop
            if not LSC.IO.End_Of_Stream
            then
               Next_Bytes (Byte_Pos) := LSC.IO.Read_Byte;
               Block_Len             := Block_Len + 8;
            else
               Next_Bytes (Byte_Pos) := 0;
            end if;
         end loop;

         Block (Index) := To_Word64 (Next_Bytes);

      end loop;

      if Block_Len = 1024
      then
         LSC.SHA2.Context_Update (Ctx, Block);
         Block_Len := 0;
      end if;

   end loop;

   LSC.SHA2.Context_Finalize (Ctx, Block, Block_Len);
   Hash := LSC.SHA2.SHA512_Get_Hash (Ctx);
   LSC.IO.Print_Hash (Hash);

end Main;
