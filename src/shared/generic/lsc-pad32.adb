-------------------------------------------------------------------------------
--  This file is part of the sparkcrypto library.
--
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>
--  Copyright (C) 2010  secunet Security Networks AG
--
--  This program is free software: you can redistribute it and/or modify it
--  under the terms of the GNU General Public License as published by the Free
--  Software Foundation, either version 3 of the License, or (at your option)
--  any later version.
--
--  This program is distributed in the hope that it will be useful, but WITHOUT
--  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
--  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
--  more details.
--  
--  You should have received a copy of the GNU General Public License along
--  with this program.  If not, see <http://www.gnu.org/licenses/>.
--  
--  As a special exception, if other files instantiate generics from this unit,
--  or you link this unit with other files to produce an executable, this unit
--  does not by itself cause the resulting executable to be covered by the GNU
--  General Public License. This exception does not however invalidate any
--  other reasons why the executable file might be covered by the GNU Public
--  License.
-------------------------------------------------------------------------------

with LSC.Byteorder32;

package body LSC.Pad32 is

   procedure Block_Terminate
     (Block  : in out Types.Word32_Array_Type;
      Length : in     Types.Word64)
   is
      pragma Inline (Block_Terminate);
      Temp   : Types.Word32;
      Index  : Types.Index;
      Offset : Natural;
   begin

      -- index of partial block
      Index := Types.Index'First + Types.Index (Length / 32);

      --# check Length = 0   -> Index =  0;
      --# check Length = 31  -> Index =  0;
      --# check Length = 32  -> Index =  1;
      --# check Length = 511 -> Index = 15;

      -- bit offset within the partial block
      Offset := Natural (31 - Length mod 32);

      --# check Length = 0   -> Offset = 31;
      --# check Length = 31  -> Offset =  0;
      --# check Length = 32  -> Offset = 31;
      --# check Length = 511 -> Offset =  0;

      Temp := Byteorder32.Native_To_BE (Block (Index));
      Temp := Temp and Types.SHL32 (not 0, Offset);
      Temp := Temp  or Types.SHL32 (1, Offset);
      Block (Index) := Byteorder32.BE_To_Native (Temp);

      if Index < Block'Last
      then
         for I in Types.Index range (Index + 1) .. Block'Last
         loop
            Block (I) := 0;
            --# assert
            --#    (for all P in Types.Index range
            --#       (Types.Index'First + Index + 1) .. I => (Block (P) = 0)) and
            --#    Index = Types.Index'First + Types.Index (Length / 32);
         end loop;
      end if;

   end Block_Terminate;

end LSC.Pad32;
