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

package body LSC.Ops64 is

   function Bytes_To_Word
      (Byte0 : Types.Byte;
       Byte1 : Types.Byte;
       Byte2 : Types.Byte;
       Byte3 : Types.Byte;
       Byte4 : Types.Byte;
       Byte5 : Types.Byte;
       Byte6 : Types.Byte;
       Byte7 : Types.Byte) return Types.Word64
   is
   begin
      return Types.Byte_Array64_To_Word64
          (Types.Byte_Array64_Type'(Byte7, Byte6, Byte5, Byte4,
                                    Byte3, Byte2, Byte1, Byte0));
   end Bytes_To_Word;

   ----------------------------------------------------------------------------

   function XOR2 (V0, V1 : Types.Word64) return Types.Word64
   is
   begin
      return V0 xor V1;
   end XOR2;

   ----------------------------------------------------------------------------

   procedure Block_XOR
     (Left   : in     Types.Word64_Array_Type;
      Right  : in     Types.Word64_Array_Type;
      Result :    out Types.Word64_Array_Type)
   is
   begin
      for I in Types.Index range Result'First .. Result'Last
      loop

         --# check
         --#    I <= Left'Last   and
         --#    I <= Right'Last  and
         --#    I <= Result'Last;

         --# accept Flow, 23, Result, "Initialized in complete loop";
         Result (I) := XOR2 (Left (I), Right (I));

         --# assert
         --#   (for all Pos in Types.Index range Result'First .. I =>
         --#       (Result (Pos) = XOR2 (Left (Pos), Right (Pos))));

      end loop;

      --# accept Flow, 602, Result, Result, "Initialized in complete loop";
   end Block_XOR;

end LSC.Ops64;
