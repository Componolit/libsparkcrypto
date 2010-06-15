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

package body LSC.Ops64 is

   function Bytes64_To_Word64
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
   end Bytes64_To_Word64;

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
      Result : in out Types.Word64_Array_Type)
   is
   begin
      for I in Types.Index range Result'First .. Result'Last
      loop
         --# check
         --#    I <= Left'Last   and
         --#    I <= Right'Last  and
         --#    I <= Result'Last;
         Result (I) := XOR2 (Left (I), Right (I));
         --# assert
         --#   (for all Pos in Types.Index range Result'First .. I =>
         --#       (Result (Pos) = XOR2 (Left (Pos), Right (Pos))));
      end loop;
   end Block_XOR;

   ----------------------------------------------------------------------------

   function Byte_Swap (Value : Types.Word64) return Types.Word64
   is
      Temp : Types.Byte_Array64_Type;
   begin
      Temp := Types.Word64_To_Byte_Array64 (Value);
      return Bytes64_To_Word64 (Temp (0), Temp (1), Temp (2), Temp (3),
                                Temp (4), Temp (5), Temp (6), Temp (7));
   end Byte_Swap;

end LSC.Ops64;
