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

with LSC.Types, LSC.IO;
with Ada.Text_IO.Text_Streams;
with Unchecked_Conversion;

use type LSC.Types.Word64;
use type LSC.Types.Word32;
use type LSC.Types.Byte;

package body LSC.IO is

   subtype Nibble is Natural range 0 .. 15;

   procedure Put (T : String) renames Ada.Text_IO.Put;
   procedure Put_Line (T : String) renames Ada.Text_IO.Put_Line;

   procedure New_Line is
   begin
      Ada.Text_IO.New_Line;
   end New_Line;

   function Read_Byte return  Types.Byte is
      Result : Types.Byte;
   begin
      Types.Byte'Read
        (Ada.Text_IO.Text_Streams.Stream (Ada.Text_IO.Standard_Input),
         Result);
      return Result;
   end Read_Byte;

   function End_Of_Stream return Boolean is
   begin
      return Ada.Text_IO.End_Of_File (Ada.Text_IO.Standard_Input);
   end End_Of_Stream;

   function Num_To_Char (N : Nibble) return Character is
      Digit  : Character;
   begin
      case N is
      when 16#0# =>
         Digit := '0';
      when 16#1# =>
         Digit := '1';
      when 16#2# =>
         Digit := '2';
      when 16#3# =>
         Digit := '3';
      when 16#4# =>
         Digit := '4';
      when 16#5# =>
         Digit := '5';
      when 16#6# =>
         Digit := '6';
      when 16#7# =>
         Digit := '7';
      when 16#8# =>
         Digit := '8';
      when 16#9# =>
         Digit := '9';
      when 16#A# =>
         Digit := 'a';
      when 16#B# =>
         Digit := 'b';
      when 16#C# =>
         Digit := 'c';
      when 16#D# =>
         Digit := 'd';
      when 16#E# =>
         Digit := 'e';
      when 16#F# =>
         Digit := 'f';
      end case;
      return Digit;
   end Num_To_Char;

   procedure Print_Byte (Item : in Types.Byte) is
   begin
      IO.Put (Num_To_Char (Nibble (Item / 16)) & Num_To_Char (Nibble (Item rem 16)));
   end Print_Byte;

   procedure Print_Word32 (Item : in Types.Word32) is
      subtype HD_Index is Positive range 1 .. 8;
      subtype HD_Type is String (HD_Index);

      Result : HD_Type;
      Number : Types.Word32;
   begin

      Number := Item;
      Result := HD_Type'(others => 'X');

      for Index in HD_Index
         --# assert Index in HD_Index;
      loop
         Result ((HD_Index'Last - Index) + 1)   := Num_To_Char (Nibble (Number mod 16));
         Number                                 := Number / 16;
      end loop;

      IO.Put (Result);
   end Print_Word32;

   procedure Print_Word64 (Item : in Types.Word64) is
      subtype HD_Index is Positive range 1 .. 16;
      subtype HD_Type is String (HD_Index);

      Result : HD_Type;
      Number : Types.Word64;
   begin

      Number := Item;
      Result := HD_Type'(others => 'X');

      for Index in HD_Index
         --# assert Index in HD_Index;
      loop
         Result ((HD_Index'Last - Index) + 1)   := Num_To_Char (Nibble (Number mod 16));
         Number                                 := Number / 16;
      end loop;

      IO.Put (Result);
   end Print_Word64;

   procedure Print_Hash (Hash : SHA2.SHA512_Hash_Type) is
   begin
      for Index in SHA2.SHA512_Hash_Index
         --# assert Index in SHA2.Hash_Index;
      loop
         Print_Word64 (Hash (Index));
      end loop;
   end Print_Hash;

   procedure Print_Block (Block : SHA2.Block_Type) is
   begin
      for Index in SHA2.Block_Index
         --# assert Index in SHA2.Block_Index;
      loop
         Print_Word64 (Block (Index));
         IO.Put ("  ");
         if Index mod 4 = 3
         then
            IO.New_Line;
         end if;
      end loop;
      IO.New_Line;
   end Print_Block;

   procedure Print_Index (I : in Types.Index)
   is
      package SIIO is new Ada.Text_IO.Integer_IO (LSC.Types.Index);
   begin
       SIIO.Put (Item => I, Width => 3);
   end Print_Index;

   procedure Print_Natural (I : Natural) is
      package IIO is new Ada.Text_IO.Integer_IO (Natural);
   begin
      IIO.Put (I);
   end Print_Natural;

   procedure Print_Word32_Array (Block : in Types.Word32_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean)
   is
   begin

      for I in Types.Index range Block'First .. Block'Last
      loop

         Print_Word32 (Block (I));

         -- space separate values
         for S in 1 .. Space
         loop
            IO.Put (" ");
         end loop;

         -- intermediate new line
         if I mod Break = Break - 1
         then
            IO.New_Line;
         end if;

      end loop;

      -- final new line
      if Newln
      then
         IO.New_Line;
      end if;

   end Print_Word32_Array;

   procedure Print_Word64_Array (Block : in Types.Word64_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean)
   is
   begin

      for I in Types.Index range Block'First .. Block'Last
      loop

         Print_Word64 (Block (I));

         -- space separate values
         for S in 1 .. Space
         loop
            IO.Put (" ");
         end loop;

         -- intermediate new line
         if I mod Break = Break - 1
         then
            IO.New_Line;
         end if;

      end loop;

      -- final new line
      if Newln
      then
         IO.New_Line;
      end if;

   end Print_Word64_Array;

end LSC.IO;
