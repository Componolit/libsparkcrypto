-------------------------------------------------------------------------------
-- This file is part of the sparkcrypto library.
--
-- Copyright (C) 2010  Alexander Senier <mail@senier.net>
-- Copyright (C) 2010  secunet Security Networks AG
--
-- libsparkcrypto is  free software; you  can redistribute it and/or  modify it
-- under  terms of  the GNU  General Public  License as  published by  the Free
-- Software  Foundation;  either version  3,  or  (at  your option)  any  later
-- version.  libsparkcrypto  is  distributed  in  the  hope  that  it  will  be
-- useful,  but WITHOUT  ANY WARRANTY;  without  even the  implied warranty  of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
--
-- As a  special exception under  Section 7 of GPL  version 3, you  are granted
-- additional  permissions  described in  the  GCC  Runtime Library  Exception,
-- version 3.1, as published by the Free Software Foundation.
--
-- You should  have received  a copy of  the GNU General  Public License  and a
-- copy  of  the  GCC  Runtime  Library  Exception  along  with  this  program;
-- see  the  files  COPYING3  and COPYING.RUNTIME  respectively.  If  not,  see
-- <http://www.gnu.org/licenses/>.
-------------------------------------------------------------------------------

with LSC.Debug;

package body LSC.AES.Print is

   procedure Print_Round (T : String;
                          R : LSC.AES.Schedule_Index;
                          B : LSC.AES.Block_Type)
   is
   begin
      LSC.Debug.Put ("round[");
      LSC.Debug.Print_Index (R);
      LSC.Debug.Put ("]." & T & "      ");
      LSC.Debug.Print_Word32_Array (B, 1, Types.Index'Last, True);
   end Print_Round;

   ----------------------------------------------------------------------------

   procedure Block
      (Header : String;
       Line   : String;
       Block  : Block_Type;
       Index  : LSC.AES.Schedule_Index)
   is
   begin
      Debug.Put_Line (Header);
      Debug.Print_Word32_Array (Block, 1, 8, True);
      Debug.New_Line;
      Debug.New_Line;
      Print.Print_Round (Line, Index, Block);
   end Block;

   ----------------------------------------------------------------------------

   procedure Header
      (Initial_Schedule : Types.Word32_Array_Type)
   is
   begin
      Debug.Put_Line ("Initial schedule:");                                                                    --
      Debug.Print_Word32_Array (Initial_Schedule, 1, 4, True);                                                           --
      Debug.New_Line;                                                                                          --
      Debug.Put_Line (" -----+----------+----------+----------+----------+----------+----------+---------- "); --
      Debug.Put_Line ("|  i  |          |  After   |  After   |          |After XOR |          |  w[i] =  |"); --
      Debug.Put_Line ("|(dec)|   temp   |RotWord() |SubWord() |Rcon[i/Nk]|with Rcon | w[i-Nk]  | temp XOR |"); --
      Debug.Put_Line ("|     |          |          |          |          |          |          |  w[i-Nk] |"); --
      Debug.Put_Line (" -----+----------+----------+----------+----------+----------+----------+---------- "); --
   end Header;

   ----------------------------------------------------------------------------

   procedure Footer
      (Final_Schedule : Types.Word32_Array_Type)
   is
   begin
      Debug.Put_Line (" -----+----------+----------+----------+----------+----------+----------+---------- ");
      Debug.Put_Line ("Final schedule:");
      Debug.Print_Word32_Array (Final_Schedule, 1, 4, True);
   end Footer;

   ----------------------------------------------------------------------------

   procedure Index (I : Types.Index)
   is
   begin
      Debug.Put ("| ");
      Debug.Print_Index (I);
      Debug.Put (" |");
   end Index;

   ----------------------------------------------------------------------------

   procedure Row (I : Types.Word32)
   is
   begin
      Debug.Put (" ");
      Debug.Print_Word32 (I);
      Debug.Put (" |");
   end Row;

   ----------------------------------------------------------------------------

   procedure Empty (N : Positive)
   is
   begin
      for I in 1 .. N
      loop
         Debug.Put ("          |"); --
      end loop;
   end Empty;

end LSC.AES.Print;
