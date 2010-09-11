-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2010, Alexander Senier
-- Copyright (C) 2010, secunet Security Networks AG
-- All rights reserved.
--
-- Redistribution  and  use  in  source  and  binary  forms,  with  or  without
-- modification, are permitted provided that the following conditions are met:
--
--    * Redistributions of source code must retain the above copyright notice,
--      this list of conditions and the following disclaimer.
--
--    * Redistributions in binary form must reproduce the above copyright
--      notice, this list of conditions and the following disclaimer in the
--      documentation and/or other materials provided with the distribution.
--
--    * Neither the name of the  nor the names of its contributors may be used
--      to endorse or promote products derived from this software without
--      specific prior written permission.
--
-- THIS SOFTWARE IS PROVIDED BY THE  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-- AND ANY  EXPRESS OR IMPLIED WARRANTIES,  INCLUDING, BUT NOT LIMITED  TO, THE
-- IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
-- ARE  DISCLAIMED. IN  NO EVENT  SHALL  THE COPYRIGHT  HOLDER OR  CONTRIBUTORS
-- BE  LIABLE FOR  ANY  DIRECT, INDIRECT,  INCIDENTAL,  SPECIAL, EXEMPLARY,  OR
-- CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT  LIMITED  TO,  PROCUREMENT  OF
-- SUBSTITUTE GOODS  OR SERVICES; LOSS  OF USE,  DATA, OR PROFITS;  OR BUSINESS
-- INTERRUPTION)  HOWEVER CAUSED  AND ON  ANY THEORY  OF LIABILITY,  WHETHER IN
-- CONTRACT,  STRICT LIABILITY,  OR  TORT (INCLUDING  NEGLIGENCE OR  OTHERWISE)
-- ARISING IN ANY WAY  OUT OF THE USE OF THIS SOFTWARE, EVEN  IF ADVISED OF THE
-- POSSIBILITY OF SUCH DAMAGE.
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
