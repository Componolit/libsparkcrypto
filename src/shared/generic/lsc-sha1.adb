-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2011, Adrian-Ken Rueegsegger
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

with LSC.Ops32;
with LSC.Pad32;
with LSC.Debug;
with LSC.Byteorder32;

package body LSC.SHA1 is

   function Init_Data_Length return Data_Length is
   begin
      return Data_Length'(0, 0);
   end Init_Data_Length;

   ---------------------------------------------------------------------------

   procedure Add (Item  : in out Data_Length;
                  Value : in     Types.Word32)
   --# derives Item from *,
   --#                   Value;
   is
   begin
      if Item.LSW > Types.Word32'Last - Value then
         Item.MSW := Item.MSW + 1;
      end if;

      Item.LSW := Item.LSW + Value;
   end Add;

   ----------------------------------------------------------------------------

   function Ch
     (x    : Types.Word32;
      y    : Types.Word32;
      z    : Types.Word32)
      return Types.Word32
   --# return (x and y) xor ((not x) and z);
   is
      pragma Inline (Ch);

      -- This is a workaround for the simplifier, which is not able
      -- to discharge the (not x) expression directly due to a search
      -- depth limit.
      Not_X : Types.Word32;
   begin
      Not_X := not x;
      --# assert Not_X in Types.Word32 and Not_X = not x;
      return ((x and y) xor (Not_X and z));
   end Ch;

   ----------------------------------------------------------------------------

   function Maj
     (x    : Types.Word32;
      y    : Types.Word32;
      z    : Types.Word32)
      return Types.Word32
   --# return (x and y) xor (x and z) xor (y and z);
   is
      pragma Inline (Maj);
   begin
      return (x and y) xor (x and z) xor (y and z);
   end Maj;

   ---------------------------------------------------------------------------

   function Context_Init return Context_Type
   is
   begin
      return Context_Type'
        (Length => Init_Data_Length,
         H      => Hash_Type'(0 => 16#67452301#,
                              1 => 16#efcdab89#,
                              2 => 16#98badcfe#,
                              3 => 16#10325476#,
                              4 => 16#c3d2e1f0#));
   end Context_Init;

   ---------------------------------------------------------------------------

   procedure Context_Update_Internal
     (Context : in out Context_Type;
      Block   : in     Block_Type)
   --# derives Context from *,
   --#                      Block;
   is
      W                   : Schedule_Type := Null_Schedule;
      a, b, c, d, e, Temp : Types.Word32;
   begin

      pragma Debug (Debug.Put_Line ("BLOCK UPDATE:"));

      -- Print out initial state of H
      pragma Debug (Debug.Put_Line ("SHA-1 initial hash values:"));
      pragma Debug (Debug.Print_Word32_Array (Context.H, 2, Types.Index'Last, True));

      -------------------------------------------
      --  Section 6.1.2 SHA-1 Hash Computations
      -------------------------------------------

      --  1. Prepare the message schedule, W(t):
      for t in Schedule_Index range 0 .. 15
      loop
         W (t) := Byteorder32.Native_To_BE (Block (t));
      end loop;

      for t in Schedule_Index range 16 .. 79
      loop
         W (t) := Types.ROTL32
           (Ops32.XOR4
              (W (t - 3),
               W (t - 8),
               W (t - 14),
               W (t - 16)), 1);
      end loop;

      pragma Debug (Debug.Put_Line ("Message block:"));
      pragma Debug (Debug.Print_Word32_Array (W, 2, 8, True));

      -- 2. Initialize the five working variables a, b, c, d and e with the
      --    (i-1)st hash value:
      a := Context.H (0);
      b := Context.H (1);
      c := Context.H (2);
      d := Context.H (3);
      e := Context.H (4);

      -- 3. For t = 0 to 79:

      for I in Schedule_Index range 0 .. 19
      loop
         Temp := Types.ROTL32 (a, 5) + Ch (b, c, d) + e + K1 + W (I);
         e := d;
         d := c;
         c := Types.ROTL32 (b, 30);
         b := a;
         a := Temp;
      end loop;

      for I in Schedule_Index range 20 .. 39
      loop
         Temp := Types.ROTL32 (a, 5) + Ops32.XOR3 (b, c, d) + e + K2 + W (I);
         e := d;
         d := c;
         c := Types.ROTL32 (b, 30);
         b := a;
         a := Temp;
      end loop;

      for I in Schedule_Index range 40 .. 59
      loop
         Temp := Types.ROTL32 (a, 5) + Maj (b, c, d) + e + K3 + W (I);
         e := d;
         d := c;
         c := Types.ROTL32 (b, 30);
         b := a;
         a := Temp;
      end loop;

      for I in Schedule_Index range 60 .. 79
      loop
         Temp := Types.ROTL32 (a, 5) + Ops32.XOR3 (b, c, d) + e + K4 + W (I);
         e := d;
         d := c;
         c := Types.ROTL32 (b, 30);
         b := a;
         a := Temp;
      end loop;

      -- 4. Compute the i-th intermediate hash value H-i:
      Context.H := Hash_Type'
        (0 => a + Context.H (0),
         1 => b + Context.H (1),
         2 => c + Context.H (2),
         3 => d + Context.H (3),
         4 => e + Context.H (4));

      pragma Debug (Debug.Put_Line ("SHA-1 final hash values:"));
      pragma Debug (Debug.Print_Word32_Array (Context.H, 2, Types.Index'Last, True));

   end Context_Update_Internal;

   ---------------------------------------------------------------------------

   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type)
   is
   begin
      Context_Update_Internal (Context, Block);
      Add (Context.Length, 512);
   end Context_Update;

   ---------------------------------------------------------------------------

   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     Block_Type;
      Length  : in     Block_Length_Type)
   is
      Final_Block : Block_Type;
   begin

      pragma Debug (Debug.Put_Line ("FINAL BLOCK:"));

      Final_Block := Block;

      --  Add length of last block to data length.
      Add (Context.Length, Length);

      --  Set trailing '1' marker and zero out rest of the block.
      Pad32.Block_Terminate (Block  => Final_Block,
                             Length => Types.Word64 (Length));

      --  Terminator and length values won't fit into current block.
      if Length >= 448 then
         Context_Update_Internal (Context => Context, Block => Final_Block);
         Final_Block := Null_Block;
      end if;

      --  Set length in final block.
      Final_Block (Block_Type'Last - 1) := Byteorder32.BE_To_Native (Context.Length.MSW);
      Final_Block (Block_Type'Last)     := Byteorder32.BE_To_Native (Context.Length.LSW);

      Context_Update_Internal (Context => Context, Block => Final_Block);

   end Context_Finalize;

   ---------------------------------------------------------------------------

   function Get_Hash (Context : Context_Type) return Hash_Type is
   begin
      return Hash_Type'(0 => Byteorder32.BE_To_Native (Context.H (0)),
                        1 => Byteorder32.BE_To_Native (Context.H (1)),
                        2 => Byteorder32.BE_To_Native (Context.H (2)),
                        3 => Byteorder32.BE_To_Native (Context.H (3)),
                        4 => Byteorder32.BE_To_Native (Context.H (4)));
   end Get_Hash;

   ---------------------------------------------------------------------------

   procedure Hash_Context
      (Message : in     Message_Type;
       Length  : in     Types.Word64;
       Ctx     : in out Context_Type)
   is
      Dummy       : constant Block_Type := Null_Block;
      Last_Length : Block_Length_Type;
      Last_Block  : Types.Word64;
   begin
      Last_Length := Types.Word32 (Length mod Block_Size);
      Last_Block  := Message'First + Length / Block_Size;

      -- handle all blocks, but the last.
      if Last_Block > Message'First then
         for I in Message_Index range Message'First .. Last_Block - 1
         loop
            --# assert
            --#    Last_Block = Last_Block% and
            --#    Last_Block - 1 <= Message'Last and
            --#    (Last_Length /= 0 -> Last_Block <= Message'Last) and
            --#    I < Last_Block;
            Context_Update (Ctx, Message (I));
         end loop;
      end if;

      if Last_Length = 0 then
         Context_Finalize (Ctx, Dummy, 0);
      else
         Context_Finalize (Ctx, Message (Last_Block), Last_Length);
      end if;
   end Hash_Context;

   ----------------------------------------------------------------------------

   function Hash
      (Message : Message_Type;
       Length  : Types.Word64) return Hash_Type
   is
      Ctx : Context_Type;
   begin
      Ctx := Context_Init;
      Hash_Context (Message, Length, Ctx);

      return Get_Hash (Ctx);
   end Hash;

end LSC.SHA1;
