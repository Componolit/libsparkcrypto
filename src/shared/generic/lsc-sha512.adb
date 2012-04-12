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
with LSC.Byteorder64;
with LSC.SHA512.Tables;
with LSC.Pad64;

package body LSC.SHA512 is

   function Init_Data_Length return Data_Length is
   begin
      return Data_Length'(0, 0);
   end Init_Data_Length;

   ----------------------------------------------------------------------------

   procedure Add (Item  : in out Data_Length;
                  Value : in     Types.Word64)
   --# derives Item from *,
   --#                   Value;
   is
      pragma Inline (Add);
   begin
      if Item.LSW <= Types.Word64'Last - Value then
         Item.LSW := Item.LSW + Value;
      else
         Item.MSW := Item.MSW + 1;
         Item.LSW := Types.Word64'Last - Value;
      end if;
   end Add;

   ----------------------------------------------------------------------------

   function Ch
     (x    : Types.Word64;
      y    : Types.Word64;
      z    : Types.Word64) return Types.Word64
   --# return (x and y) xor ((not x) and z);
   is
      pragma Inline (Ch);

      -- This is a workaround for the simplifier, which is not able
      -- to discharge the (not x) expression directly due to a search
      -- depth limit.
      Not_X : Types.Word64;
   begin
      Not_X := not x;
      --# assert Not_X in Types.Word64 and Not_X = not x;
      return ((x and y) xor (Not_X and z));
   end Ch;

   ----------------------------------------------------------------------------

   function Maj
     (x    : Types.Word64;
      y    : Types.Word64;
      z    : Types.Word64) return Types.Word64
   --# return (x and y) xor (x and z) xor (y and z);
   is
      pragma Inline (Maj);
   begin
      return (x and y) xor (x and z) xor (y and z);
   end Maj;

   ----------------------------------------------------------------------------

   function Cap_Sigma_0_512 (x : Types.Word64) return Types.Word64
   is
      pragma Inline (Cap_Sigma_0_512);
   begin
      return Types.ROTR (x, 28) xor
             Types.ROTR (x, 34) xor
             Types.ROTR (x, 39);
   end Cap_Sigma_0_512;

   ----------------------------------------------------------------------------

   function Cap_Sigma_1_512 (x : Types.Word64) return Types.Word64
   is
      pragma Inline (Cap_Sigma_1_512);
   begin
      return Types.ROTR (x, 14) xor
             Types.ROTR (x, 18) xor
             Types.ROTR (x, 41);
   end Cap_Sigma_1_512;

   ----------------------------------------------------------------------------

   function Sigma_0_512 (x : Types.Word64) return Types.Word64
   is
      pragma Inline (Sigma_0_512);
   begin
      return Types.ROTR (x, 1) xor
             Types.ROTR (x, 8) xor
             Types.SHR (x, 7);
   end Sigma_0_512;

   ----------------------------------------------------------------------------

   function Sigma_1_512 (x : Types.Word64) return Types.Word64
   is
      pragma Inline (Sigma_1_512);
   begin
      return Types.ROTR (x, 19) xor
             Types.ROTR (x, 61) xor
             Types.SHR (x, 6);
   end Sigma_1_512;

   ----------------------------------------------------------------------------

   function SHA512_Context_Init return Context_Type is
   begin
      return Context_Type'
        (Length => Init_Data_Length,
         H      => SHA512_Hash_Type'(0 => 16#6a09e667f3bcc908#,
                                     1 => 16#bb67ae8584caa73b#,
                                     2 => 16#3c6ef372fe94f82b#,
                                     3 => 16#a54ff53a5f1d36f1#,
                                     4 => 16#510e527fade682d1#,
                                     5 => 16#9b05688c2b3e6c1f#,
                                     6 => 16#1f83d9abfb41bd6b#,
                                     7 => 16#5be0cd19137e2179#),
         W      => Null_Schedule);
   end SHA512_Context_Init;

   ----------------------------------------------------------------------------

   function SHA384_Context_Init return Context_Type is
   begin
      return Context_Type'
        (Length => Init_Data_Length,
         H      => SHA512_Hash_Type'(0 => 16#cbbb9d5dc1059ed8#,
                                     1 => 16#629a292a367cd507#,
                                     2 => 16#9159015a3070dd17#,
                                     3 => 16#152fecd8f70e5939#,
                                     4 => 16#67332667ffc00b31#,
                                     5 => 16#8eb44a8768581511#,
                                     6 => 16#db0c2e0d64f98fa7#,
                                     7 => 16#47b5481dbefa4fa4#),
         W      => Null_Schedule);
   end SHA384_Context_Init;

   ----------------------------------------------------------------------------

   procedure Context_Update_Internal
     (Context : in out Context_Type;
      Block   : in     Block_Type)
   --# derives Context from *,
   --#                      Block;
   is
      a, b, c, d, e, f, g, h : Types.Word64;

      procedure SHA512_Op (r  : in     Schedule_Index;
                         a0 : in     Types.Word64;
                         a1 : in     Types.Word64;
                         a2 : in     Types.Word64;
                         a3 : in out Types.Word64;
                         a4 : in     Types.Word64;
                         a5 : in     Types.Word64;
                         a6 : in     Types.Word64;
                         a7 : in out Types.Word64)
      --# global
      --#    Context;
      --# derives
      --#    a3 from *, a4, a5, a6, a7, r, Context &
      --#    a7 from a0, a1, a2, a4, a5, a6, a7, r, Context;
      is
         T1, T2 : Types.Word64;
      begin
         T1 := a7 + Cap_Sigma_1_512 (a4) + Ch (a4, a5, a6) + Tables.K (r) + Context.W (r);
         T2 := Cap_Sigma_0_512 (a0) + Maj (a0, a1, a2);
         a3 := a3 + T1;
         a7 := T1 + T2;
      end SHA512_Op;

   begin

      pragma Debug (Debug.Put_Line ("BLOCK UPDATE:"));

      -- Print out initial state of H
      pragma Debug (Debug.Put_Line ("SHA-512 initial hash values:"));
      pragma Debug (Debug.Print_Word64_Array (Context.H, 2, Types.Index'Last, True));

      -------------------------------------------
      --  Section 6.3.2 SHA-512 Hash Computations
      -------------------------------------------

      --  1. Prepare the message schedule, Context.W(t):
      for t in Schedule_Index range 0 .. 15
      loop
         Context.W (t) := Byteorder64.Native_To_BE (Block (t));
      end loop;

      for t in Schedule_Index range 16 .. 79
      loop
         Context.W (t) := Sigma_1_512 (Context.W (t - 2)) +
                                       Context.W (t - 7) +
                                       Sigma_0_512 (Context.W (t - 15)) +
                                       Context.W (t - 16);
      end loop;

      pragma Debug (Debug.Put_Line ("Message block:"));
      pragma Debug (Debug.Print_Word64_Array (Context.W, 2, 8, True));

      -- 2. Initialize the eight working variables a, b, c, d, e, f, g, and
      --    h with the (i-1)st hash value:
      a := Context.H (0);
      b := Context.H (1);
      c := Context.H (2);
      d := Context.H (3);
      e := Context.H (4);
      f := Context.H (5);
      g := Context.H (6);
      h := Context.H (7);

      -- 3. For t = 0 to 79:

      SHA512_Op  (0, a, b, c, d, e, f, g, h);
      SHA512_Op  (1, h, a, b, c, d, e, f, g);
      SHA512_Op  (2, g, h, a, b, c, d, e, f);
      SHA512_Op  (3, f, g, h, a, b, c, d, e);
      SHA512_Op  (4, e, f, g, h, a, b, c, d);
      SHA512_Op  (5, d, e, f, g, h, a, b, c);
      SHA512_Op  (6, c, d, e, f, g, h, a, b);
      SHA512_Op  (7, b, c, d, e, f, g, h, a);
      --# assert True;

      SHA512_Op  (8, a, b, c, d, e, f, g, h);
      SHA512_Op  (9, h, a, b, c, d, e, f, g);
      SHA512_Op (10, g, h, a, b, c, d, e, f);
      SHA512_Op (11, f, g, h, a, b, c, d, e);
      SHA512_Op (12, e, f, g, h, a, b, c, d);
      SHA512_Op (13, d, e, f, g, h, a, b, c);
      SHA512_Op (14, c, d, e, f, g, h, a, b);
      SHA512_Op (15, b, c, d, e, f, g, h, a);
      --# assert True;

      SHA512_Op (16, a, b, c, d, e, f, g, h);
      SHA512_Op (17, h, a, b, c, d, e, f, g);
      SHA512_Op (18, g, h, a, b, c, d, e, f);
      SHA512_Op (19, f, g, h, a, b, c, d, e);
      SHA512_Op (20, e, f, g, h, a, b, c, d);
      SHA512_Op (21, d, e, f, g, h, a, b, c);
      SHA512_Op (22, c, d, e, f, g, h, a, b);
      SHA512_Op (23, b, c, d, e, f, g, h, a);
      --# assert True;

      SHA512_Op (24, a, b, c, d, e, f, g, h);
      SHA512_Op (25, h, a, b, c, d, e, f, g);
      SHA512_Op (26, g, h, a, b, c, d, e, f);
      SHA512_Op (27, f, g, h, a, b, c, d, e);
      SHA512_Op (28, e, f, g, h, a, b, c, d);
      SHA512_Op (29, d, e, f, g, h, a, b, c);
      SHA512_Op (30, c, d, e, f, g, h, a, b);
      SHA512_Op (31, b, c, d, e, f, g, h, a);
      --# assert True;

      SHA512_Op (32, a, b, c, d, e, f, g, h);
      SHA512_Op (33, h, a, b, c, d, e, f, g);
      SHA512_Op (34, g, h, a, b, c, d, e, f);
      SHA512_Op (35, f, g, h, a, b, c, d, e);
      SHA512_Op (36, e, f, g, h, a, b, c, d);
      SHA512_Op (37, d, e, f, g, h, a, b, c);
      SHA512_Op (38, c, d, e, f, g, h, a, b);
      SHA512_Op (39, b, c, d, e, f, g, h, a);
      --# assert True;

      SHA512_Op (40, a, b, c, d, e, f, g, h);
      SHA512_Op (41, h, a, b, c, d, e, f, g);
      SHA512_Op (42, g, h, a, b, c, d, e, f);
      SHA512_Op (43, f, g, h, a, b, c, d, e);
      SHA512_Op (44, e, f, g, h, a, b, c, d);
      SHA512_Op (45, d, e, f, g, h, a, b, c);
      SHA512_Op (46, c, d, e, f, g, h, a, b);
      SHA512_Op (47, b, c, d, e, f, g, h, a);
      --# assert True;

      SHA512_Op (48, a, b, c, d, e, f, g, h);
      SHA512_Op (49, h, a, b, c, d, e, f, g);
      SHA512_Op (50, g, h, a, b, c, d, e, f);
      SHA512_Op (51, f, g, h, a, b, c, d, e);
      SHA512_Op (52, e, f, g, h, a, b, c, d);
      SHA512_Op (53, d, e, f, g, h, a, b, c);
      SHA512_Op (54, c, d, e, f, g, h, a, b);
      SHA512_Op (55, b, c, d, e, f, g, h, a);
      --# assert True;

      SHA512_Op (56, a, b, c, d, e, f, g, h);
      SHA512_Op (57, h, a, b, c, d, e, f, g);
      SHA512_Op (58, g, h, a, b, c, d, e, f);
      SHA512_Op (59, f, g, h, a, b, c, d, e);
      SHA512_Op (60, e, f, g, h, a, b, c, d);
      SHA512_Op (61, d, e, f, g, h, a, b, c);
      SHA512_Op (62, c, d, e, f, g, h, a, b);
      SHA512_Op (63, b, c, d, e, f, g, h, a);
      --# assert True;

      SHA512_Op (64, a, b, c, d, e, f, g, h);
      SHA512_Op (65, h, a, b, c, d, e, f, g);
      SHA512_Op (66, g, h, a, b, c, d, e, f);
      SHA512_Op (67, f, g, h, a, b, c, d, e);
      SHA512_Op (68, e, f, g, h, a, b, c, d);
      SHA512_Op (69, d, e, f, g, h, a, b, c);
      SHA512_Op (70, c, d, e, f, g, h, a, b);
      SHA512_Op (71, b, c, d, e, f, g, h, a);
      --# assert True;

      SHA512_Op (72, a, b, c, d, e, f, g, h);
      SHA512_Op (73, h, a, b, c, d, e, f, g);
      SHA512_Op (74, g, h, a, b, c, d, e, f);
      SHA512_Op (75, f, g, h, a, b, c, d, e);
      SHA512_Op (76, e, f, g, h, a, b, c, d);
      SHA512_Op (77, d, e, f, g, h, a, b, c);
      SHA512_Op (78, c, d, e, f, g, h, a, b);
      SHA512_Op (79, b, c, d, e, f, g, h, a);
      --# assert True;

      -- 4. Compute the i-th intermediate hash value H-i:
      Context.H :=
        SHA512_Hash_Type'
        (0 => a + Context.H (0),
         1 => b + Context.H (1),
         2 => c + Context.H (2),
         3 => d + Context.H (3),
         4 => e + Context.H (4),
         5 => f + Context.H (5),
         6 => g + Context.H (6),
         7 => h + Context.H (7));

      pragma Debug (Debug.Put_Line ("SHA-512 final hash values:"));
      pragma Debug (Debug.Print_Word64_Array (Context.H, 2, Types.Index'Last, True));

   end Context_Update_Internal;

   ----------------------------------------------------------------------------

   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type)
   is
   begin
      Context_Update_Internal (Context, Block);
      Add (Context.Length, 1024);
   end Context_Update;

   ----------------------------------------------------------------------------

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
      Pad64.Block_Terminate (Block => Final_Block, Length => Length);

      --  Terminator and length values won't fit into current block.
      if Length >= 896 then
         Context_Update_Internal (Context => Context, Block => Final_Block);
         Final_Block := Null_Block;
      end if;

      --  Set length in final block.
      Final_Block (Block_Type'Last - 1) := Byteorder64.BE_To_Native (Context.Length.MSW);
      Final_Block (Block_Type'Last)     := Byteorder64.BE_To_Native (Context.Length.LSW);

      Context_Update_Internal (Context => Context, Block => Final_Block);

   end Context_Finalize;

   ----------------------------------------------------------------------------

   function SHA512_Get_Hash (Context : Context_Type) return SHA512_Hash_Type is
   begin
      return SHA512_Hash_Type'(0 => Byteorder64.BE_To_Native (Context.H (0)),
                               1 => Byteorder64.BE_To_Native (Context.H (1)),
                               2 => Byteorder64.BE_To_Native (Context.H (2)),
                               3 => Byteorder64.BE_To_Native (Context.H (3)),
                               4 => Byteorder64.BE_To_Native (Context.H (4)),
                               5 => Byteorder64.BE_To_Native (Context.H (5)),
                               6 => Byteorder64.BE_To_Native (Context.H (6)),
                               7 => Byteorder64.BE_To_Native (Context.H (7)));
   end SHA512_Get_Hash;

   ----------------------------------------------------------------------------

   function SHA384_Get_Hash (Context : Context_Type) return SHA384_Hash_Type is
   begin
      return SHA384_Hash_Type'(0 => Byteorder64.BE_To_Native (Context.H (0)),
                               1 => Byteorder64.BE_To_Native (Context.H (1)),
                               2 => Byteorder64.BE_To_Native (Context.H (2)),
                               3 => Byteorder64.BE_To_Native (Context.H (3)),
                               4 => Byteorder64.BE_To_Native (Context.H (4)),
                               5 => Byteorder64.BE_To_Native (Context.H (5)));
   end SHA384_Get_Hash;

   ----------------------------------------------------------------------------

   procedure Hash_Context
      (Message : in     Message_Type;
       Length  : in     Types.Word64;
       Ctx     : in out Context_Type)
   is
      Dummy       : constant Block_Type := Null_Block;
      Last_Length : Block_Length_Type;
      Last_Block  : Types.Word64;
   begin
      Last_Length := Length mod Block_Size;
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

   function SHA512_Hash
      (Message : Message_Type;
       Length  : Types.Word64) return SHA512_Hash_Type
   is
      Ctx : Context_Type;
   begin
      Ctx := SHA512_Context_Init;
      Hash_Context (Message, Length, Ctx);

      return SHA512_Get_Hash (Ctx);
   end SHA512_Hash;

   ----------------------------------------------------------------------------

   function SHA384_Hash
      (Message : Message_Type;
       Length  : Types.Word64) return SHA384_Hash_Type
   is
      Ctx : Context_Type;
   begin
      Ctx := SHA384_Context_Init;
      Hash_Context (Message, Length, Ctx);

      return SHA384_Get_Hash (Ctx);
   end SHA384_Hash;

end LSC.SHA512;
