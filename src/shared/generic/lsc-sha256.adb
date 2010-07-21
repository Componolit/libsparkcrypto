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

with LSC.SHA256.Tables;

package body LSC.SHA256 is

   function Init_Data_Length return Data_Length is
   begin
      return Data_Length'(0, 0);
   end Init_Data_Length;

   ----------------------------------------------------------------------------

   procedure Add (Item  : in out Data_Length;
                  Value : in     Types.Word32) is
   begin
      if (Item.LSW + Value) <= Types.Word32'Last
      then
         Item.LSW := Item.LSW + Value;
      else
         Item.MSW := Item.MSW + 1;
         Item.LSW := Types.Word32'Last - Value;
      end if;
   end Add;

   ----------------------------------------------------------------------------

   function Ch
     (x    : Types.Word32;
      y    : Types.Word32;
      z    : Types.Word32)
      return Types.Word32
   is
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
   is
   begin
      return (x and y) xor (x and z) xor (y and z);
   end Maj;

   ----------------------------------------------------------------------------

   function Cap_Sigma_0_256 (x : Types.Word32) return Types.Word32 is
   begin
      return Types.ROTR32 (x,  2) xor
             Types.ROTR32 (x, 13) xor
             Types.ROTR32 (x, 22);
   end Cap_Sigma_0_256;

   ----------------------------------------------------------------------------

   function Cap_Sigma_1_256 (x : Types.Word32) return Types.Word32 is
   begin
      return Types.ROTR32 (x,  6) xor
             Types.ROTR32 (x, 11) xor
             Types.ROTR32 (x, 25);
   end Cap_Sigma_1_256;

   ----------------------------------------------------------------------------

   function Sigma_0_256 (x : Types.Word32) return Types.Word32 is
   begin
      return Types.ROTR32 (x,  7) xor
             Types.ROTR32 (x, 18) xor
             Types.SHR32  (x,  3);
   end Sigma_0_256;

   ----------------------------------------------------------------------------

   function Sigma_1_256 (x : Types.Word32) return Types.Word32 is
   begin
      return Types.ROTR32 (x, 17) xor
             Types.ROTR32 (x, 19) xor
             Types.SHR32  (x, 10);
   end Sigma_1_256;

   ----------------------------------------------------------------------------

   function SHA256_Context_Init return Context_Type is
   begin
      return Context_Type'
        (Length => Init_Data_Length,
         H      => SHA256_Hash_Type'(0 => 16#6a09e667#,
                                     1 => 16#bb67ae85#,
                                     2 => 16#3c6ef372#,
                                     3 => 16#a54ff53a#,
                                     4 => 16#510e527f#,
                                     5 => 16#9b05688c#,
                                     6 => 16#1f83d9ab#,
                                     7 => 16#5be0cd19#),
         W      => Schedule_Type'(others => 0));
   end SHA256_Context_Init;

   ----------------------------------------------------------------------------

   procedure Context_Update_Internal
     (Context : in out Context_Type;
      Block   : in     Block_Type)
   is
      a, b, c, d, e, f, g, h : Types.Word32;

      procedure SHA256_Op (r  : in     Schedule_Index;
                           a0 : in     Types.Word32;
                           a1 : in     Types.Word32;
                           a2 : in     Types.Word32;
                           a3 : in out Types.Word32;
                           a4 : in     Types.Word32;
                           a5 : in     Types.Word32;
                           a6 : in     Types.Word32;
                           a7 : in out Types.Word32)
      --# global
      --#    Context;
      --# derives
      --#    a3 from *, a4, a5, a6, a7, r, Context &
      --#    a7 from a0, a1, a2, a4, a5, a6, a7, r, Context;
      is
         T1, T2 : Types.Word32;
      begin

         if r > 0
         then
            Debug.Print_Word32 (Types.Word32 (r - 1));
            Debug.Put (": ");
            Debug.Print_Word32 (a0); Debug.Put ("  ");
            Debug.Print_Word32 (a1); Debug.Put ("  ");
            Debug.Print_Word32 (a2); Debug.Put ("  ");
            Debug.Print_Word32 (a3); Debug.Put ("  ");
            Debug.Print_Word32 (a4); Debug.Put ("  ");
            Debug.Print_Word32 (a5); Debug.Put ("  ");
            Debug.Print_Word32 (a6); Debug.Put ("  ");
            Debug.Print_Word32 (a7); Debug.New_Line;
         end if;

         T1 := a7 + Cap_Sigma_1_256 (a4) + Ch (a4, a5, a6) + Tables.K (r) + Context.W (r);
         T2 := Cap_Sigma_0_256 (a0) + Maj (a0, a1, a2);
         a3 := a3 + T1;
         a7 := T1 + T2;

      end SHA256_Op;
      pragma Inline (SHA256_Op);

   begin

      Debug.Put_Line ("BLOCK UPDATE:");

      -- Print out initial state of H
      Debug.Put_Line ("SHA-256 initial hash values:");
      Debug.Print_Word32_Array (Context.H, 2, Types.Index'Last, True);

      -------------------------------------------
      --  Section 6.3.2 SHA-256 Hash Computations
      -------------------------------------------

      --  1. Prepare the message schedule, Context.W(t):
      for t in Schedule_Index range 0 .. 15
         --# assert t in 0 .. 15;
      loop
         Context.W (t) := Byteorder32.Native_To_BE (Block (t));
      end loop;

      for t in Schedule_Index range 16 .. 63
         --# assert t in 16 .. 63;
      loop
         Context.W (t) := Sigma_1_256 (Context.W (t - 2)) +
                                       Context.W (t - 7) +
                                       Sigma_0_256 (Context.W (t - 15)) +
                                       Context.W (t - 16);
      end loop;

      Debug.Put_Line ("Message block:");
      Debug.Print_Word32_Array (Context.W, 2, 8, True);

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

      -- 3. For t = 0 to 63:

      SHA256_Op ( 0, a, b, c, d, e, f, g, h);
      SHA256_Op ( 1, h, a, b, c, d, e, f, g);
      SHA256_Op ( 2, g, h, a, b, c, d, e, f);
      SHA256_Op ( 3, f, g, h, a, b, c, d, e);
      SHA256_Op ( 4, e, f, g, h, a, b, c, d);
      SHA256_Op ( 5, d, e, f, g, h, a, b, c);
      SHA256_Op ( 6, c, d, e, f, g, h, a, b);
      SHA256_Op ( 7, b, c, d, e, f, g, h, a);
      --# assert true;

      SHA256_Op ( 8, a, b, c, d, e, f, g, h);
      SHA256_Op ( 9, h, a, b, c, d, e, f, g);
      SHA256_Op (10, g, h, a, b, c, d, e, f);
      SHA256_Op (11, f, g, h, a, b, c, d, e);
      SHA256_Op (12, e, f, g, h, a, b, c, d);
      SHA256_Op (13, d, e, f, g, h, a, b, c);
      SHA256_Op (14, c, d, e, f, g, h, a, b);
      SHA256_Op (15, b, c, d, e, f, g, h, a);
      --# assert true;

      SHA256_Op (16, a, b, c, d, e, f, g, h);
      SHA256_Op (17, h, a, b, c, d, e, f, g);
      SHA256_Op (18, g, h, a, b, c, d, e, f);
      SHA256_Op (19, f, g, h, a, b, c, d, e);
      SHA256_Op (20, e, f, g, h, a, b, c, d);
      SHA256_Op (21, d, e, f, g, h, a, b, c);
      SHA256_Op (22, c, d, e, f, g, h, a, b);
      SHA256_Op (23, b, c, d, e, f, g, h, a);
      --# assert true;

      SHA256_Op (24, a, b, c, d, e, f, g, h);
      SHA256_Op (25, h, a, b, c, d, e, f, g);
      SHA256_Op (26, g, h, a, b, c, d, e, f);
      SHA256_Op (27, f, g, h, a, b, c, d, e);
      SHA256_Op (28, e, f, g, h, a, b, c, d);
      SHA256_Op (29, d, e, f, g, h, a, b, c);
      SHA256_Op (30, c, d, e, f, g, h, a, b);
      SHA256_Op (31, b, c, d, e, f, g, h, a);
      --# assert true;

      SHA256_Op (32, a, b, c, d, e, f, g, h);
      SHA256_Op (33, h, a, b, c, d, e, f, g);
      SHA256_Op (34, g, h, a, b, c, d, e, f);
      SHA256_Op (35, f, g, h, a, b, c, d, e);
      SHA256_Op (36, e, f, g, h, a, b, c, d);
      SHA256_Op (37, d, e, f, g, h, a, b, c);
      SHA256_Op (38, c, d, e, f, g, h, a, b);
      SHA256_Op (39, b, c, d, e, f, g, h, a);
      --# assert true;

      SHA256_Op (40, a, b, c, d, e, f, g, h);
      SHA256_Op (41, h, a, b, c, d, e, f, g);
      SHA256_Op (42, g, h, a, b, c, d, e, f);
      SHA256_Op (43, f, g, h, a, b, c, d, e);
      SHA256_Op (44, e, f, g, h, a, b, c, d);
      SHA256_Op (45, d, e, f, g, h, a, b, c);
      SHA256_Op (46, c, d, e, f, g, h, a, b);
      SHA256_Op (47, b, c, d, e, f, g, h, a);
      --# assert true;

      SHA256_Op (48, a, b, c, d, e, f, g, h);
      SHA256_Op (49, h, a, b, c, d, e, f, g);
      SHA256_Op (50, g, h, a, b, c, d, e, f);
      SHA256_Op (51, f, g, h, a, b, c, d, e);
      SHA256_Op (52, e, f, g, h, a, b, c, d);
      SHA256_Op (53, d, e, f, g, h, a, b, c);
      SHA256_Op (54, c, d, e, f, g, h, a, b);
      SHA256_Op (55, b, c, d, e, f, g, h, a);
      --# assert true;

      SHA256_Op (56, a, b, c, d, e, f, g, h);
      SHA256_Op (57, h, a, b, c, d, e, f, g);
      SHA256_Op (58, g, h, a, b, c, d, e, f);
      SHA256_Op (59, f, g, h, a, b, c, d, e);
      SHA256_Op (60, e, f, g, h, a, b, c, d);
      SHA256_Op (61, d, e, f, g, h, a, b, c);
      SHA256_Op (62, c, d, e, f, g, h, a, b);
      SHA256_Op (63, b, c, d, e, f, g, h, a);
      --# assert true;

      -- 4. Compute the i-th intermediate hash value H-i:
      Context.H :=
        SHA256_Hash_Type'
        (0 => a + Context.H (0),
         1 => b + Context.H (1),
         2 => c + Context.H (2),
         3 => d + Context.H (3),
         4 => e + Context.H (4),
         5 => f + Context.H (5),
         6 => g + Context.H (6),
         7 => h + Context.H (7));

      Debug.Put_Line ("SHA-256 final hash values:");
      Debug.Print_Word32_Array (Context.H, 2, Types.Index'Last, True);

   end Context_Update_Internal;

   ----------------------------------------------------------------------------

   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type)
   is
   begin
      Context_Update_Internal (Context, Block);
      Add (Context.Length, 512);
   end Context_Update;

   ----------------------------------------------------------------------------

   procedure Block_Terminate
     (Block  : in out Block_Type;
      Length : in     Block_Length_Type)
   is
      Index  : Block_Index;
      Offset : Natural;
   begin

      Index  := Block_Index (Length / 32);
      Offset := Natural (31 - Length mod 32);

      Debug.Put ("Terminator offset =");
      Debug.Print_Natural (Offset);
      Debug.New_Line;

      Block (Index) := Byteorder32.Native_To_BE (Block (Index));
      Block (Index) := Block (Index) xor Types.SHL32 (1, Offset);
      Block (Index) := Block (Index) and Types.SHL32 (not 0, Offset);
      Block (Index) := Byteorder32.BE_To_Native (Block (Index));

      if Index < Block_Index'Last
      then
         for I in Block_Index range (Index + 1) .. Block_Index'Last
            --# assert I in Block_Index;
         loop
            Block (I) := 0;
         end loop;
      end if;

   end Block_Terminate;

   ----------------------------------------------------------------------------

   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     Block_Type;
      Length  : in     Block_Length_Type)
   is
      Final_Block : Block_Type;
   begin

      Debug.Put_Line ("FINAL BLOCK:");

      Final_Block := Block;

      --  Add length of last block to data length.
      Add (Context.Length, Length);

      --  Set trailing '1' marker and zero out rest of the block.
      Block_Terminate (Block => Final_Block, Length => Length);

      --  Terminator and length values won't fit into current block.
      if Length >= 448
      then

         Context_Update_Internal (Context => Context, Block => Final_Block);

         Final_Block := Block_Type'(others => 0);

      end if;

      --  Set length in final block.
      Final_Block (Block_Type'Last - 1) := Byteorder32.BE_To_Native (Context.Length.MSW);
      Final_Block (Block_Type'Last)     := Byteorder32.BE_To_Native (Context.Length.LSW);

      Context_Update_Internal (Context => Context, Block => Final_Block);

   end Context_Finalize;

   ----------------------------------------------------------------------------

   function SHA256_Get_Hash (Context : Context_Type) return SHA256_Hash_Type is
   begin
      return SHA256_Hash_Type'(0 => Byteorder32.BE_To_Native (Context.H (0)),
                               1 => Byteorder32.BE_To_Native (Context.H (1)),
                               2 => Byteorder32.BE_To_Native (Context.H (2)),
                               3 => Byteorder32.BE_To_Native (Context.H (3)),
                               4 => Byteorder32.BE_To_Native (Context.H (4)),
                               5 => Byteorder32.BE_To_Native (Context.H (5)),
                               6 => Byteorder32.BE_To_Native (Context.H (6)),
                               7 => Byteorder32.BE_To_Native (Context.H (7)));
   end SHA256_Get_Hash;

end LSC.SHA256;
