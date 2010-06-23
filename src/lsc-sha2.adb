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

with LSC.SHA2.Tables;

package body LSC.SHA2 is

   function Init_Data_Length return Data_Length is
   begin
      return Data_Length'(0, 0);
   end Init_Data_Length;

   ----------------------------------------------------------------------------

   procedure Add (Item  : in out Data_Length;
                  Value : in     Types.Word64) is
   begin
      if (Item.LSW + Value) <= Types.Word64'Last
      then
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
      z    : Types.Word64)
      return Types.Word64
   is
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
      z    : Types.Word64)
      return Types.Word64
   is
   begin
      return (x and y) xor (x and z) xor (y and z);
   end Maj;

   ----------------------------------------------------------------------------

   function Cap_Sigma_0_512 (x : Types.Word64) return Types.Word64 is
   begin
      return Types.ROTR (x, 28) xor
             Types.ROTR (x, 34) xor
             Types.ROTR (x, 39);
   end Cap_Sigma_0_512;

   ----------------------------------------------------------------------------

   function Cap_Sigma_1_512 (x : Types.Word64) return Types.Word64 is
   begin
      return Types.ROTR (x, 14) xor
             Types.ROTR (x, 18) xor
             Types.ROTR (x, 41);
   end Cap_Sigma_1_512;

   ----------------------------------------------------------------------------

   function Sigma_0_512 (x : Types.Word64) return Types.Word64 is
   begin
      return Types.ROTR (x, 1) xor
             Types.ROTR (x, 8) xor
             Types.SHR (x, 7);
   end Sigma_0_512;

   ----------------------------------------------------------------------------

   function Sigma_1_512 (x : Types.Word64) return Types.Word64 is
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
                                     7 => 16#5be0cd19137e2179#));
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
                                     7 => 16#47b5481dbefa4fa4#));
   end SHA384_Context_Init;

   ----------------------------------------------------------------------------

   procedure Context_Update_Internal
     (Context : in out Context_Type;
      Block   : in     Block_Type)
   is
      W      : Schedule_Type;
      a, b, c, d, e, f, g, h : Types.Word64;

      procedure SHA2_Op (r  : in     Schedule_Index;
                         a0 : in     Types.Word64;
                         a1 : in     Types.Word64;
                         a2 : in     Types.Word64;
                         a3 : in out Types.Word64;
                         a4 : in     Types.Word64;
                         a5 : in     Types.Word64;
                         a6 : in     Types.Word64;
                         a7 : in out Types.Word64)
      --# global
      --#    W;
      --# derives
      --#    a3 from *, a4, a5, a6, a7, r, W &
      --#    a7 from a0, a1, a2, a4, a5, a6, a7, r, W;
      is
         T1, T2 : Types.Word64;
      begin
         T1 := a7 + Cap_Sigma_1_512 (a4) + Ch (a4, a5, a6) + Tables.K (r) + W (r);
         T2 := Cap_Sigma_0_512 (a0) + Maj (a0, a1, a2);
         a3 := a3 + T1;
         a7 := T1 + T2;
      end SHA2_Op;
      pragma Inline (SHA2_Op);

   begin

      W := Schedule_Type'(others => 0);

      Debug.Put_Line ("BLOCK UPDATE:");

      -- Print out initial state of H
      Debug.Put_Line ("SHA-512 initial hash values:");
      Debug.Print_Word64_Array (Context.H, 2, Types.Index'Last, True);

      -------------------------------------------
      --  Section 6.3.2 SHA-512 Hash Computations
      -------------------------------------------

      --  1. Prepare the message schedule, W(t):
      for t in Schedule_Index range 0 .. 15
         --# assert t in 0 .. 15;
      loop
         W (t) := Byteorder.Native_To_BE64 (Block (t));
      end loop;

      for t in Schedule_Index range 16 .. 79
         --# assert t in 16 .. 79;
      loop
         W (t) := Sigma_1_512 (W (t - 2)) +
                  W (t - 7) +
                  Sigma_0_512 (W (t - 15)) +
                  W (t - 16);
      end loop;

      Debug.Put_Line ("Message block:");
      Debug.Print_Word64_Array (W, 2, 8, True);

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
      for t in Schedule_Index range 0 .. 9
      --# assert true;
      loop
         SHA2_Op (8 * t + 0, a, b, c, d, e, f, g, h);
         SHA2_Op (8 * t + 1, h, a, b, c, d, e, f, g);
         SHA2_Op (8 * t + 2, g, h, a, b, c, d, e, f);
         SHA2_Op (8 * t + 3, f, g, h, a, b, c, d, e);
         SHA2_Op (8 * t + 4, e, f, g, h, a, b, c, d);
         SHA2_Op (8 * t + 5, d, e, f, g, h, a, b, c);
         SHA2_Op (8 * t + 6, c, d, e, f, g, h, a, b);
         SHA2_Op (8 * t + 7, b, c, d, e, f, g, h, a);
      end loop;

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

      Debug.Put_Line ("SHA-512 final hash values:");
      Debug.Print_Word64_Array (Context.H, 2, Types.Index'Last, True);

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

   procedure Block_Terminate
     (Block  : in out Block_Type;
      Length : in     Block_Length_Type)
   is
      Index  : Block_Index;
      Offset : Natural;
   begin

      Index  := Block_Index (Length / 64);
      Offset := Natural (63 - Length mod 64);

      Debug.Put ("Terminator offset =");
      Debug.Print_Natural (Offset);
      Debug.New_Line;

      Block (Index) := Byteorder.Native_To_BE64 (Block (Index));
      Block (Index) := Block (Index) xor Types.SHL (1, Offset);
      Block (Index) := Block (Index) and Types.SHL (not 0, Offset);
      Block (Index) := Byteorder.BE_To_Native64 (Block (Index));

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
      if Length >= 896
      then

         Context_Update_Internal (Context => Context, Block => Final_Block);

         Final_Block := Block_Type'(others => 0);

      end if;

      --  Set length in final block.
      Final_Block (Block_Type'Last - 1) := Byteorder.BE_To_Native64 (Context.Length.MSW);
      Final_Block (Block_Type'Last)     := Byteorder.BE_To_Native64 (Context.Length.LSW);

      Context_Update_Internal (Context => Context, Block => Final_Block);

   end Context_Finalize;

   ----------------------------------------------------------------------------

   function SHA512_Get_Hash (Context : Context_Type) return SHA512_Hash_Type is
   begin
      return SHA512_Hash_Type'(0 => Byteorder.BE_To_Native64 (Context.H (0)),
                               1 => Byteorder.BE_To_Native64 (Context.H (1)),
                               2 => Byteorder.BE_To_Native64 (Context.H (2)),
                               3 => Byteorder.BE_To_Native64 (Context.H (3)),
                               4 => Byteorder.BE_To_Native64 (Context.H (4)),
                               5 => Byteorder.BE_To_Native64 (Context.H (5)),
                               6 => Byteorder.BE_To_Native64 (Context.H (6)),
                               7 => Byteorder.BE_To_Native64 (Context.H (7)));
   end SHA512_Get_Hash;

   ----------------------------------------------------------------------------

   function SHA384_Get_Hash (Context : Context_Type) return SHA384_Hash_Type is
   begin
      return SHA384_Hash_Type'(0 => Byteorder.BE_To_Native64 (Context.H (0)),
                               1 => Byteorder.BE_To_Native64 (Context.H (1)),
                               2 => Byteorder.BE_To_Native64 (Context.H (2)),
                               3 => Byteorder.BE_To_Native64 (Context.H (3)),
                               4 => Byteorder.BE_To_Native64 (Context.H (4)),
                               5 => Byteorder.BE_To_Native64 (Context.H (5)));
   end SHA384_Get_Hash;

end LSC.SHA2;
