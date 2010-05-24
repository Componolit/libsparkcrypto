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

with LSC.Debug, LSC.Types, LSC.SHA2.Print, LSC.SHA2.Tables;
use type LSC.Types.Word64;

package body LSC.SHA2 is

   function Init_Data_Length return Data_Length is
   begin
      return Data_Length'(0, 0);
   end Init_Data_Length;

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

   function Maj
     (x    : Types.Word64;
      y    : Types.Word64;
      z    : Types.Word64)
      return Types.Word64
   is
   begin
      return (x and y) xor (x and z) xor (y and z);
   end Maj;

   function Cap_Sigma_0_512 (x : Types.Word64) return Types.Word64 is
   begin
      return Types.ROTR (x, 28) xor
             Types.ROTR (x, 34) xor
             Types.ROTR (x, 39);
   end Cap_Sigma_0_512;

   function Cap_Sigma_1_512 (x : Types.Word64) return Types.Word64 is
   begin
      return Types.ROTR (x, 14) xor
             Types.ROTR (x, 18) xor
             Types.ROTR (x, 41);
   end Cap_Sigma_1_512;

   function Sigma_0_512 (x : Types.Word64) return Types.Word64 is
   begin
      return Types.ROTR (x, 1) xor
             Types.ROTR (x, 8) xor
             Types.SHR (x, 7);
   end Sigma_0_512;

   function Sigma_1_512 (x : Types.Word64) return Types.Word64 is
   begin
      return Types.ROTR (x, 19) xor
             Types.ROTR (x, 61) xor
             Types.SHR (x, 6);
   end Sigma_1_512;

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

   procedure Context_Update_Internal
     (Context : in out Context_Type;
      Block   : in     Block_Type)
   is
      W      : Schedule_Type;
      S      : State_Type;
      T1, T2 : Types.Word64;
   begin

      W := Schedule_Type'(others => 0);

      Debug.Put_Line ("BLOCK UPDATE:");

      -- Print out initial state of H
      Debug.Put_Line ("SHA-512 initial hash values:");
      Print.Put_Hash (Context.H);

      -------------------------------------------
      --  Section 6.3.2 SHA-512 Hash Computations
      -------------------------------------------

      --  1. Prepare the message schedule, W(t):
      for t in Schedule_Index range 0 .. 15
         --# assert t in 0 .. 15;
      loop
         W (t) := Block (Block_Index (t));
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
      Print.Put_Schedule (W);

      -- 2. Initialize the eight working variables a, b, c, d, e, f, g, and
      --    h with the (i-1)st hash value:
      S :=
        State_Type'
        (a => Context.H (0),
         b => Context.H (1),
         c => Context.H (2),
         d => Context.H (3),
         e => Context.H (4),
         f => Context.H (5),
         g => Context.H (6),
         h => Context.H (7));

      Debug.Put_Line ("Initial state:");
      Print.Put_State (S);

      -- 3. For t = 0 to 79:
      for t in Schedule_Index range 0 .. 79
         --# assert t in 0 .. 79;
      loop
         T1 := S (h) +
               Cap_Sigma_1_512 (S (e)) +
               Ch (S (e), S (f), S (g)) +
               Tables.K (t) +
               W (t);
         T2 := Cap_Sigma_0_512 (S (a)) + Maj (S (a), S (b), S (c));

         S :=
           State_Type'
           (h => S (g),
            g => S (f),
            f => S (e),
            e => S (d) + T1,
            d => S (c),
            c => S (b),
            b => S (a),
            a => T1 + T2);

         Print.Put_T (t);
         Print.Put_State (S);
      end loop;

      -- 4. Compute the i-th intermediate hash value H-i:
      Context.H :=
        SHA512_Hash_Type'
        (0 => S (a) + Context.H (0),
         1 => S (b) + Context.H (1),
         2 => S (c) + Context.H (2),
         3 => S (d) + Context.H (3),
         4 => S (e) + Context.H (4),
         5 => S (f) + Context.H (5),
         6 => S (g) + Context.H (6),
         7 => S (h) + Context.H (7));

      Debug.Put_Line ("SHA-512 final hash values:");
      Print.Put_Hash (Context.H);

   end Context_Update_Internal;

   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type)
   is
   begin
      Context_Update_Internal (Context, Block);
      Add (Context.Length, 1024);
   end Context_Update;

   procedure Block_Terminate
     (Block  : in out Block_Type;
      Length : in     Block_Length_Type)
   is
      Index  : Block_Index;
      Offset : Natural;
   begin

      Index  := Block_Index (Length / 64);
      Offset := Natural (63 - Length mod 64);

      Debug.Put_Line ("Terminator offset:");
      Print.Put_Natural (Offset);
      Debug.Put_Line (".");

      Block (Index) := Block (Index) xor Types.SHL (1, Offset);
      Block (Index) := Block (Index) and Types.SHL (not 0, Offset);

      if Index < Block_Index'Last
      then
         for I in Block_Index range (Index + 1) .. Block_Index'Last
            --# assert I in Block_Index;
         loop
            Block (I) := 0;
         end loop;
      end if;

   end Block_Terminate;

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
      Final_Block (Block_Type'Last - 1) := Context.Length.MSW;
      Final_Block (Block_Type'Last)     := Context.Length.LSW;

      Context_Update_Internal (Context => Context, Block => Final_Block);

   end Context_Finalize;

   function SHA512_Get_Hash (Context : Context_Type) return SHA512_Hash_Type is
   begin
      return Context.H;
   end SHA512_Get_Hash;

   function SHA384_Get_Hash (Context : Context_Type) return SHA384_Hash_Type is
   begin
      return SHA384_Hash_Type'(0 => Context.H (0),
                               1 => Context.H (1),
                               2 => Context.H (2),
                               3 => Context.H (3),
                               4 => Context.H (4),
                               5 => Context.H (5));
   end SHA384_Get_Hash;

end LSC.SHA2;
