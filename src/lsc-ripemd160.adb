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

with LSC.RIPEMD160.Tables;

package body LSC.RIPEMD160 is

   function Init_Data_Length return Data_Length is
   begin
      return Data_Length'(0, 0);
   end Init_Data_Length;

   ---------------------------------------------------------------------------

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

   ---------------------------------------------------------------------------

   function Context_Init return Context_Type
   is
   begin
      Debug.New_Line;
      Debug.New_Line;
      Debug.Put_Line ("RIPEMD-160 INIT");
      return Context_Type'
         (Length => Init_Data_Length,
          H      => Hash_Type'(0 => 16#67452301#,
                               1 => 16#efcdab89#,
                               2 => 16#98badcfe#,
                               3 => 16#10325476#,
                               4 => 16#c3d2e1f0#));
   end Context_Init;

   ---------------------------------------------------------------------------

   function f
      (x : Types.Word32;
       y : Types.Word32;
       z : Types.Word32) return Types.Word32
   is
   begin
      return Ops.XOR3 (x, y, z);
   end f;

   ---------------------------------------------------------------------------

   function g
      (x : Types.Word32;
       y : Types.Word32;
       z : Types.Word32) return Types.Word32
   is
      --  WORKAROUND: The temporary variable for the negation is necessary to
      --  keep the evaluation depth for the simplifier low enough to simplify
      --  this automatically!

      Not_x : Types.Word32;
   begin
      Not_x := not x;
      --# assert Not_x in Types.Word32;
      return (x and y) or (Not_x and z);
   end g;

   ---------------------------------------------------------------------------

   function h
      (x : Types.Word32;
       y : Types.Word32;
       z : Types.Word32) return Types.Word32
   is
      Not_y : Types.Word32;
   begin
      Not_y := not y;
      --# assert Not_y in Types.Word32;
      return Ops.XOR2 (x or Not_y, z);
   end h;

   ---------------------------------------------------------------------------

   function i
      (x : Types.Word32;
       y : Types.Word32;
       z : Types.Word32) return Types.Word32
   is
      Not_z : Types.Word32;
   begin
      Not_z := not z;
      --# assert Not_z in Types.Word32;
      return (x and z) or (y and Not_z);
   end i;

   ---------------------------------------------------------------------------

   function j
      (x : Types.Word32;
       y : Types.Word32;
       z : Types.Word32) return Types.Word32
   is
      Not_z : Types.Word32;
   begin
      Not_z := not z;
      --# assert Not_z in Types.Word32;
      return Ops.XOR2 (x, y or Not_z);
   end j;

   ---------------------------------------------------------------------------

   procedure ff (A : in out Types.Word32;
                 B : in     Types.Word32;
                 C : in out Types.Word32;
                 D : in     Types.Word32;
                 E : in     Types.Word32;
                 X : in     Types.Word32;
                 S : in     Natural)
   is
   begin
      Debug.Put ("A=");
      Debug.Print_Word32 (A);
      A := A + f (B, C, D) + X;
      Debug.Put ("  X=");
      Debug.Print_Word32 (X);
      Debug.New_Line;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
   end ff;

   ---------------------------------------------------------------------------

   procedure gg (A : in out Types.Word32;
                 B : in     Types.Word32;
                 C : in out Types.Word32;
                 D : in     Types.Word32;
                 E : in     Types.Word32;
                 X : in     Types.Word32;
                 S : in     Natural)
   is
   begin
      A := g (B, C, D) + X + 16#5a82_7999#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
   end gg;

   ---------------------------------------------------------------------------

   procedure hh (A : in out Types.Word32;
                 B : in     Types.Word32;
                 C : in out Types.Word32;
                 D : in     Types.Word32;
                 E : in     Types.Word32;
                 X : in     Types.Word32;
                 S : in     Natural)
   is
   begin
      A := h (B, C, D) + X + 16#6ed9_eba1#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
   end hh;

   ---------------------------------------------------------------------------

   procedure ii (A : in out Types.Word32;
                 B : in     Types.Word32;
                 C : in out Types.Word32;
                 D : in     Types.Word32;
                 E : in     Types.Word32;
                 X : in     Types.Word32;
                 S : in     Natural)
   is
   begin
      A := i (B, C, D) + X + 16#8f1b_bcdc#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
   end ii;

   ---------------------------------------------------------------------------

   procedure jj (A : in out Types.Word32;
                 B : in     Types.Word32;
                 C : in out Types.Word32;
                 D : in     Types.Word32;
                 E : in     Types.Word32;
                 X : in     Types.Word32;
                 S : in     Natural)
   is
   begin
      A := j (B, C, D) + X + 16#a953_fd4e#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
   end jj;

   ---------------------------------------------------------------------------

   procedure fff (A : in out Types.Word32;
                  B : in     Types.Word32;
                  C : in out Types.Word32;
                  D : in     Types.Word32;
                  E : in     Types.Word32;
                  X : in     Types.Word32;
                  S : in     Natural)
   is
   begin
      A := f (B, C, D) + X;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
   end fff;

   ---------------------------------------------------------------------------

   procedure ggg (A : in out Types.Word32;
                  B : in     Types.Word32;
                  C : in out Types.Word32;
                  D : in     Types.Word32;
                  E : in     Types.Word32;
                  X : in     Types.Word32;
                  S : in     Natural)
   is
   begin
      A := g (B, C, D) + X + 16#7a6d_76e9#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
   end ggg;

   ---------------------------------------------------------------------------

   procedure hhh (A : in out Types.Word32;
                  B : in     Types.Word32;
                  C : in out Types.Word32;
                  D : in     Types.Word32;
                  E : in     Types.Word32;
                  X : in     Types.Word32;
                  S : in     Natural)
   is
   begin
      A := h (B, C, D) + X + 16#6d70_3ef3#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
   end hhh;

   ---------------------------------------------------------------------------

   procedure iii (A : in out Types.Word32;
                  B : in     Types.Word32;
                  C : in out Types.Word32;
                  D : in     Types.Word32;
                  E : in     Types.Word32;
                  X : in     Types.Word32;
                  S : in     Natural)
   is
   begin
      A := i (B, C, D) + X + 16#5c4d_d124#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
   end iii;

   ---------------------------------------------------------------------------

   procedure jjj (A : in out Types.Word32;
                  B : in     Types.Word32;
                  C : in out Types.Word32;
                  D : in     Types.Word32;
                  E : in     Types.Word32;
                  X : in     Types.Word32;
                  S : in     Natural)
   is
   begin
      A := j (B, C, D) + X + 16#50a2_8be6#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
   end jjj;

   ---------------------------------------------------------------------------

   procedure Context_Update_Internal
     (Context : in out Context_Type;
      X       : in     Block_Type)
   is
      H, H1 : Hash_Type;
   begin

      H  := Context.H;
      H1 := Context.H;

      Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      Debug.New_Line;

      --  Round 1
      ff (H (0), H (1), H (2), H (3), H (4), X ( 0), 11); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ff (H (4), H (0), H (1), H (2), H (3), X ( 1), 14); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ff (H (3), H (4), H (0), H (1), H (2), X ( 2), 15); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ff (H (2), H (3), H (4), H (0), H (1), X ( 3), 12); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ff (H (1), H (2), H (3), H (4), H (0), X ( 4),  5); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ff (H (0), H (1), H (2), H (3), H (4), X ( 5),  8); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ff (H (4), H (0), H (1), H (2), H (3), X ( 6),  7); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ff (H (3), H (4), H (0), H (1), H (2), X ( 7),  9); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ff (H (2), H (3), H (4), H (0), H (1), X ( 8), 11); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ff (H (1), H (2), H (3), H (4), H (0), X ( 9), 13); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ff (H (0), H (1), H (2), H (3), H (4), X (10), 14); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ff (H (4), H (0), H (1), H (2), H (3), X (11), 15); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ff (H (3), H (4), H (0), H (1), H (2), X (12),  6); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ff (H (2), H (3), H (4), H (0), H (1), X (13),  7); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ff (H (1), H (2), H (3), H (4), H (0), X (14),  9); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ff (H (0), H (1), H (2), H (3), H (4), X (15),  8); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);

      --  Round 2

      gg (H (4), H (0), H (1), H (2), H (3), X ( 7),  7); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      gg (H (3), H (4), H (0), H (1), H (2), X ( 4),  6); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      gg (H (2), H (3), H (4), H (0), H (1), X (13),  8); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      gg (H (1), H (2), H (3), H (4), H (0), X ( 1), 13); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      gg (H (0), H (1), H (2), H (3), H (4), X (10), 11); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      gg (H (4), H (0), H (1), H (2), H (3), X ( 6),  9); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      gg (H (3), H (4), H (0), H (1), H (2), X (15),  7); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      gg (H (2), H (3), H (4), H (0), H (1), X ( 3), 15); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      gg (H (1), H (2), H (3), H (4), H (0), X (12),  7); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      gg (H (0), H (1), H (2), H (3), H (4), X ( 0), 12); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      gg (H (4), H (0), H (1), H (2), H (3), X ( 9), 15); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      gg (H (3), H (4), H (0), H (1), H (2), X ( 5),  9); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      gg (H (2), H (3), H (4), H (0), H (1), X ( 2), 11); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      gg (H (1), H (2), H (3), H (4), H (0), X (14),  7); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      gg (H (0), H (1), H (2), H (3), H (4), X (11), 13); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      gg (H (4), H (0), H (1), H (2), H (3), X ( 8), 12); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);

      --  Round 3

      hh (H (3), H (4), H (0), H (1), H (2), X ( 3), 11); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      hh (H (2), H (3), H (4), H (0), H (1), X (10), 13); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      hh (H (1), H (2), H (3), H (4), H (0), X (14),  6); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      hh (H (0), H (1), H (2), H (3), H (4), X ( 4),  7); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      hh (H (4), H (0), H (1), H (2), H (3), X ( 9), 14); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      hh (H (3), H (4), H (0), H (1), H (2), X (15),  9); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      hh (H (2), H (3), H (4), H (0), H (1), X ( 8), 13); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      hh (H (1), H (2), H (3), H (4), H (0), X ( 1), 15); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      hh (H (0), H (1), H (2), H (3), H (4), X ( 2), 14); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      hh (H (4), H (0), H (1), H (2), H (3), X ( 7),  8); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      hh (H (3), H (4), H (0), H (1), H (2), X ( 0), 13); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      hh (H (2), H (3), H (4), H (0), H (1), X ( 6),  6); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      hh (H (1), H (2), H (3), H (4), H (0), X (13),  5); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      hh (H (0), H (1), H (2), H (3), H (4), X (11), 12); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      hh (H (4), H (0), H (1), H (2), H (3), X ( 5),  7); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      hh (H (3), H (4), H (0), H (1), H (2), X (12),  5); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);

      --  Round 4

      ii (H (2), H (3), H (4), H (0), H (1), X ( 1), 11); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ii (H (1), H (2), H (3), H (4), H (0), X ( 9), 12); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ii (H (0), H (1), H (2), H (3), H (4), X (11), 14); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ii (H (4), H (0), H (1), H (2), H (3), X (10), 15); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ii (H (3), H (4), H (0), H (1), H (2), X ( 0), 14); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ii (H (2), H (3), H (4), H (0), H (1), X ( 8), 15); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ii (H (1), H (2), H (3), H (4), H (0), X (12),  9); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ii (H (0), H (1), H (2), H (3), H (4), X ( 4),  8); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ii (H (4), H (0), H (1), H (2), H (3), X (13),  9); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ii (H (3), H (4), H (0), H (1), H (2), X ( 3), 14); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ii (H (2), H (3), H (4), H (0), H (1), X ( 7),  5); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ii (H (1), H (2), H (3), H (4), H (0), X (15),  6); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ii (H (0), H (1), H (2), H (3), H (4), X (14),  8); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ii (H (4), H (0), H (1), H (2), H (3), X ( 5),  6); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ii (H (3), H (4), H (0), H (1), H (2), X ( 6),  5); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      ii (H (2), H (3), H (4), H (0), H (1), X ( 2), 12); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);

      --  Round 5

      jj (H (1), H (2), H (3), H (4), H (0), X ( 4),  9); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      jj (H (0), H (1), H (2), H (3), H (4), X ( 0), 15); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      jj (H (4), H (0), H (1), H (2), H (3), X ( 5),  5); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      jj (H (3), H (4), H (0), H (1), H (2), X ( 9), 11); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      jj (H (2), H (3), H (4), H (0), H (1), X ( 7),  6); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      jj (H (1), H (2), H (3), H (4), H (0), X (12),  8); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      jj (H (0), H (1), H (2), H (3), H (4), X ( 2), 13); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      jj (H (4), H (0), H (1), H (2), H (3), X (10), 12); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      jj (H (3), H (4), H (0), H (1), H (2), X (14),  5); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      jj (H (2), H (3), H (4), H (0), H (1), X ( 1), 12); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      jj (H (1), H (2), H (3), H (4), H (0), X ( 3), 13); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      jj (H (0), H (1), H (2), H (3), H (4), X ( 8), 14); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      jj (H (4), H (0), H (1), H (2), H (3), X (11), 11); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      jj (H (3), H (4), H (0), H (1), H (2), X ( 6),  8); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      jj (H (2), H (3), H (4), H (0), H (1), X (15),  5); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);
      jj (H (1), H (2), H (3), H (4), H (0), X (13),  6); Debug.Print_Word32_Array (H, 1, Types.Index'Last, True);

      --  Parallel round 1

      jjj (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X ( 5),  8);
      jjj (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X (14),  9);
      jjj (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X ( 7),  9);
      jjj (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X ( 0), 11);
      jjj (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X ( 9), 13);
      jjj (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X ( 2), 15);
      jjj (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X (11), 15);
      jjj (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X ( 4),  5);
      jjj (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X (13),  7);
      jjj (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X ( 6),  7);
      jjj (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X (15),  8);
      jjj (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X ( 8), 11);
      jjj (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X ( 1), 14);
      jjj (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X (10), 14);
      jjj (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X ( 3), 12);
      jjj (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X (12),  6);

      --  Parallel round 2

      iii (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X ( 6),  9);
      iii (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X (11), 13);
      iii (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X ( 3), 15);
      iii (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X ( 7),  7);
      iii (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X ( 0), 12);
      iii (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X (13),  8);
      iii (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X ( 5),  9);
      iii (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X (10), 11);
      iii (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X (14),  7);
      iii (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X (15),  7);
      iii (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X ( 8), 12);
      iii (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X (12),  7);
      iii (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X ( 4),  6);
      iii (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X ( 9), 15);
      iii (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X ( 1), 13);
      iii (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X ( 2), 11);

      --  Parallel round 3

      hhh (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X (15),  9);
      hhh (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X ( 5),  7);
      hhh (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X ( 1), 15);
      hhh (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X ( 3), 11);
      hhh (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X ( 7),  8);
      hhh (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X (14),  6);
      hhh (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X ( 6),  6);
      hhh (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X ( 9), 14);
      hhh (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X (11), 12);
      hhh (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X ( 8), 13);
      hhh (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X (12),  5);
      hhh (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X ( 2), 14);
      hhh (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X (10), 13);
      hhh (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X ( 0), 13);
      hhh (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X ( 4),  7);
      hhh (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X (13),  5);

      --  Parallel round 4

      ggg (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X ( 8), 15);
      ggg (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X ( 6),  5);
      ggg (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X ( 4),  8);
      ggg (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X ( 1), 11);
      ggg (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X ( 3), 14);
      ggg (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X (11), 14);
      ggg (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X (15),  6);
      ggg (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X ( 0), 14);
      ggg (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X ( 5),  6);
      ggg (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X (12),  9);
      ggg (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X ( 2), 12);
      ggg (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X (13),  9);
      ggg (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X ( 9), 12);
      ggg (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X ( 7),  5);
      ggg (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X (10), 15);
      ggg (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X (14),  8);

      --  Parallel round 5.

      fff (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X (12),  8);
      fff (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X (15),  5);
      fff (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X (10), 12);
      fff (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X ( 4),  9);
      fff (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X ( 1), 12);
      fff (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X ( 5),  5);
      fff (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X ( 8), 14);
      fff (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X ( 7),  6);
      fff (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X ( 6),  8);
      fff (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X ( 2), 13);
      fff (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X (13),  6);
      fff (H1 (0), H1 (1), H1 (2), H1 (3), H1 (4), X (14),  5);
      fff (H1 (4), H1 (0), H1 (1), H1 (2), H1 (3), X ( 0), 15);
      fff (H1 (3), H1 (4), H1 (0), H1 (1), H1 (2), X ( 3), 13);
      fff (H1 (2), H1 (3), H1 (4), H1 (0), H1 (1), X ( 9), 11);
      fff (H1 (1), H1 (2), H1 (3), H1 (4), H1 (0), X (11), 11);

      --  Combine results.

      H1 (3)        := Context.H (1) + H (2) + H1 (3);
      Context.H (1) := Context.H (2) + H (3) + H1 (4);
      Context.H (2) := Context.H (3) + H (4) + H1 (0);
      Context.H (3) := Context.H (4) + H (0) + H1 (1);
      Context.H (4) := Context.H (0) + H (1) + H1 (2);
      Context.H (0) := H1 (3);

   end Context_Update_Internal;

   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type)
   is
   begin
      Debug.Put_Line ("RIPEMD-160 UPDATE");

      Context_Update_Internal (Context, Block);
      Add (Context.Length, 512);
   end Context_Update;

   procedure Block_Terminate
     (Block  : in out Block_Type;
      Length : in     Block_Length_Type)
   is
      Index  : Block_Index;
      Offset : Natural;
   begin

      Index := Block_Index (Length / 32);
      Offset := Natural (Length mod 32 / 8);

      Debug.Put ("   Terminator offset =");
      Debug.Print_Natural (Offset);
      Debug.New_Line; 

      Block (Index) := Block (Index) xor Types.SHL32 (16#80#, 8 * Offset);
--      Block (Index) := Block (Index) and Types.SHL32 (not 16#80#, 8 * Offset);

--      if Index < Block_Index'Last
--      then
--         for I in Block_Index range Block_Index'First .. (Index - 1)
--            --# assert I in Block_Index;
--         loop
--            Block (I) := 0;
--         end loop;
--      end if;

   end Block_Terminate;

   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     Block_Type;
      Length  : in     Block_Length_Type)
   is
      B1 : Block_Type;
      B2 : Block_Type := Block_Type'(others => 0);
   begin

      Debug.Put_Line ("RIPEMD-160 FINAL");

      B1 := Block;

      --  Add length of last block to data length.
      Add (Context.Length, Length);

      --  Set trailing '1' marker and zero out rest of the block.
      Block_Terminate (B1, Length);

      Debug.Put_Line ("   Last data block:");
      Debug.Print_Word32_Array (B1, 1, 8, True);

      --  Update block
      Context_Update_Internal (Context, B1);

      --  Set length in final block.
      B2 (Block_Type'Last - 1) := Context.Length.MSW;
      B2 (Block_Type'Last)     := Context.Length.LSW;

      Debug.Put_Line ("   Final block:");
      Debug.Print_Word32_Array (B2, 1, 8, True);

      --  Update final block
      Context_Update_Internal (Context, B2);

   end Context_Finalize;

   function Get_Hash (Context : Context_Type) return Hash_Type is
   begin
      Debug.Put_Line ("RIPEMD-160 GET_HASH");
      Debug.Put ("            ");
      Debug.Print_Word32_Array (Context.H, 1, Types.Index'Last, True);
      return Context.H;
   end Get_Hash;

end LSC.RIPEMD160;
