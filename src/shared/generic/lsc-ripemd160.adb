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

with LSC.Ops32;
with LSC.Pad32;
with LSC.Debug;
with LSC.RIPEMD160.Print;

package body LSC.RIPEMD160 is

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

   function f
      (x : Types.Word32;
       y : Types.Word32;
       z : Types.Word32) return Types.Word32
   is
   begin
      return Ops32.XOR3 (x, y, z);
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
      --  WORKAROUND: The temporary variable for the negation is necessary to
      --  keep the evaluation depth for the simplifier low enough to simplify
      --  this automatically!

      Not_y : Types.Word32;
   begin
      Not_y := not y;
      --# assert Not_y in Types.Word32;
      return Ops32.XOR2 (x or Not_y, z);
   end h;

   ---------------------------------------------------------------------------

   function i
      (x : Types.Word32;
       y : Types.Word32;
       z : Types.Word32) return Types.Word32
   is
      --  WORKAROUND: The temporary variable for the negation is necessary to
      --  keep the evaluation depth for the simplifier low enough to simplify
      --  this automatically!

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
      --  WORKAROUND: The temporary variable for the negation is necessary to
      --  keep the evaluation depth for the simplifier low enough to simplify
      --  this automatically!

      Not_z : Types.Word32;
   begin
      Not_z := not z;
      --# assert Not_z in Types.Word32;
      return Ops32.XOR2 (x, y or Not_z);
   end j;

   ---------------------------------------------------------------------------

   procedure ff (A : in out Types.Word32;
                 B : in     Types.Word32;
                 C : in out Types.Word32;
                 D : in     Types.Word32;
                 E : in     Types.Word32;
                 X : in     Types.Word32;
                 S : in     Natural)
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;
   is
   begin
      pragma Debug (Print.Print_Schedule (" FF/S", A, B, C, D, E, X, S));
      A := A + f (B, C, D) + X;

      pragma Debug (Debug.Put ("       "));
      pragma Debug (Debug.Print_Word32 (A));
      pragma Debug (Debug.Put (" "));

      A := Types.ROTL32 (A, S) + E;

      pragma Debug (Debug.Print_Word32 (A));
      pragma Debug (Debug.New_Line);

      C := Types.ROTL32 (C, 10);

      pragma Debug (Print.Print_Schedule (" FF/E", A, B, C, D, E, X, S));
      pragma Debug (Debug.New_Line);
   end ff;

   ---------------------------------------------------------------------------

   procedure gg (A : in out Types.Word32;
                 B : in     Types.Word32;
                 C : in out Types.Word32;
                 D : in     Types.Word32;
                 E : in     Types.Word32;
                 X : in     Types.Word32;
                 S : in     Natural)
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;
   is
   begin
      pragma Debug (Print.Print_Schedule (" GG/S", A, B, C, D, E, X, S));
      A := A + g (B, C, D) + X + 16#5a82_7999#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
      pragma Debug (Print.Print_Schedule (" GG/E", A, B, C, D, E, X, S));
      pragma Debug (Debug.New_Line);
   end gg;

   ---------------------------------------------------------------------------

   procedure hh (A : in out Types.Word32;
                 B : in     Types.Word32;
                 C : in out Types.Word32;
                 D : in     Types.Word32;
                 E : in     Types.Word32;
                 X : in     Types.Word32;
                 S : in     Natural)
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;
   is
   begin
      pragma Debug (Print.Print_Schedule (" HH/S", A, B, C, D, E, X, S));
      A := A + h (B, C, D) + X + 16#6ed9_eba1#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
      pragma Debug (Print.Print_Schedule (" HH/E", A, B, C, D, E, X, S));
      pragma Debug (Debug.New_Line);
   end hh;

   ---------------------------------------------------------------------------

   procedure ii (A : in out Types.Word32;
                 B : in     Types.Word32;
                 C : in out Types.Word32;
                 D : in     Types.Word32;
                 E : in     Types.Word32;
                 X : in     Types.Word32;
                 S : in     Natural)
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;
   is
   begin
      pragma Debug (Print.Print_Schedule (" II/S", A, B, C, D, E, X, S));
      A := A + i (B, C, D) + X + 16#8f1b_bcdc#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
      pragma Debug (Print.Print_Schedule (" II/E", A, B, C, D, E, X, S));
      pragma Debug (Debug.New_Line);
   end ii;

   ---------------------------------------------------------------------------

   procedure jj (A : in out Types.Word32;
                 B : in     Types.Word32;
                 C : in out Types.Word32;
                 D : in     Types.Word32;
                 E : in     Types.Word32;
                 X : in     Types.Word32;
                 S : in     Natural)
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;
   is
   begin
      pragma Debug (Print.Print_Schedule (" JJ/S", A, B, C, D, E, X, S));
      A := A + j (B, C, D) + X + 16#a953_fd4e#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
      pragma Debug (Print.Print_Schedule (" JJ/E", A, B, C, D, E, X, S));
      pragma Debug (Debug.New_Line);
   end jj;

   ---------------------------------------------------------------------------

   procedure fff (A : in out Types.Word32;
                  B : in     Types.Word32;
                  C : in out Types.Word32;
                  D : in     Types.Word32;
                  E : in     Types.Word32;
                  X : in     Types.Word32;
                  S : in     Natural)
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;
   is
   begin
      pragma Debug (Print.Print_Schedule ("FFF/S", A, B, C, D, E, X, S));
      A := A + f (B, C, D) + X;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
      pragma Debug (Print.Print_Schedule ("FFF/E", A, B, C, D, E, X, S));
      pragma Debug (Debug.New_Line);
   end fff;

   ---------------------------------------------------------------------------

   procedure ggg (A : in out Types.Word32;
                  B : in     Types.Word32;
                  C : in out Types.Word32;
                  D : in     Types.Word32;
                  E : in     Types.Word32;
                  X : in     Types.Word32;
                  S : in     Natural)
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;
   is
   begin
      pragma Debug (Print.Print_Schedule ("GGG/S", A, B, C, D, E, X, S));
      A := A + g (B, C, D) + X + 16#7a6d_76e9#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
      pragma Debug (Print.Print_Schedule ("GGG/E", A, B, C, D, E, X, S));
      pragma Debug (Debug.New_Line);
   end ggg;

   ---------------------------------------------------------------------------

   procedure hhh (A : in out Types.Word32;
                  B : in     Types.Word32;
                  C : in out Types.Word32;
                  D : in     Types.Word32;
                  E : in     Types.Word32;
                  X : in     Types.Word32;
                  S : in     Natural)
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;
   is
   begin
      pragma Debug (Print.Print_Schedule ("HHH/S", A, B, C, D, E, X, S));
      A := A + h (B, C, D) + X + 16#6d70_3ef3#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
      pragma Debug (Print.Print_Schedule ("HHH/E", A, B, C, D, E, X, S));
      pragma Debug (Debug.New_Line);
   end hhh;

   ---------------------------------------------------------------------------

   procedure iii (A : in out Types.Word32;
                  B : in     Types.Word32;
                  C : in out Types.Word32;
                  D : in     Types.Word32;
                  E : in     Types.Word32;
                  X : in     Types.Word32;
                  S : in     Natural)
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;
   is
   begin
      pragma Debug (Print.Print_Schedule ("III/S", A, B, C, D, E, X, S));
      A := A + i (B, C, D) + X + 16#5c4d_d124#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
      pragma Debug (Print.Print_Schedule ("III/E", A, B, C, D, E, X, S));
      pragma Debug (Debug.New_Line);
   end iii;

   ---------------------------------------------------------------------------

   procedure jjj (A : in out Types.Word32;
                  B : in     Types.Word32;
                  C : in out Types.Word32;
                  D : in     Types.Word32;
                  E : in     Types.Word32;
                  X : in     Types.Word32;
                  S : in     Natural)
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;
   is
   begin
      pragma Debug (Print.Print_Schedule ("JJJ/S", A, B, C, D, E, X, S));
      A := A + j (B, C, D) + X + 16#50a2_8be6#;
      A := Types.ROTL32 (A, S) + E;
      C := Types.ROTL32 (C, 10);
      pragma Debug (Print.Print_Schedule ("JJJ/E", A, B, C, D, E, X, S));
      pragma Debug (Debug.New_Line);
   end jjj;

   ---------------------------------------------------------------------------

   procedure Context_Update_Internal
     (Context : in out Context_Type;
      X       : in     Block_Type)
   --# derives Context from *,
   --#                      X;
   is
      H0,  H1,  H2,  H3,  H4 : Types.Word32;
      HH0, HH1, HH2, HH3, HH4 : Types.Word32;
   begin

      -- DEBUG -------------------------------------------------------------
      pragma Debug (Debug.Put ("Context_Update_Internal:"));
      pragma Debug (Debug.Print_Word32_Array (X, 1, Types.Index'Last, True));
      ----------------------------------------------------------------------

      H0  := Context.H (0);
      H1  := Context.H (1);
      H2  := Context.H (2);
      H3  := Context.H (3);
      H4  := Context.H (4);

      HH0 := Context.H (0);
      HH1 := Context.H (1);
      HH2 := Context.H (2);
      HH3 := Context.H (3);
      HH4 := Context.H (4);

      --  Round 1
      --# assert True;

      ff (H0, H1, H2, H3, H4, X  (0), 11);
      ff (H4, H0, H1, H2, H3, X  (1), 14);
      ff (H3, H4, H0, H1, H2, X  (2), 15);
      ff (H2, H3, H4, H0, H1, X  (3), 12);
      ff (H1, H2, H3, H4, H0, X  (4),  5);
      ff (H0, H1, H2, H3, H4, X  (5),  8);
      ff (H4, H0, H1, H2, H3, X  (6),  7);
      ff (H3, H4, H0, H1, H2, X  (7),  9);
      ff (H2, H3, H4, H0, H1, X  (8), 11);
      ff (H1, H2, H3, H4, H0, X  (9), 13);
      ff (H0, H1, H2, H3, H4, X (10), 14);
      ff (H4, H0, H1, H2, H3, X (11), 15);
      ff (H3, H4, H0, H1, H2, X (12),  6);
      ff (H2, H3, H4, H0, H1, X (13),  7);
      ff (H1, H2, H3, H4, H0, X (14),  9);
      ff (H0, H1, H2, H3, H4, X (15),  8);

      --  Round 2
      --# assert True;

      gg (H4, H0, H1, H2, H3, X  (7),  7);
      gg (H3, H4, H0, H1, H2, X  (4),  6);
      gg (H2, H3, H4, H0, H1, X (13),  8);
      gg (H1, H2, H3, H4, H0, X  (1), 13);
      gg (H0, H1, H2, H3, H4, X (10), 11);
      gg (H4, H0, H1, H2, H3, X  (6),  9);
      gg (H3, H4, H0, H1, H2, X (15),  7);
      gg (H2, H3, H4, H0, H1, X  (3), 15);
      gg (H1, H2, H3, H4, H0, X (12),  7);
      gg (H0, H1, H2, H3, H4, X  (0), 12);
      gg (H4, H0, H1, H2, H3, X  (9), 15);
      gg (H3, H4, H0, H1, H2, X  (5),  9);
      gg (H2, H3, H4, H0, H1, X  (2), 11);
      gg (H1, H2, H3, H4, H0, X (14),  7);
      gg (H0, H1, H2, H3, H4, X (11), 13);
      gg (H4, H0, H1, H2, H3, X  (8), 12);

      --  Round 3
      --# assert True;

      hh (H3, H4, H0, H1, H2, X  (3), 11);
      hh (H2, H3, H4, H0, H1, X (10), 13);
      hh (H1, H2, H3, H4, H0, X (14),  6);
      hh (H0, H1, H2, H3, H4, X  (4),  7);
      hh (H4, H0, H1, H2, H3, X  (9), 14);
      hh (H3, H4, H0, H1, H2, X (15),  9);
      hh (H2, H3, H4, H0, H1, X  (8), 13);
      hh (H1, H2, H3, H4, H0, X  (1), 15);
      hh (H0, H1, H2, H3, H4, X  (2), 14);
      hh (H4, H0, H1, H2, H3, X  (7),  8);
      hh (H3, H4, H0, H1, H2, X  (0), 13);
      hh (H2, H3, H4, H0, H1, X  (6),  6);
      hh (H1, H2, H3, H4, H0, X (13),  5);
      hh (H0, H1, H2, H3, H4, X (11), 12);
      hh (H4, H0, H1, H2, H3, X  (5),  7);
      hh (H3, H4, H0, H1, H2, X (12),  5);

      --  Round 4
      --# assert True;

      ii (H2, H3, H4, H0, H1, X  (1), 11);
      ii (H1, H2, H3, H4, H0, X  (9), 12);
      ii (H0, H1, H2, H3, H4, X (11), 14);
      ii (H4, H0, H1, H2, H3, X (10), 15);
      ii (H3, H4, H0, H1, H2, X  (0), 14);
      ii (H2, H3, H4, H0, H1, X  (8), 15);
      ii (H1, H2, H3, H4, H0, X (12),  9);
      ii (H0, H1, H2, H3, H4, X  (4),  8);
      ii (H4, H0, H1, H2, H3, X (13),  9);
      ii (H3, H4, H0, H1, H2, X  (3), 14);
      ii (H2, H3, H4, H0, H1, X  (7),  5);
      ii (H1, H2, H3, H4, H0, X (15),  6);
      ii (H0, H1, H2, H3, H4, X (14),  8);
      ii (H4, H0, H1, H2, H3, X  (5),  6);
      ii (H3, H4, H0, H1, H2, X  (6),  5);
      ii (H2, H3, H4, H0, H1, X  (2), 12);

      --  Round 5
      --# assert True;

      jj (H1, H2, H3, H4, H0, X  (4),  9);
      jj (H0, H1, H2, H3, H4, X  (0), 15);
      jj (H4, H0, H1, H2, H3, X  (5),  5);
      jj (H3, H4, H0, H1, H2, X  (9), 11);
      jj (H2, H3, H4, H0, H1, X  (7),  6);
      jj (H1, H2, H3, H4, H0, X (12),  8);
      jj (H0, H1, H2, H3, H4, X  (2), 13);
      jj (H4, H0, H1, H2, H3, X (10), 12);
      jj (H3, H4, H0, H1, H2, X (14),  5);
      jj (H2, H3, H4, H0, H1, X  (1), 12);
      jj (H1, H2, H3, H4, H0, X  (3), 13);
      jj (H0, H1, H2, H3, H4, X  (8), 14);
      jj (H4, H0, H1, H2, H3, X (11), 11);
      jj (H3, H4, H0, H1, H2, X  (6),  8);
      jj (H2, H3, H4, H0, H1, X (15),  5);
      jj (H1, H2, H3, H4, H0, X (13),  6);

      --  Parallel round 1
      --# assert True;

      jjj (HH0, HH1, HH2, HH3, HH4, X  (5),  8);
      jjj (HH4, HH0, HH1, HH2, HH3, X (14),  9);
      jjj (HH3, HH4, HH0, HH1, HH2, X  (7),  9);
      jjj (HH2, HH3, HH4, HH0, HH1, X  (0), 11);
      jjj (HH1, HH2, HH3, HH4, HH0, X  (9), 13);
      jjj (HH0, HH1, HH2, HH3, HH4, X  (2), 15);
      jjj (HH4, HH0, HH1, HH2, HH3, X (11), 15);
      jjj (HH3, HH4, HH0, HH1, HH2, X  (4),  5);
      jjj (HH2, HH3, HH4, HH0, HH1, X (13),  7);
      jjj (HH1, HH2, HH3, HH4, HH0, X  (6),  7);
      jjj (HH0, HH1, HH2, HH3, HH4, X (15),  8);
      jjj (HH4, HH0, HH1, HH2, HH3, X  (8), 11);
      jjj (HH3, HH4, HH0, HH1, HH2, X  (1), 14);
      jjj (HH2, HH3, HH4, HH0, HH1, X (10), 14);
      jjj (HH1, HH2, HH3, HH4, HH0, X  (3), 12);
      jjj (HH0, HH1, HH2, HH3, HH4, X (12),  6);

      --  Parallel round 2
      --# assert True;

      iii (HH4, HH0, HH1, HH2, HH3, X  (6),  9);
      iii (HH3, HH4, HH0, HH1, HH2, X (11), 13);
      iii (HH2, HH3, HH4, HH0, HH1, X  (3), 15);
      iii (HH1, HH2, HH3, HH4, HH0, X  (7),  7);
      iii (HH0, HH1, HH2, HH3, HH4, X  (0), 12);
      iii (HH4, HH0, HH1, HH2, HH3, X (13),  8);
      iii (HH3, HH4, HH0, HH1, HH2, X  (5),  9);
      iii (HH2, HH3, HH4, HH0, HH1, X (10), 11);
      iii (HH1, HH2, HH3, HH4, HH0, X (14),  7);
      iii (HH0, HH1, HH2, HH3, HH4, X (15),  7);
      iii (HH4, HH0, HH1, HH2, HH3, X  (8), 12);
      iii (HH3, HH4, HH0, HH1, HH2, X (12),  7);
      iii (HH2, HH3, HH4, HH0, HH1, X  (4),  6);
      iii (HH1, HH2, HH3, HH4, HH0, X  (9), 15);
      iii (HH0, HH1, HH2, HH3, HH4, X  (1), 13);
      iii (HH4, HH0, HH1, HH2, HH3, X  (2), 11);

      --  Parallel round 3
      --# assert True;

      hhh (HH3, HH4, HH0, HH1, HH2, X (15),  9);
      hhh (HH2, HH3, HH4, HH0, HH1, X  (5),  7);
      hhh (HH1, HH2, HH3, HH4, HH0, X  (1), 15);
      hhh (HH0, HH1, HH2, HH3, HH4, X  (3), 11);
      hhh (HH4, HH0, HH1, HH2, HH3, X  (7),  8);
      hhh (HH3, HH4, HH0, HH1, HH2, X (14),  6);
      hhh (HH2, HH3, HH4, HH0, HH1, X  (6),  6);
      hhh (HH1, HH2, HH3, HH4, HH0, X  (9), 14);
      hhh (HH0, HH1, HH2, HH3, HH4, X (11), 12);
      hhh (HH4, HH0, HH1, HH2, HH3, X  (8), 13);
      hhh (HH3, HH4, HH0, HH1, HH2, X (12),  5);
      hhh (HH2, HH3, HH4, HH0, HH1, X  (2), 14);
      hhh (HH1, HH2, HH3, HH4, HH0, X (10), 13);
      hhh (HH0, HH1, HH2, HH3, HH4, X  (0), 13);
      hhh (HH4, HH0, HH1, HH2, HH3, X  (4),  7);
      hhh (HH3, HH4, HH0, HH1, HH2, X (13),  5);

      --  Parallel round 4
      --# assert True;

      ggg (HH2, HH3, HH4, HH0, HH1, X  (8), 15);
      ggg (HH1, HH2, HH3, HH4, HH0, X  (6),  5);
      ggg (HH0, HH1, HH2, HH3, HH4, X  (4),  8);
      ggg (HH4, HH0, HH1, HH2, HH3, X  (1), 11);
      ggg (HH3, HH4, HH0, HH1, HH2, X  (3), 14);
      ggg (HH2, HH3, HH4, HH0, HH1, X (11), 14);
      ggg (HH1, HH2, HH3, HH4, HH0, X (15),  6);
      ggg (HH0, HH1, HH2, HH3, HH4, X  (0), 14);
      ggg (HH4, HH0, HH1, HH2, HH3, X  (5),  6);
      ggg (HH3, HH4, HH0, HH1, HH2, X (12),  9);
      ggg (HH2, HH3, HH4, HH0, HH1, X  (2), 12);
      ggg (HH1, HH2, HH3, HH4, HH0, X (13),  9);
      ggg (HH0, HH1, HH2, HH3, HH4, X  (9), 12);
      ggg (HH4, HH0, HH1, HH2, HH3, X  (7),  5);
      ggg (HH3, HH4, HH0, HH1, HH2, X (10), 15);
      ggg (HH2, HH3, HH4, HH0, HH1, X (14),  8);

      --  Parallel round 5.
      --# assert True;

      fff (HH1, HH2, HH3, HH4, HH0, X (12),  8);
      fff (HH0, HH1, HH2, HH3, HH4, X (15),  5);
      fff (HH4, HH0, HH1, HH2, HH3, X (10), 12);
      fff (HH3, HH4, HH0, HH1, HH2, X  (4),  9);
      fff (HH2, HH3, HH4, HH0, HH1, X  (1), 12);
      fff (HH1, HH2, HH3, HH4, HH0, X  (5),  5);
      fff (HH0, HH1, HH2, HH3, HH4, X  (8), 14);
      fff (HH4, HH0, HH1, HH2, HH3, X  (7),  6);
      fff (HH3, HH4, HH0, HH1, HH2, X  (6),  8);
      fff (HH2, HH3, HH4, HH0, HH1, X  (2), 13);
      fff (HH1, HH2, HH3, HH4, HH0, X (13),  6);
      fff (HH0, HH1, HH2, HH3, HH4, X (14),  5);
      fff (HH4, HH0, HH1, HH2, HH3, X  (0), 15);
      fff (HH3, HH4, HH0, HH1, HH2, X  (3), 13);
      fff (HH2, HH3, HH4, HH0, HH1, X  (9), 11);
      fff (HH1, HH2, HH3, HH4, HH0, X (11), 11);

      --  Combine results.
      --# assert True;

      HH3           := Context.H (1) + H2 + HH3;
      Context.H (1) := Context.H (2) + H3 + HH4;
      Context.H (2) := Context.H (3) + H4 + HH0;
      Context.H (3) := Context.H (4) + H0 + HH1;
      Context.H (4) := Context.H (0) + H1 + HH2;
      Context.H (0) := HH3;

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

      Final_Block := Block;

      pragma Debug (Debug.Put ("Finalize start: "));
      pragma Debug (Debug.Print_Word32_Array (Final_Block, 1, Types.Index'Last, True));

      --  Add length of last block to data length.
      Add (Context.Length, Length);

      --  Set trailing '1' marker and zero out rest of the block.
      Pad32.Block_Terminate (Final_Block, Types.Word64 (Length));

      --  Terminator and length values won't fit into current block.
      if Length > 447 then
         Context_Update_Internal (Context, Final_Block);
         Final_Block := Null_Block;
      end if;

      --  Set length in final block.
      Final_Block (Block_Type'Last - 1) := Context.Length.LSW;
      Final_Block (Block_Type'Last)     := Context.Length.MSW;

      pragma Debug (Debug.Put ("Finalize end:   "));
      pragma Debug (Debug.Print_Word32_Array (Final_Block, 1, Types.Index'Last, True));

      --  Update final block
      Context_Update_Internal (Context, Final_Block);

   end Context_Finalize;

   ---------------------------------------------------------------------------

   function Get_Hash (Context : Context_Type) return Hash_Type is
   begin
      pragma Debug (Debug.Put_Line ("HASH:"));
      pragma Debug (Debug.Print_Word32_Array (Context.H, 1, Types.Index'Last, True));
      return Context.H;
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
         for K in Message_Index range Message'First .. Last_Block - 1
         loop
            --# assert
            --#    Last_Block = Last_Block% and
            --#    Last_Block - 1 <= Message'Last and
            --#    (Last_Length /= 0 -> Last_Block <= Message'Last) and
            --#    K < Last_Block;
            Context_Update (Ctx, Message (K));
         end loop;
      end if;

      if Last_Length = 0 then
         Context_Finalize (Ctx, Dummy, 0);
      else
         Context_Finalize (Ctx, Message (Last_Block), Last_Length);
      end if;
   end Hash_Context;

   ---------------------------------------------------------------------------

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

end LSC.RIPEMD160;
