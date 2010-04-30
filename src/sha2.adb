--  Copyright (C) 2010  Alexander Senier <mail@senier.net>
--
--  This program is free software: you can redistribute it and/or modify
--  it under the terms of the GNU General Public License as published by
--  the Free Software Foundation, either version 3 of the License, or
--  (at your option) any later version.
--
--  This program is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with this program.  If not, see <http://www.gnu.org/licenses/>.

with Types, SHA2.Debug;
use type Types.Word64;

package body SHA2 is

    function Init_Data_Length return Data_Length
    is
    begin
       return Data_Length'(0, 0);
    end Init_Data_Length;

    procedure Add (Item  : in out Data_Length;
                   Value : in     Types.Word64)
    is
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
        (x : Types.Word64;
         y : Types.Word64;
         z : Types.Word64) return Types.Word64
    is
    begin
        return ((x and y) xor ((not x) and z));
    end Ch;

    function Maj
        (x : Types.Word64;
         y : Types.Word64;
         z : Types.Word64) return Types.Word64
    is
    begin
        return (x and y) xor (x and z) xor (y and z);
    end Maj;

    function Cap_Sigma_0_512 (x : Types.Word64) return Types.Word64
    is
    begin
        return Types.ROTR (x, 28) xor
               Types.ROTR (x, 34) xor
               Types.ROTR (x, 39);
    end Cap_Sigma_0_512;

    function Cap_Sigma_1_512 (x : Types.Word64) return Types.Word64
    is
    begin
        return Types.ROTR (x, 14) xor
               Types.ROTR (x, 18) xor
               Types.ROTR (x, 41);
    end Cap_Sigma_1_512;

    function Sigma_0_512 (x : Types.Word64) return Types.Word64
    is
    begin
        return Types.ROTR (x, 1) xor
               Types.ROTR (x, 8) xor
               Types.SHR  (x, 7);
    end Sigma_0_512;

    function Sigma_1_512 (x : Types.Word64) return Types.Word64
    is
    begin
        return Types.ROTR (x, 19) xor
               Types.ROTR (x, 61) xor
               Types.SHR  (x, 6);
    end Sigma_1_512;

    function Context_Init return Context_Type
    is
    begin
        return Context_Type'
            (Length => Init_Data_Length,
             H      => Hash_Type'(0 => 16#6a09e667f3bcc908#,
                                  1 => 16#bb67ae8584caa73b#,
                                  2 => 16#3c6ef372fe94f82b#,
                                  3 => 16#a54ff53a5f1d36f1#,
                                  4 => 16#510e527fade682d1#,
                                  5 => 16#9b05688c2b3e6c1f#,
                                  6 => 16#1f83d9abfb41bd6b#,
                                  7 => 16#5be0cd19137e2179#));
    end Context_Init;

    procedure Context_Update
        (Context : in out Context_Type;
         M       : in     Block_Type)
    is
        W      : Schedule_Type;
        S      : State_Type;
        T1, T2 : Types.Word64;
    begin

        W := Schedule_Type'(others => 0);

        -- Print out initial state of H
        Debug.Put_Line ("SHA-512 initial hash values:");
        Debug.Put_Hash (Context.H);

        -------------------------------------------
        --  Section 6.3.2 SHA-512 Hash Computations
        -------------------------------------------

        --  1. Prepare the message schedule, W(t):
        for t in Schedule_Index range 0 .. 15
            --# assert t in 0 .. 15;
        loop
            W (t) := M (Block_Index (t));
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
        Debug.Put_Schedule (W);

        -- 2. Initialize the eight working variables a, b, c, d, e, f, g, and
        --    h with the (i-1)st hash value:
        S := State_Type'(a => Context.H (0),
                         b => Context.H (1),
                         c => Context.H (2),
                         d => Context.H (3),
                         e => Context.H (4),
                         f => Context.H (5),
                         g => Context.H (6),
                         h => Context.H (7));

        Debug.Put_Line ("Initial state:");
        Debug.Put_State (S);

        -- 3. For t = 0 to 79:
        for t in Schedule_Index range 0 .. 79
            --# assert t in 0 .. 79;
        loop
            T1 := S (h) + Cap_Sigma_1_512 (S (e)) + Ch (S (e), S (f), S (g)) + K (t) + W (t);
            T2 := Cap_Sigma_0_512 (S (a)) + Maj (S (a), S (b), S (c));

             S := State_Type'(h => S (g),
                              g => S (f),
                              f => S (e),
                              e => S (d) + T1,
                              d => S (c),
                              c => S (b),
                              b => S (a),
                              a => T1 + T2);

            Debug.Put_T (t);
            Debug.Put_State (S);
        end loop;

        -- 4. Compute the i-th intermediate hash value H-i:
        Context.H := Hash_Type'(0 => S (a) + Context.H (0),
                                1 => S (b) + Context.H (1),
                                2 => S (c) + Context.H (2),
                                3 => S (d) + Context.H (3),
                                4 => S (e) + Context.H (4),
                                5 => S (f) + Context.H (5),
                                6 => S (g) + Context.H (6),
                                7 => S (h) + Context.H (7));

        Debug.Put_Line ("SHA-512 final hash values:");
        Debug.Put_Hash (Context.H);

    end Context_Update;

    procedure Block_Terminate
        (M      : in out Block_Type;
         Length : in Block_Length_Type)
    is
       Index  : Block_Index;
       Offset : Natural;
    begin

       Index     := Block_Index (Length / 64);
       Offset    := Natural (63 - Length mod 64);

       Debug.Put_Line ("Terminator offset:");
       Debug.Put_Natural (Offset);
       Debug.Put_Line (".");

       M (Index) := M (Index) xor Types.SHL (1, Offset);

    end Block_Terminate;

    procedure Context_Finalize
        (Context : in out Context_Type;
         M       : in     Block_Type;
         Length  : in     Block_Length_Type)
    is
        Final_Block : Block_Type;

    begin

        Final_Block := M;

        --  Add length of last block to data length.
        Add (Context.Length, Length);

        --  Set trailing '1' marker.
        Block_Terminate
           (M      => Final_Block,
            Length => Length);

        --  Set length in final block.
        Final_Block (Block_Type'Last - 1) := Context.Length.MSW;
        Final_Block (Block_Type'Last)     := Context.Length.LSW;

        Context_Update
           (Context => Context,
            M       => Final_Block);

    end Context_Finalize;

end SHA2;
