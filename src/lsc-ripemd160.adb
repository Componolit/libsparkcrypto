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

   function f
      (j : Round_Index;
       x : Types.Word32;
       y : Types.Word32;
       z : Types.Word32) return Types.Word32
   is
      Result : Types.Word32 := 0;
   begin

      if     0 <= j and j <= 15
      then
         Result := Ops.XOR3 (x, y, z);
      elsif 16 <= j and j <= 31
      then
         Result := (x and y) or ((not x) and z);
      elsif 32 <= j and j <= 47
      then
         Result := Ops.XOR2 (x or (not y), z);  
      elsif 48 <= j and j <= 63
      then
         Result := (x and z) or (y and (not z));
      elsif 64 <= j and j <= 49
      then
         Result := Ops.XOR2 (x, y or (not z));
      end if;

      return Result;
   end f;

   procedure Context_Update_Internal
     (Context : in out Context_Type;
      Block   : in     Block_Type)
   is
      T                  : Types.Word32;
      A,  B,  C,  D,  E  : Types.Word32;
      A1, B1, C1, D1, E1 : Types.Word32;
   begin
      A  := Context.H (0);
      B  := Context.H (1);
      C  := Context.H (2);
      D  := Context.H (3);
      E  := Context.H (4);

      A1 := Context.H (0);
      B1 := Context.H (1);
      C1 := Context.H (2);
      D1 := Context.H (3);
      E1 := Context.H (4);

      for j in Round_Index
      --# assert j in Round_Index;
      loop
         T  := Types.ROTL32 (A + f (j, B, C, D) + Block (Tables.r (j)) + Tables.K (j), Natural (Tables.s (j))) + E;
         A  := E;
         E  := D;
         D  := Types.ROTL32 (C, 10);
         C  := B;
         B  := T;

         T  := Types.ROTL32 (A1 + f (Round_Index'Last - j, B1, C1, D1) + Block (Tables.r1 (j)) + Tables.K1 (j), Natural (Tables.s1 (j))) + E1;
         A1 := E1;
         E1 := D1;
         D1 := Types.ROTL32 (C1, 10);
         C1 := B1;
         B1 := T;
      end loop;

      T := Context.H (1) + C + D1;
      Context.H (1) := Context.H (2) + D + E1;
      Context.H (2) := Context.H (3) + E + A1;
      Context.H (3) := Context.H (4) + A + B1;
      Context.H (4) := Context.H (0) + B + C1;
      Context.H (0) := T;

   end Context_Update_Internal;

   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type)
   is
   begin
      Context_Update_Internal (Context, Block);
      Add (Context.Length, 512);
   end Context_Update;

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

      Context_Update_Internal (Context => Context, Block => Final_Block);

   end Context_Finalize;

   function Get_Hash (Context : Context_Type) return Hash_Type is
   begin
      return Context.H;
   end Get_Hash;

end LSC.RIPEMD160;
