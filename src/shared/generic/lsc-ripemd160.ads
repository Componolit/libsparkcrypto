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
--  References:
--
--  Hans Dobbertin and Antoon Bosselaers and Bart Preneel, RIPEMD-160: A
--  Strengthened Version of RIPEMD, April 1996
--  [doc/specs/sp800-38a.pdf]
--
--  R. Rivest, The MD4 Message-Digest Algorithm, RFC 1320, April 1992
--  [doc/specs/rfc1320.txt.pdf]
-------------------------------------------------------------------------------

with LSC.Types, LSC.Ops32, LSC.Byteorder32, LSC.Debug;
use type LSC.Types.Word32;
use type LSC.Types.Index;
--# inherit LSC.Types,
--#         LSC.Ops32,
--#         LSC.Byteorder32,
--#         LSC.Debug;

package LSC.RIPEMD160 is

   type Context_Type is private;

   subtype Block_Index is Types.Index range 0 .. 15;
   subtype Block_Type is Types.Word32_Array_Type (Block_Index);

   subtype Hash_Index is Types.Index range 0 .. 4;
   subtype Hash_Type is Types.Word32_Array_Type (Hash_Index);

   subtype Block_Length_Type is Types.Word32 range 0 .. 511;

   -- Initialize RIPEMD-160 context.
   function Context_Init return Context_Type;

   -- Update RIPEMD-160 context with message block.
   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type);
   --# derives Context from *,
   --#                      Block;

   -- Finalize RIPEMD-160 context with final message block.
   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     Block_Type;
      Length  : in     Block_Length_Type);
   --# derives Context from *,
   --#                      Block,
   --#                      Length;

   -- Return RIPEMD-160 hash.
   function Get_Hash (Context : Context_Type) return Hash_Type;

private

   type Data_Length is record
      LSW : Types.Word32;
      MSW : Types.Word32;
   end record;

   type Context_Type is record
      Length : Data_Length;
      H      : Hash_Type;
   end record;

   function Init_Data_Length return Data_Length;

   procedure Add (Item  : in out Data_Length;
                  Value : in     Types.Word32);
   --# derives Item from *,
   --#                   Value;

   procedure Block_Terminate
     (Block  : in out Block_Type;
      Length : in     Block_Length_Type);
   --# derives Block from *,
   --#                    Length;

   procedure Context_Update_Internal
     (Context : in out Context_Type;
      X       : in     Block_Type);
   --# derives Context from *,
   --#                      X;


   --  nonlinear functions at bit level
   function f (x, y, z : Types.Word32) return Types.Word32;
   function g (x, y, z : Types.Word32) return Types.Word32;
   function h (x, y, z : Types.Word32) return Types.Word32;
   function i (x, y, z : Types.Word32) return Types.Word32;
   function j (x, y, z : Types.Word32) return Types.Word32;

   --  round procedures

   procedure ff (A : in out Types.Word32;
                 B : in     Types.Word32;
                 C : in out Types.Word32;
                 D : in     Types.Word32;
                 E : in     Types.Word32;
                 X : in     Types.Word32;
                 S : in     Natural);
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;

   procedure gg (A : in out Types.Word32;
                 B : in     Types.Word32;
                 C : in out Types.Word32;
                 D : in     Types.Word32;
                 E : in     Types.Word32;
                 X : in     Types.Word32;
                 S : in     Natural);
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;

   procedure hh (A : in out Types.Word32;
                 B : in     Types.Word32;
                 C : in out Types.Word32;
                 D : in     Types.Word32;
                 E : in     Types.Word32;
                 X : in     Types.Word32;
                 S : in     Natural);
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;

   procedure ii (A : in out Types.Word32;
                 B : in     Types.Word32;
                 C : in out Types.Word32;
                 D : in     Types.Word32;
                 E : in     Types.Word32;
                 X : in     Types.Word32;
                 S : in     Natural);
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;

   procedure jj (A : in out Types.Word32;
                 B : in     Types.Word32;
                 C : in out Types.Word32;
                 D : in     Types.Word32;
                 E : in     Types.Word32;
                 X : in     Types.Word32;
                 S : in     Natural);
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;

   procedure fff (A : in out Types.Word32;
                  B : in     Types.Word32;
                  C : in out Types.Word32;
                  D : in     Types.Word32;
                  E : in     Types.Word32;
                  X : in     Types.Word32;
                  S : in     Natural);
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;

   procedure ggg (A : in out Types.Word32;
                  B : in     Types.Word32;
                  C : in out Types.Word32;
                  D : in     Types.Word32;
                  E : in     Types.Word32;
                  X : in     Types.Word32;
                  S : in     Natural);
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;

   procedure hhh (A : in out Types.Word32;
                  B : in     Types.Word32;
                  C : in out Types.Word32;
                  D : in     Types.Word32;
                  E : in     Types.Word32;
                  X : in     Types.Word32;
                  S : in     Natural);
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;

   procedure iii (A : in out Types.Word32;
                  B : in     Types.Word32;
                  C : in out Types.Word32;
                  D : in     Types.Word32;
                  E : in     Types.Word32;
                  X : in     Types.Word32;
                  S : in     Natural);
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;

   procedure jjj (A : in out Types.Word32;
                  B : in     Types.Word32;
                  C : in out Types.Word32;
                  D : in     Types.Word32;
                  E : in     Types.Word32;
                  X : in     Types.Word32;
                  S : in     Natural);
   --# derives A from A, B, C, D, E, X, S &
   --#         C from C;

end LSC.RIPEMD160;
