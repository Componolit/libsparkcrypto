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

with LSC.Types, LSC.Ops, LSC.Debug;
use type LSC.Types.Word32;
use type LSC.Types.Index;
--# inherit LSC.Types,
--#         LSC.Ops,
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

   subtype Round_Index is Types.Index range 0 .. 79;

   subtype K_Type is Types.Word32_Array_Type (Round_Index);
   type SR_Type is array (Round_Index) of Block_Index;

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
      Block   : in     Block_Type);
   --# derives Context from *,
   --#                      Block;


   --  nonlinear functions at bit level
   function f
      (j : Round_Index;
       x : Types.Word32;
       y : Types.Word32;
       z : Types.Word32) return Types.Word32;

end LSC.RIPEMD160;
