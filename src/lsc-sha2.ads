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

with LSC.Types, LSC.Debug, LSC.Byteorder;
use type LSC.Types.Index;
use type LSC.Types.Word64;
--# inherit LSC.Types,
--#         LSC.Debug,
--#         LSC.Byteorder;

package LSC.SHA2 is

   type Context_Type is private;

   subtype Block_Index is Types.Index range 0 .. 15;
   subtype Block_Type is Types.Word64_Array_Type (Block_Index);

   subtype SHA512_Hash_Index is Types.Index range 0 .. 7;
   subtype SHA512_Hash_Type is Types.Word64_Array_Type (SHA512_Hash_Index);

   subtype SHA384_Hash_Index is Types.Index range 0 .. 5;
   subtype SHA384_Hash_Type is Types.Word64_Array_Type (SHA384_Hash_Index);

   subtype Block_Length_Type is Types.Word64 range 0 .. 1023;

   -- Initialize SHA2 context.
   function SHA512_Context_Init return Context_Type;
   function SHA384_Context_Init return Context_Type;

   -- Update SHA2 context with message block.
   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type);
   --# derives Context from *,
   --#                      Block;

   -- Finalize SHA2 context with final message block.
   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     Block_Type;
      Length  : in     Block_Length_Type);
   --# derives Context from *,
   --#                      Block,
   --#                      Length;

   -- Return SHA2 hash.
   function SHA512_Get_Hash (Context : Context_Type) return SHA512_Hash_Type;
   function SHA384_Get_Hash (Context : Context_Type) return SHA384_Hash_Type;

private

   type Data_Length is record
      LSW : Types.Word64;
      MSW : Types.Word64;
   end record;

   type State_Index is (a, b, c, d, e, f, g, h);
   type State_Type is array (State_Index) of Types.Word64;

   subtype Schedule_Index is Types.Index range 0 .. 79;
   subtype Schedule_Type is Types.Word64_Array_Type (Schedule_Index);

   type Context_Type is record
      Length : Data_Length;
      H      : SHA512_Hash_Type;
   end record;

   function Init_Data_Length return Data_Length;

   procedure Add (Item  : in out Data_Length;
                  Value : in     Types.Word64);
   --# derives Item from *,
   --#                   Value;

   procedure Block_Terminate
     (Block  : in out Block_Type;
      Length : in     Block_Length_Type);
   --# derives Block from *,
   --#                    Length;

   function Ch
     (x    : Types.Word64;
      y    : Types.Word64;
      z    : Types.Word64)
      return Types.Word64;
   --# return (x and y) xor ((not x) and z);

   function Maj
     (x    : Types.Word64;
      y    : Types.Word64;
      z    : Types.Word64)
      return Types.Word64;
   --# return (x and y) xor (x and z) xor (y and z);

   function Cap_Sigma_0_512 (x : Types.Word64) return Types.Word64;
   function Cap_Sigma_1_512 (x : Types.Word64) return Types.Word64;
   function Sigma_0_512 (x : Types.Word64) return Types.Word64;
   function Sigma_1_512 (x : Types.Word64) return Types.Word64;


   procedure Context_Update_Internal
     (Context : in out Context_Type;
      Block   : in     Block_Type);
   --# derives Context from *,
   --#                      Block;

end LSC.SHA2;
