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
--  FIPS PUB 180-3, Secure Hash Standard (SHS), National Institute of Standards
--  and Technology, U.S. Department of Commerce, October 2008.
--  [doc/specs/fips180-3_final.pdf]
--
-------------------------------------------------------------------------------

with LSC.Types, LSC.Debug, LSC.Byteorder32;
use type LSC.Types.Index;
use type LSC.Types.Word32;
use type LSC.Types.Word64;
--# inherit LSC.Types,
--#         LSC.Debug,
--#         LSC.Byteorder32;

package LSC.SHA256 is

   type Context_Type is private;

   subtype Block_Index is Types.Index range 0 .. 15;
   subtype Block_Type is Types.Word32_Array_Type (Block_Index);

   subtype SHA256_Hash_Index is Types.Index range 0 .. 7;
   subtype SHA256_Hash_Type is Types.Word32_Array_Type (SHA256_Hash_Index);

   subtype Block_Length_Type is Types.Word32 range 0 .. 511;

   --  A SHA256 message can be at most 2^64 bit long. As one block has 511 bit,
   --  this makes 2^53 blocks.
   subtype Message_Index is Types.Word64 range 1 .. 2 ** 53;
   type Message_Type is array (Message_Index range <>) of Block_Type;

   -- Initialize SHA256 context.
   function SHA256_Context_Init return Context_Type;

   -- Update SHA256 context with message block.
   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type);
   --# derives Context from *,
   --#                      Block;
   pragma Inline (Context_Update);

   -- Finalize SHA256 context with final message block.
   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     Block_Type;
      Length  : in     Block_Length_Type);
   --# derives Context from *,
   --#                      Block,
   --#                      Length;

   -- Return SHA256 hash.
   function SHA256_Get_Hash (Context : Context_Type) return SHA256_Hash_Type;

private

   type Data_Length is record
      LSW : Types.Word32;
      MSW : Types.Word32;
   end record;

   subtype Schedule_Index is Types.Index range 0 .. 63;
   subtype Schedule_Type is Types.Word32_Array_Type (Schedule_Index);

   type Context_Type is record
      Length : Data_Length;
      H      : SHA256_Hash_Type;
      W      : Schedule_Type;
   end record;

   function Init_Data_Length return Data_Length;

   procedure Add (Item  : in out Data_Length;
                  Value : in     Types.Word32);
   --# derives Item from *,
   --#                   Value;
   pragma Inline (Add);

   procedure Block_Terminate
     (Block  : in out Block_Type;
      Length : in     Block_Length_Type);
   --# derives Block from *,
   --#                    Length;
   pragma Inline (Block_Terminate);

   function Ch
     (x    : Types.Word32;
      y    : Types.Word32;
      z    : Types.Word32)
      return Types.Word32;
   --# return (x and y) xor ((not x) and z);
   pragma Inline (Ch);

   function Maj
     (x    : Types.Word32;
      y    : Types.Word32;
      z    : Types.Word32)
      return Types.Word32;
   --# return (x and y) xor (x and z) xor (y and z);
   pragma Inline (Maj);

   function Cap_Sigma_0_256 (x : Types.Word32) return Types.Word32;
   pragma Inline (Cap_Sigma_0_256);

   function Cap_Sigma_1_256 (x : Types.Word32) return Types.Word32;
   pragma Inline (Cap_Sigma_1_256);

   function Sigma_0_256 (x : Types.Word32) return Types.Word32;
   pragma Inline (Sigma_0_256);

   function Sigma_1_256 (x : Types.Word32) return Types.Word32;
   pragma Inline (Sigma_1_256);

   procedure Context_Update_Internal
     (Context : in out Context_Type;
      Block   : in     Block_Type);
   --# derives Context from *,
   --#                      Block;

end LSC.SHA256;
