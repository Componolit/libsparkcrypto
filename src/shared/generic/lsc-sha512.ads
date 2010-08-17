-------------------------------------------------------------------------------
-- This file is part of the sparkcrypto library.
--
-- Copyright (C) 2010  Alexander Senier <mail@senier.net>
-- Copyright (C) 2010  secunet Security Networks AG
--
-- libsparkcrypto is  free software; you  can redistribute it and/or  modify it
-- under  terms of  the GNU  General Public  License as  published by  the Free
-- Software  Foundation;  either version  3,  or  (at  your option)  any  later
-- version.  libsparkcrypto  is  distributed  in  the  hope  that  it  will  be
-- useful,  but WITHOUT  ANY WARRANTY;  without  even the  implied warranty  of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
--
-- As a  special exception under  Section 7 of GPL  version 3, you  are granted
-- additional  permissions  described in  the  GCC  Runtime Library  Exception,
-- version 3.1, as published by the Free Software Foundation.
--
-- You should  have received  a copy of  the GNU General  Public License  and a
-- copy  of  the  GCC  Runtime  Library  Exception  along  with  this  program;
-- see  the  files  COPYING3  and COPYING.RUNTIME  respectively.  If  not,  see
-- <http://www.gnu.org/licenses/>.
-------------------------------------------------------------------------------

with LSC.Types;

use type LSC.Types.Index;
use type LSC.Types.Word64;

--# inherit
--#    LSC.Types,
--#    LSC.Debug,
--#    LSC.Byteorder64,
--#    LSC.Pad64;

-------------------------------------------------------------------------------
--  References:
--
--  FIPS PUB 180-3, Secure Hash Standard (SHS), National Institute of Standards
--  and Technology, U.S. Department of Commerce, October 2008.
--  [doc/specs/fips180-3_final.pdf]
--
-------------------------------------------------------------------------------
package LSC.SHA512 is

   type Context_Type is private;

   subtype Block_Index is Types.Index range 0 .. 15;
   subtype Block_Type is Types.Word64_Array_Type (Block_Index);

   Block_Size : constant := 1024;

   subtype SHA512_Hash_Index is Types.Index range 0 .. 7;
   subtype SHA512_Hash_Type is Types.Word64_Array_Type (SHA512_Hash_Index);

   subtype SHA384_Hash_Index is Types.Index range 0 .. 5;
   subtype SHA384_Hash_Type is Types.Word64_Array_Type (SHA384_Hash_Index);

   subtype Block_Length_Type is Types.Word64 range 0 .. Block_Size - 1;

   --  A SHA512 hash can be at most 2^128 bit long. As one block has 1024 bit,
   --  this makes 2^118 blocks. We support a size of 2^64 only!
   subtype Message_Index is Types.Word64 range 0 .. 2**64 - 1;
   type Message_Type is array (Message_Index range <>) of Block_Type;

   -- Initialize SHA512 context.
   function SHA512_Context_Init return Context_Type;
   function SHA384_Context_Init return Context_Type;

   -- Update SHA512 context with message block.
   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type);
   --# derives Context from *,
   --#                      Block;
   pragma Inline (Context_Update);

   -- Finalize SHA512 context with final message block.
   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     Block_Type;
      Length  : in     Block_Length_Type);
   --# derives Context from *,
   --#                      Block,
   --#                      Length;

   -- Return SHA512 hash.
   function SHA512_Get_Hash (Context : Context_Type) return SHA512_Hash_Type;
   function SHA384_Get_Hash (Context : Context_Type) return SHA384_Hash_Type;

private

   type Data_Length is record
      LSW : Types.Word64;
      MSW : Types.Word64;
   end record;

   subtype Schedule_Index is Types.Index range 0 .. 79;
   subtype Schedule_Type is Types.Word64_Array_Type (Schedule_Index);

   type Context_Type is record
      Length : Data_Length;
      H      : SHA512_Hash_Type;
      W      : Schedule_Type;
   end record;

   function Init_Data_Length return Data_Length;

   procedure Add (Item  : in out Data_Length;
                  Value : in     Types.Word64);
   --# derives Item from *,
   --#                   Value;
   pragma Inline (Add);

   function Ch
     (x    : Types.Word64;
      y    : Types.Word64;
      z    : Types.Word64)
      return Types.Word64;
   --# return (x and y) xor ((not x) and z);
   pragma Inline (Ch);

   function Maj
     (x    : Types.Word64;
      y    : Types.Word64;
      z    : Types.Word64)
      return Types.Word64;
   --# return (x and y) xor (x and z) xor (y and z);
   pragma Inline (Maj);

   function Cap_Sigma_0_512 (x : Types.Word64) return Types.Word64;
   pragma Inline (Cap_Sigma_0_512);

   function Cap_Sigma_1_512 (x : Types.Word64) return Types.Word64;
   pragma Inline (Cap_Sigma_1_512);

   function Sigma_0_512 (x : Types.Word64) return Types.Word64;
   pragma Inline (Sigma_0_512);

   function Sigma_1_512 (x : Types.Word64) return Types.Word64;
   pragma Inline (Sigma_1_512);

   procedure Context_Update_Internal
     (Context : in out Context_Type;
      Block   : in     Block_Type);
   --# derives Context from *,
   --#                      Block;

end LSC.SHA512;
