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
-- The SHA-512 and SHA-386 hash algorithms
--
-- <ul>
-- <li>
-- <a href="http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf">
-- FIPS PUB 180-3, Secure Hash Standard (SHS), National Institute of
-- Standards and Technology, U.S. Department of Commerce, October 2008. </a>
-- </li>
-- </ul>
-------------------------------------------------------------------------------
package LSC.SHA512 is

   -- SHA-512 context
   type Context_Type is private;

   -- Index for SHA-512 block
   subtype Block_Index is Types.Index range 0 .. 15;

   -- SHA-512 block
   subtype Block_Type is Types.Word64_Array_Type (Block_Index);

   -- SHA-512 block size
   Block_Size : constant := 1024;

   -- Index for SHA-512 hash
   subtype SHA512_Hash_Index is Types.Index range 0 .. 7;

   -- SHA-512 hash
   subtype SHA512_Hash_Type is Types.Word64_Array_Type (SHA512_Hash_Index);

   -- Index for SHA-384 hash
   subtype SHA384_Hash_Index is Types.Index range 0 .. 5;

   -- SHA-384 hash
   subtype SHA384_Hash_Type is Types.Word64_Array_Type (SHA384_Hash_Index);

   -- SHA-512 block length
   subtype Block_Length_Type is Types.Word64 range 0 .. Block_Size - 1;

   -- Index for SHA-512 message
   --
   -- A SHA-512 hash can be at most 2^128 bit long. As one block has 1024 bit,
   -- this makes 2^118 blocks. <strong> NOTE: We support a size of 2^64 only!
   -- </strong>
   subtype Message_Index is Types.Word64 range 0 .. 2**64 - 1;

   -- SHA-512 message
   type Message_Type is array (Message_Index range <>) of Block_Type;

   -- Initialize SHA-512 context.
   function SHA512_Context_Init return Context_Type;

   -- Initialize SHA-384 context.
   function SHA384_Context_Init return Context_Type;

   -- Update SHA-512 @Context@ context with message block @Block@.
   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type);
   --# derives Context from *,
   --#                      Block;
   pragma Inline (Context_Update);

   -- Finalize SHA-512 context @Context@ using @Length@ bits of final message
   -- block @Block@.
   --
   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     Block_Type;
      Length  : in     Block_Length_Type);
   --# derives Context from *,
   --#                      Block,
   --#                      Length;

   -- Return SHA-512 hash.
   function SHA512_Get_Hash (Context : Context_Type) return SHA512_Hash_Type;

   -- Return SHA-384 hash.
   function SHA384_Get_Hash (Context : Context_Type) return SHA384_Hash_Type;

   -- Empty block
   Null_Block : constant Block_Type;

   -- Empty SHA-384 hash
   Null_SHA384_Hash : constant SHA384_Hash_Type;

   -- Empty SHA-512 hash
   Null_SHA512_Hash : constant SHA512_Hash_Type;

private

   type Data_Length is record
      LSW : Types.Word64;
      MSW : Types.Word64;
   end record;

   subtype Schedule_Index is Types.Index range 0 .. 79;
   subtype Schedule_Type is Types.Word64_Array_Type (Schedule_Index);

   Null_Schedule : constant Schedule_Type := Schedule_Type'(Schedule_Index => 0);

   type Context_Type is record
      Length : Data_Length;
      H      : SHA512_Hash_Type;
      W      : Schedule_Type;
   end record;

   Null_Block       : constant Block_Type :=
      Block_Type'(Block_Index => 0);

   Null_SHA384_Hash : constant SHA384_Hash_Type :=
      SHA384_Hash_Type'(SHA384_Hash_Index => 0);

   Null_SHA512_Hash : constant SHA512_Hash_Type :=
      SHA512_Hash_Type'(SHA512_Hash_Index => 0);

end LSC.SHA512;
