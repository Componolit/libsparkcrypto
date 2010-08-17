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
use type LSC.Types.Word32;
use type LSC.Types.Word64;

--# inherit
--#    LSC.Types,
--#    LSC.Debug,
--#    LSC.Byteorder32,
--#    LSC.Pad32;

-------------------------------------------------------------------------------
--  The SHA-256 hash algorithm
--
--  <ul>
--  <li> FIPS PUB 180-3, Secure Hash Standard (SHS), National Institute of
--  Standards and Technology, U.S. Department of Commerce, October 2008.
--  [doc/specs/fips180-3_final.pdf] </li>
--  </ul>
-------------------------------------------------------------------------------
package LSC.SHA256 is

   -- SHA-256 context
   type Context_Type is private;

   -- Index for SHA-256 block
   subtype Block_Index is Types.Index range 0 .. 15;

   -- SHA-256 block
   subtype Block_Type is Types.Word32_Array_Type (Block_Index);

   -- SHA-256 block size
   Block_Size : constant := 512;

   -- Index for SHA-256 hash
   subtype SHA256_Hash_Index is Types.Index range 0 .. 7;

   -- SHA-256 hash
   subtype SHA256_Hash_Type is Types.Word32_Array_Type (SHA256_Hash_Index);

   -- SHA-256 block length
   subtype Block_Length_Type is Types.Word32 range 0 .. Block_Size - 1;

   -- Index for SHA-256 message
   --
   -- A SHA-256 message can be at most 2^64 bit long. As one block has 511 bit,
   -- this makes 2^53 blocks.
   subtype Message_Index is Types.Word64 range 0 .. 2 ** 53 - 1;

   -- SHA-256 message
   type Message_Type is array (Message_Index range <>) of Block_Type;

   -- Initialize SHA-256 context.
   function SHA256_Context_Init return Context_Type;

   -- Update SHA-256 @Context@ with message block @Block@.
   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type);
   --# derives Context from *,
   --#                      Block;
   pragma Inline (Context_Update);

   -- Finalize SHA-256 @Context@ using @Length@ bits of final message block
   -- @Block@.
   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     Block_Type;
      Length  : in     Block_Length_Type);
   --# derives Context from *,
   --#                      Block,
   --#                      Length;

   -- Return SHA-256 hash from @Context@.
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

end LSC.SHA256;
