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
use type LSC.Types.Word32;
use type LSC.Types.Word64;
use type LSC.Types.Index;
--# inherit
--#    LSC.Types,
--#    LSC.Ops32,
--#    LSC.Pad32,
--#    LSC.Debug;

-------------------------------------------------------------------------------
--  The RIPEMD-160 hash algorithm
--
--  <ul>
--  <li> Hans Dobbertin and Antoon Bosselaers and Bart Preneel, RIPEMD-160: A
--  Strengthened Version of RIPEMD, April 1996 [doc/specs/sp800-38a.pdf] </li>
--  <li> R. Rivest, The MD4 Message-Digest Algorithm, RFC 1320, April 1992
--  [doc/specs/rfc1320.txt.pdf] </li>
--  </ul>
-------------------------------------------------------------------------------
package LSC.RIPEMD160 is

   -- RIPEMD-160 context
   type Context_Type is private;

   -- Index for RIPEMD-160 block
   subtype Block_Index is Types.Index range 0 .. 15;

   -- RIPEMD-160 block
   subtype Block_Type is Types.Word32_Array_Type (Block_Index);

   -- RIPEMD-160 block size
   Block_Size : constant := 512;

   -- Index for RIPEMD-160 hash
   subtype Hash_Index is Types.Index range 0 .. 4;

   -- RIPEMD-160 hash
   subtype Hash_Type is Types.Word32_Array_Type (Hash_Index);

   -- RIPEMD-160 block length
   subtype Block_Length_Type is Types.Word32 range 0 .. Block_Size - 1;

   -- Index for RIPEMD-160 message
   --
   --  A RIPEMD160 message can be at most 2^64 bit long. As one block has 511 bit,
   --  this makes 2^53 blocks.
   subtype Message_Index is Types.Word64 range 0 .. 2 ** 53 - 1;

   -- RIPEMD-160 message
   type Message_Type is array (Message_Index range <>) of Block_Type;

   -- Initialize RIPEMD-160 context.
   function Context_Init return Context_Type;

   -- Update RIPEMD-160 @Context@ with message block @Block@.
   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type);
   --# derives Context from *,
   --#                      Block;

   -- Finalize RIPEMD-160 context using @Length@ bits of final message block
   -- @Block@.
   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     Block_Type;
      Length  : in     Block_Length_Type);
   --# derives Context from *,
   --#                      Block,
   --#                      Length;

   -- Return RIPEMD-160 hash from Context@.
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

end LSC.RIPEMD160;
