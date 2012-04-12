-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2010, Alexander Senier
-- Copyright (C) 2010, secunet Security Networks AG
-- All rights reserved.
--
-- Redistribution  and  use  in  source  and  binary  forms,  with  or  without
-- modification, are permitted provided that the following conditions are met:
--
--    * Redistributions of source code must retain the above copyright notice,
--      this list of conditions and the following disclaimer.
--
--    * Redistributions in binary form must reproduce the above copyright
--      notice, this list of conditions and the following disclaimer in the
--      documentation and/or other materials provided with the distribution.
--
--    * Neither the name of the  nor the names of its contributors may be used
--      to endorse or promote products derived from this software without
--      specific prior written permission.
--
-- THIS SOFTWARE IS PROVIDED BY THE  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-- AND ANY  EXPRESS OR IMPLIED WARRANTIES,  INCLUDING, BUT NOT LIMITED  TO, THE
-- IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
-- ARE  DISCLAIMED. IN  NO EVENT  SHALL  THE COPYRIGHT  HOLDER OR  CONTRIBUTORS
-- BE  LIABLE FOR  ANY  DIRECT, INDIRECT,  INCIDENTAL,  SPECIAL, EXEMPLARY,  OR
-- CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT  LIMITED  TO,  PROCUREMENT  OF
-- SUBSTITUTE GOODS  OR SERVICES; LOSS  OF USE,  DATA, OR PROFITS;  OR BUSINESS
-- INTERRUPTION)  HOWEVER CAUSED  AND ON  ANY THEORY  OF LIABILITY,  WHETHER IN
-- CONTRACT,  STRICT LIABILITY,  OR  TORT (INCLUDING  NEGLIGENCE OR  OTHERWISE)
-- ARISING IN ANY WAY  OUT OF THE USE OF THIS SOFTWARE, EVEN  IF ADVISED OF THE
-- POSSIBILITY OF SUCH DAMAGE.
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
--  <li>
--  <a href="http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf">
--  FIPS PUB 180-3, Secure Hash Standard (SHS), National Institute of Standards
--  and Technology, U.S. Department of Commerce, October 2008. </a>
--  </li>
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
   -- A SHA-256 message can be at most 2^64 bit long. As one block has 512 bit,
   -- this makes 2^55 blocks.
   subtype Message_Index is Types.Word64 range 0 .. 2 ** 55 - 1;

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

   procedure Hash_Context
      (Message : in     Message_Type;
       Length  : in     Types.Word64;
       Ctx     : in out Context_Type);
   --# derives Ctx from Ctx, Message, Length;
   --# pre
   --#    Universal_Integer (Length) <= Message'Length * Block_Size;

   -- Compute hash value of @Length@ bits of @Message@.
   function Hash
      (Message : Message_Type;
       Length  : Types.Word64) return SHA256_Hash_Type;
   --# pre
   --#    Universal_Integer (Length) <= Message'Length * Block_Size;

   -- Empty block
   Null_Block : constant Block_Type;

   -- Empty Hash
   SHA256_Null_Hash : constant SHA256_Hash_Type;

private

   type Data_Length is record
      LSW : Types.Word32;
      MSW : Types.Word32;
   end record;

   subtype Schedule_Index is Types.Index range 0 .. 63;
   subtype Schedule_Type is Types.Word32_Array_Type (Schedule_Index);

   Null_Schedule : constant Schedule_Type :=
      Schedule_Type'(Schedule_Index => 0);

   type Context_Type is record
      Length : Data_Length;
      H      : SHA256_Hash_Type;
      W      : Schedule_Type;
   end record;

   Null_Block : constant Block_Type :=
      Block_Type'(Block_Index => 0);

   SHA256_Null_Hash : constant SHA256_Hash_Type :=
      SHA256_Hash_Type'(SHA256_Hash_Index => 0);

end LSC.SHA256;
