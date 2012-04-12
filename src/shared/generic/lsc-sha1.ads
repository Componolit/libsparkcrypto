-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2011, Adrian-Ken Rueegsegger
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
use type LSC.Types.Word32;
use type LSC.Types.Word64;
use type LSC.Types.Index;
--# inherit
--#    LSC.Types,
--#    LSC.Byteorder32,
--#    LSC.Ops32,
--#    LSC.Pad32,
--#    LSC.Debug;

-------------------------------------------------------------------------------
-- The SHA-1 hash algorithm
--
--  <ul>
--  <li>
--  <a href="http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf">
--  FIPS PUB 180-3, Secure Hash Standard (SHS), National Institute of Standards
--  and Technology, U.S. Department of Commerce, October 2008. </a>
--  </li>
--  </ul>
-------------------------------------------------------------------------------
package LSC.SHA1 is

   -- SHA-1 context
   type Context_Type is private;

   -- Index for SHA-1 block
   subtype Block_Index is Types.Index range 0 .. 15;

   -- SHA-1 block
   subtype Block_Type is Types.Word32_Array_Type (Block_Index);

   -- SHA-1 block size
   Block_Size : constant := 512;

   -- Index for SHA-1 hash
   subtype Hash_Index is Types.Index range 0 .. 4;

   -- SHA-1 hash
   subtype Hash_Type is Types.Word32_Array_Type (Hash_Index);

   -- SHA-1 block length
   subtype Block_Length_Type is Types.Word32 range 0 .. Block_Size - 1;

   -- Index for SHA-1 message
   --
   --  A SHA-1 message can be at most 2^64 bit long. As one block has 512 bit,
   --  this makes 2^55 blocks.
   subtype Message_Index is Types.Word64 range 0 .. 2 ** 55 - 1;

   -- SHA-1 message
   type Message_Type is array (Message_Index range <>) of Block_Type;

   -- Initialize SHA-1 context.
   function Context_Init return Context_Type;

   -- Update SHA-1 @Context@ with message block @Block@.
   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type);
   --# derives Context from *,
   --#                      Block;

   -- Finalize SHA-1 context using @Length@ bits of final message block
   -- @Block@.
   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     Block_Type;
      Length  : in     Block_Length_Type);
   --# derives Context from *,
   --#                      Block,
   --#                      Length;

   -- Return SHA-1 hash from @Context@.
   function Get_Hash (Context : Context_Type) return Hash_Type;

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
       Length  : Types.Word64) return Hash_Type;
   --# pre
   --#    Universal_Integer (Length) <= Message'Length * Block_Size;

   -- Empty block
   Null_Block : constant Block_Type;

   -- Empty hash
   Null_Hash : constant Hash_Type;

private

   type Data_Length is record
      LSW : Types.Word32;
      MSW : Types.Word32;
   end record;

   subtype Schedule_Index is Types.Index range 0 .. 79;
   subtype Schedule_Type is Types.Word32_Array_Type (Schedule_Index);

   Null_Schedule : constant Schedule_Type :=
     Schedule_Type'(Schedule_Index => 0);

   K1 : constant Types.Word32 := 16#5a827999#;
   K2 : constant Types.Word32 := 16#6ed9eba1#;
   K3 : constant Types.Word32 := 16#8f1bbcdc#;
   K4 : constant Types.Word32 := 16#ca62c1d6#;

   type Context_Type is record
      Length : Data_Length;
      H      : Hash_Type;
   end record;

   Null_Block : constant Block_Type := Block_Type'(Block_Index => 0);
   Null_Hash  : constant Hash_Type  := Hash_Type'(Hash_Index => 0);

end LSC.SHA1;
