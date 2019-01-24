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

with LSC.Internal.Types;

use type LSC.Internal.Types.Index;
use type LSC.Internal.Types.Word64;

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
package LSC.Internal.SHA512 is

   pragma Pure;

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
   -- (i.e. 2^54 blocks)
   -- </strong>
   type Message_Index is range 0 .. 2 ** 54 - 1;

   -- SHA-512 message
   type Message_Type is array (Message_Index range <>) of Block_Type;

   -- Initialize SHA-512 context.
   function SHA512_Context_Init return Context_Type;

   -- Initialize SHA-384 context.
   function SHA384_Context_Init return Context_Type;

   -- Update SHA-512 @Context@ context with message block @Block@.
   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type)
     with Depends => (Context =>+ Block);
   pragma Inline (Context_Update);

   -- Finalize SHA-512 context @Context@ using @Length@ bits of final message
   -- block @Block@.
   --
   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     Block_Type;
      Length  : in     Block_Length_Type)
     with Depends => (Context =>+ (Block, Length));

   -- Return SHA-512 hash.
   function SHA512_Get_Hash (Context : Context_Type) return SHA512_Hash_Type;

   -- Return SHA-384 hash.
   function SHA384_Get_Hash (Context : Context_Type) return SHA384_Hash_Type;

   procedure Hash_Context
      (Message : in     Message_Type;
       Length  : in     Message_Index;
       Ctx     : in out Context_Type)
     with
       Depends => (Ctx =>+ (Message, Length)),
       Pre =>
         Message'First <= Message'Last and
         Length / Block_Size +
         (if Length mod Block_Size = 0 then 0 else 1) <= Message'Length;

   -- Compute SHA-512 hash value of @Length@ bits of @Message@.
   function SHA512_Hash
      (Message : Message_Type;
       Length  : Message_Index) return SHA512_Hash_Type
     with
       Pre =>
         Message'First <= Message'Last and
         Length / Block_Size +
         (if Length mod Block_Size = 0 then 0 else 1) <= Message'Length;

   -- Compute SHA-384 hash value of @Length@ bits of @Message@.
   function SHA384_Hash
      (Message : Message_Type;
       Length  : Message_Index) return SHA384_Hash_Type
     with
       Pre =>
         Message'First <= Message'Last and
         Length / Block_Size +
         (if Length mod Block_Size = 0 then 0 else 1) <= Message'Length;

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

end LSC.Internal.SHA512;
