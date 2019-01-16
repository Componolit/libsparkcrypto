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
use type LSC.Internal.Types.Word32;
use type LSC.Internal.Types.Word64;
use type LSC.Internal.Types.Index;

-------------------------------------------------------------------------------
-- The RIPEMD-160 hash algorithm
--
-- <ul>
-- <li>
-- <a href="http://homes.esat.kuleuven.be/~cosicart/pdf/AB-9601/AB-9601.pdf">
-- Hans Dobbertin and Antoon Bosselaers and Bart Preneel, RIPEMD-160: A
-- Strengthened Version of RIPEMD, April 1996 </a>
-- </li>
--
-- <li>
-- <a href="http://www.faqs.org/rfcs/rfc1320.html">
-- R. Rivest, The MD4 Message-Digest Algorithm, RFC 1320, April 1992 </a>
-- </li>
-- </ul>
-------------------------------------------------------------------------------
package LSC.Internal.RIPEMD160 is

   pragma Preelaborate;

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
   --  A RIPEMD160 message can be at most 2^64 bit long. As one block has 512 bit,
   --  this makes 2^55 blocks.
   subtype Message_Index is Types.Word64 range 0 .. 2 ** 55 - 1;

   -- RIPEMD-160 message
   type Message_Type is array (Message_Index range <>) of Block_Type;

   -- Initialize RIPEMD-160 context.
   function Context_Init return Context_Type;

   -- Update RIPEMD-160 @Context@ with message block @Block@.
   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     Block_Type)
     with Depends => (Context =>+ Block);

   -- Finalize RIPEMD-160 context using @Length@ bits of final message block
   -- @Block@.
   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     Block_Type;
      Length  : in     Block_Length_Type)
     with Depends => (Context =>+ (Block, Length));

   -- Return RIPEMD-160 hash from @Context@.
   function Get_Hash (Context : Context_Type) return Hash_Type;

   procedure Hash_Context
      (Message : in     Message_Type;
       Length  : in     Types.Word64;
       Ctx     : in out Context_Type)
     with
       Depends => (Ctx =>+ (Message, Length)),
       Pre =>
         Message'First <= Message'Last and
         Length / Block_Size +
         (if Length mod Block_Size = 0 then 0 else 1) <= Message'Length;

   -- Compute hash value of @Length@ bits of @Message@.
   function Hash
      (Message : Message_Type;
       Length  : Types.Word64) return Hash_Type
     with
       Pre =>
         Message'First <= Message'Last and
         Length / Block_Size +
         (if Length mod Block_Size = 0 then 0 else 1) <= Message'Length;

   -- Empty block
   Null_Block : constant Block_Type;

   -- Empty hash
   Null_Hash : constant Hash_Type;

private

   type Data_Length is record
      LSW : Types.Word32;
      MSW : Types.Word32;
   end record;

   type Context_Type is record
      Length : Data_Length;
      H      : Hash_Type;
   end record;

   Null_Block : constant Block_Type := Block_Type'(Block_Index => 0);
   Null_Hash : constant Hash_Type := Hash_Type'(Hash_Index => 0);

end LSC.Internal.RIPEMD160;
