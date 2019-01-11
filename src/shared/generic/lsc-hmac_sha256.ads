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

with LSC.SHA256, LSC.Types;
use type LSC.Types.Word32;
use type LSC.Types.Word64;
use type LSC.SHA256.Message_Index;

-------------------------------------------------------------------------------
-- The HMAC-SHA-256 message authentication code
--
-- <ul>
-- <li>
-- <a href="http://www.faqs.org/rfcs/rfc4868.html">
-- S. Kelly, Using HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 with
-- IPsec, RFC 4868, May 2007 </a>
-- </li>
-- </ul>
-------------------------------------------------------------------------------
package LSC.HMAC_SHA256 is

   pragma Preelaborate;

   -- HMAC-SHA-256 context
   type Context_Type is private;

   -- Index for HMAC-SHA-256 authenticator
   subtype Auth_Index is Types.Index range 0 .. 3;

   -- HMAC-SHA-256 authenticator
   subtype Auth_Type is Types.Word32_Array_Type (Auth_Index);

   -- Initialize HMAC-SHA-256 context using @Key@.
   function Context_Init (Key : SHA256.Block_Type) return Context_Type;

   -- Update HMAC-SHA-256 @Context@ with message block @Block@.
   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     SHA256.Block_Type)
     with Depends => (Context =>+ Block);

   -- Finalize HMAC-SHA-256 @Context@ using @Length@ bits of final message
   -- block @Block@.
   --
   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     SHA256.Block_Type;
      Length  : in     SHA256.Block_Length_Type)
     with Depends => (Context =>+ (Block, Length));

   -- Get pseudo-random function value from @Context@
   function Get_Prf  (Context : in Context_Type) return SHA256.SHA256_Hash_Type;

   -- Get authentication value from @Context@
   function Get_Auth (Context : in Context_Type) return Auth_Type;

   -- Compute hash value of @Length@ bits of @Message@ using @Key@.
   --
   function Pseudorandom
      (Key     : SHA256.Block_Type;
       Message : SHA256.Message_Type;
       Length  : SHA256.Message_Index) return SHA256.SHA256_Hash_Type
     with
       Pre =>
         Message'First <= Message'Last and
         Length / SHA256.Block_Size +
         (if Length mod SHA256.Block_Size = 0 then 0 else 1) <= Message'Length;

   -- Perform authentication of @Length@ bits of @Message@ using @Key@ and
   -- return the authentication value.
   --
   function Authenticate
      (Key     : SHA256.Block_Type;
       Message : SHA256.Message_Type;
       Length  : SHA256.Message_Index) return Auth_Type
     with
       Pre =>
         Message'First <= Message'Last and
         Length / SHA256.Block_Size +
         (if Length mod SHA256.Block_Size = 0 then 0 else 1) <= Message'Length;

private

   type Context_Type is record
      SHA256_Context : SHA256.Context_Type;
      Key            : SHA256.Block_Type;
   end record;

end LSC.HMAC_SHA256;
