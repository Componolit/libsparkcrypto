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

with LSC.SHA512, LSC.Types;
use type LSC.Types.Word64;

-------------------------------------------------------------------------------
-- The HMAC-SHA-384 message authentication code
--
-- <ul>
-- <li>
-- <a href="http://www.faqs.org/rfcs/rfc4868.html">
-- S. Kelly, Using HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 with
-- IPsec, RFC 4868, May 2007 </a>
-- </li>
-- </ul>
-------------------------------------------------------------------------------
package LSC.HMAC_SHA384 is

   -- HMAC-SHA-384 context
   type Context_Type is private;

   -- Index for HMAC-SHA-384 authenticator
   subtype Auth_Index is Types.Index range 0 .. 2;

   -- HMAC-SHA-384 authenticator
   subtype Auth_Type is Types.Word64_Array_Type (Auth_Index);

   -- Initialize HMAC-SHA-384 context using @Key@.
   function Context_Init (Key : SHA512.Block_Type) return Context_Type;

   -- Update HMAC-SHA-384 @Context@ with message block @Block@.
   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     SHA512.Block_Type)
     with Depends => (Context =>+ Block);

   -- Finalize HMAC-SHA-384 @Context@ using @Length@ bits of final message
   -- block @Block@.
   --
   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     SHA512.Block_Type;
      Length  : in     SHA512.Block_Length_Type)
     with Depends => (Context =>+ (Block, Length));

   -- Get pseudo-random function value from @Context@
   function Get_Prf  (Context : in Context_Type) return SHA512.SHA384_Hash_Type;

   -- Get authentication value from @Context@
   function Get_Auth (Context : in Context_Type) return Auth_Type;

   -- Compute hash value of @Length@ bits of @Message@ using @Key@.
   --
   function Pseudorandom
      (Key     : SHA512.Block_Type;
       Message : SHA512.Message_Type;
       Length  : Types.Word64) return SHA512.SHA384_Hash_Type
     with Pre => Length <= Message'Length * SHA512.Block_Size;

   -- Perform authentication of @Length@ bits of @Message@ using @Key@ and
   -- return the authentication value.
   --
   function Authenticate
      (Key     : SHA512.Block_Type;
       Message : SHA512.Message_Type;
       Length  : Types.Word64) return Auth_Type
     with Pre => Length <= Message'Length * SHA512.Block_Size;

   -- Empty authenticator
   Null_Auth : constant Auth_Type;

private

   type Context_Type is record
      SHA384_Context : SHA512.Context_Type;
      Key            : SHA512.Block_Type;
   end record;

   Null_Auth : constant Auth_Type :=
      Auth_Type'(Auth_Index => 0);

end LSC.HMAC_SHA384;
