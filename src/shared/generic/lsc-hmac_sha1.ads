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

with LSC.SHA1, LSC.Types;

use type LSC.Types.Word32;
use type LSC.Types.Word64;

-------------------------------------------------------------------------------
-- The HMAC-SHA-1 message authentication
--
-- <ul>
-- <li>
-- <a href="http://www.faqs.org/rfcs/rfc2202.html">
-- P. Cheng, Test Cases for HMAC-MD5 and HMAC-SHA-1, RFC 2202,
-- September 1997. </a>
-- </li>
-- </ul>
-------------------------------------------------------------------------------
package LSC.HMAC_SHA1 is

   pragma Preelaborate;

   -- HMAC-SHA-1 context
   type Context_Type is private;

   -- Initialize HMAC-SHA-1 context using @Key@.
   function Context_Init (Key : SHA1.Block_Type) return Context_Type;

   -- Update HMAC-SHA-1 @Context@ with message block @Block@.
   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     SHA1.Block_Type)
     with Depends => (Context =>+ Block);
   pragma Inline (Context_Update);

   -- Finalize HMAC-SHA-1 @Context@ using @Length@ bits of final message
   -- block @Block@.
   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     SHA1.Block_Type;
      Length  : in     SHA1.Block_Length_Type)
     with Depends => (Context =>+ (Block, Length));
   pragma Inline (Context_Finalize);

   -- Get authentication value from @Context@
   function Get_Auth (Context : in Context_Type) return SHA1.Hash_Type;

   -- Perform authentication of @Length@ bits of @Message@ using @Key@ and
   -- return the authentication value.
   function Authenticate
      (Key     : SHA1.Block_Type;
       Message : SHA1.Message_Type;
       Length  : Types.Word64) return SHA1.Hash_Type
     with
       Pre =>
         Message'First <= Message'Last and
         Length / SHA1.Block_Size +
         (if Length mod SHA1.Block_Size = 0 then 0 else 1) <= Message'Length;

private

   type Context_Type is record
      SHA1_Context : SHA1.Context_Type;
      Key          : SHA1.Block_Type;
   end record;

end LSC.HMAC_SHA1;
