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

with LSC.RIPEMD160, LSC.Types;

use type LSC.Types.Word32;
use type LSC.Types.Word64;

--# inherit
--#    LSC.Debug,
--#    LSC.RIPEMD160,
--#    LSC.Ops32,
--#    LSC.Types;

-------------------------------------------------------------------------------
-- The HMAC-RIPEMD-160 message authentication
--
-- <ul>
-- <li>
-- <a href="http://www.faqs.org/rfcs/rfc2286.html">
-- J. Kapp, Test Cases for HMAC-RIPEMD160 and HMAC-RIPEMD128, RFC 2286,
-- February 1998. </a>
-- </li>
-- </ul>
-------------------------------------------------------------------------------
package LSC.HMAC_RIPEMD160 is

   -- HMAC-RIPEMD-160 context
   type Context_Type is private;

   -- Initialize HMAC-RIPEMD-160 context using @Key@.
   function Context_Init (Key : RIPEMD160.Block_Type) return Context_Type;

   -- Update HMAC-RIPEMD-160 @Context@ with message block @Block@.
   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     RIPEMD160.Block_Type);
   --# derives Context from *,
   --#                      Block;
   pragma Inline (Context_Update);

   -- Finalize HMAC-RIPEMD-160 @Context@ using @Length@ bits of final message
   -- block @Block@.
   --
   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     RIPEMD160.Block_Type;
      Length  : in     RIPEMD160.Block_Length_Type);
   --# derives Context from *,
   --#                      Block,
   --#                      Length;
   pragma Inline (Context_Finalize);

   -- Get authentication value from @Context@
   function Get_Auth (Context : in Context_Type) return RIPEMD160.Hash_Type;

   -- Perform authentication of @Length@ bits of @Message@ using @Key@ and
   -- return the authentication value.
   --
   function Authenticate
      (Key     : RIPEMD160.Block_Type;
       Message : RIPEMD160.Message_Type;
       Length  : Types.Word64) return RIPEMD160.Hash_Type;
   --# pre
   --#    Length <= Message'Length * Types.Word64 (RIPEMD160.Block_Size);

private

   type Context_Type is record
      RIPEMD160_Context : RIPEMD160.Context_Type;
      Key               : RIPEMD160.Block_Type;
   end record;

end LSC.HMAC_RIPEMD160;
