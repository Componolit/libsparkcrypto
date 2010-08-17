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

with LSC.RIPEMD160, LSC.Types;

use type LSC.Types.Word32;
use type LSC.Types.Word64;

--# inherit
--#    LSC.Debug,
--#    LSC.RIPEMD160,
--#    LSC.Ops32,
--#    LSC.Types;

-------------------------------------------------------------------------------
--  The HMAC-RIPEMD-160 message authentication
--
--  <ul>
--  <li> J. Kapp, Test Cases for HMAC-RIPEMD160 and HMAC-RIPEMD128, RFC 2286,
--  February 1998. [doc/specs/rfc2286.txt.pdf] </li>
--  </ul>
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
   --#    Message'First + (Length / RIPEMD160.Block_Size) in Message'Range;

private

   type Context_Type is record
      RIPEMD160_Context : RIPEMD160.Context_Type;
      Key               : RIPEMD160.Block_Type;
   end record;

end LSC.HMAC_RIPEMD160;
