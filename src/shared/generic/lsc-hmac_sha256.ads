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

with LSC.SHA256, LSC.Types;
use type LSC.Types.Word32;
use type LSC.Types.Word64;

--# inherit
--#    LSC.Debug,
--#    LSC.SHA256,
--#    LSC.Ops32,
--#    LSC.Types;

-------------------------------------------------------------------------------
-- The HMAC-SHA-256 message authentication code
--
-- <ul>
-- <li> S. Kelly, Using HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 with
-- IPsec, RFC 4868, May 2007 [doc/specs/rfc4868.txt.pdf] </li>
-- </ul>
-------------------------------------------------------------------------------
package LSC.HMAC_SHA256 is

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
      Block   : in     SHA256.Block_Type);
   --# derives Context from *,
   --#                      Block;

   -- Finalize HMAC-SHA-256 @Context@ using @Length@ bits of final message
   -- block @Block@.
   --
   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     SHA256.Block_Type;
      Length  : in     SHA256.Block_Length_Type);
   --# derives Context from *,
   --#                      Block,
   --#                      Length;

   -- Get pseudo-random function value from @Context@
   function Get_Prf  (Context : in Context_Type) return SHA256.SHA256_Hash_Type;

   -- Get authentication value from @Context@
   function Get_Auth (Context : in Context_Type) return Auth_Type;

   -- Perform authentication of @Length@ bits of @Message@ using @Key@ and
   -- return the authentication value.
   --
   function Authenticate
      (Key     : SHA256.Block_Type;
       Message : SHA256.Message_Type;
       Length  : Types.Word64) return Auth_Type;
   --# pre
   --#    Message'First + (Length / SHA256.Block_Size) in Message'Range;

private

   type Context_Type is record
      SHA256_Context : SHA256.Context_Type;
      Key            : SHA256.Block_Type;
   end record;

end LSC.HMAC_SHA256;
