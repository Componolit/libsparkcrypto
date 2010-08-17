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

with LSC.SHA512, LSC.Types;
use type LSC.Types.Word64;

--# inherit
--#    LSC.Debug,
--#    LSC.SHA512,
--#    LSC.Ops64,
--#    LSC.Types;

-------------------------------------------------------------------------------
--  References:
--
--  S. Kelly, Using HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 with IPsec,
--  RFC 4868, May 2007
--  [doc/specs/rfc4868.txt.pdf]
-------------------------------------------------------------------------------
package LSC.HMAC_SHA512 is

   type Context_Type is private;

   Auth_Length : constant := 32;
   subtype Auth_Index is Types.Index range 0 .. 3;
   subtype Auth_Type is Types.Word64_Array_Type (Auth_Index);

   function Context_Init (Key : SHA512.Block_Type) return Context_Type;

   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     SHA512.Block_Type);
   --# derives Context from *,
   --#                      Block;

   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     SHA512.Block_Type;
      Length  : in     SHA512.Block_Length_Type);
   --# derives Context from *,
   --#                      Block,
   --#                      Length;

   function Get_Prf  (Context : in Context_Type) return SHA512.SHA512_Hash_Type;
   function Get_Auth (Context : in Context_Type) return Auth_Type;

   function Authenticate
      (Key     : SHA512.Block_Type;
       Message : SHA512.Message_Type;
       Length  : Types.Word64) return Auth_Type;
   --# pre
   --#    Message'First + (Length / SHA512.Block_Size) in Message'Range;

private

   type Context_Type is record
      SHA512_Context : SHA512.Context_Type;
      Key            : SHA512.Block_Type;
   end record;

   function To_Block (Item : SHA512.SHA512_Hash_Type) return SHA512.Block_Type;
   --# return Result =>
   --#     (for all I in SHA512.SHA512_Hash_Index => (Result (I) = Item (I)));

end LSC.HMAC_SHA512;
