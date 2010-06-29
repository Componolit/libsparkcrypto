--  This file is part of the sparkcrypto library.

--  Copyright (C) 2010  secunet Security Networks AG
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>

--  This library  is free software:  you can  redistribute it and/or  modify it
--  under the  terms of the GNU  Lesser General Public License  as published by
--  the Free Software Foundation, either version  3 of the License, or (at your
--  option) any later version.

--  This library is distributed in the hope that it will be useful, but WITHOUT
--  ANY  WARRANTY; without  even  the implied  warranty  of MERCHANTABILITY  or
--  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
--  for more details.

--  You should  have received a copy  of the GNU Lesser  General Public License
--  along with this library. If not, see <http://www.gnu.org/licenses/>.

-------------------------------------------------------------------------------
--  References:
--
--  S. Kelly, Using HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 with IPsec,
--  RFC 4868, May 2007
--  [doc/specs/rfc4868.txt.pdf]
-------------------------------------------------------------------------------

with LSC.SHA512, LSC.Types, LSC.Ops64, LSC.Debug;
use type LSC.Types.Word64;

--# inherit LSC.Debug,
--#         LSC.SHA512,
--#         LSC.Ops64,
--#         LSC.Types;

package LSC.HMAC_SHA512 is

   type Context_Type is private;

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

private

   type Context_Type is record
      SHA512_Context : SHA512.Context_Type;
      Key            : SHA512.Block_Type;
   end record;

   function To_Block (Item : SHA512.SHA512_Hash_Type) return SHA512.Block_Type;
   --# return Result =>
   --#     (for all I in SHA512.SHA512_Hash_Index => (Result (I) = Item (I)));

end LSC.HMAC_SHA512;