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
--  J. Kapp, Test Cases for HMAC-RIPEMD160 and HMAC-RIPEMD128, RFC 2286,
--  February 1998.
--  [doc/specs/rfc2286.txt.pdf]
-------------------------------------------------------------------------------

with LSC.RIPEMD160, LSC.Types, LSC.Ops32, LSC.Debug;
use type LSC.Types.Word32;

--# inherit LSC.Debug,
--#         LSC.RIPEMD160,
--#         LSC.Ops32,
--#         LSC.Types;

package LSC.HMAC_RIPEMD160 is

   type Context_Type is private;

   function Context_Init (Key : RIPEMD160.Block_Type) return Context_Type;

   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     RIPEMD160.Block_Type);
   --# derives Context from *,
   --#                      Block;

   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     RIPEMD160.Block_Type;
      Length  : in     RIPEMD160.Block_Length_Type);
   --# derives Context from *,
   --#                      Block,
   --#                      Length;

   function Get_Auth (Context : in Context_Type) return RIPEMD160.Hash_Type;

private

   type Context_Type is record
      RIPEMD160_Context : RIPEMD160.Context_Type;
      Key               : RIPEMD160.Block_Type;
   end record;

   function To_Block (Item : RIPEMD160.Hash_Type) return RIPEMD160.Block_Type;

end LSC.HMAC_RIPEMD160;
