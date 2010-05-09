--  This file is part of the sparkcrypto library.
--
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

with SHA2, Types, LSC.Debug;
use type Types.Word64;

--# inherit LSC.Debug,
--#         SHA2,
--#         Types;

package HMAC.SHA512 is

   type Context_Type is private;

   subtype Auth_Index is Natural range 0 .. 3;
   subtype Auth_Type is SHA2.Word64_Array_Type (Auth_Index);

   function Context_Init (Key : SHA2.Block_Type) return Context_Type;

   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in SHA2.Block_Type);
   --# derives Context from *,
   --#                      Block;

   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in SHA2.Block_Type;
      Length  : in SHA2.Block_Length_Type);
   --# derives Context from *,
   --#                      Block,
   --#                      Length;

   function Get_Prf  (Context : in Context_Type) return SHA2.Hash_Type;
   function Get_Auth (Context : in Context_Type) return Auth_Type;

private

   type Context_Type is record
      SHA512_Context : SHA2.Context_Type;
      Key            : SHA2.Block_Type;
   end record;

   function Block_XOR
     (Left  : SHA2.Block_Type;
      Right : SHA2.Block_Type)
      return  SHA2.Block_Type;
   --# return Result =>
   --#    (for all I in SHA2.Block_Index =>
   --#         (Result (I) = (Left (I) xor Right (I))));

   function To_Block (Item : SHA2.Hash_Type) return SHA2.Block_Type;
   --# return Result =>
   --#     (for all I in SHA2.Hash_Index => (Result (I) = Item (I)));

end HMAC.SHA512;
