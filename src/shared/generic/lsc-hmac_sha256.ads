-------------------------------------------------------------------------------
--  This file is part of the sparkcrypto library.
--
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>
--  Copyright (C) 2010  secunet Security Networks AG
--
--  This program is free software: you can redistribute it and/or modify it
--  under the terms of the GNU General Public License as published by the Free
--  Software Foundation, either version 3 of the License, or (at your option)
--  any later version.
--
--  This program is distributed in the hope that it will be useful, but WITHOUT
--  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
--  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
--  more details.
--  
--  You should have received a copy of the GNU General Public License along
--  with this program.  If not, see <http://www.gnu.org/licenses/>.
--  
--  As a special exception, if other files instantiate generics from this unit,
--  or you link this unit with other files to produce an executable, this unit
--  does not by itself cause the resulting executable to be covered by the GNU
--  General Public License. This exception does not however invalidate any
--  other reasons why the executable file might be covered by the GNU Public
--  License.
-------------------------------------------------------------------------------
--  References:
--
--  S. Kelly, Using HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 with IPsec,
--  RFC 4868, May 2007
--  [doc/specs/rfc4868.txt.pdf]
-------------------------------------------------------------------------------

with LSC.SHA256, LSC.Types, LSC.Ops32, LSC.Debug;
use type LSC.Types.Word32;

--# inherit LSC.Debug,
--#         LSC.SHA256,
--#         LSC.Ops32,
--#         LSC.Types;

package LSC.HMAC_SHA256 is

   type Context_Type is private;

   subtype Auth_Index is Types.Index range 0 .. 3;
   subtype Auth_Type is Types.Word32_Array_Type (Auth_Index);

   function Context_Init (Key : SHA256.Block_Type) return Context_Type;

   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in     SHA256.Block_Type);
   --# derives Context from *,
   --#                      Block;

   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     SHA256.Block_Type;
      Length  : in     SHA256.Block_Length_Type);
   --# derives Context from *,
   --#                      Block,
   --#                      Length;

   function Get_Prf  (Context : in Context_Type) return SHA256.SHA256_Hash_Type;
   function Get_Auth (Context : in Context_Type) return Auth_Type;

private

   type Context_Type is record
      SHA256_Context : SHA256.Context_Type;
      Key            : SHA256.Block_Type;
   end record;

   function To_Block (Item : SHA256.SHA256_Hash_Type) return SHA256.Block_Type;

end LSC.HMAC_SHA256;
