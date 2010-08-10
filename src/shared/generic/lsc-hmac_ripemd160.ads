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
--  J. Kapp, Test Cases for HMAC-RIPEMD160 and HMAC-RIPEMD128, RFC 2286,
--  February 1998.
--  [doc/specs/rfc2286.txt.pdf]
-------------------------------------------------------------------------------

with LSC.RIPEMD160, LSC.Types;

use type LSC.Types.Word32;
use type LSC.Types.Word64;

--# inherit
--#    LSC.Debug,
--#    LSC.RIPEMD160,
--#    LSC.Ops32,
--#    LSC.Types;

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

   function Authenticate
      (Key     : RIPEMD160.Block_Type;
       Message : RIPEMD160.Message_Type;
       Length  : Types.Word64) return RIPEMD160.Hash_Type;
   --# pre
   --#    Message'First + (Length / RIPEMD160.Block_Size) <= Message'Last;

private

   type Context_Type is record
      RIPEMD160_Context : RIPEMD160.Context_Type;
      Key               : RIPEMD160.Block_Type;
   end record;

   function To_Block (Item : RIPEMD160.Hash_Type) return RIPEMD160.Block_Type;

end LSC.HMAC_RIPEMD160;
