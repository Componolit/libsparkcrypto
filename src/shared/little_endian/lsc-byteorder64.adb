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

with LSC.Byteswap64;

package body LSC.Byteorder64 is

   function Native_To_BE (Item : Types.Word64) return Types.Word64
   is
   begin
      return Byteswap64.Swap (Item);
   end Native_To_BE;

   ---------------------------------------------------------------------------

   function Native_To_LE (Item : Types.Word64) return Types.Word64
   is
   begin
      return Item;
   end Native_To_LE;

   ---------------------------------------------------------------------------

   function BE_To_Native (Item : Types.Word64) return Types.Word64
   is
   begin
      return Byteswap64.Swap (Item);
   end BE_To_Native;

   ---------------------------------------------------------------------------

   function LE_To_Native (Item : Types.Word64) return Types.Word64
   is
   begin
      return Item;
   end LE_To_Native;

end LSC.Byteorder64;
