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

with Unchecked_Conversion;
with LSC.Byteswap32;

package body LSC.Byteswap64 is

   function Swap (Value : Types.Word64) return Types.Word64
   is
      type W32A is
      record
         MSB : Types.Word32;
         LSB : Types.Word32;
      end record;

      function To_Word64 is new Unchecked_Conversion (W32A, Types.Word64);
      function To_W32A   is new Unchecked_Conversion (Types.Word64, W32A);

      Temp : constant W32A := To_W32A (Value);
   begin
      return To_Word64 (W32A'(MSB => LSC.Byteswap32.Swap (Temp.LSB),
                              LSB => LSC.Byteswap32.Swap (Temp.MSB)));
   end Swap;

end LSC.Byteswap64;
