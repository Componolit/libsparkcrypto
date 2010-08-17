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

with LSC.SHA256,
     LSC.SHA512,
     LSC.IO,
     LSC.Test,
     LSC.Types,
     LSC.Byteorder32,
     LSC.Byteorder64;

use type LSC.SHA512.SHA512_Hash_Type;
use type LSC.SHA256.SHA256_Hash_Type;

--# inherit LSC.IO,
--#         LSC.SHA256,
--#         LSC.SHA512,
--#         LSC.Byteorder32,
--#         LSC.Byteorder64,
--#         LSC.Types,
--#         LSC.Test;

--# main_program;
procedure Main
   --# derives ;
is
   function N (Item : LSC.Types.Word64) return LSC.Types.Word64
   is
   begin
      return LSC.Byteorder64.BE_To_Native (Item);
   end N;

   function M (Item : LSC.Types.Word32) return LSC.Types.Word32
   is
   begin
      return LSC.Byteorder32.BE_To_Native (Item);
   end M;

   procedure SHA256_Tests
   --# derives ;
   is separate;

   procedure SHA384_Tests
   --# derives ;
   is separate;

   procedure SHA512_Tests
   --# derives ;
   is separate;

begin

   SHA256_Tests;
   SHA384_Tests;
   SHA512_Tests;

end Main;
