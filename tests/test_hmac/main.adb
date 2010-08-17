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
     LSC.RIPEMD160,
     LSC.HMAC_SHA256,
     LSC.HMAC_SHA512,
     LSC.HMAC_SHA384,
     LSC.HMAC_RIPEMD160,
     LSC.IO,
     LSC.Types,
     LSC.Byteorder32,
     LSC.Byteorder64,
     LSC.Debug,
     LSC.Test;

use type LSC.Types.Word32_Array_Type;
use type LSC.Types.Word64_Array_Type;
use type LSC.Types.Word64;

--# inherit LSC.IO,
--#         LSC.SHA256,
--#         LSC.SHA512,
--#         LSC.RIPEMD160,
--#         LSC.HMAC_SHA256,
--#         LSC.HMAC_SHA512,
--#         LSC.HMAC_SHA384,
--#         LSC.HMAC_RIPEMD160,
--#         LSC.Types,
--#         LSC.Byteorder32,
--#         LSC.Byteorder64,
--#         LSC.Debug,
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

   procedure HMAC_SHA256_Tests
   --# derives ;
   is separate;

   procedure HMAC_SHA384_Tests
   --# derives ;
   is separate;

   procedure HMAC_SHA512_Tests
   --# derives ;
   is separate;

   procedure HMAC_RIPEMD160_Tests
   --# derives ;
   is separate;

begin

   HMAC_SHA256_Tests;
   HMAC_SHA384_Tests;
   HMAC_SHA512_Tests;
   HMAC_RIPEMD160_Tests;

end Main;
