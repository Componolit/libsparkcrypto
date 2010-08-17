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

with LSC.Types;
use type LSC.Types.Word32;
use type LSC.Types.Word64;
use type LSC.Types.Index;
--# inherit
--#    LSC.Types,
--#    LSC.Byteorder32;

-------------------------------------------------------------------------------
-- Cryptographic padding for arrays of 32-bit words
-------------------------------------------------------------------------------
package LSC.Pad32
is

   -- Terminate a Word32 array
   --
   -- The array @Block@ is terminated by setting the bit at (@Length@ + 1) to 1
   -- and all following bits to 0.
   --
   procedure Block_Terminate
     (Block  : in out Types.Word32_Array_Type;
      Length : in     Types.Word64);
   --
   -- <strong> NOTE: The postcondition currently does not completely express
   --          the intended behaviour of the operation! </strong>
   --
   --# derives Block from *,
   --#                    Length;
   --# pre
   --#    Types.Index'First + Types.Index (Length / 32) in Block'Range;
   --# post
   --#    (for all I in Types.Index range
   --#        Types.Index'First + Types.Index (Length / 32) + 1 .. Block'Last => (Block (I) = 0));

end LSC.Pad32;
