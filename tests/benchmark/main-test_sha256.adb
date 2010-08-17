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

separate (Main)
procedure Test_SHA256
is
   Block1, Block2  : LSC.SHA256.Block_Type;
   SHA256_Context1 : OpenSSL.SHA256_Context_Type;
   SHA256_Context2 : LSC.SHA256.Context_Type;
   H1, H2          : LSC.SHA256.SHA256_Hash_Type;
begin
   Block1  := LSC.SHA256.Block_Type'(others => 16#cafebabe#);
   Block2  := LSC.SHA256.Block_Type'(others => 16#00636261#);

   S1 := Clock;
   for I in 1 .. 500000
   loop
      OpenSSL.SHA256_Context_Init (SHA256_Context1);
      OpenSSL.SHA256_Context_Update (SHA256_Context1, Block1);
      OpenSSL.SHA256_Context_Finalize (SHA256_Context1, Block2, 56);
   end loop;
   H1 := OpenSSL.SHA256_Get_Hash (SHA256_Context1);
   D1 := Clock - S1;

   S2 := Clock;
   for I in 1 .. 500000
   loop
      SHA256_Context2 := LSC.SHA256.SHA256_Context_Init;
      LSC.SHA256.Context_Update (SHA256_Context2, Block1);
      LSC.SHA256.Context_Finalize (SHA256_Context2, Block2, 56);
   end loop;
   H2 := LSC.SHA256.SHA256_Get_Hash (SHA256_Context2);
   D2 := Clock - S2;

   Result ("     SHA256", H1 = H2, D1, D2);
end Test_SHA256;
