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
procedure Test_RIPEMD160
is
   Block1, Block2     : LSC.RIPEMD160.Block_Type;
   RIPEMD160_Context1 : OpenSSL.RIPEMD160_Context_Type;
   RIPEMD160_Context2 : LSC.RIPEMD160.Context_Type;
   H1, H2             : LSC.RIPEMD160.Hash_Type;
begin
   Block1  := LSC.RIPEMD160.Block_Type'(others => 16#cafebabe#);
   Block2  := LSC.RIPEMD160.Block_Type'(others => 16#00636261#);

   S1 := Clock;
   for I in 1 .. 200000
   loop
      OpenSSL.RIPEMD160_Context_Init (RIPEMD160_Context1);
      OpenSSL.RIPEMD160_Context_Update (RIPEMD160_Context1, Block1);
      OpenSSL.RIPEMD160_Context_Finalize (RIPEMD160_Context1, Block2, 56);
   end loop;
   H1 := OpenSSL.RIPEMD160_Get_Hash (RIPEMD160_Context1);
   D1 := Clock - S1;

   S2 := Clock;
   for I in 1 .. 200000
   loop
      RIPEMD160_Context2 := LSC.RIPEMD160.Context_Init;
      LSC.RIPEMD160.Context_Update (RIPEMD160_Context2, Block1);
      LSC.RIPEMD160.Context_Finalize (RIPEMD160_Context2, Block2, 56);
   end loop;
   H2 := LSC.RIPEMD160.Get_Hash (RIPEMD160_Context2);
   D2 := Clock - S2;

   Result ("  RIPEMD160", H1 = H2, D1, D2);
end;
