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
procedure Test_SHA384
is
   Block1, Block2  : LSC.SHA512.Block_Type;
   SHA384_Context1 : OpenSSL.SHA384_Context_Type;
   SHA384_Context2 : LSC.SHA512.Context_Type;
   H1, H2          : LSC.SHA512.SHA384_Hash_Type;
begin
   Block1  := LSC.SHA512.Block_Type'(others => 16#deadbeefcafebabe#);
   Block2  := LSC.SHA512.Block_Type'(others => 16#0000000000636261#);

   S1 := Clock;
   for I in 1 .. 500000
   loop
      OpenSSL.SHA384_Context_Init (SHA384_Context1);
      OpenSSL.SHA384_Context_Update (SHA384_Context1, Block1);
      OpenSSL.SHA384_Context_Finalize (SHA384_Context1, Block2, 56);
   end loop;
   H1 := OpenSSL.SHA384_Get_Hash (SHA384_Context1);
   D1 := Clock - S1;

   S2 := Clock;
   for I in 1 .. 500000
   loop
      SHA384_Context2 := LSC.SHA512.SHA384_Context_Init;
      LSC.SHA512.Context_Update (SHA384_Context2, Block1);
      LSC.SHA512.Context_Finalize (SHA384_Context2, Block2, 56);
   end loop;
   H2 := LSC.SHA512.SHA384_Get_Hash (SHA384_Context2);
   D2 := Clock - S2;

   Result ("     SHA384", H1 = H2, D1, D2);
end Test_SHA384;
