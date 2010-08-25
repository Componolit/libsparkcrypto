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
procedure Test_HMAC_RMD160
is
   Message : OpenSSL.RMD160_Message_Type := OpenSSL.RMD160_Message_Type'
      (others => LSC.RIPEMD160.Block_Type'(others => 16#dead_beef#));

   Key : LSC.RIPEMD160.Block_Type := LSC.RIPEMD160.Block_Type'
      (others => 16#c0deaffe#);

   H1 : LSC.RIPEMD160.Hash_Type;
   H2 : LSC.RIPEMD160.Hash_Type;
begin

   S1 := Clock;
   for I in 1 .. 50000
   loop
      H1 := OpenSSL.Authenticate_RMD160 (Key, Message, 10000);
   end loop;
   D1 := Clock - S1;

   S2 := Clock;
   for I in 1 .. 50000
   loop
      H2 := LSC.HMAC_RIPEMD160.Authenticate (Key, Message, 10000);
   end loop;
   D2 := Clock - S2;

   Result ("HMAC_RMD160", H1 = H2, D1, D2);
end Test_HMAC_RMD160;
