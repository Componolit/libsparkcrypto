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

-------------------------------------------------------------------------------
-- AES Debug package
--
-- Debug is done through Debug pragmas. As the compiler has to with the debug
-- package to make it available to this pragma, this is an empty package which
-- makes the SPARK Examiner accept the respective with clause. Debug functions,
-- however, cannot (and should not) be use from within SPARK.
-------------------------------------------------------------------------------
private package LSC.AES.Print
is
end LSC.AES.Print;
