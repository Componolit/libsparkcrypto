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

with LSC.SHA256;
--# inherit LSC.SHA256;

private package LSC.SHA256.Tables is

K : constant SHA256.Schedule_Type := SHA256.Schedule_Type'
  (16#428a2f98#, 16#71374491#, 16#b5c0fbcf#, 16#e9b5dba5#, 16#3956c25b#, 16#59f111f1#, 16#923f82a4#, 16#ab1c5ed5#,
   16#d807aa98#, 16#12835b01#, 16#243185be#, 16#550c7dc3#, 16#72be5d74#, 16#80deb1fe#, 16#9bdc06a7#, 16#c19bf174#,
   16#e49b69c1#, 16#efbe4786#, 16#0fc19dc6#, 16#240ca1cc#, 16#2de92c6f#, 16#4a7484aa#, 16#5cb0a9dc#, 16#76f988da#,
   16#983e5152#, 16#a831c66d#, 16#b00327c8#, 16#bf597fc7#, 16#c6e00bf3#, 16#d5a79147#, 16#06ca6351#, 16#14292967#,
   16#27b70a85#, 16#2e1b2138#, 16#4d2c6dfc#, 16#53380d13#, 16#650a7354#, 16#766a0abb#, 16#81c2c92e#, 16#92722c85#,
   16#a2bfe8a1#, 16#a81a664b#, 16#c24b8b70#, 16#c76c51a3#, 16#d192e819#, 16#d6990624#, 16#f40e3585#, 16#106aa070#,
   16#19a4c116#, 16#1e376c08#, 16#2748774c#, 16#34b0bcb5#, 16#391c0cb3#, 16#4ed8aa4a#, 16#5b9cca4f#, 16#682e6ff3#,
   16#748f82ee#, 16#78a5636f#, 16#84c87814#, 16#8cc70208#, 16#90befffa#, 16#a4506ceb#, 16#bef9a3f7#, 16#c67178f2#);

end LSC.SHA256.Tables;
