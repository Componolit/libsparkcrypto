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
with LSC.AES;

private package LSC.AES.Print is

   procedure Print_Round (T : String;
                          R : LSC.AES.Schedule_Index;
                          B : LSC.AES.Block_Type);

   procedure Block
      (Header : String;
       Line   : String;
       Block  : LSC.AES.Block_Type;
       Index  : LSC.AES.Schedule_Index);

   procedure Header
      (Initial_Schedule : Types.Word32_Array_Type);

   procedure Footer
      (Final_Schedule : Types.Word32_Array_Type);

   procedure Index (I : Types.Index);

   procedure Row (I : Types.Word32);

   procedure Empty (N : Positive);

end LSC.AES.Print;
