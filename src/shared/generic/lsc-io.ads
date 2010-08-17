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
use type LSC.Types.Index;
--# inherit LSC.Types;

package LSC.IO is

   procedure Put (T : String);
   --# derives null from T;

   procedure Put_Line (T : String);
   --# derives null from T;

   procedure New_Line;
   --# derives ;

   function Read_Byte return  Types.Byte;

   function End_Of_Stream return Boolean;

   procedure Print_Byte (Item : in Types.Byte);
   --# derives null from Item;

   procedure Print_Word32 (Item : in Types.Word32);
   --# derives null from Item;

   procedure Print_Word64 (Item : in Types.Word64);
   --# derives null from Item;

   procedure Print_Index (I : in Types.Index);
   --# derives null from I;

   procedure Print_Natural (I : in Natural);
   --# derives null from I;

   procedure Print_Word32_Array (Block : in Types.Word32_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean);
   --# derives null from Block, Space, Break, Newln;
   --# pre
   --#    Break > 0;

   procedure Print_Word64_Array (Block : in Types.Word64_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean);
   --# derives null from Block, Space, Break, Newln;
   --# pre
   --#    Break > 0;

end LSC.IO;
