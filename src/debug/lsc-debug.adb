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

with LSC.Types, LSC.IO;
use type LSC.Types.Word64;

package body LSC.Debug is

   procedure Put (T : String) renames LSC.IO.Put;

   ----------------------------------------------------------------------------

   procedure Put_Line (T : String) renames LSC.IO.Put_Line;

   ----------------------------------------------------------------------------

   procedure New_Line renames LSC.IO.New_Line;

   ----------------------------------------------------------------------------

   procedure Print_Byte (I : in LSC.Types.Byte) renames LSC.IO.Print_Byte;

   ----------------------------------------------------------------------------

   procedure Print_Word32 (I : in LSC.Types.Word32) renames LSC.IO.Print_Word32;

   ----------------------------------------------------------------------------

   procedure Print_Word64 (I : in LSC.Types.Word64) renames LSC.IO.Print_Word64;

   ----------------------------------------------------------------------------

   procedure Print_Index (I : in Types.Index) renames LSC.IO.Print_Index;

   ----------------------------------------------------------------------------

   procedure Print_Natural (I : in Natural) renames LSC.IO.Print_Natural;

   ----------------------------------------------------------------------------

   procedure Print_Word32_Array (Block : in Types.Word32_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean) renames LSC.IO.Print_Word32_Array;

   ----------------------------------------------------------------------------

   procedure Print_Word64_Array (Block : in Types.Word64_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean) renames LSC.IO.Print_Word64_Array;
end LSC.Debug;
