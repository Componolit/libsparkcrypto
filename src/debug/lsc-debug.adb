-------------------------------------------------------------------------------
--  This file is part of the sparkcrypto library.
--
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>
--  Copyright (C) 2010  secunet Security Networks AG
--
--  This program is free software: you can redistribute it and/or modify it
--  under the terms of the GNU General Public License as published by the Free
--  Software Foundation, either version 3 of the License, or (at your option)
--  any later version.
--
--  This program is distributed in the hope that it will be useful, but WITHOUT
--  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
--  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
--  more details.
--  
--  You should have received a copy of the GNU General Public License along
--  with this program.  If not, see <http://www.gnu.org/licenses/>.
--  
--  As a special exception, if other files instantiate generics from this unit,
--  or you link this unit with other files to produce an executable, this unit
--  does not by itself cause the resulting executable to be covered by the GNU
--  General Public License. This exception does not however invalidate any
--  other reasons why the executable file might be covered by the GNU Public
--  License.
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
