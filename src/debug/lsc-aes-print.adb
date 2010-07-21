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

with Ada.Text_IO, LSC.Debug, LSC.IO;

package body LSC.AES.Print is

   procedure Print_Round (T : String;
                          R : LSC.AES.Schedule_Index;
                          B : LSC.AES.Block_Type)
   is
   begin
      LSC.Debug.Put ("round[");
      LSC.Debug.Print_Index (R);
      LSC.Debug.Put ("]." & T & "      ");
      LSC.Debug.Print_Word32_Array (B, 1, Types.Index'Last, True);
   end Print_Round;

end LSC.AES.Print;
