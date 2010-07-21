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

with LSC.Debug;

package body LSC.RIPEMD160.Print is

   procedure Print_Schedule (M : String;
                             A : Types.Word32;
                             B : Types.Word32;
                             C : Types.Word32;
                             D : Types.Word32;
                             E : Types.Word32;
                             X : Types.Word32;
                             S : Natural)
   is
   begin
      Debug.Put (M);
      Debug.Put (": ");

      Debug.Print_Word32 (A);
      Debug.Put (" ");

      Debug.Print_Word32 (B);
      Debug.Put (" ");

      Debug.Print_Word32 (C);
      Debug.Put (" ");

      Debug.Print_Word32 (D);
      Debug.Put (" ");

      Debug.Print_Word32 (E);
      Debug.Put (" ");

      Debug.Print_Word32 (X);
      Debug.Put (" ");

      Debug.Print_Natural (S);

      Debug.New_Line;
   end Print_Schedule;

end LSC.RIPEMD160.Print;
