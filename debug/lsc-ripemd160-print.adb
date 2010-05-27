--  This file is part of the sparkcrypto library.

--  Copyright (C) 2010  secunet Security Networks AG
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>

--  This library  is free software:  you can  redistribute it and/or  modify it
--  under the  terms of the GNU  Lesser General Public License  as published by
--  the Free Software Foundation, either version  3 of the License, or (at your
--  option) any later version.

--  This library is distributed in the hope that it will be useful, but WITHOUT
--  ANY  WARRANTY; without  even  the implied  warranty  of MERCHANTABILITY  or
--  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
--  for more details.

--  You should  have received a copy  of the GNU Lesser  General Public License
--  along with this library. If not, see <http://www.gnu.org/licenses/>.

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
