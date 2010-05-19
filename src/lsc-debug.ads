--  This file is part of the sparkcrypto library.
--
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

with LSC, LSC.Types;
--  inherit LSC.Types;

package LSC.Debug is

   procedure Put (T : String);
   --# derives null from T;

   procedure Put_Line (T : String);
   --# derives null from T;

   procedure New_Line;
   --# derives ;

   procedure Print_Byte (I : in LSC.Types.Byte);
   --# derives null from I;

   procedure Print_Word32 (I : in LSC.Types.Word32);
   --# derives null from I;

   procedure Print_Word64 (I : in LSC.Types.Word64);
   --# derives null from I;

end LSC.Debug;
