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

with LSC.Types, LSC.SHA2;
use type LSC.Types.Index;
--# inherit LSC.SHA2,
--#         LSC.Types;

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

   procedure Print_Hash (Hash : SHA2.SHA512_Hash_Type);
   --# derives null from Hash;

   procedure Print_Block (Block : SHA2.Block_Type);
   --# derives null from Block;

end LSC.IO;
