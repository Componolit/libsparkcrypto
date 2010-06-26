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

with LSC.Types;
--# inherit LSC.Types;

package LSC.Debug is

   pragma Pure;

   procedure Put (T : String);
   --# derives null from T;
   pragma Inline (Put);

   procedure Put_Line (T : String);
   --# derives null from T;
   pragma Inline (Put_Line);

   procedure New_Line;
   --# derives ;
   pragma Inline (New_Line);

   procedure Print_Byte (I : in Types.Byte);
   --# derives null from I;
   pragma Inline (Print_Byte);

   procedure Print_Word32 (I : in Types.Word32);
   --# derives null from I;
   pragma Inline (Print_Word32);

   procedure Print_Word64 (I : in Types.Word64);
   --# derives null from I;
   pragma Inline (Print_Word64);

   procedure Print_Index (I : in Types.Index);
   --# derives null from I;
   pragma Inline (Print_Index);

   procedure Print_Natural (I : in Natural);
   --# derives null from I;
   pragma Inline (Print_Natural);

   procedure Print_Word32_Array (Block : in Types.Word32_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean);
   --# derives null from Block, Space, Break, Newln;
   pragma Inline (Print_Word32_Array);

   procedure Print_Word64_Array (Block : in Types.Word64_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean);
   --# derives null from Block, Space, Break, Newln;
   --# pre
   --#    Break > 0;
   pragma Inline (Print_Word64_Array);

end LSC.Debug;
