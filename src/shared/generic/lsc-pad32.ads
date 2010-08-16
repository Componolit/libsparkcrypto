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

with LSC.Types;
use type LSC.Types.Word32;
use type LSC.Types.Word64;
use type LSC.Types.Index;
--# inherit
--#    LSC.Types,
--#    LSC.Byteorder32;

package LSC.Pad32
is
   -- Terminate a block by setting the bit at (Length + 1) to 1 and all following
   -- bits to 0.
   procedure Block_Terminate
     (Block  : in out Types.Word32_Array_Type;
      Length : in     Types.Word64);
   --# derives Block from *,
   --#                    Length;
   --# pre
   --#    Types.Index'First + Types.Index (Length / 32) in Block'Range;
   --# post
   --#    (for all I in Types.Index range
   --#        Types.Index'First + Types.Index (Length / 32) + 1 .. Block'Last => (Block (I) = 0));

end LSC.Pad32;
