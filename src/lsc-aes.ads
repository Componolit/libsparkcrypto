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

with LSC.Types, LSC.Debug, LSC.Ops;
use type LSC.Types.Word32;
use type LSC.Types.Index;
--# inherit Types,
--#         LSC.Debug,
--#         LSC.Ops;

package LSC.AES is

   type AES_Context is private;

   subtype Key_Index is LSC.Types.Index range 0 .. 7;
   type Key_Type is array (Key_Index range <>) of LSC.Types.Word32;

   subtype AES128_Key_Index is LSC.Types.Index range 0 .. 3;
   subtype AES128_Key_Type is Key_Type (AES128_Key_Index);

   subtype AES192_Key_Index is LSC.Types.Index range 0 .. 5;
   subtype AES192_Key_Type is Key_Type (AES192_Key_Index);

   subtype AES256_Key_Index is LSC.Types.Index range 0 .. 7;
   subtype AES256_Key_Type is Key_Type (AES256_Key_Index);

   subtype Block_Index is Natural range 0 .. 3;
   type Block_Type is array (Block_Index) of LSC.Types.Word32;

   function Create_AES128_Context (Key : AES128_Key_Type) return AES_Context;
   function Create_AES192_Context (Key : AES192_Key_Type) return AES_Context;
   function Create_AES256_Context (Key : AES256_Key_Type) return AES_Context;

   function Encrypt (Context   : AES_Context;
                     Plaintext : Block_Type) return Block_Type;

private

   Nb : constant LSC.Types.Index :=  4;

   subtype Schedule_Index is LSC.Types.Index range 0 .. 15 * Nb - 1;
   type Schedule_Type is array (Schedule_Index) of LSC.Types.Word32;

   subtype Nr_Type is LSC.Types.Index range 10 .. 14;
   subtype Nk_Type is LSC.Types.Index range  4 ..  8;

   type AES_Context is
   record
      Schedule : Schedule_Type;
      Nr       : Nr_Type;
   end record;

   function Key_Expansion (Key : Key_Type; Nk : Nk_Type) return Schedule_Type;
   function Rot_Word (Value : LSC.Types.Word32) return LSC.Types.Word32;

end LSC.AES;
