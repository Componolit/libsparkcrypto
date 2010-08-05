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
--  References:
--
--  FIPS PUB 197, Advanced Encryption Standard (AES), National Institute of
--  Standards and Technology, U.S. Department of Commerce, November 2001.
--  [doc/specs/fips-197.pdf]
--
--  Joan Daemen and Vincent Rijmen, AES submission document on Rijndael,
--  Version 2, September 1999.
--  [doc/specs/Rijndael-amended.pdf]
-------------------------------------------------------------------------------

with LSC.Types;
use type LSC.Types.Word32;
use type LSC.Types.Index;
--# inherit
--#    LSC.Types,
--#    LSC.Debug,
--#    LSC.Ops32,
--#    LSC.Byteorder32;

package LSC.AES is

   type AES_Enc_Context is private;
   type AES_Dec_Context is private;

   subtype Key_Index is Types.Index range 0 .. 7;
   type Key_Type is array (Key_Index range <>) of Types.Word32;

   subtype AES128_Key_Index is Types.Index range 0 .. 3;
   subtype AES128_Key_Type is Key_Type (AES128_Key_Index);

   subtype AES192_Key_Index is Types.Index range 0 .. 5;
   subtype AES192_Key_Type is Key_Type (AES192_Key_Index);

   subtype AES256_Key_Index is Types.Index range 0 .. 7;
   subtype AES256_Key_Type is Key_Type (AES256_Key_Index);

   subtype Block_Index is Types.Index range 0 .. 3;
   subtype Block_Type is Types.Word32_Array_Type (Block_Index);

   subtype Message_Index is Natural;
   type Message_Type is array (Message_Index range <>) of Block_Type;

   function Create_AES128_Enc_Context (Key : AES128_Key_Type) return AES_Enc_Context;
   function Create_AES192_Enc_Context (Key : AES192_Key_Type) return AES_Enc_Context;
   function Create_AES256_Enc_Context (Key : AES256_Key_Type) return AES_Enc_Context;

   function Encrypt (Context   : AES_Enc_Context;
                     Plaintext : Block_Type) return Block_Type;

   function Create_AES128_Dec_Context (Key : AES128_Key_Type) return AES_Dec_Context;
   function Create_AES192_Dec_Context (Key : AES192_Key_Type) return AES_Dec_Context;
   function Create_AES256_Dec_Context (Key : AES256_Key_Type) return AES_Dec_Context;

   function Decrypt (Context    : AES_Dec_Context;
                     Ciphertext : Block_Type) return Block_Type;

   Null_Block : constant Block_Type;

private

   Nb : constant Types.Index :=  4;

   subtype Schedule_Index is Types.Index range 0 .. 15 * Nb - 1;
   subtype Schedule_Type is Types.Word32_Array_Type (Schedule_Index);

   subtype Nr_Type is Types.Index range 10 .. 14;
   subtype Nk_Type is Types.Index range  4 ..  8;

   type AES_Enc_Context is
   record
      Schedule : Schedule_Type;
      Nr       : Nr_Type;
   end record;

   type AES_Dec_Context is
   record
      Schedule : Schedule_Type;
      Nr       : Nr_Type;
   end record;

   function Enc_Key_Expansion (Key : Key_Type;
                               Nk  : Nk_Type;
                               Nr  : Nr_Type) return Schedule_Type;
   --# pre
   --#   Key'Length = Nk and
   --#   Nk < (Nb * (Nr + 1) - 1);

   function Dec_Key_Expansion (Key : Key_Type;
                               Nk  : Nk_Type;
                               Nr  : Nr_Type) return Schedule_Type;
   --# pre
   --#   Key'Length = Nk and
   --#   Nk < (Nb * (Nr + 1) - 1);

   function Rot_Word (Value : Types.Word32) return Types.Word32;

   Null_Block : constant Block_Type := Block_Type'(others => 0);

end LSC.AES;
