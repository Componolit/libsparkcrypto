-------------------------------------------------------------------------------
-- This file is part of the sparkcrypto library.
--
-- Copyright (C) 2010  Alexander Senier <mail@senier.net>
-- Copyright (C) 2010  secunet Security Networks AG
--
-- libsparkcrypto is  free software; you  can redistribute it and/or  modify it
-- under  terms of  the GNU  General Public  License as  published by  the Free
-- Software  Foundation;  either version  3,  or  (at  your option)  any  later
-- version.  libsparkcrypto  is  distributed  in  the  hope  that  it  will  be
-- useful,  but WITHOUT  ANY WARRANTY;  without  even the  implied warranty  of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
--
-- As a  special exception under  Section 7 of GPL  version 3, you  are granted
-- additional  permissions  described in  the  GCC  Runtime Library  Exception,
-- version 3.1, as published by the Free Software Foundation.
--
-- You should  have received  a copy of  the GNU General  Public License  and a
-- copy  of  the  GCC  Runtime  Library  Exception  along  with  this  program;
-- see  the  files  COPYING3  and COPYING.RUNTIME  respectively.  If  not,  see
-- <http://www.gnu.org/licenses/>.
-------------------------------------------------------------------------------

with LSC.Types;
use type LSC.Types.Word32;
--# inherit
--#    LSC.Types;

-------------------------------------------------------------------------------
-- Operations over 32-bit words
-------------------------------------------------------------------------------
package LSC.Ops32 is

   -- Convert the four byte values @Byte0@, @Byte1@, @Byte2@ and @Byte3@ to a
   -- 32-bit word
   function Bytes_To_Word
      (Byte0 : Types.Byte;
       Byte1 : Types.Byte;
       Byte2 : Types.Byte;
       Byte3 : Types.Byte) return Types.Word32;
   pragma Inline (Bytes_To_Word);

   -- Return a byte at @Position@ of the 32-bit word @Value@
   function ByteX (Value    : Types.Word32;
                   Position : Types.Byte_Array32_Index) return Types.Byte;
   pragma Inline (ByteX);

   -- Return the first byte of the 32-bit word @Value@
   function Byte0 (Value : Types.Word32) return Types.Byte;
   pragma Inline (Byte0);

   -- Return the second byte of the 32-bit word @Value@
   function Byte1 (Value : Types.Word32) return Types.Byte;
   pragma Inline (Byte1);

   -- Return the third byte of the 32-bit word @Value@
   function Byte2 (Value : Types.Word32) return Types.Byte;
   pragma Inline (Byte2);

   -- Return the fourth byte of the 32-bit word @Value@
   function Byte3 (Value : Types.Word32) return Types.Byte;
   pragma Inline (Byte3);

   -- Perform XOR on two 32-bit words @V0@ and @V1@
   function XOR2 (V0, V1 : Types.Word32) return Types.Word32;
   --# return V0 xor V1;
   pragma Inline (XOR2);

   -- Perform XOR on three 32-bit words @V0@, @V1@ and @V2@
   function XOR3 (V0, V1, V2 : Types.Word32) return Types.Word32;
   --# return V0 xor V1 xor V2;
   pragma Inline (XOR3);

   -- Perform XOR on four 32-bit words @V0@, @V1@, @V2@ and @V3@
   function XOR4 (V0, V1, V2, V3 : Types.Word32) return Types.Word32;
   --# return V0 xor V1 xor V2 xor V3;
   pragma Inline (XOR4);

   -- Perform XOR on four 32-bit words @V0@, @V1@, @V2@, @V3@ and @V4@
   function XOR5 (V0, V1, V2, V3, V4 : Types.Word32) return Types.Word32;
   --# return V0 xor V1 xor V2 xor V3 xor V4;
   pragma Inline (XOR5);

   -- Perform XOR on two arrays of 32-bit words
   --
   -- @Left@   - First input array <br>
   -- @Right@  - Second input array <br>
   -- @Result@ - Result array <br>
   procedure Block_XOR
     (Left   : in     Types.Word32_Array_Type;
      Right  : in     Types.Word32_Array_Type;
      Result :    out Types.Word32_Array_Type);
   --# derives
   --#   Result from Left, Right;
   --# pre
   --#   Left'First  = Right'First and
   --#   Left'Last   = Right'Last  and
   --#   Right'First = Result'First and
   --#   Right'Last  = Result'Last;
   --# post
   --#   (for all I in Types.Index range Left'First .. Left'Last =>
   --#        (Result (I) = XOR2 (Left (I), Right (I))));
   pragma Inline (Block_XOR);

end LSC.Ops32;
