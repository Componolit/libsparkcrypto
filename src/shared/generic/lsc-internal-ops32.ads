-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2010, Alexander Senier
-- Copyright (C) 2010, secunet Security Networks AG
-- All rights reserved.
--
-- Redistribution  and  use  in  source  and  binary  forms,  with  or  without
-- modification, are permitted provided that the following conditions are met:
--
--    * Redistributions of source code must retain the above copyright notice,
--      this list of conditions and the following disclaimer.
--
--    * Redistributions in binary form must reproduce the above copyright
--      notice, this list of conditions and the following disclaimer in the
--      documentation and/or other materials provided with the distribution.
--
--    * Neither the name of the  nor the names of its contributors may be used
--      to endorse or promote products derived from this software without
--      specific prior written permission.
--
-- THIS SOFTWARE IS PROVIDED BY THE  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-- AND ANY  EXPRESS OR IMPLIED WARRANTIES,  INCLUDING, BUT NOT LIMITED  TO, THE
-- IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
-- ARE  DISCLAIMED. IN  NO EVENT  SHALL  THE COPYRIGHT  HOLDER OR  CONTRIBUTORS
-- BE  LIABLE FOR  ANY  DIRECT, INDIRECT,  INCIDENTAL,  SPECIAL, EXEMPLARY,  OR
-- CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT  LIMITED  TO,  PROCUREMENT  OF
-- SUBSTITUTE GOODS  OR SERVICES; LOSS  OF USE,  DATA, OR PROFITS;  OR BUSINESS
-- INTERRUPTION)  HOWEVER CAUSED  AND ON  ANY THEORY  OF LIABILITY,  WHETHER IN
-- CONTRACT,  STRICT LIABILITY,  OR  TORT (INCLUDING  NEGLIGENCE OR  OTHERWISE)
-- ARISING IN ANY WAY  OUT OF THE USE OF THIS SOFTWARE, EVEN  IF ADVISED OF THE
-- POSSIBILITY OF SUCH DAMAGE.
-------------------------------------------------------------------------------

with LSC.Internal.Types;
use type LSC.Internal.Types.Word32;
use type LSC.Internal.Types.Index;

-------------------------------------------------------------------------------
--  Operations over 32-bit words
-------------------------------------------------------------------------------
package LSC.Internal.Ops32 is

   pragma Pure;

   --  Convert the four byte values @Byte0@, @Byte1@, @Byte2@ and @Byte3@ to a
   --  32-bit word
   function Bytes_To_Word
      (Byte0 : Types.Byte;
       Byte1 : Types.Byte;
       Byte2 : Types.Byte;
       Byte3 : Types.Byte) return Types.Word32;
   pragma Inline (Bytes_To_Word);

   --  Return a byte at @Position@ of the 32-bit word @Value@
   function ByteX (Value    : Types.Word32;
                   Position : Types.Byte_Array32_Index) return Types.Byte;
   pragma Inline (ByteX);

   --  Return the first byte of the 32-bit word @Value@
   function Byte0 (Value : Types.Word32) return Types.Byte;
   pragma Inline (Byte0);

   --  Return the second byte of the 32-bit word @Value@
   function Byte1 (Value : Types.Word32) return Types.Byte;
   pragma Inline (Byte1);

   --  Return the third byte of the 32-bit word @Value@
   function Byte2 (Value : Types.Word32) return Types.Byte;
   pragma Inline (Byte2);

   --  Return the fourth byte of the 32-bit word @Value@
   function Byte3 (Value : Types.Word32) return Types.Byte;
   pragma Inline (Byte3);

   --  Perform XOR on two 32-bit words @V0@ and @V1@
   function XOR2 (V0, V1 : Types.Word32) return Types.Word32
     with Post => XOR2'Result = (V0 xor V1);
   pragma Inline (XOR2);

   --  Perform XOR on three 32-bit words @V0@, @V1@ and @V2@
   function XOR3 (V0, V1, V2 : Types.Word32) return Types.Word32
     with Post => XOR3'Result = (V0 xor V1 xor V2);
   pragma Inline (XOR3);

   --  Perform XOR on four 32-bit words @V0@, @V1@, @V2@ and @V3@
   function XOR4 (V0, V1, V2, V3 : Types.Word32) return Types.Word32
     with Post => XOR4'Result = (V0 xor V1 xor V2 xor V3);
   pragma Inline (XOR4);

   --  Perform XOR on four 32-bit words @V0@, @V1@, @V2@, @V3@ and @V4@
   function XOR5 (V0, V1, V2, V3, V4 : Types.Word32) return Types.Word32
     with Post => XOR5'Result = (V0 xor V1 xor V2 xor V3 xor V4);
   pragma Inline (XOR5);

   --  Perform XOR on two arrays of 32-bit words
   --
   --  @Left@   - First input array <br>
   --  @Right@  - Second input array <br>
   --  @Result@ - Result array <br>
   procedure Block_XOR
     (Left   : in     Types.Word32_Array_Type;
      Right  : in     Types.Word32_Array_Type;
      Result :    out Types.Word32_Array_Type)
     with
       Depends =>
         (Result =>+ (Left, Right)),
       Pre =>
         Left'First  = Right'First and
         Left'Last   = Right'Last  and
         Right'First = Result'First and
         Right'Last  = Result'Last,
       Post =>
         (for all I in Types.Index range Left'First .. Left'Last =>
            (Result (I) = XOR2 (Left (I), Right (I))));
   pragma Inline (Block_XOR);

   --  Copy all elements of @Source@ to @Dest@. Should @Source@ be shorter than
   --  @Dest@, remaining elements stay unchanged.
   procedure Block_Copy
      (Source : in     Types.Word32_Array_Type;
       Dest   : in out Types.Word32_Array_Type)
     with
       Depends =>
         (Dest =>+ Source),
       Pre =>
         Source'First  = Dest'First and
         Source'Last  <= Dest'Last,
       Post =>
         (for all P in Types.Index range Source'First .. Source'Last =>
            (Dest (P) = Source (P)));
   pragma Inline (Block_Copy);

end LSC.Internal.Ops32;
