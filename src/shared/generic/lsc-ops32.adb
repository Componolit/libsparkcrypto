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

package body LSC.Ops32 is

   function Bytes_To_Word
      (Byte0 : Types.Byte;
       Byte1 : Types.Byte;
       Byte2 : Types.Byte;
       Byte3 : Types.Byte) return Types.Word32
   is
   begin
      return Types.Byte_Array32_To_Word32 (Types.Byte_Array32_Type'(Byte3, Byte2, Byte1, Byte0));
   end Bytes_To_Word;

   ----------------------------------------------------------------------------

   function ByteX (Value    : Types.Word32;
                   Position : Types.Byte_Array32_Index) return Types.Byte
   is
      Temp : Types.Byte_Array32_Type;
   begin
      Temp := Types.Word32_To_Byte_Array32 (Value);
      return Temp (Position);
   end ByteX;

   ----------------------------------------------------------------------------

   function Byte0 (Value : Types.Word32) return Types.Byte
   is
   begin
      return ByteX (Value, 3);
   end Byte0;

   ----------------------------------------------------------------------------

   function Byte1 (Value : Types.Word32) return Types.Byte
   is
   begin
      return ByteX (Value, 2);
   end Byte1;

   ----------------------------------------------------------------------------

   function Byte2 (Value : Types.Word32) return Types.Byte
   is
   begin
      return ByteX (Value, 1);
   end Byte2;

   ----------------------------------------------------------------------------

   function Byte3 (Value : Types.Word32) return Types.Byte
   is
   begin
      return ByteX (Value, 0);
   end Byte3;

   ----------------------------------------------------------------------------

   function XOR2 (V0, V1 : Types.Word32) return Types.Word32
   is
   begin
      return V0 xor V1;
   end XOR2;

   ----------------------------------------------------------------------------

   function XOR3 (V0, V1, V2 : Types.Word32) return Types.Word32
   is
   begin
      return V0 xor V1 xor V2;
   end XOR3;

   ----------------------------------------------------------------------------

   function XOR4 (V0, V1, V2, V3 : Types.Word32) return Types.Word32
   is
   begin
      return V0 xor V1 xor V2 xor V3;
   end XOR4;

   ----------------------------------------------------------------------------

   function XOR5 (V0, V1, V2, V3, V4 : Types.Word32) return Types.Word32
   is
   begin
      return V0 xor V1 xor V2 xor V3 xor V4;
   end XOR5;

   ----------------------------------------------------------------------------

   procedure Block_XOR
     (Left   : in     Types.Word32_Array_Type;
      Right  : in     Types.Word32_Array_Type;
      Result :    out Types.Word32_Array_Type)
   is
   begin
      for I in Types.Index range Result'First .. Result'Last
      loop
         pragma Warnings (Off, """Result"" might not be initialized");
         Result (I) := XOR2 (Left (I), Right (I));
         pragma Loop_Invariant
           (for all Pos in Types.Index range Result'First .. I =>
              (Result (Pos) = XOR2 (Left (Pos), Right (Pos))));
         pragma Warnings (On, """Result"" might not be initialized");
      end loop;
   end Block_XOR;

   ----------------------------------------------------------------------------

   procedure Block_Copy
     (Source : in     Types.Word32_Array_Type;
      Dest   : in out Types.Word32_Array_Type)
   is
   begin

      for I in Types.Index range Source'First .. Source'Last
      loop
         Dest (I) := Source (I);

         pragma Loop_Invariant
           (for all P in Types.Index range Source'First .. I =>
              (Dest (P) = Source (P)));
      end loop;

   end Block_Copy;

end LSC.Ops32;
