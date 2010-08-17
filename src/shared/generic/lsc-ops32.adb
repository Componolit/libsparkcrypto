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
         --# check
         --#    I <= Left'Last   and
         --#    I <= Right'Last  and
         --#    I <= Result'Last;

         --# accept Flow, 23, Result, "Initialized in complete loop";
         Result (I) := XOR2 (Left (I), Right (I));
         --# assert
         --#   (for all Pos in Types.Index range Result'First .. I =>
         --#       (Result (Pos) = XOR2 (Left (Pos), Right (Pos))));
      end loop;

      --# accept Flow, 602, Result, Result, "Initialized in complete loop";
   end Block_XOR;

end LSC.Ops32;
