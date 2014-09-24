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

with Ada.Unchecked_Conversion;

package body LSC.Types
  with SPARK_Mode => Off
is

   function ROTR (Value : Word64; Amount : Natural) return Word64
   is
   begin
      return Interfaces.Rotate_Right (Value, Amount);
   end ROTR;

   ----------------------------------------------------------------------------

   function SHR (Value : Word64; Amount : Natural) return Word64
   is
   begin
      return Interfaces.Shift_Right (Value, Amount);
   end SHR;

   ----------------------------------------------------------------------------

   function SHL (Value : Word64; Amount : Natural) return Word64
   is
   begin
      return Interfaces.Shift_Left (Value, Amount);
   end SHL;

   ----------------------------------------------------------------------------

   function ROTL32 (Value : Word32; Amount : Natural) return Word32
   is
   begin
      return Interfaces.Rotate_Left (Value, Amount);
   end ROTL32;

   ----------------------------------------------------------------------------

   function ROTR32 (Value : Word32; Amount : Natural) return Word32
   is
   begin
      return Interfaces.Rotate_Right (Value, Amount);
   end ROTR32;

   ----------------------------------------------------------------------------

   function SHL32 (Value : Word32; Amount : Natural) return Word32
   is
   begin
      return Interfaces.Shift_Left (Value, Amount);
   end SHL32;

   ----------------------------------------------------------------------------

   function SHR32 (Value : Word32; Amount : Natural) return Word32
   is
   begin
      return Interfaces.Shift_Right (Value, Amount);
   end SHR32;

   ----------------------------------------------------------------------------

   function Word32_To_Byte_Array32 (Value : Word32) return Byte_Array32_Type
   is
      function W322W8A is new Ada.Unchecked_Conversion
        (Word32, Byte_Array32_Type);
   begin
      return W322W8A (Value);
   end Word32_To_Byte_Array32;

   ----------------------------------------------------------------------------

   function Byte_Array32_To_Word32 (Value : Byte_Array32_Type) return Word32
   is
      function W8A2W32 is new Ada.Unchecked_Conversion
        (Byte_Array32_Type, Word32);
   begin
      return W8A2W32 (Value);
   end Byte_Array32_To_Word32;

   ----------------------------------------------------------------------------

   function Word64_To_Byte_Array64 (Value : Word64) return Byte_Array64_Type
   is
      function W642W8A is new Ada.Unchecked_Conversion
        (Word64, Byte_Array64_Type);
   begin
      return W642W8A (Value);
   end Word64_To_Byte_Array64;

   ----------------------------------------------------------------------------

   function Byte_Array64_To_Word64 (Value : Byte_Array64_Type) return Word64
   is
      function W8A2W64 is new Ada.Unchecked_Conversion
        (Byte_Array64_Type, Word64);
   begin
      return W8A2W64 (Value);
   end Byte_Array64_To_Word64;

end LSC.Types;
