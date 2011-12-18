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

with Interfaces;
--# inherit Interfaces;

-------------------------------------------------------------------------------
-- Primitive types and operations
-------------------------------------------------------------------------------
package LSC.Types is

   pragma Pure;

   -- Base index type
   type Index is range 0 .. 79;

   -- 8-bit word
   subtype Byte is Interfaces.Unsigned_8;

   -- 32-bit word
   subtype Word32 is Interfaces.Unsigned_32;

   -- 64-bit word
   subtype Word64 is Interfaces.Unsigned_64;

   -- Index for 32-bit byte array
   subtype Byte_Array32_Index is Index range 0 .. 3;

   -- 32-bit byte array
   type Byte_Array32_Type is array (Byte_Array32_Index) of Byte;

   -- Index for 64-bit byte array
   subtype Byte_Array64_Index is Index range 0 .. 7;

   -- 64-bit byte array
   type Byte_Array64_Type is array (Byte_Array64_Index) of Byte;

   -- Unconstrained array of 32-bit words
   type Word32_Array_Type is array (Index range <>) of Word32;

   -- Unconstrained array of 64-bit words
   type Word64_Array_Type is array (Index range <>) of Word64;

   -- Left rotate 64-bit @Value@ by @Amount@
   function ROTR (Value : Word64; Amount : Natural) return Word64;
   pragma Inline (ROTR);

   -- Right shift 64-bit @Value@ by @Amount@
   function SHR (Value : Word64; Amount : Natural) return Word64;
   --# return Result => Result = Value / 2 ** Amount;
   pragma Inline (SHR);

   -- Left shift 64-bit @Value@ by @Amount@
   function SHL (Value : Word64; Amount : Natural) return Word64;
   --# return Result => Result = Value * 2 ** Amount;
   pragma Inline (SHL);

   -- Right rotate 32-bit @Value@ by @Amount@
   function ROTR32 (Value : Word32; Amount : Natural) return Word32;
   pragma Inline (ROTR32);

   -- Left rotate 32-bit @Value@ by @Amount@
   function ROTL32 (Value : Word32; Amount : Natural) return Word32;
   pragma Inline (ROTL32);

   -- Left shift 32-bit @Value@ by @Amount@
   function SHL32 (Value : Word32; Amount : Natural) return Word32;
   --# return Result => Result = Value * 2 ** Amount;
   pragma Inline (SHL32);

   -- Right shift 32-bit @Value@ by @Amount@
   function SHR32 (Value : Word32; Amount : Natural) return Word32;
   --# return Result => Result = Value / 2 ** Amount;
   pragma Inline (SHR32);

   -- Convert 32-bit word to 32-bit byte array
   function Word32_To_Byte_Array32 (Value : Word32) return Byte_Array32_Type;
   pragma Inline (Word32_To_Byte_Array32);

   -- Convert 32-bit byte array to 32-bit word
   function Byte_Array32_To_Word32 (Value : Byte_Array32_Type) return Word32;
   pragma Inline (Byte_Array32_To_Word32);

   -- Convert 64-bit word to 64-bit byte array
   function Word64_To_Byte_Array64 (Value : Word64) return Byte_Array64_Type;
   pragma Inline (Word64_To_Byte_Array64);

   -- Convert 64-bit byte array to 64-bit word
   function Byte_Array64_To_Word64 (Value : Byte_Array64_Type) return Word64;
   pragma Inline (Byte_Array64_To_Word64);

end LSC.Types;
