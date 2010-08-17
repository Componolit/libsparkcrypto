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
   pragma Inline (SHR);

   -- Left shift 64-bit @Value@ by @Amount@
   function SHL (Value : Word64; Amount : Natural) return Word64;
   pragma Inline (SHL);

   -- Right rotate 32-bit @Value@ by @Amount@
   function ROTR32 (Value : Word32; Amount : Natural) return Word32;
   pragma Inline (ROTR32);

   -- Left rotate 32-bit @Value@ by @Amount@
   function ROTL32 (Value : Word32; Amount : Natural) return Word32;
   pragma Inline (ROTL32);

   -- Left shift 32-bit @Value@ by @Amount@
   function SHL32 (Value : Word32; Amount : Natural) return Word32;
   pragma Inline (SHL32);

   -- Right shift 32-bit @Value@ by @Amount@
   function SHR32 (Value : Word32; Amount : Natural) return Word32;
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
