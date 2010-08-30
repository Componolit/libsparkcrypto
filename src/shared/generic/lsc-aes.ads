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
use type LSC.Types.Index;
--# inherit
--#    LSC.Types,
--#    LSC.Debug,
--#    LSC.Ops32,
--#    LSC.Byteorder32;

-------------------------------------------------------------------------------
--  The AES algorithm
--
--  <ul>
--  <li> FIPS PUB 197, Advanced Encryption Standard (AES),<br> National Institute of
--  Standards and Technology, U.S. Department of Commerce, November 2001.
--  [doc/specs/fips-197.pdf] </li>
--
--  <li> Joan Daemen and Vincent Rijmen, AES submission document on Rijndael,<br>
--  Version 2, September 1999. [doc/specs/Rijndael-amended.pdf] </li>
--  </ul>
-------------------------------------------------------------------------------
package LSC.AES is

   --  AES encryption context
   type AES_Enc_Context is private;

   --  AES decryption context
   type AES_Dec_Context is private;

   --  Index of AES key
   subtype Key_Index is Types.Index range 0 .. 7;

   --  AES key
   type Key_Type is array (Key_Index range <>) of Types.Word32;

   --  Index of AES-128 key
   subtype AES128_Key_Index is Types.Index range 0 .. 3;

   --  AES-128 key
   subtype AES128_Key_Type is Key_Type (AES128_Key_Index);

   --  Index of AES-192 key
   subtype AES192_Key_Index is Types.Index range 0 .. 5;

   --  AES-192 key
   subtype AES192_Key_Type is Key_Type (AES192_Key_Index);

   --  Index of AES-256 key
   subtype AES256_Key_Index is Types.Index range 0 .. 7;

   --  AES-256 key
   subtype AES256_Key_Type is Key_Type (AES256_Key_Index);

   --  Index of AES block
   subtype Block_Index is Types.Index range 0 .. 3;

   --  AES block
   subtype Block_Type is Types.Word32_Array_Type (Block_Index);

   --  Index of AES message
   subtype Message_Index is Natural;

   --  AES message (unconstrained array of AES blocks)
   type Message_Type is array (Message_Index range <>) of Block_Type;

   --  Create AES-128 encryption context from AES-128 @Key@
   function Create_AES128_Enc_Context (Key : AES128_Key_Type) return AES_Enc_Context;

   --  Create AES-192 encryption context from AES-192 @Key@
   function Create_AES192_Enc_Context (Key : AES192_Key_Type) return AES_Enc_Context;

   --  Create AES-256 encryption context from AES-256 @Key@
   function Create_AES256_Enc_Context (Key : AES256_Key_Type) return AES_Enc_Context;

   --  Encrypt one @Plaintext@ block using given @Context@, return one block of
   --  ciphertext
   function Encrypt (Context   : AES_Enc_Context;
                     Plaintext : Block_Type) return Block_Type;

   --  Create AES-128 decryption context from AES-128 @Key@
   function Create_AES128_Dec_Context (Key : AES128_Key_Type) return AES_Dec_Context;

   --  Create AES-192 decryption context from AES-192 @Key@
   function Create_AES192_Dec_Context (Key : AES192_Key_Type) return AES_Dec_Context;

   --  Create AES-256 decryption context from AES-256 @Key@
   function Create_AES256_Dec_Context (Key : AES256_Key_Type) return AES_Dec_Context;

   --  Decrypt one @Ciphertext@ block using given @Context@, return one block of
   --  plaintext
   function Decrypt (Context    : AES_Dec_Context;
                     Ciphertext : Block_Type) return Block_Type;

   --  Empty AES block
   Null_Block : constant Block_Type;

   --  Empty AES-128 key
   Null_AES128_Key : constant AES128_Key_Type;

   --  Empty AES-192 key
   Null_AES192_Key : constant AES192_Key_Type;

   --  Empty AES-256 key
   Null_AES256_Key : constant AES256_Key_Type;

private

   Nb : constant Types.Index :=  4;

   subtype Schedule_Index is Types.Index range 0 .. 15 * Nb - 1;
   subtype Schedule_Type is Types.Word32_Array_Type (Schedule_Index);

   Null_Schedule : constant Schedule_Type :=
      Schedule_Type'(Schedule_Index => 0);

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

   Null_Block : constant Block_Type :=
      Block_Type'(Block_Index => 0);

   Null_AES128_Key : constant AES128_Key_Type :=
      AES128_Key_Type'(AES128_Key_Index => 0);

   Null_AES192_Key : constant AES192_Key_Type :=
      AES192_Key_Type'(AES192_Key_Index => 0);

   Null_AES256_Key : constant AES256_Key_Type :=
      AES256_Key_Type'(AES256_Key_Index => 0);

end LSC.AES;
