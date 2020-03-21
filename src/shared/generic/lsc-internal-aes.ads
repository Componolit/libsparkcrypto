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
--  The AES algorithm
--
--  <ul>
--  <li>
--  <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">
--  FIPS PUB 197, Advanced Encryption Standard (AES), National Institute of
--  Standards and Technology, U.S. Department of Commerce, November 2001. </a>
--  </li>
--
--  <li>
--  <a href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">
--  Joan Daemen and Vincent Rijmen, AES submission document on Rijndael,
--  Version 2, September 1999.</a>
--  </li>
--  </ul>
-------------------------------------------------------------------------------
package LSC.Internal.AES is

   pragma Pure;

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
                     Plaintext : Block_Type) return Block_Type
     with Global => null;

   --  Create AES-128 decryption context from AES-128 @Key@
   function Create_AES128_Dec_Context (Key : AES128_Key_Type) return AES_Dec_Context;

   --  Create AES-192 decryption context from AES-192 @Key@
   function Create_AES192_Dec_Context (Key : AES192_Key_Type) return AES_Dec_Context;

   --  Create AES-256 decryption context from AES-256 @Key@
   function Create_AES256_Dec_Context (Key : AES256_Key_Type) return AES_Dec_Context;

   --  Decrypt one @Ciphertext@ block using given @Context@, return one block of
   --  plaintext
   function Decrypt (Context    : AES_Dec_Context;
                     Ciphertext : Block_Type) return Block_Type
     with Global => null;

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

end LSC.Internal.AES;
