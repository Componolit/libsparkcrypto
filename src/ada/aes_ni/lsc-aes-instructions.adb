-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2014, Stefan Berghofer
-- Copyright (C) 2014, secunet Security Networks AG
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
--    * Neither the name of the author nor the names of its contributors may be
--      used to endorse or promote products derived from this software without
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
with GNAT.SSE.Vector_Types;
with Interfaces.C;

package body LSC.AES.Instructions
is

   subtype v2di is GNAT.SSE.Vector_Types.m128i;

   function AES_Block_To_v2di is new Ada.Unchecked_Conversion
     (AES.Block_Type, v2di);

   function v2di_To_AES_Block is new Ada.Unchecked_Conversion
     (v2di, AES.Block_Type);

   ----------------------------------------------------------------------------

   function ia32_aesenc128 (X, Y : v2di) return v2di;
   pragma Import (Intrinsic, ia32_aesenc128, "__builtin_ia32_aesenc128");

   function Encrypt (X, Y : AES.Block_Type)
     return AES.Block_Type
   is
   begin
      return v2di_To_AES_Block (ia32_aesenc128
        (AES_Block_To_v2di (X), AES_Block_To_v2di (Y)));
   end Encrypt;

   ----------------------------------------------------------------------------

   function ia32_aesenclast128 (X, Y : v2di) return v2di;
   pragma Import (Intrinsic, ia32_aesenclast128, "__builtin_ia32_aesenclast128");

   function Encrypt_Last (X, Y : AES.Block_Type)
     return AES.Block_Type
   is
   begin
      return v2di_To_AES_Block (ia32_aesenclast128
        (AES_Block_To_v2di (X), AES_Block_To_v2di (Y)));
   end Encrypt_Last;

   ----------------------------------------------------------------------------

   function ia32_aesdec128 (X, Y : v2di) return v2di;
   pragma Import (Intrinsic, ia32_aesdec128, "__builtin_ia32_aesdec128");

   function Decrypt (X, Y : AES.Block_Type)
     return AES.Block_Type
   is
   begin
      return v2di_To_AES_Block (ia32_aesdec128
        (AES_Block_To_v2di (X), AES_Block_To_v2di (Y)));
   end Decrypt;

   ----------------------------------------------------------------------------

   function ia32_aesdeclast128 (X, Y : v2di) return v2di;
   pragma Import (Intrinsic, ia32_aesdeclast128, "__builtin_ia32_aesdeclast128");

   function Decrypt_Last (X, Y : AES.Block_Type)
     return AES.Block_Type
   is
   begin
      return v2di_To_AES_Block (ia32_aesdeclast128
        (AES_Block_To_v2di (X), AES_Block_To_v2di (Y)));
   end Decrypt_Last;

   ----------------------------------------------------------------------------

   function ia32_aesimc128 (X : v2di) return v2di;
   pragma Import (Intrinsic, ia32_aesimc128, "__builtin_ia32_aesimc128");

   function Inv_Mix_Columns (X : AES.Block_Type)
     return AES.Block_Type
   is
   begin
      return v2di_To_AES_Block (ia32_aesimc128 (AES_Block_To_v2di (X)));
   end Inv_Mix_Columns;

   ----------------------------------------------------------------------------

   function ia32_aeskeygenassist128 (X : v2di; Rcon : Interfaces.C.int) return v2di;
   pragma Import (Intrinsic, ia32_aeskeygenassist128, "__builtin_ia32_aeskeygenassist128");

   function Keygen_Assist (X : AES.Block_Type; Rcon : Types.Index)
     return AES.Block_Type
   is
   begin
      case Rcon is
         when 1 =>
            return v2di_To_AES_Block (ia32_aeskeygenassist128
              (AES_Block_To_v2di (X), 16#01#));
         when 2 =>
            return v2di_To_AES_Block (ia32_aeskeygenassist128
              (AES_Block_To_v2di (X), 16#02#));
         when 3 =>
            return v2di_To_AES_Block (ia32_aeskeygenassist128
              (AES_Block_To_v2di (X), 16#04#));
         when 4 =>
            return v2di_To_AES_Block (ia32_aeskeygenassist128
              (AES_Block_To_v2di (X), 16#08#));
         when 5 =>
            return v2di_To_AES_Block (ia32_aeskeygenassist128
              (AES_Block_To_v2di (X), 16#10#));
         when 6 =>
            return v2di_To_AES_Block (ia32_aeskeygenassist128
              (AES_Block_To_v2di (X), 16#20#));
         when 7 =>
            return v2di_To_AES_Block (ia32_aeskeygenassist128
              (AES_Block_To_v2di (X), 16#40#));
         when 8 =>
            return v2di_To_AES_Block (ia32_aeskeygenassist128
              (AES_Block_To_v2di (X), 16#80#));
         when 9 =>
            return v2di_To_AES_Block (ia32_aeskeygenassist128
              (AES_Block_To_v2di (X), 16#1B#));
         when 10 =>
            return v2di_To_AES_Block (ia32_aeskeygenassist128
              (AES_Block_To_v2di (X), 16#36#));
         when others =>
            return v2di_To_AES_Block (ia32_aeskeygenassist128
              (AES_Block_To_v2di (X), 0));
      end case;
   end Keygen_Assist;

end LSC.AES.Instructions;
