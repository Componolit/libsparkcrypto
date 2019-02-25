-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- @author Alexander Senier
-- @date   2019-01-24
--
-- Copyright (C) 2018 Componolit GmbH
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
with LSC.Internal.RIPEMD160;

package body LSC.RIPEMD160_Generic
is
   ----------
   -- Hash --
   ----------

   function Hash (Message : Message_Data_Type) return Hash_Data_Type
   is
      Block_Len : constant := 64;

      subtype MIT is Message_Index_Type;
      subtype RIPEMD160_Block_Type is
         Message_Data_Type (MIT'Val (1) .. MIT'Val (Block_Len));
      function To_Internal is new Ada.Unchecked_Conversion (RIPEMD160_Block_Type, Internal.RIPEMD160.Block_Type);

      subtype RIPEMD160_Hash_Type is Hash_Data_Type (Hash_Index_Type'Val (1) .. Hash_Index_Type'Val (20));
      function To_Public is new Ada.Unchecked_Conversion (Internal.RIPEMD160.Hash_Type, RIPEMD160_Hash_Type);

      use type Internal.RIPEMD160.Block_Length_Type;

      Temp    : RIPEMD160_Block_Type;
      Context : Internal.RIPEMD160.Context_Type := Internal.RIPEMD160.Context_Init;

      Full_Blocks   : constant Natural := Message'Length / Block_Len;
      Partial_Bytes : constant Natural := Message'Length - Full_Blocks * Block_Len;
   begin
      for I in 0 .. Full_Blocks - 1
      loop
         Internal.RIPEMD160.Context_Update
            (Context => Context,
             Block   => To_Internal (Message (MIT'Val (MIT'Pos (Message'First) + I * Block_Len) ..
                                              MIT'Val (MIT'Pos (Message'First) + I * Block_Len + Block_Len - 1))));
      end loop;

      Temp (Temp'First .. MIT'Val (MIT'Pos (Temp'First) + Partial_Bytes - 1)) :=
         Message (MIT'Val (MIT'Pos (Message'First) + Block_Len * Full_Blocks) ..
                  MIT'Val (MIT'Pos (Message'First) + Block_Len * Full_Blocks + Partial_Bytes - 1));

      Internal.RIPEMD160.Context_Finalize
         (Context => Context,
          Block   => To_Internal (Temp),
          Length  => 8 * Internal.RIPEMD160.Block_Length_Type (Partial_Bytes));

      return To_Public (Internal.RIPEMD160.Get_Hash (Context));
   end Hash;

end LSC.RIPEMD160_Generic;
