-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- @author Alexander Senier
-- @date   2019-01-23
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
with LSC.Internal.SHA1;

package body LSC.SHA1_Generic
is
   ----------
   -- Hash --
   ----------

   function Hash (Message : Message_Data_Type) return Hash_Data_Type
   is
      subtype MIT is Message_Index_Type;

      use type Internal.SHA1.Block_Length_Type;

      Block_Len : constant := 64;
      subtype SHA1_Block_Type is
         Message_Data_Type (MIT'First .. MIT'Val (MIT'Pos (MIT'First) + Block_Len - 1));
      function To_Internal is new Ada.Unchecked_Conversion (SHA1_Block_Type, Internal.SHA1.Block_Type);
      function To_Public is new Ada.Unchecked_Conversion (Internal.SHA1.Hash_Type, Hash_Data_Type);

      type Byte is mod 2**8 with Size => 8;
      function To_Internal is new Ada.Unchecked_Conversion (Byte, Message_Elem_Type);
      Null_Elem : constant Message_Elem_Type := To_Internal (0);

      Temp    : SHA1_Block_Type := (others => Null_Elem);
      Context : Internal.SHA1.Context_Type := Internal.SHA1.Context_Init;

      Full_Blocks   : constant Natural := Message'Length / Block_Len;
      Partial_Bytes : constant Natural := Message'Length - Full_Blocks * Block_Len;
   begin
      for I in 0 .. Full_Blocks - 1
      loop
         Internal.SHA1.Context_Update
            (Context => Context,
             Block   => To_Internal (Message (MIT'Val (MIT'Pos (Message'First) + I * Block_Len) ..
                                              MIT'Val (MIT'Pos (Message'First) + I * Block_Len + Block_Len - 1))));
      end loop;

      Temp (Temp'First .. MIT'Val (MIT'Pos (Temp'First) + Partial_Bytes - 1)) :=
         Message (MIT'Val (MIT'Pos (Message'First) + Block_Len * Full_Blocks) ..
                  MIT'Val (MIT'Pos (Message'First) + Block_Len * Full_Blocks + Partial_Bytes - 1));

      Internal.SHA1.Context_Finalize
         (Context => Context,
          Block   => To_Internal (Temp),
          Length  => 8 * Internal.SHA1.Block_Length_Type (Partial_Bytes));

      return To_Public (Internal.SHA1.Get_Hash (Context));
   end Hash;

end LSC.SHA1_Generic;
