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

with LSC.RIPEMD160_Generic;
with LSC.Internal.RIPEMD160;
with LSC.Internal.HMAC_RIPEMD160;
with LSC.Internal.Convert_HMAC;

package body LSC.RIPEMD160_Generic.HMAC is

   ----------
   -- HMAC --
   ----------

   function HMAC
     (Key        : Key_Type;
      Message    : Message_Type;
      Output_Len : Natural := 20) return Hash_Type
   is
      subtype Internal_Key_Index is Key_Index_Type range Key'First .. Key'Last;
      subtype Internal_Key_Type is Key_Type (Internal_Key_Index);

      function Hash_Key is new LSC.RIPEMD160_Generic.Hash
         (Key_Index_Type, Key_Elem_Type, Key_Type,
          Internal_Key_Index, Key_Elem_Type, Internal_Key_Type);

      function HMAC_Internal is new Internal.Convert_HMAC.HMAC_Generic
         (Key_Index_Type,
          Key_Elem_Type,
          Key_Type,
          Message_Index_Type,
          Message_Elem_Type,
          Message_Type,
          Hash_Index_Type,
          Hash_Elem_Type,
          Hash_Type,
          Internal.HMAC_RIPEMD160.Context_Type,
          Internal.RIPEMD160.Block_Type,
          Internal.RIPEMD160.Block_Length_Type,
          Internal.RIPEMD160.Hash_Type,
          Internal.HMAC_RIPEMD160.Context_Init,
          Internal.HMAC_RIPEMD160.Context_Update,
          Internal.HMAC_RIPEMD160.Context_Finalize,
          Internal.HMAC_RIPEMD160.Get_Auth,
          Hash_Key);
   begin
      return HMAC_Internal (Key, Message, Output_Len);
   end HMAC;

--   function HMAC
--     (Key        : Key_Type;
--      Message    : Message_Type;
--      Output_Len : Natural := 20) return Hash_Type
--   is
--      subtype MIT is Message_Index_Type;
--      subtype HIT is Hash_Index_Type;
--      subtype KIT is Key_Index_Type;
--
--      Block_Len : constant := 64;
--      subtype Block_Type is Message_Type
--         (MIT'First .. MIT'Val (MIT'Pos (MIT'First) + Block_Len - 1));
--      function To_Internal is new Ada.Unchecked_Conversion (Block_Type, Internal.RIPEMD160.Block_Type);
--
--      Hash_Len : constant := 20;
--      subtype Hash_Block_Type is Hash_Type
--         (HIT'First .. HIT'Val (HIT'Pos (HIT'First) + Hash_Len - 1));
--      function To_Public is new Ada.Unchecked_Conversion (Internal.RIPEMD160.Hash_Type, Hash_Block_Type);
--
--      Full_Blocks   : constant Natural := Message'Length / Block_Len;
--      Partial_Bytes : constant Natural := Message'Length - Full_Blocks * Block_Len;
--
--      Context  : Internal.HMAC_RIPEMD160.Context_Type;
--      Temp     : Block_Type;
--
--      subtype Full_Key_Type is Key_Type (KIT'First .. KIT'Val (KIT'Pos (KIT'First) + Block_Len - 1));
--      Full_Key : Full_Key_Type;
--      function To_Internal is new Ada.Unchecked_Conversion (Full_Key_Type, Internal.RIPEMD160.Block_Type);
--
--      function Hash_Key is new LSC.RIPEMD160_Generic.Hash
--         (Key_Index_Type, Key_Elem_Type, Key_Type,
--          Key_Index_Type, Key_Elem_Type, Key_Type);
--
--      use type Internal.RIPEMD160.Block_Length_Type;
--   begin
--
--      if Key'Length <= Block_Len
--      then
--         Full_Key (Full_Key'First .. KIT'Val (KIT'Pos (Full_Key'First) + Key'Length - 1)) := Key;
--      else
--         Full_Key (Full_Key'First .. KIT'Val (KIT'Pos (Full_Key'First) + Hash_Len - 1)) := Hash_Key (Key);
--      end if;
--
--      Context := Internal.HMAC_RIPEMD160.Context_Init (To_Internal (Full_Key));
--
--      for I in 0 .. Full_Blocks - 1
--      loop
--         Internal.HMAC_RIPEMD160.Context_Update
--            (Context => Context,
--             Block   => To_Internal (Message (MIT'Val (MIT'Pos (Message'First) + I * Block_Len) ..
--                                              MIT'Val (MIT'Pos (Message'First) + I * Block_Len + Block_Len - 1))));
--      end loop;
--
--      Temp (Temp'First .. MIT'Val (MIT'Pos (Temp'First) + Partial_Bytes - 1)) :=
--         Message (MIT'Val (MIT'Pos (Message'First) + Block_Len * Full_Blocks) ..
--                  MIT'Val (MIT'Pos (Message'First) + Block_Len * Full_Blocks + Partial_Bytes - 1));
--
--      Internal.HMAC_RIPEMD160.Context_Finalize
--         (Context => Context,
--          Block   => To_Internal (Temp),
--          Length  => 8 * Internal.RIPEMD160.Block_Length_Type (Partial_Bytes));
--
--      return To_Public (Internal.HMAC_RIPEMD160.Get_Auth (Context)) (HIT'First .. HIT'Val (HIT'Pos (HIT'First) + Output_Len));
--
--   end HMAC;

end LSC.RIPEMD160_Generic.HMAC;
