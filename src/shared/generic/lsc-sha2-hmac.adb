-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- @author Alexander Senier
-- @date   2019-01-21
--
-- Copyright (C) 2018-2019 Componolit GmbH
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

with LSC.Internal.HMAC_SHA256;
with LSC.Internal.HMAC_SHA384;
with LSC.Internal.HMAC_SHA512;

package body LSC.SHA2.HMAC is

   -----------------
   -- HMAC_SHA256 --
   -----------------

   function HMAC_SHA256
     (Key       : LSC.Types.Bytes;
      Message   : LSC.Types.Bytes;
      Length    : LSC.Types.Natural_Index) return LSC.Types.Bytes
   is
      use type Internal.SHA256.Block_Length_Type;

      Temp          : SHA256_Block_Type := (others => 0);
      Full_Blocks   : constant Natural := Message'Length / SHA256_Block_Len;
      Partial_Bytes : constant Natural := Message'Length - Full_Blocks * SHA256_Block_Len;

      Context  : Internal.HMAC_SHA256.Context_Type;
      Full_Key : SHA2.SHA256_Block_Type := (others => 0);
   begin

      if Key'Length <= SHA256_Block_Len
      then
         Full_Key (Full_Key'First .. Full_Key'First + Key'Length - 1) := Key;
      else
         Full_Key (Full_Key'First .. Full_Key'First + SHA256_Hash_Len - 1) := LSC.SHA2.Hash (LSC.SHA2.SHA256, Key);
      end if;

      Context := Internal.HMAC_SHA256.Context_Init (To_Internal (Full_Key));

      for I in 0 .. Full_Blocks - 1
      loop
         Internal.HMAC_SHA256.Context_Update
            (Context => Context,
             Block   => To_Internal (Message (Message'First + I * SHA256_Block_Len ..
                                              Message'First + I * SHA256_Block_Len + SHA256_Block_Len - 1)));
      end loop;

      Temp (Temp'First .. Temp'First + Partial_Bytes - 1) :=
         Message (Message'First + SHA256_Block_Len * Full_Blocks ..
                  Message'First + SHA256_Block_Len * Full_Blocks + Partial_Bytes - 1);

      Internal.HMAC_SHA256.Context_Finalize
         (Context => Context,
          Block   => To_Internal (Temp),
          Length  => 8 * Internal.SHA256.Block_Length_Type (Partial_Bytes));

      return To_Public (Internal.HMAC_SHA256.Get_Prf (Context)) (1 .. Length);

   end HMAC_SHA256;

   -----------------
   -- HMAC_SHA384 --
   -----------------

   function HMAC_SHA384
     (Key       : LSC.Types.Bytes;
      Message   : LSC.Types.Bytes;
      Length    : LSC.Types.Natural_Index) return LSC.Types.Bytes
   is
      use type Internal.SHA512.Block_Length_Type;

      Temp          : SHA512_Block_Type := (others => 0);
      Full_Blocks   : constant Natural := Message'Length / SHA512_Block_Len;
      Partial_Bytes : constant Natural := Message'Length - Full_Blocks * SHA512_Block_Len;

      Context  : Internal.HMAC_SHA384.Context_Type;
      Full_Key : SHA2.SHA512_Block_Type := (others => 0);
   begin

      if Key'Length <= SHA512_Block_Len
      then
         Full_Key (Full_Key'First .. Full_Key'First + Key'Length - 1) := Key;
      else
         Full_Key (Full_Key'First .. Full_Key'First + SHA384_Hash_Len - 1) := LSC.SHA2.Hash (LSC.SHA2.SHA384, Key);
      end if;

      Context := Internal.HMAC_SHA384.Context_Init (To_Internal (Full_Key));

      for I in 0 .. Full_Blocks - 1
      loop
         Internal.HMAC_SHA384.Context_Update
            (Context => Context,
             Block   => To_Internal (Message (Message'First + I * SHA512_Block_Len ..
                                              Message'First + I * SHA512_Block_Len + SHA512_Block_Len - 1)));
      end loop;

      Temp (Temp'First .. Temp'First + Partial_Bytes - 1) :=
         Message (Message'First + SHA512_Block_Len * Full_Blocks ..
                  Message'First + SHA512_Block_Len * Full_Blocks + Partial_Bytes - 1);

      Internal.HMAC_SHA384.Context_Finalize
         (Context => Context,
          Block   => To_Internal (Temp),
          Length  => 8 * Internal.SHA512.Block_Length_Type (Partial_Bytes));

      return To_Public_384 (Internal.HMAC_SHA384.Get_Prf (Context)) (1 .. Length);

   end HMAC_SHA384;

   -----------------
   -- HMAC_SHA512 --
   -----------------

   function HMAC_SHA512
     (Key       : LSC.Types.Bytes;
      Message   : LSC.Types.Bytes;
      Length    : LSC.Types.Natural_Index) return LSC.Types.Bytes
   is
      use type Internal.SHA512.Block_Length_Type;

      Temp          : SHA512_Block_Type := (others => 0);
      Full_Blocks   : constant Natural := Message'Length / SHA512_Block_Len;
      Partial_Bytes : constant Natural := Message'Length - Full_Blocks * SHA512_Block_Len;

      Context  : Internal.HMAC_SHA512.Context_Type;
      Full_Key : SHA2.SHA512_Block_Type := (others => 0);
   begin

      if Key'Length <= SHA512_Block_Len
      then
         Full_Key (Full_Key'First .. Full_Key'First + Key'Length - 1) := Key;
      else
         Full_Key (Full_Key'First .. Full_Key'First + SHA512_Hash_Len - 1) := LSC.SHA2.Hash (LSC.SHA2.SHA512, Key);
      end if;

      Context := Internal.HMAC_SHA512.Context_Init (To_Internal (Full_Key));

      for I in 0 .. Full_Blocks - 1
      loop
         Internal.HMAC_SHA512.Context_Update
            (Context => Context,
             Block   => To_Internal (Message (Message'First + I * SHA512_Block_Len ..
                                              Message'First + I * SHA512_Block_Len + SHA512_Block_Len - 1)));
      end loop;

      Temp (Temp'First .. Temp'First + Partial_Bytes - 1) :=
         Message (Message'First + SHA512_Block_Len * Full_Blocks ..
                  Message'First + SHA512_Block_Len * Full_Blocks + Partial_Bytes - 1);

      Internal.HMAC_SHA512.Context_Finalize
         (Context => Context,
          Block   => To_Internal (Temp),
          Length  => 8 * Internal.SHA512.Block_Length_Type (Partial_Bytes));

      return To_Public_512 (Internal.HMAC_SHA512.Get_Prf (Context)) (1 .. Length);

   end HMAC_SHA512;

   ----------
   -- HMAC --
   ----------

   function HMAC
     (Algorithm  : SHA2.Algorithm_Type;
      Key        : LSC.Types.Bytes;
      Message    : LSC.Types.Bytes;
      Output_Len : LSC.Types.Natural_Index := 16) return LSC.Types.Bytes
   is
     (case Algorithm is
         when SHA2.SHA256 => HMAC_SHA256 (Key, Message, Output_Len),
         when SHA2.SHA384 => HMAC_SHA384 (Key, Message, Output_Len),
         when SHA2.SHA512 => HMAC_SHA512 (Key, Message, Output_Len));

end LSC.SHA2.HMAC;
