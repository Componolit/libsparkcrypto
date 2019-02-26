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

with Ada.Unchecked_Conversion;
with LSC.Internal.HMAC_SHA256;
with LSC.Internal.HMAC_SHA384;
with LSC.Internal.HMAC_SHA512;
with LSC.Internal.SHA256;
with LSC.Internal.SHA512;

package body LSC.SHA2_Generic.HMAC is

   -----------------
   -- HMAC_SHA256 --
   -----------------

   generic
      type Key_Index_Type is (<>);
      type Key_Elem_Type is (<>);
      type Key_Type is array (Key_Index_Type range <>) of Key_Elem_Type;
      type Message_Index_Type is (<>);
      type Message_Elem_Type is (<>);
      type Message_Type is array (Message_Index_Type range <>) of Message_Elem_Type;
      type Hash_Index_Type is (<>);
      type Hash_Elem_Type is (<>);
      type Hash_Type is array (Hash_Index_Type range <>) of Hash_Elem_Type;
   function HMAC_SHA256_Generic
     (Key           : Key_Type;
      Message       : Message_Type;
      Output_Length : Natural) return Hash_Type;

   function HMAC_SHA256_Generic
     (Key           : Key_Type;
      Message       : Message_Type;
      Output_Length : Natural) return Hash_Type
   is
      subtype MIT is Message_Index_Type;
      subtype HIT is Hash_Index_Type;
      subtype KIT is Key_Index_Type;

      use type Internal.SHA256.Block_Length_Type;

      Block_Len : constant := 64;
      subtype SHA256_Block_Type is
         Message_Type (MIT'First .. MIT'Val (MIT'Pos (MIT'First) + Block_Len - 1));
      function To_Internal is new Ada.Unchecked_Conversion (SHA256_Block_Type, Internal.SHA256.Block_Type);

      Hash_Len : constant := 32;
      subtype SHA256_Hash_Type is
         Hash_Type (HIT'First .. HIT'Val (HIT'Pos (HIT'First) + Hash_Len - 1));
      function To_Public is new Ada.Unchecked_Conversion (Internal.SHA256.SHA256_Hash_Type, SHA256_Hash_Type);

      Full_Blocks   : constant Natural := Message'Length / Block_Len;
      Partial_Bytes : constant Natural := Message'Length - Full_Blocks * Block_Len;

      Context : Internal.HMAC_SHA256.Context_Type;
      Temp    : SHA256_Block_Type;

      subtype Full_Key_Type is Key_Type (KIT'First .. KIT'Val (KIT'Pos (KIT'First) + Block_Len - 1));
      Full_Key : Full_Key_Type;
      function To_Internal is new Ada.Unchecked_Conversion (Full_Key_Type, Internal.SHA256.Block_Type);

      function Hash_Key is new LSC.SHA2_Generic.Hash
         (Key_Index_Type, Key_Elem_Type, Key_Type,
          Key_Index_Type, Key_Elem_Type, Key_Type);
   begin

      if Key'Length <= Block_Len
      then
         Full_Key (Full_Key'First .. KIT'Val (KIT'Pos (Full_Key'First) + Key'Length - 1)) := Key;
      else
         Full_Key (Full_Key'First .. KIT'Val (KIT'Pos (Full_Key'First) + Hash_Len - 1)) := Hash_Key (LSC.SHA2_Generic.SHA256, Key);
      end if;

      Context := Internal.HMAC_SHA256.Context_Init (To_Internal (Full_Key));

      for I in 0 .. Full_Blocks - 1
      loop
         Internal.HMAC_SHA256.Context_Update
            (Context => Context,
             Block   => To_Internal (Message (MIT'Val (MIT'Pos (Message'First) + I * Block_Len) ..
                                              MIT'Val (MIT'Pos (Message'First) + I * Block_Len + Block_Len - 1))));
      end loop;

      Temp (Temp'First .. MIT'Val (MIT'Pos (Temp'First) + Partial_Bytes - 1)) :=
         Message (MIT'Val (MIT'Pos (Message'First) + Block_Len * Full_Blocks) ..
                  MIT'Val (MIT'Pos (Message'First) + Block_Len * Full_Blocks + Partial_Bytes - 1));

      Internal.HMAC_SHA256.Context_Finalize
         (Context => Context,
          Block   => To_Internal (Temp),
          Length  => 8 * Internal.SHA256.Block_Length_Type (Partial_Bytes));

      return To_Public (Internal.HMAC_SHA256.Get_Prf (Context)) (HIT'First .. HIT'Val (HIT'Pos (HIT'First) + Output_Length - 1));

   end HMAC_SHA256_Generic;

   -----------------
   -- HMAC_SHA384 --
   -----------------

   generic
      type Key_Index_Type is (<>);
      type Key_Elem_Type is (<>);
      type Key_Type is array (Key_Index_Type range <>) of Key_Elem_Type;
      type Message_Index_Type is (<>);
      type Message_Elem_Type is (<>);
      type Message_Type is array (Message_Index_Type range <>) of Message_Elem_Type;
      type Hash_Index_Type is (<>);
      type Hash_Elem_Type is (<>);
      type Hash_Type is array (Hash_Index_Type range <>) of Hash_Elem_Type;
   function HMAC_SHA384_Generic
     (Key           : Key_Type;
      Message       : Message_Type;
      Output_Length : Natural) return Hash_Type;

   function HMAC_SHA384_Generic
     (Key           : Key_Type;
      Message       : Message_Type;
      Output_Length : Natural) return Hash_Type
   is
      subtype MIT is Message_Index_Type;
      subtype HIT is Hash_Index_Type;
      subtype KIT is Key_Index_Type;

      use type Internal.SHA512.Block_Length_Type;

      Block_Len : constant := 128;
      subtype SHA512_Block_Type is
         Message_Type (MIT'First .. MIT'Val (MIT'Pos (MIT'First) + Block_Len - 1));
      function To_Internal is new Ada.Unchecked_Conversion (SHA512_Block_Type, Internal.SHA512.Block_Type);

      Hash_Len : constant := 48;
      subtype SHA384_Hash_Type is
         Hash_Type (HIT'First .. HIT'Val (HIT'Pos (HIT'First) + Hash_Len - 1));
      function To_Public is new Ada.Unchecked_Conversion (Internal.SHA512.SHA384_Hash_Type, SHA384_Hash_Type);

      Full_Blocks   : constant Natural := Message'Length / Block_Len;
      Partial_Bytes : constant Natural := Message'Length - Full_Blocks * Block_Len;

      Context  : Internal.HMAC_SHA384.Context_Type;
      Temp     : SHA512_Block_Type;

      subtype Full_Key_Type is Key_Type (KIT'First .. KIT'Val (KIT'Pos (KIT'First) + Block_Len - 1));
      Full_Key : Full_Key_Type;
      function To_Internal is new Ada.Unchecked_Conversion (Full_Key_Type, Internal.SHA512.Block_Type);

      function Hash_Key is new LSC.SHA2_Generic.Hash
         (Key_Index_Type, Key_Elem_Type, Key_Type,
          Key_Index_Type, Key_Elem_Type, Key_Type);
   begin

      if Key'Length <= Block_Len
      then
         Full_Key (Full_Key'First .. KIT'Val (KIT'Pos (Full_Key'First) + Key'Length - 1)) := Key;
      else
         Full_Key (Full_Key'First .. KIT'Val (KIT'Pos (Full_Key'First) + Hash_Len - 1)) := Hash_Key (LSC.SHA2_Generic.SHA384, Key);
      end if;

      Context := Internal.HMAC_SHA384.Context_Init (To_Internal (Full_Key));

      for I in 0 .. Full_Blocks - 1
      loop
         Internal.HMAC_SHA384.Context_Update
            (Context => Context,
             Block   => To_Internal (Message (MIT'Val (MIT'Pos (Message'First) + I * Block_Len) ..
                                              MIT'Val (MIT'Pos (Message'First) + I * Block_Len + Block_Len - 1))));
      end loop;

      Temp (Temp'First .. MIT'Val (MIT'Pos (Temp'First) + Partial_Bytes - 1)) :=
         Message (MIT'Val (MIT'Pos (Message'First) + Block_Len * Full_Blocks) ..
                  MIT'Val (MIT'Pos (Message'First) + Block_Len * Full_Blocks + Partial_Bytes - 1));

      Internal.HMAC_SHA384.Context_Finalize
         (Context => Context,
          Block   => To_Internal (Temp),
          Length  => 8 * Internal.SHA512.Block_Length_Type (Partial_Bytes));

      return To_Public (Internal.HMAC_SHA384.Get_Prf (Context)) (HIT'First .. HIT'Val (HIT'Pos (HIT'First) + Output_Length - 1));

   end HMAC_SHA384_Generic;

   -----------------
   -- HMAC_SHA512 --
   -----------------

   generic
      type Key_Index_Type is (<>);
      type Key_Elem_Type is (<>);
      type Key_Type is array (Key_Index_Type range <>) of Key_Elem_Type;
      type Message_Index_Type is (<>);
      type Message_Elem_Type is (<>);
      type Message_Type is array (Message_Index_Type range <>) of Message_Elem_Type;
      type Hash_Index_Type is (<>);
      type Hash_Elem_Type is (<>);
      type Hash_Type is array (Hash_Index_Type range <>) of Hash_Elem_Type;
   function HMAC_SHA512_Generic
     (Key           : Key_Type;
      Message       : Message_Type;
      Output_Length : Natural) return Hash_Type;

   function HMAC_SHA512_Generic
     (Key           : Key_Type;
      Message       : Message_Type;
      Output_Length : Natural) return Hash_Type
   is
      subtype MIT is Message_Index_Type;
      subtype HIT is Hash_Index_Type;
      subtype KIT is Key_Index_Type;

      use type Internal.SHA512.Block_Length_Type;

      Block_Len : constant := 128;
      subtype SHA512_Block_Type is
         Message_Type (MIT'First .. MIT'Val (MIT'Pos (MIT'First) + Block_Len - 1));
      function To_Internal is new Ada.Unchecked_Conversion (SHA512_Block_Type, Internal.SHA512.Block_Type);

      Hash_Len : constant := 64;
      subtype SHA512_Hash_Type is
         Hash_Type (HIT'First .. HIT'Val (HIT'Pos (HIT'First) + Hash_Len - 1));
      function To_Public_512 is new Ada.Unchecked_Conversion (Internal.SHA512.SHA512_Hash_Type, SHA512_Hash_Type);

      Full_Blocks   : constant Natural := Message'Length / Block_Len;
      Partial_Bytes : constant Natural := Message'Length - Full_Blocks * Block_Len;

      Context  : Internal.HMAC_SHA512.Context_Type;
      Temp     : SHA512_Block_Type;

      subtype Full_Key_Type is Key_Type (KIT'First .. KIT'Val (KIT'Pos (KIT'First) + Block_Len - 1));
      Full_Key : Full_Key_Type;
      function To_Internal is new Ada.Unchecked_Conversion (Full_Key_Type, Internal.SHA512.Block_Type);

      function Hash_Key is new LSC.SHA2_Generic.Hash
         (Key_Index_Type, Key_Elem_Type, Key_Type,
          Key_Index_Type, Key_Elem_Type, Key_Type);
   begin

      if Key'Length <= Block_Len
      then
         Full_Key (Full_Key'First .. KIT'Val (KIT'Pos (Full_Key'First) + Key'Length - 1)) := Key;
      else
         Full_Key (Full_Key'First .. KIT'Val (KIT'Pos (Full_Key'First) + Hash_Len - 1)) := Hash_Key (LSC.SHA2_Generic.SHA512, Key);
      end if;

      Context := Internal.HMAC_SHA512.Context_Init (To_Internal (Full_Key));

      for I in 0 .. Full_Blocks - 1
      loop
         Internal.HMAC_SHA512.Context_Update
            (Context => Context,
             Block   => To_Internal (Message (MIT'Val (MIT'Pos (Message'First) + I * Block_Len) ..
                                              MIT'Val (MIT'Pos (Message'First) + I * Block_Len + Block_Len - 1))));
      end loop;

      Temp (Temp'First .. MIT'Val (MIT'Pos (Temp'First) + Partial_Bytes - 1)) :=
         Message (MIT'Val (MIT'Pos (Message'First) + Block_Len * Full_Blocks) ..
                  MIT'Val (MIT'Pos (Message'First) + Block_Len * Full_Blocks + Partial_Bytes - 1));

      Internal.HMAC_SHA512.Context_Finalize
         (Context => Context,
          Block   => To_Internal (Temp),
          Length  => 8 * Internal.SHA512.Block_Length_Type (Partial_Bytes));

      return To_Public_512 (Internal.HMAC_SHA512.Get_Prf (Context)) (HIT'First .. HIT'Val (HIT'Pos (HIT'First) + Output_Length - 1));

   end HMAC_SHA512_Generic;

   ----------
   -- HMAC --
   ----------

   function HMAC
     (Algorithm  : SHA2_Generic.Algorithm_Type;
      Key        : Key_Type;
      Message    : Message_Type;
      Output_Len : Natural := 16) return Hash_Type
   is
      function HMAC_SHA256 is new HMAC_SHA256_Generic
         (Key_Index_Type, Key_Elem_Type, Key_Type,
          Message_Index_Type, Message_Elem_Type, Message_Type,
          Hash_Index_Type, Hash_Elem_Type, Hash_Type);

      function HMAC_SHA384 is new HMAC_SHA384_Generic
         (Key_Index_Type, Key_Elem_Type, Key_Type,
          Message_Index_Type, Message_Elem_Type, Message_Type,
          Hash_Index_Type, Hash_Elem_Type, Hash_Type);

      function HMAC_SHA512 is new HMAC_SHA512_Generic
         (Key_Index_Type, Key_Elem_Type, Key_Type,
          Message_Index_Type, Message_Elem_Type, Message_Type,
          Hash_Index_Type, Hash_Elem_Type, Hash_Type);
   begin
      case Algorithm is
         when SHA2_Generic.SHA256 => return HMAC_SHA256 (Key, Message, Output_Len);
         when SHA2_Generic.SHA384 => return HMAC_SHA384 (Key, Message, Output_Len);
         when SHA2_Generic.SHA512 => return HMAC_SHA512 (Key, Message, Output_Len);
      end case;
   end HMAC;

end LSC.SHA2_Generic.HMAC;
