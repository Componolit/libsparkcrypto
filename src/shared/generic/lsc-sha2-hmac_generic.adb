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
with LSC.Internal.SHA256;
with LSC.Internal.SHA512;
with LSC.Internal.Convert_HMAC;
with LSC.SHA2_Generic;

package body LSC.SHA2.HMAC_Generic
is

   -----------------
   -- HMAC_SHA256 --
   -----------------

   function HMAC_SHA256
     (Key           : Key_Type;
      Message       : Message_Type) return Hash_Type
   is
      subtype Internal_Key_Index is Key_Index_Type range Key'First .. Key'Last;
      subtype Internal_Key_Type is Key_Type (Internal_Key_Index);

      function Hash_Key is new LSC.SHA2_Generic.Hash_SHA256
         (Key_Index_Type, Key_Elem_Type, Key_Type,
          Internal_Key_Index, Key_Elem_Type, Internal_Key_Type);

      function HMAC_Internal is new Internal.Convert_HMAC.HMAC_Generic
         (Block_Len                  => Internal.SHA256.Block_Size / 8,
          Hash_Len                   => 32,
          Key_Index_Type             => Key_Index_Type,
          Key_Elem_Type              => Key_Elem_Type,
          Key_Type                   => Key_Type,
          Message_Index_Type         => Message_Index_Type,
          Message_Elem_Type          => Message_Elem_Type,
          Message_Type               => Message_Type,
          Hash_Index_Type            => Hash_Index_Type,
          Hash_Elem_Type             => Hash_Elem_Type,
          Hash_Type                  => Hash_Type,
          Internal_Context_Type      => Internal.HMAC_SHA256.Context_Type,
          Internal_Block_Type        => Internal.SHA256.Block_Type,
          Internal_Block_Length_Type => Internal.SHA256.Block_Length_Type,
          Internal_Hash_Type         => Internal.SHA256.SHA256_Hash_Type,
          Context_Init               => Internal.HMAC_SHA256.Context_Init,
          Context_Update             => Internal.HMAC_SHA256.Context_Update,
          Context_Finalize           => Internal.HMAC_SHA256.Context_Finalize,
          Get_Auth                   => Internal.HMAC_SHA256.Get_Prf,
          Hash_Key                   => Hash_Key);
   begin
      return HMAC_Internal (Key, Message);
   end HMAC_SHA256;

   -----------------
   -- HMAC_SHA384 --
   -----------------

   function HMAC_SHA384
     (Key           : Key_Type;
      Message       : Message_Type) return Hash_Type
   is
      subtype Internal_Key_Index is Key_Index_Type range Key'First .. Key'Last;
      subtype Internal_Key_Type is Key_Type (Internal_Key_Index);

      function Hash_Key is new LSC.SHA2_Generic.Hash_SHA384
         (Key_Index_Type, Key_Elem_Type, Key_Type,
          Internal_Key_Index, Key_Elem_Type, Internal_Key_Type);

      function Hash_Key_SHA384 (Key : Key_Type) return Internal_Key_Type is (Hash_Key (Key));

      function HMAC_Internal is new Internal.Convert_HMAC.HMAC_Generic
         (Block_Len                  => 128,
          Hash_Len                   => 48,
          Key_Index_Type             => Key_Index_Type,
          Key_Elem_Type              => Key_Elem_Type,
          Key_Type                   => Key_Type,
          Message_Index_Type         => Message_Index_Type,
          Message_Elem_Type          => Message_Elem_Type,
          Message_Type               => Message_Type,
          Hash_Index_Type            => Hash_Index_Type,
          Hash_Elem_Type             => Hash_Elem_Type,
          Hash_Type                  => Hash_Type,
          Internal_Context_Type      => Internal.HMAC_SHA384.Context_Type,
          Internal_Block_Type        => Internal.SHA512.Block_Type,
          Internal_Block_Length_Type => Internal.SHA512.Block_Length_Type,
          Internal_Hash_Type         => Internal.SHA512.SHA384_Hash_Type,
          Context_Init               => Internal.HMAC_SHA384.Context_Init,
          Context_Update             => Internal.HMAC_SHA384.Context_Update,
          Context_Finalize           => Internal.HMAC_SHA384.Context_Finalize,
          Get_Auth                   => Internal.HMAC_SHA384.Get_Prf,
          Hash_Key                   => Hash_Key_SHA384);
   begin
      return HMAC_Internal (Key, Message);
   end HMAC_SHA384;

   -----------------
   -- HMAC_SHA512 --
   -----------------

   function HMAC_SHA512
     (Key           : Key_Type;
      Message       : Message_Type) return Hash_Type
   is
      subtype Internal_Key_Index is Key_Index_Type range Key'First .. Key'Last;
      subtype Internal_Key_Type is Key_Type (Internal_Key_Index);

      function Hash_Key is new LSC.SHA2_Generic.Hash_SHA512
         (Key_Index_Type, Key_Elem_Type, Key_Type,
          Internal_Key_Index, Key_Elem_Type, Internal_Key_Type);

      function Hash_Key_SHA512 (Key : Key_Type) return Internal_Key_Type is (Hash_Key (Key));

      function HMAC_Internal is new Internal.Convert_HMAC.HMAC_Generic
         (Block_Len                  => 128,
          Hash_Len                   => 64,
          Key_Index_Type             => Key_Index_Type,
          Key_Elem_Type              => Key_Elem_Type,
          Key_Type                   => Key_Type,
          Message_Index_Type         => Message_Index_Type,
          Message_Elem_Type          => Message_Elem_Type,
          Message_Type               => Message_Type,
          Hash_Index_Type            => Hash_Index_Type,
          Hash_Elem_Type             => Hash_Elem_Type,
          Hash_Type                  => Hash_Type,
          Internal_Context_Type      => Internal.HMAC_SHA512.Context_Type,
          Internal_Block_Type        => Internal.SHA512.Block_Type,
          Internal_Block_Length_Type => Internal.SHA512.Block_Length_Type,
          Internal_Hash_Type         => Internal.SHA512.SHA512_Hash_Type,
          Context_Init               => Internal.HMAC_SHA512.Context_Init,
          Context_Update             => Internal.HMAC_SHA512.Context_Update,
          Context_Finalize           => Internal.HMAC_SHA512.Context_Finalize,
          Get_Auth                   => Internal.HMAC_SHA512.Get_Prf,
          Hash_Key                   => Hash_Key_SHA512);
   begin
      return HMAC_Internal (Key, Message);
   end HMAC_SHA512;

end LSC.SHA2.HMAC_Generic;
