-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- @author Alexander Senier
-- @date   2019-01-21
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

with LSC.Internal.SHA256;
with LSC.Internal.SHA512;
with LSC.Internal.Convert_Hash;

package body LSC.SHA2_Generic is

   -----------------
   -- Hash_SHA256 --
   -----------------

   function Hash_SHA256 (Message : Message_Type) return Hash_Type
   is
      function Hash_Internal is new Internal.Convert_Hash.Hash
         (64,
          Message_Index_Type,
          Message_Elem_Type,
          Message_Type,
          Hash_Index_Type,
          Hash_Elem_Type,
          Hash_Type,
          Internal.SHA256.Context_Type,
          Internal.SHA256.Block_Type,
          Internal.SHA256.Block_Length_Type,
          Internal.SHA256.SHA256_Hash_Type,
          Internal.SHA256.SHA256_Context_Init,
          Internal.SHA256.Context_Update,
          Internal.SHA256.Context_Finalize,
          Internal.SHA256.SHA256_Get_Hash);
   begin
      return Hash_Internal (Message);
   end Hash_SHA256;

   -----------------
   -- Hash_SHA384 --
   -----------------

   function Hash_SHA384 (Message : Message_Type) return Hash_Type
   is
      function Hash_Internal is new Internal.Convert_Hash.Hash
         (128,
          Message_Index_Type,
          Message_Elem_Type,
          Message_Type,
          Hash_Index_Type,
          Hash_Elem_Type,
          Hash_Type,
          Internal.SHA512.Context_Type,
          Internal.SHA512.Block_Type,
          Internal.SHA512.Block_Length_Type,
          Internal.SHA512.SHA384_Hash_Type,
          Internal.SHA512.SHA384_Context_Init,
          Internal.SHA512.Context_Update,
          Internal.SHA512.Context_Finalize,
          Internal.SHA512.SHA384_Get_Hash);
   begin
      return Hash_Internal (Message);
   end Hash_SHA384;

   -----------------
   -- Hash_SHA512 --
   -----------------

   function Hash_SHA512 (Message : Message_Type) return Hash_Type
   is
      function Hash_Internal is new Internal.Convert_Hash.Hash
         (128,
          Message_Index_Type,
          Message_Elem_Type,
          Message_Type,
          Hash_Index_Type,
          Hash_Elem_Type,
          Hash_Type,
          Internal.SHA512.Context_Type,
          Internal.SHA512.Block_Type,
          Internal.SHA512.Block_Length_Type,
          Internal.SHA512.SHA512_Hash_Type,
          Internal.SHA512.SHA512_Context_Init,
          Internal.SHA512.Context_Update,
          Internal.SHA512.Context_Finalize,
          Internal.SHA512.SHA512_Get_Hash);
   begin
      return Hash_Internal (Message);
   end Hash_SHA512;

end LSC.SHA2_Generic;
